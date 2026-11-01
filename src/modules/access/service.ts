import {
  createMongoAbility,
  ForbiddenError,
  subject as asSubject,
  type RawRuleOf,
} from "@casl/ability";
import type { PrismaClient } from "../../generated/prisma/client";
import {
  AccessConfigError,
  UnresolvedPlaceholderError,
  type AppAbility,
  type CheckPermissionBody,
  type DefinePolicyBody,
  type DefineRoleBody,
  type Environment,
  type GrantBody,
  type GrantInput,
  type GrantRecord,
  type PolicyInput,
  type PolicyRecord,
  type Principal,
  type RoleInput,
  type RoleRecord,
  type RuleDefinition,
} from "./model";

type RawRule = RawRuleOf<AppAbility>;

// ============================================================================
// 1. Template Placeholder Interpolation & Validation
// ============================================================================

const WHOLE_PLACEHOLDER = /^\$\{\s*([\w.]+)\s*\}$/;
const PARTIAL_PLACEHOLDER = /\$\{\s*([\w.]+)\s*\}/g;
const FORBIDDEN_SEGMENTS = new Set(["__proto__", "prototype", "constructor"]);
const MAX_DEPTH = 8;
const NAME_REGEX = /^[A-Za-z0-9_.:-]{1,64}$/;

type Primitive = string | number | boolean;
const isPrimitive = (v: unknown): v is Primitive =>
  typeof v === "string" || typeof v === "number" || typeof v === "boolean";

function lookup(context: unknown, path: string): unknown {
  let current: unknown = context;
  for (const segment of path.split(".")) {
    if (
      FORBIDDEN_SEGMENTS.has(segment) ||
      current === null ||
      typeof current !== "object" ||
      !Object.prototype.hasOwnProperty.call(current, segment)
    ) {
      return undefined;
    }
    current = (current as Record<string, unknown>)[segment];
  }
  return current;
}

function resolveValue(context: unknown, path: string): Primitive | Primitive[] {
  const value = lookup(context, path);
  if (isPrimitive(value)) return value;
  if (Array.isArray(value) && value.every(isPrimitive)) return [...value];
  throw new UnresolvedPlaceholderError(path);
}

export function interpolate<T>(input: T, context: unknown, depth = 0): T {
  if (depth > MAX_DEPTH) {
    throw new AccessConfigError("Condition is nested too deeply");
  }
  if (typeof input === "string") {
    const whole = WHOLE_PLACEHOLDER.exec(input);
    if (whole) return resolveValue(context, whole[1]!) as T;
    return input.replace(PARTIAL_PLACEHOLDER, (_, path: string) => {
      const value = resolveValue(context, path);
      if (Array.isArray(value)) throw new UnresolvedPlaceholderError(path);
      return String(value);
    }) as T;
  }
  if (Array.isArray(input)) {
    return input.map((item) => interpolate(item, context, depth + 1)) as T;
  }
  if (input !== null && typeof input === "object") {
    const out: Record<string, unknown> = {};
    for (const [key, value] of Object.entries(input)) {
      if (FORBIDDEN_SEGMENTS.has(key)) {
        throw new AccessConfigError(`Forbidden key in condition: ${key}`);
      }
      out[key] = interpolate(value, context, depth + 1);
    }
    return out as T;
  }
  return input;
}

function assertSafeStructure(value: unknown, depth = 0): void {
  if (depth > MAX_DEPTH) {
    throw new AccessConfigError("Condition is nested too deeply");
  }
  if (Array.isArray(value)) {
    for (const item of value) assertSafeStructure(item, depth + 1);
  } else if (value !== null && typeof value === "object") {
    for (const [key, item] of Object.entries(value)) {
      if (FORBIDDEN_SEGMENTS.has(key)) {
        throw new AccessConfigError(`Forbidden key in condition: ${key}`);
      }
      assertSafeStructure(item, depth + 1);
    }
  }
}

export function validateConditions(conditions: unknown, label = "conditions"): void {
  if (conditions === null || typeof conditions !== "object" || Array.isArray(conditions)) {
    throw new AccessConfigError(`${label} must be an object`);
  }
  assertSafeStructure(conditions);
}

function assertNames(value: unknown, label: string): asserts value is string | string[] {
  const list = Array.isArray(value) ? value : [value];
  if (list.length === 0 || !list.every((v) => typeof v === "string" && NAME_REGEX.test(v))) {
    throw new AccessConfigError(
      `Rule ${label} must be a non-empty string (or array) matching ${NAME_REGEX}`
    );
  }
}

export function validateRule(rule: RuleDefinition): RuleDefinition {
  if (rule === null || typeof rule !== "object") {
    throw new AccessConfigError("Rule must be an object");
  }
  assertNames(rule.action, "action");
  assertNames(rule.subject, "subject");
  if (rule.fields !== undefined) {
    if (!Array.isArray(rule.fields) || !rule.fields.every((f) => typeof f === "string")) {
      throw new AccessConfigError("Rule fields must be an array of strings");
    }
  }
  if (rule.conditions !== undefined) {
    validateConditions(rule.conditions, "Rule conditions");
  }
  return rule;
}

// ============================================================================
// 2. CASL Ability Builder (RBAC -> ABAC -> ACL Precedence)
// ============================================================================

export function expandRoles(assigned: string[], roles: RoleRecord[]): RoleRecord[] {
  const byName = new Map(roles.map((r) => [r.name, r]));
  const ordered: RoleRecord[] = [];
  const done = new Set<string>();

  const visit = (name: string, path: Set<string>) => {
    if (done.has(name) || path.has(name)) return;
    const role = byName.get(name);
    if (!role) return;
    path.add(name);
    for (const parent of role.parents) visit(parent, path);
    path.delete(name);
    done.add(name);
    ordered.push(role);
  };

  for (const name of assigned) visit(name, new Set());
  return ordered;
}

export function toRawRule(def: RuleDefinition, context: unknown): RawRule | null {
  let conditions: Record<string, unknown> | undefined;
  try {
    conditions = def.conditions ? interpolate(def.conditions, context) : undefined;
  } catch (error) {
    if (!(error instanceof UnresolvedPlaceholderError)) throw error;
    if (!def.inverted) return null;
    conditions = undefined;
  }
  const raw: Record<string, unknown> = { action: def.action, subject: def.subject };
  if (conditions && Object.keys(conditions).length > 0) raw.conditions = conditions;
  if (def.fields?.length) raw.fields = def.fields;
  if (def.inverted) raw.inverted = true;
  if (def.reason) raw.reason = def.reason;
  return raw as unknown as RawRule;
}

const TARGET_SUBJECT = "__PolicyTarget__";

function matchesTarget(target: Record<string, unknown> | undefined, context: unknown): boolean {
  if (!target || Object.keys(target).length === 0) return true;
  let conditions: Record<string, unknown>;
  try {
    conditions = interpolate(target, context);
  } catch (error) {
    if (error instanceof UnresolvedPlaceholderError) return false;
    throw error;
  }
  const matcher = createMongoAbility([
    { action: "match", subject: TARGET_SUBJECT, conditions },
  ] as RawRule[]);
  return matcher.can("match", asSubject(TARGET_SUBJECT, context as object));
}

export interface BuildInput {
  principal: Principal;
  roles: RoleRecord[];
  assignedRoles: string[];
  policies: PolicyRecord[];
  grants: GrantRecord[];
  env?: Environment;
  now?: Date;
}

export function buildAbility(input: BuildInput): AppAbility {
  const { principal, env = {}, now = new Date() } = input;
  const roleRecords = expandRoles(input.assignedRoles, input.roles);

  const context = {
    user: {
      id: principal.id,
      roles: roleRecords.map((r) => r.name),
      attrs: principal.attributes ?? {},
    },
    env,
  };

  const rules: RawRule[] = [];
  const push = (defs: RuleDefinition[]) => {
    for (const def of defs) {
      const raw = toRawRule(def, context);
      if (raw) rules.push(raw);
    }
  };

  // 1. RBAC (Roles, parents evaluated before child so child rules take precedence)
  for (const role of roleRecords) push(role.rules);

  // 2. ABAC (Policies matching target, ordered by ascending priority)
  const policies = input.policies
    .filter((p) => p.enabled && matchesTarget(p.target, context))
    .sort((a, b) => a.priority - b.priority);
  for (const policy of policies) push(policy.rules);

  // 3. ACL (Direct user grants and explicit denials - highest precedence)
  for (const grant of input.grants) {
    if (grant.userId !== principal.id) continue;
    if (grant.expiresAt && grant.expiresAt.getTime() <= now.getTime()) continue;
    push([grant.rule]);
  }

  return createMongoAbility(rules);
}

// ============================================================================
// 3. Storage Layer: Interface & Implementations
// ============================================================================

export interface AccessStore {
  init?(): Promise<void>;
  close?(): Promise<void>;

  // RBAC
  listRoles(): Promise<RoleRecord[]>;
  upsertRole(role: RoleRecord): Promise<void>;
  deleteRole(name: string): Promise<boolean>;
  getUserRoles(userId: string): Promise<string[]>;
  assignRole(userId: string, role: string): Promise<void>;
  revokeRole(userId: string, role: string): Promise<boolean>;

  // ABAC
  listPolicies(): Promise<PolicyRecord[]>;
  upsertPolicy(policy: PolicyRecord): Promise<void>;
  deletePolicy(id: string): Promise<boolean>;

  // ACL
  listGrants(userId: string, now?: Date): Promise<GrantRecord[]>;
  addGrant(grant: GrantRecord): Promise<void>;
  removeGrant(id: string): Promise<boolean>;
}

export class MemoryAccessStore implements AccessStore {
  private roles = new Map<string, RoleRecord>();
  private userRoles = new Map<string, Set<string>>();
  private policies = new Map<string, PolicyRecord>();
  private grants = new Map<string, GrantRecord>();

  async listRoles() {
    return structuredClone([...this.roles.values()]);
  }

  async upsertRole(role: RoleRecord) {
    this.roles.set(role.name, structuredClone(role));
  }

  async deleteRole(name: string) {
    for (const set of this.userRoles.values()) set.delete(name);
    return this.roles.delete(name);
  }

  async getUserRoles(userId: string) {
    return [...(this.userRoles.get(userId) ?? [])];
  }

  async assignRole(userId: string, role: string) {
    const set = this.userRoles.get(userId) ?? new Set<string>();
    set.add(role);
    this.userRoles.set(userId, set);
  }

  async revokeRole(userId: string, role: string) {
    return this.userRoles.get(userId)?.delete(role) ?? false;
  }

  async listPolicies() {
    return structuredClone([...this.policies.values()]);
  }

  async upsertPolicy(policy: PolicyRecord) {
    this.policies.set(policy.id, structuredClone(policy));
  }

  async deletePolicy(id: string) {
    return this.policies.delete(id);
  }

  async listGrants(userId: string, now = new Date()) {
    return structuredClone(
      [...this.grants.values()].filter(
        (g) => g.userId === userId && (!g.expiresAt || g.expiresAt.getTime() > now.getTime())
      )
    );
  }

  async addGrant(grant: GrantRecord) {
    this.grants.set(grant.id, structuredClone(grant));
  }

  async removeGrant(id: string) {
    return this.grants.delete(id);
  }
}

export class PrismaAccessStore implements AccessStore {
  constructor(private readonly prisma: PrismaClient) {}

  async listRoles(): Promise<RoleRecord[]> {
    const rows = await this.prisma.accessRole.findMany({
      orderBy: { name: "asc" },
    });
    return rows.map((r) => ({
      name: r.name,
      description: r.description ?? undefined,
      parents: Array.isArray(r.parents) ? (r.parents as string[]) : [],
      rules: (r.rules as unknown as RuleDefinition[]) ?? [],
    }));
  }

  async upsertRole(role: RoleRecord): Promise<void> {
    await this.prisma.accessRole.upsert({
      where: { name: role.name },
      update: {
        description: role.description ?? null,
        parents: role.parents,
        rules: role.rules as any,
      },
      create: {
        name: role.name,
        description: role.description ?? null,
        parents: role.parents,
        rules: role.rules as any,
      },
    });
  }

  async deleteRole(name: string): Promise<boolean> {
    try {
      await this.prisma.accessRole.delete({ where: { name } });
      return true;
    } catch {
      return false;
    }
  }

  async getUserRoles(userId: string): Promise<string[]> {
    const rows = await this.prisma.accessUserRole.findMany({
      where: { userId },
      select: { role: true },
    });
    return rows.map((r) => r.role);
  }

  async assignRole(userId: string, role: string): Promise<void> {
    await this.prisma.accessUserRole.upsert({
      where: { userId_role: { userId, role } },
      update: {},
      create: { userId, role },
    });
  }

  async revokeRole(userId: string, role: string): Promise<boolean> {
    try {
      await this.prisma.accessUserRole.delete({
        where: { userId_role: { userId, role } },
      });
      return true;
    } catch {
      return false;
    }
  }

  async listPolicies(): Promise<PolicyRecord[]> {
    const rows = await this.prisma.accessPolicy.findMany({
      orderBy: [{ priority: "asc" }, { name: "asc" }],
    });
    return rows.map((r) => ({
      id: r.id,
      name: r.name,
      enabled: r.enabled,
      priority: r.priority,
      target: (r.target as Record<string, unknown> | null) ?? undefined,
      rules: (r.rules as unknown as RuleDefinition[]) ?? [],
    }));
  }

  async upsertPolicy(policy: PolicyRecord): Promise<void> {
    await this.prisma.accessPolicy.upsert({
      where: { id: policy.id },
      update: {
        name: policy.name,
        enabled: policy.enabled,
        priority: policy.priority,
        target: (policy.target as any) ?? null,
        rules: policy.rules as any,
      },
      create: {
        id: policy.id,
        name: policy.name,
        enabled: policy.enabled,
        priority: policy.priority,
        target: (policy.target as any) ?? null,
        rules: policy.rules as any,
      },
    });
  }

  async deletePolicy(id: string): Promise<boolean> {
    try {
      await this.prisma.accessPolicy.delete({ where: { id } });
      return true;
    } catch {
      return false;
    }
  }

  async listGrants(userId: string, now = new Date()): Promise<GrantRecord[]> {
    const rows = await this.prisma.accessGrant.findMany({
      where: {
        userId,
        OR: [{ expiresAt: null }, { expiresAt: { gt: now } }],
      },
      orderBy: [{ createdAt: "asc" }, { id: "asc" }],
    });
    return rows.map((r) => ({
      id: r.id,
      userId: r.userId,
      rule: r.rule as unknown as RuleDefinition,
      expiresAt: r.expiresAt,
    }));
  }

  async addGrant(grant: GrantRecord): Promise<void> {
    await this.prisma.accessGrant.upsert({
      where: { id: grant.id },
      update: {
        userId: grant.userId,
        rule: grant.rule as any,
        expiresAt: grant.expiresAt ?? null,
      },
      create: {
        id: grant.id,
        userId: grant.userId,
        rule: grant.rule as any,
        expiresAt: grant.expiresAt ?? null,
      },
    });
  }

  async removeGrant(id: string): Promise<boolean> {
    try {
      await this.prisma.accessGrant.delete({ where: { id } });
      return true;
    } catch {
      return false;
    }
  }
}

// ============================================================================
// 4. AccessManager Facade
// ============================================================================

export interface AccessManagerOptions {
  store: AccessStore;
  cacheTtlMs?: number;
}

export class AccessManager {
  readonly store: AccessStore;
  private readonly cacheTtlMs: number;
  private cache?: { roles: RoleRecord[]; policies: PolicyRecord[]; expires: number };
  private ready?: Promise<void>;

  constructor(options: AccessManagerOptions) {
    this.store = options.store;
    this.cacheTtlMs = options.cacheTtlMs ?? 5000;
  }

  init(): Promise<void> {
    this.ready ??= (this.store.init?.() ?? Promise.resolve()).catch((error) => {
      this.ready = undefined;
      throw error;
    });
    return this.ready;
  }

  invalidate(): void {
    this.cache = undefined;
  }

  private async definitions() {
    await this.init();
    const now = Date.now();
    if (this.cache && this.cache.expires > now) return this.cache;
    const [roles, policies] = await Promise.all([
      this.store.listRoles(),
      this.store.listPolicies(),
    ]);
    this.cache = { roles, policies, expires: now + this.cacheTtlMs };
    return this.cache;
  }

  readonly rbac = {
    defineRole: async (input: RoleInput): Promise<RoleRecord> => {
      if (!NAME_REGEX.test(input.name)) {
        throw new AccessConfigError(`Invalid role name: ${input.name}`);
      }
      const parents = [...new Set(input.parents ?? [])];
      for (const p of parents) {
        if (!NAME_REGEX.test(p)) throw new AccessConfigError(`Invalid parent role: ${p}`);
      }
      const rules = (input.rules ?? []).map(validateRule);
      const record: RoleRecord = {
        name: input.name,
        description: input.description,
        parents,
        rules,
      };
      await this.store.upsertRole(record);
      this.invalidate();
      return record;
    },

    removeRole: async (name: string): Promise<boolean> => {
      const removed = await this.store.deleteRole(name);
      if (removed) this.invalidate();
      return removed;
    },

    listRoles: async (): Promise<RoleRecord[]> => {
      const { roles } = await this.definitions();
      return roles;
    },

    assign: async (userId: string, roleName: string): Promise<void> => {
      if (!NAME_REGEX.test(roleName)) {
        throw new AccessConfigError(`Invalid role name: ${roleName}`);
      }
      const { roles } = await this.definitions();
      if (!roles.some((r) => r.name === roleName)) {
        throw new AccessConfigError(`Cannot assign unknown role: ${roleName}`);
      }
      await this.store.assignRole(userId, roleName);
    },

    revoke: async (userId: string, roleName: string): Promise<boolean> => {
      return this.store.revokeRole(userId, roleName);
    },

    rolesFor: async (userId: string): Promise<string[]> => {
      return this.store.getUserRoles(userId);
    },

    rolesOf: async (userId: string): Promise<string[]> => {
      return this.store.getUserRoles(userId);
    },
  };

  readonly abac = {
    definePolicy: async (input: PolicyInput): Promise<PolicyRecord> => {
      if (input.target) validateConditions(input.target, "Policy target");
      const rules = input.rules.map(validateRule);
      const id = input.name.toLowerCase().replace(/[^a-z0-9_.:-]/g, "-");
      const record: PolicyRecord = {
        id,
        name: input.name,
        enabled: input.enabled ?? true,
        priority: input.priority ?? 0,
        target: input.target,
        rules,
      };
      await this.store.upsertPolicy(record);
      this.invalidate();
      return record;
    },

    removePolicy: async (id: string): Promise<boolean> => {
      const removed = await this.store.deletePolicy(id);
      if (removed) this.invalidate();
      return removed;
    },

    listPolicies: async (): Promise<PolicyRecord[]> => {
      const { policies } = await this.definitions();
      return policies;
    },

    enable: async (id: string, enabled = true): Promise<void> => {
      const { policies } = await this.definitions();
      const policy = policies.find((p) => p.id === id);
      if (!policy) throw new AccessConfigError(`Policy ${id} does not exist`);
      await this.store.upsertPolicy({ ...policy, enabled });
      this.invalidate();
    },

    disable: (id: string) => this.abac.enable(id, false),
    setEnabled: (id: string, enabled: boolean) => this.abac.enable(id, enabled),
  };

  readonly acl = {
    grant: async (userId: string, input: GrantInput): Promise<GrantRecord> => {
      const rule = this.buildAclRule(input, false);
      const id = crypto.randomUUID();
      const record: GrantRecord = {
        id,
        userId,
        rule,
        expiresAt: input.expiresAt,
      };
      await this.store.addGrant(record);
      return record;
    },

    deny: async (userId: string, input: GrantInput): Promise<GrantRecord> => {
      const rule = this.buildAclRule(input, true);
      const id = crypto.randomUUID();
      const record: GrantRecord = {
        id,
        userId,
        rule,
        expiresAt: input.expiresAt,
      };
      await this.store.addGrant(record);
      return record;
    },

    revoke: async (grantId: string): Promise<boolean> => {
      return this.store.removeGrant(grantId);
    },

    list: async (userId: string): Promise<GrantRecord[]> => {
      return this.store.listGrants(userId);
    },
  };

  private buildAclRule(input: GrantInput, inverted: boolean): RuleDefinition {
    let conditions = input.conditions ? { ...input.conditions } : undefined;
    if (input.resourceId !== undefined) {
      const field = input.idField ?? "id";
      conditions = { ...conditions, [field]: input.resourceId };
    }
    const rule: RuleDefinition = {
      action: input.action,
      subject: input.subject,
      conditions,
      fields: input.fields,
      inverted: inverted ? true : undefined,
      reason: input.reason,
    };
    return validateRule(rule);
  }

  async abilityFor(principal: Principal, env?: Environment): Promise<AppAbility> {
    const [{ roles, policies }, storeRoles, grants] = await Promise.all([
      this.definitions(),
      this.store.getUserRoles(principal.id),
      this.store.listGrants(principal.id),
    ]);
    const assignedRoles = [...new Set([...(principal.roles ?? []), ...storeRoles])];
    return buildAbility({
      principal,
      roles,
      assignedRoles,
      policies,
      grants,
      env,
    });
  }

  async can(
    principal: Principal,
    action: string,
    subject: unknown,
    field?: string,
    env?: Environment
  ): Promise<boolean> {
    const ability = await this.abilityFor(principal, env);
    return ability.can(action as any, subject as any, field);
  }

  async authorize(
    principal: Principal,
    action: string,
    subject: unknown,
    field?: string,
    env?: Environment
  ): Promise<void> {
    const ability = await this.abilityFor(principal, env);
    ForbiddenError.from(ability).throwUnlessCan(action as any, subject as any, field);
  }
}

// ============================================================================
// 5. Decoupled Access Service (Controller Business Logic)
// ============================================================================

export abstract class AccessService {
  static async listRoles(manager: AccessManager) {
    return manager.rbac.listRoles();
  }

  static async defineRole(manager: AccessManager, data: DefineRoleBody) {
    return manager.rbac.defineRole({
      name: data.name,
      description: data.description,
      parents: data.parents,
      rules: data.rules as any,
    });
  }

  static async deleteRole(manager: AccessManager, name: string) {
    const deleted = await manager.rbac.removeRole(name);
    return { success: deleted, message: `Role ${name} deleted` };
  }

  static async listPolicies(manager: AccessManager) {
    return manager.abac.listPolicies();
  }

  static async definePolicy(manager: AccessManager, data: DefinePolicyBody) {
    return manager.abac.definePolicy({
      name: data.name,
      priority: data.priority,
      enabled: data.enabled,
      target: data.target,
      rules: data.rules as any,
    });
  }

  static async deletePolicy(manager: AccessManager, id: string) {
    const deleted = await manager.abac.removePolicy(id);
    return { success: deleted, message: `Policy ${id} deleted` };
  }

  static async listGrants(manager: AccessManager, userId: string) {
    return manager.acl.list(userId);
  }

  static async grant(manager: AccessManager, userId: string, data: GrantBody) {
    return manager.acl.grant(userId, {
      action: data.action,
      subject: data.subject,
      resourceId: data.resourceId,
      conditions: data.conditions,
      expiresAt: data.expiresAt,
      reason: data.reason,
    });
  }

  static async deny(manager: AccessManager, userId: string, data: GrantBody) {
    return manager.acl.deny(userId, {
      action: data.action,
      subject: data.subject,
      resourceId: data.resourceId,
      conditions: data.conditions,
      expiresAt: data.expiresAt,
      reason: data.reason,
    });
  }

  static async revokeGrant(manager: AccessManager, grantId: string) {
    const revoked = await manager.acl.revoke(grantId);
    return { success: revoked, message: `Grant ${grantId} revoked` };
  }

  static async checkPermission(
    manager: AccessManager,
    userId: string,
    data: CheckPermissionBody
  ) {
    const allowed = await manager.can(
      { id: userId, attributes: data.attributes },
      data.action,
      data.subject,
      data.field
    );

    return {
      allowed,
      action: data.action,
      subject: data.subject,
      userId,
    };
  }
}
