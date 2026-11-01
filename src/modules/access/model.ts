import type { MongoAbility } from "@casl/ability";
import type { Context } from "elysia";
import { t } from "elysia";
import type { Auth } from "../../lib/auth";

// ============================================================================
// Core Access Types
// ============================================================================

/** The ability type produced by CASL with MongoDB-style conditions. */
export type AppAbility = MongoAbility;

/**
 * A permission rule that maps to a CASL raw rule.
 * `conditions` may contain `${user.*}` or `${env.*}` placeholders for ABAC.
 */
export interface RuleDefinition {
  /** Action name(s) e.g. "read", "update", "create", or "manage" for all. */
  action: string | string[];
  /** Subject name(s) e.g. "Post", "User", or "all" for every subject. */
  subject: string | string[];
  /** MongoDB query conditions with optional ${user.id} templates. */
  conditions?: Record<string, unknown>;
  /** Restrict the rule to specific fields. */
  fields?: string[];
  /** When true, this is an explicit denial (cannot). */
  inverted?: boolean;
  /** Explanation surfaced in ForbiddenError messages. */
  reason?: string;
}

/** The authenticated caller resolved from session, JWT, or headers. */
export interface Principal {
  id: string;
  roles?: string[];
  attributes?: Record<string, unknown>;
}

/** Request/environment attributes for ABAC (${env.<name>}). */
export type Environment = Record<string, unknown>;

/** RBAC role definition with parent role inheritance. */
export interface RoleRecord {
  name: string;
  description?: string;
  parents: string[];
  rules: RuleDefinition[];
}

/** ABAC policy definition applied dynamically based on target matching. */
export interface PolicyRecord {
  id: string;
  name: string;
  enabled: boolean;
  priority: number;
  target?: Record<string, unknown>;
  rules: RuleDefinition[];
}

/** ACL direct user grant or denial override. */
export interface GrantRecord {
  id: string;
  userId: string;
  rule: RuleDefinition;
  expiresAt?: Date | null;
}

// ============================================================================
// Errors
// ============================================================================

export class AccessConfigError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "AccessConfigError";
  }
}

export class UnresolvedPlaceholderError extends Error {
  constructor(readonly path: string) {
    super(`Unresolved placeholder: \${${path}}`);
    this.name = "UnresolvedPlaceholderError";
  }
}

// ============================================================================
// Input & Options Types
// ============================================================================

export interface RoleInput {
  name: string;
  description?: string;
  parents?: string[];
  rules?: RuleDefinition[];
}

export interface PolicyInput {
  name: string;
  target?: Record<string, unknown>;
  rules: RuleDefinition[];
  priority?: number;
  enabled?: boolean;
}

export interface GrantInput {
  action: string | string[];
  subject: string | string[];
  resourceId?: string | number;
  idField?: string;
  conditions?: Record<string, unknown>;
  fields?: string[];
  reason?: string;
  expiresAt?: Date | null;
}

export interface AccessPluginOptions {
  auth?: Auth;
  resolvePrincipal?: (context: Context) => Principal | null | Promise<Principal | null>;
  resolveEnv?: (context: Context) => Environment | Promise<Environment>;
  anonymousRole?: string;
}

// ============================================================================
// Elysia Validation Schemas (Single Source of Truth)
// ============================================================================

export const AccessModel = {
  ruleDefinition: t.Object({
    action: t.Union([t.String(), t.Array(t.String())]),
    subject: t.Union([t.String(), t.Array(t.String())]),
    conditions: t.Optional(t.Record(t.String(), t.Any())),
    fields: t.Optional(t.Array(t.String())),
    inverted: t.Optional(t.Boolean()),
    reason: t.Optional(t.String()),
  }),

  defineRoleBody: t.Object({
    name: t.String({ minLength: 1, maxLength: 64 }),
    description: t.Optional(t.String()),
    parents: t.Optional(t.Array(t.String())),
    rules: t.Optional(
      t.Array(
        t.Object({
          action: t.Union([t.String(), t.Array(t.String())]),
          subject: t.Union([t.String(), t.Array(t.String())]),
          conditions: t.Optional(t.Record(t.String(), t.Any())),
          fields: t.Optional(t.Array(t.String())),
          inverted: t.Optional(t.Boolean()),
          reason: t.Optional(t.String()),
        })
      )
    ),
  }),

  definePolicyBody: t.Object({
    name: t.String({ minLength: 1 }),
    priority: t.Optional(t.Integer()),
    enabled: t.Optional(t.Boolean()),
    target: t.Optional(t.Record(t.String(), t.Any())),
    rules: t.Array(
      t.Object({
        action: t.Union([t.String(), t.Array(t.String())]),
        subject: t.Union([t.String(), t.Array(t.String())]),
        conditions: t.Optional(t.Record(t.String(), t.Any())),
        fields: t.Optional(t.Array(t.String())),
        inverted: t.Optional(t.Boolean()),
        reason: t.Optional(t.String()),
      })
    ),
  }),

  grantBody: t.Object({
    action: t.Union([t.String(), t.Array(t.String())]),
    subject: t.Union([t.String(), t.Array(t.String())]),
    resourceId: t.Optional(t.Union([t.String(), t.Number()])),
    conditions: t.Optional(t.Record(t.String(), t.Any())),
    expiresAt: t.Optional(t.Nullable(t.Date())),
    reason: t.Optional(t.String()),
  }),

  checkPermissionBody: t.Object({
    action: t.String(),
    subject: t.String(),
    field: t.Optional(t.String()),
    attributes: t.Optional(t.Record(t.String(), t.Any())),
  }),

  checkPermissionResponse: t.Object({
    allowed: t.Boolean(),
    action: t.String(),
    subject: t.String(),
    userId: t.String(),
  }),

  successResponse: t.Object({
    success: t.Boolean(),
    message: t.Optional(t.String()),
  }),

  errorResponse: t.Object({
    error: t.String(),
    message: t.Optional(t.String()),
  }),
};

export type DefineRoleBody = typeof AccessModel.defineRoleBody.static;
export type DefinePolicyBody = typeof AccessModel.definePolicyBody.static;
export type GrantBody = typeof AccessModel.grantBody.static;
export type CheckPermissionBody = typeof AccessModel.checkPermissionBody.static;
