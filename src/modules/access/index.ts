import { createMongoAbility, ForbiddenError } from "@casl/ability";
import { Elysia, type Context } from "elysia";
import {
  AccessModel,
  type AccessPluginOptions,
  type AppAbility,
  type Principal,
} from "./model";
import { AccessManager, AccessService } from "./service";

// Re-export models, types, stores and CASL primitives
export * from "./model";
export * from "./service";
export { subject, ForbiddenError } from "@casl/ability";

/** Reserved principal id for anonymous requests */
export const ANONYMOUS_ID = "__anonymous__";

/**
 * Elysia plugin that integrates Better Auth and CASL access control.
 *
 * Exposes on every request context:
 * - `user`      - Better Auth user (or null)
 * - `session`   - Better Auth session (or null)
 * - `principal` - Standard access Principal (or null)
 * - `ability`   - CASL AppAbility instance with merged RBAC, ABAC, and ACL
 *
 * Route guard macros:
 * - `auth: true`            -> 401 Unauthorized when no user/principal
 * - `can: ["read", "Post"]` -> 403 Forbidden unless allowed by CASL ability
 */
export const createAccessPlugin = (
  manager: AccessManager,
  options: AccessPluginOptions = {}
) => {
  let plugin = new Elysia({ name: "access" });

  if (options.auth) {
    plugin = plugin.mount(options.auth.handler);
  }

  return plugin
    .onError({ as: "global" }, ({ error, set }) => {
      if (error instanceof ForbiddenError) {
        set.status = 403;
        return {
          error: "Forbidden",
          message: (error as ForbiddenError<AppAbility>).message,
        };
      }
    })
    .derive({ as: "global" }, async (context) => {
      let principal: Principal | null = null;
      let session: any = null;
      let user: any = null;

      if (options.auth) {
        try {
          const authSession = await options.auth.api.getSession({
            headers: (context as Context).request.headers,
          });
          if (authSession?.user) {
            session = authSession.session;
            user = authSession.user;
            principal = {
              id: user.id,
              roles: (user as any).role ? [(user as any).role] : [],
              attributes: {
                name: user.name,
                email: user.email,
                emailVerified: user.emailVerified,
                ...(user as any),
              },
            };
          }
        } catch {
          // Unauthenticated or database not reachable
        }
      }

      if (options.resolvePrincipal) {
        const resolved = await options.resolvePrincipal(context as Context);
        if (resolved) {
          principal = principal
            ? {
                ...principal,
                ...resolved,
                roles: [...new Set([...(principal.roles ?? []), ...(resolved.roles ?? [])])],
                attributes: { ...principal.attributes, ...resolved.attributes },
              }
            : resolved;
        }
      }

      const env = (await options.resolveEnv?.(context as Context)) ?? {};

      let ability: AppAbility;
      if (principal) {
        ability = await manager.abilityFor(principal, env);
      } else if (options.anonymousRole) {
        ability = await manager.abilityFor(
          { id: ANONYMOUS_ID, roles: [options.anonymousRole] },
          env
        );
      } else {
        ability = createMongoAbility([]);
      }

      return { user, session, principal, ability };
    })
    .macro({
      auth: (required: boolean) => ({
        beforeHandle({ principal, status }: any) {
          if (required && !principal) {
            return status(401, { error: "Unauthorized", message: "Authentication required" });
          }
        },
      }),
      can: (rule: [action: string, subject: string]) => ({
        beforeHandle({ ability, status }: any) {
          const [action, subject] = rule;
          if (!(ability as AppAbility).can(action, subject)) {
            return status(403, { error: "Forbidden", message: `Cannot ${action} ${subject}` });
          }
        },
      }),
    });
};

export const access = createAccessPlugin;
export type AccessPlugin = ReturnType<typeof createAccessPlugin>;

/**
 * Access Control Administration Controller (Elysia instance as controller).
 * Exposes management endpoints for RBAC roles, ABAC policies, and ACL grants.
 */
export const createAccessController = (
  manager: AccessManager,
  accessPlugin: AccessPlugin = createAccessPlugin(manager)
) =>
  new Elysia({ prefix: "/access" })
    .use(accessPlugin)
    // List all RBAC roles
    .get(
      "/roles",
      async () => {
        return AccessService.listRoles(manager);
      },
      {
        can: ["manage", "all"],
        detail: {
          tags: ["Access Control"],
          summary: "List all RBAC roles (Admin only)",
        },
      }
    )

    // Define / update RBAC role
    .post(
      "/roles",
      async ({ body }) => {
        return AccessService.defineRole(manager, body);
      },
      {
        can: ["manage", "all"],
        body: AccessModel.defineRoleBody,
        detail: {
          tags: ["Access Control"],
          summary: "Define or update an RBAC role with rules and parent inheritance",
        },
      }
    )

    // Delete RBAC role
    .delete(
      "/roles/:name",
      async ({ params: { name } }) => {
        return AccessService.deleteRole(manager, name);
      },
      {
        can: ["manage", "all"],
        detail: {
          tags: ["Access Control"],
          summary: "Delete an RBAC role",
        },
      }
    )

    // List all ABAC policies
    .get(
      "/policies",
      async () => {
        return AccessService.listPolicies(manager);
      },
      {
        can: ["manage", "all"],
        detail: {
          tags: ["Access Control"],
          summary: "List all ABAC policies (Admin only)",
        },
      }
    )

    // Define / update ABAC policy
    .post(
      "/policies",
      async ({ body }) => {
        return AccessService.definePolicy(manager, body);
      },
      {
        can: ["manage", "all"],
        body: AccessModel.definePolicyBody,
        detail: {
          tags: ["Access Control"],
          summary: "Define or update an ABAC policy with target queries and priorities",
        },
      }
    )

    // Delete ABAC policy
    .delete(
      "/policies/:id",
      async ({ params: { id } }) => {
        return AccessService.deletePolicy(manager, id);
      },
      {
        can: ["manage", "all"],
        detail: {
          tags: ["Access Control"],
          summary: "Delete an ABAC policy by ID",
        },
      }
    )

    // List ACL grants for user
    .get(
      "/grants/:userId",
      async ({ params: { userId } }) => {
        return AccessService.listGrants(manager, userId);
      },
      {
        can: ["manage", "all"],
        detail: {
          tags: ["Access Control"],
          summary: "List ACL grants and denials for a user",
        },
      }
    )

    // Add ACL grant to user
    .post(
      "/grants/:userId",
      async ({ params: { userId }, body }) => {
        return AccessService.grant(manager, userId, body);
      },
      {
        can: ["manage", "all"],
        body: AccessModel.grantBody,
        detail: {
          tags: ["Access Control"],
          summary: "Grant direct ACL permission to a user",
        },
      }
    )

    // Add ACL deny rule to user (explicit override)
    .post(
      "/grants/:userId/deny",
      async ({ params: { userId }, body }) => {
        return AccessService.deny(manager, userId, body);
      },
      {
        can: ["manage", "all"],
        body: AccessModel.grantBody,
        detail: {
          tags: ["Access Control"],
          summary: "Add explicit ACL denial override for a user",
        },
      }
    )

    // Revoke ACL grant
    .delete(
      "/grants/item/:grantId",
      async ({ params: { grantId } }) => {
        return AccessService.revokeGrant(manager, grantId);
      },
      {
        can: ["manage", "all"],
        detail: {
          tags: ["Access Control"],
          summary: "Revoke an individual ACL grant by ID",
        },
      }
    )

    // Check permission for a user
    .post(
      "/check",
      async ({ body, principal }) => {
        const targetUserId = principal?.id || "anonymous";
        return AccessService.checkPermission(manager, targetUserId, body);
      },
      {
        body: AccessModel.checkPermissionBody,
        response: {
          200: AccessModel.checkPermissionResponse,
        },
        detail: {
          tags: ["Access Control"],
          summary: "Test and check permission for current principal",
        },
      }
    );
