import { Elysia } from "elysia";
import { UserModel } from "./model";
import { UserService } from "./service";
import { createAccessPlugin, type AccessManager, type AccessPlugin } from "../access";

/**
 * User Controller factory.
 * Takes the AccessManager and accessPlugin instances and returns an Elysia controller.
 */
export const createUserController = (
  accessManager: AccessManager,
  accessPlugin: AccessPlugin = createAccessPlugin(accessManager)
) =>
  new Elysia({ prefix: "/users" })
    .use(accessPlugin)
    // Current authenticated user profile
    .get(
      "/me",
      async ({ principal, status }) => {
        const profile = await UserService.getProfile(principal!.id, accessManager);
        if (!profile) {
          return status(404, { error: "NotFound", message: "User not found" });
        }
        return profile;
      },
      {
        auth: true,
        response: {
          200: UserModel.user,
          404: UserModel.errorResponse,
        },
        detail: {
          tags: ["Users"],
          summary: "Get current user profile and assigned roles",
        },
      }
    )

    // List all users (Protected by RBAC: requires read User)
    .get(
      "/",
      async () => {
        return UserService.listUsers(accessManager);
      },
      {
        auth: true,
        can: ["read", "User"],
        response: {
          200: UserModel.userList,
        },
        detail: {
          tags: ["Users"],
          summary: "List all users (Admin/Manager role required)",
        },
      }
    )

    // Assign role to user (Protected by RBAC: requires manage all)
    .post(
      "/:id/roles",
      async ({ params: { id }, body }) => {
        return UserService.assignRole(id, body.role, accessManager);
      },
      {
        auth: true,
        can: ["manage", "all"],
        body: UserModel.assignRoleBody,
        response: {
          200: UserModel.successResponse,
        },
        detail: {
          tags: ["Users"],
          summary: "Assign an RBAC role to a user (Admin only)",
        },
      }
    )

    // Revoke role from user (Protected by RBAC: requires manage all)
    .delete(
      "/:id/roles/:role",
      async ({ params: { id, role } }) => {
        return UserService.revokeRole(id, role, accessManager);
      },
      {
        auth: true,
        can: ["manage", "all"],
        response: {
          200: UserModel.successResponse,
        },
        detail: {
          tags: ["Users"],
          summary: "Revoke an RBAC role from a user (Admin only)",
        },
      }
    );
