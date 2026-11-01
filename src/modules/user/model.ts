import { t } from "elysia";

export const UserModel = {
  user: t.Object({
    id: t.String(),
    email: t.String(),
    name: t.String(),
    emailVerified: t.Boolean(),
    image: t.Optional(t.Nullable(t.String())),
    createdAt: t.Date(),
    roles: t.Array(t.String()),
  }),

  userList: t.Array(
    t.Object({
      id: t.String(),
      email: t.String(),
      name: t.String(),
      roles: t.Array(t.String()),
    })
  ),

  assignRoleBody: t.Object({
    role: t.String({ minLength: 1, maxLength: 64 }),
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

export type AssignRoleBody = typeof UserModel.assignRoleBody.static;
