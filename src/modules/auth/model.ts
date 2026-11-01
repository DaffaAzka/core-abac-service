import { t } from "elysia";

export const AuthModel = {
  signUpBody: t.Object({
    email: t.String({ format: "email" }),
    password: t.String({ minLength: 8 }),
    name: t.String({ minLength: 2 }),
  }),

  signInBody: t.Object({
    email: t.String({ format: "email" }),
    password: t.String({ minLength: 1 }),
  }),

  user: t.Object({
    id: t.String(),
    email: t.String(),
    name: t.String(),
    emailVerified: t.Boolean(),
    image: t.Optional(t.Nullable(t.String())),
    createdAt: t.Date(),
    updatedAt: t.Date(),
  }),

  session: t.Object({
    id: t.String(),
    token: t.String(),
    userId: t.String(),
    expiresAt: t.Date(),
  }),

  authResponse: t.Object({
    user: t.Object({
      id: t.String(),
      email: t.String(),
      name: t.String(),
    }),
    token: t.Optional(t.Nullable(t.String())),
  }),

  sessionResponse: t.Object({
    user: t.Object({
      id: t.String(),
      email: t.String(),
      name: t.String(),
      emailVerified: t.Boolean(),
    }),
    session: t.Object({
      id: t.String(),
      token: t.String(),
      userId: t.String(),
      expiresAt: t.Date(),
    }),
  }),

  messageResponse: t.Object({
    message: t.String(),
  }),

  errorResponse: t.Object({
    error: t.String(),
    message: t.Optional(t.String()),
  }),
};

export type SignUpBody = typeof AuthModel.signUpBody.static;
export type SignInBody = typeof AuthModel.signInBody.static;
