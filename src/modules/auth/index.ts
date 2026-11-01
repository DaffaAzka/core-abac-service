import { Elysia } from "elysia";
import { AuthModel } from "./model";
import { AuthService } from "./service";
import { auth } from "../../lib/auth";

/**
 * Auth Controller (Elysia instance as controller).
 * Handles HTTP routing, input validation and response shaping.
 */
export const authController = new Elysia({ prefix: "/auth" })
  // Also mount Better Auth native handler if initialized
  .mount(auth ? auth.handler : new Elysia().all("*", () => {}).fetch)

  // Explicit type-safe sign up endpoint
  .post(
    "/sign-up",
    async ({ body, request: { headers }, status }) => {
      try {
        const result = await AuthService.signUp(body, headers);
        return {
          user: {
            id: result.user.id,
            email: result.user.email,
            name: result.user.name,
          },
          token: result.token,
        };
      } catch (err: any) {
        return status(400, {
          error: "SignUpFailed",
          message: err.message || "Failed to create account",
        });
      }
    },
    {
      body: AuthModel.signUpBody,
      response: {
        200: AuthModel.authResponse,
        400: AuthModel.errorResponse,
      },
      detail: {
        tags: ["Authentication"],
        summary: "Register a new user account with email and password",
      },
    }
  )

  // Explicit type-safe sign in endpoint
  .post(
    "/sign-in",
    async ({ body, request: { headers }, status }) => {
      try {
        const result = await AuthService.signIn(body, headers);
        return {
          user: {
            id: result.user.id,
            email: result.user.email,
            name: result.user.name,
          },
          token: result.token,
        };
      } catch (err: any) {
        return status(400, {
          error: "SignInFailed",
          message: err.message || "Invalid credentials",
        });
      }
    },
    {
      body: AuthModel.signInBody,
      response: {
        200: AuthModel.authResponse,
        400: AuthModel.errorResponse,
      },
      detail: {
        tags: ["Authentication"],
        summary: "Sign in with email and password",
      },
    }
  )

  // Get current active session
  .get(
    "/session",
    async ({ request: { headers }, status }) => {
      const session = await AuthService.getSession(headers);
      if (!session) {
        return status(401, {
          error: "Unauthorized",
          message: "No active session found",
        });
      }
      return session;
    },
    {
      response: {
        200: AuthModel.sessionResponse,
        401: AuthModel.errorResponse,
      },
      detail: {
        tags: ["Authentication"],
        summary: "Get current authenticated session information",
      },
    }
  )

  // Sign out
  .post(
    "/sign-out",
    async ({ request: { headers } }) => {
      return AuthService.signOut(headers);
    },
    {
      detail: {
        tags: ["Authentication"],
        summary: "Sign out and invalidate session",
      },
    }
  );
