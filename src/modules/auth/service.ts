import { auth } from "../../lib/auth";
import type { SignUpBody, SignInBody } from "./model";

/**
 * Decoupled business logic service for Authentication.
 * Handles interaction with Better Auth without coupling to Elysia Context.
 */
export abstract class AuthService {
  static async signUp(body: SignUpBody, headers: Headers) {
    if (!auth) {
      throw new Error("Authentication database is not configured");
    }

    const res = await auth.api.signUpEmail({
      body: {
        email: body.email,
        password: body.password,
        name: body.name,
      },
      headers,
    });

    return res;
  }

  static async signIn(body: SignInBody, headers: Headers) {
    if (!auth) {
      throw new Error("Authentication database is not configured");
    }

    const res = await auth.api.signInEmail({
      body: {
        email: body.email,
        password: body.password,
      },
      headers,
    });

    return res;
  }

  static async getSession(headers: Headers) {
    if (!auth) return null;

    const session = await auth.api.getSession({
      headers,
    });

    return session;
  }

  static async signOut(headers: Headers) {
    if (!auth) return { success: true };

    await auth.api.signOut({
      headers,
    });

    return { success: true };
  }
}
