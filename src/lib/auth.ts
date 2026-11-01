import { betterAuth } from "better-auth";
import { prismaAdapter } from "@better-auth/prisma-adapter";
import { bearer } from "better-auth/plugins";
import { prisma } from "./prisma";
import type { PrismaClient } from "../generated/prisma/client";

export function createAuth(prismaClient: PrismaClient = prisma) {
  return betterAuth({
    database: prismaAdapter(prismaClient, {
      provider: "postgresql",
    }),
    emailAndPassword: {
      enabled: true,
    },
    // Supports both session cookies and Authorization: Bearer <token> headers
    plugins: [bearer()],
    secret: process.env.BETTER_AUTH_SECRET || "dev-secret-at-least-32-chars-find-cat-ely",
  });
}

const isPlaceholderDb =
  !process.env.DATABASE_URL ||
  process.env.DATABASE_URL.includes("johndoe:randompassword") ||
  process.env.USE_MEMORY_STORE === "true";

export const auth =
  process.env.DATABASE_URL && !isPlaceholderDb
    ? createAuth(prisma)
    : (null as unknown as ReturnType<typeof createAuth>);

export type Auth = ReturnType<typeof createAuth>;
