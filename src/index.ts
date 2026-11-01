import { openapi } from "@elysia/openapi";
import { Elysia } from "elysia";
import { auth } from "./lib/auth";
import { prisma } from "./lib/prisma";
import {
  AccessManager,
  MemoryAccessStore,
  PrismaAccessStore,
  access,
  createAccessController,
} from "./modules/access";
import { authController } from "./modules/auth";
import { createUserController } from "./modules/user";
import { createPostController } from "./modules/post";

// Fallback to Memory store if database is placeholder or not configured
const isPlaceholderDb =
  !process.env.DATABASE_URL ||
  process.env.DATABASE_URL.includes("johndoe:randompassword") ||
  process.env.USE_MEMORY_STORE === "true";

export const isDatabaseConnected = !isPlaceholderDb && !!prisma;

const store = isDatabaseConnected
  ? new PrismaAccessStore(prisma)
  : new MemoryAccessStore();

export const accessManager = new AccessManager({ store });

// Seed basic roles for demonstration
async function bootstrap() {
  try {
    await accessManager.rbac.defineRole({
      name: "viewer",
      description: "Can read public posts",
      rules: [{ action: "read", subject: "Post" }],
    });

    await accessManager.rbac.defineRole({
      name: "editor",
      description: "Can create and update own posts (ABAC)",
      parents: ["viewer"],
      rules: [
        {
          action: ["create", "update"],
          subject: "Post",
          conditions: { authorId: "${user.id}" },
        },
      ],
    });

    await accessManager.rbac.defineRole({
      name: "admin",
      description: "Superuser with full permissions",
      parents: ["editor"],
      rules: [{ action: "manage", subject: "all" }],
    });
  } catch (err) {
    console.warn("Access roles already initialized or database not ready:", err);
  }
}

bootstrap();

export const accessPlugin = access(accessManager, {
  auth: auth ?? undefined,
  anonymousRole: "viewer",
});

export const app = new Elysia()
  .use(
    openapi({
      documentation: {
        info: {
          title: "Find Cat Elysia API",
          description:
            "Production Elysia.js API featuring Better Auth & CASL ABAC/ACL/RBAC Engine",
          version: "1.0.0",
        },
        tags: [
          { name: "Authentication", description: "Better Auth endpoints & sessions" },
          { name: "Users", description: "User profiles and RBAC role assignments" },
          { name: "Posts", description: "Posts protected by CASL ABAC and ACL" },
          { name: "Access Control", description: "Dynamic RBAC, ABAC, and ACL administrative controls" },
        ],
      },
    })
  )
  .use(accessPlugin)
  .get("/", () => ({
    name: "Find Cat Elysia API",
    version: "1.0.0",
    docs: "/swagger",
    modules: {
      auth: "/auth",
      users: "/users",
      posts: "/posts",
      access: "/access",
    },
  }))
  .get("/health", () => ({
    status: "ok",
    database: prisma ? "postgresql" : "in-memory",
    timestamp: new Date().toISOString(),
  }))
  // Feature Controllers (Elysia instances as controllers)
  .use(authController)
  .use(createUserController(accessManager, accessPlugin))
  .use(createPostController(accessPlugin))
  .use(createAccessController(accessManager, accessPlugin));


const port = Number(process.env.PORT) || 3000;
app.listen(port);

console.log(
  `🦊 Elysia is running at http://${app.server?.hostname}:${app.server?.port}`
);

