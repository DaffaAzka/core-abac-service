import { prisma } from "../../lib/prisma";
import type { AccessManager } from "../access";

/**
 * Decoupled business logic service for User management.
 */
export abstract class UserService {
  static async getProfile(userId: string, accessManager: AccessManager) {
    if (prisma) {
      const user = await prisma.user.findUnique({
        where: { id: userId },
      });
      if (!user) return null;

      const roles = await accessManager.rbac.rolesOf(userId);

      return {
        id: user.id,
        email: user.email,
        name: user.name,
        emailVerified: user.emailVerified,
        image: user.image,
        createdAt: user.createdAt,
        roles,
      };
    }

    const roles = await accessManager.rbac.rolesOf(userId);
    return {
      id: userId,
      email: `${userId}@example.com`,
      name: `User ${userId}`,
      emailVerified: true,
      image: null,
      createdAt: new Date(),
      roles,
    };
  }

  static async listUsers(accessManager: AccessManager) {
    if (prisma) {
      const users = await prisma.user.findMany({
        orderBy: { createdAt: "desc" },
        take: 50,
      });

      return Promise.all(
        users.map(async (u) => ({
          id: u.id,
          email: u.email,
          name: u.name,
          roles: await accessManager.rbac.rolesOf(u.id),
        }))
      );
    }

    return [];
  }

  static async assignRole(userId: string, role: string, accessManager: AccessManager) {
    await accessManager.rbac.assign(userId, role);
    return { success: true, message: `Assigned role ${role} to user ${userId}` };
  }

  static async revokeRole(userId: string, role: string, accessManager: AccessManager) {
    const revoked = await accessManager.rbac.revoke(userId, role);
    return { success: revoked, message: `Revoked role ${role} from user ${userId}` };
  }
}
