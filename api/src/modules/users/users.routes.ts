import type { FastifyPluginAsync } from "fastify";
import { z } from "zod";
import { prisma } from "../../db/prisma";
import { changePasswordSchema, deleteAccountSchema } from "../auth/auth.schemas";
import { changePassword, revokeAllSessions, deleteAccount } from "../auth/auth.service";

export const userRoutes: FastifyPluginAsync = async (app) => {
  app.get("/me", { preHandler: app.requireAuth }, async (req, reply) => {
    const userId = req.user.sub;

    const user = await prisma.user.findUnique({
      where: { id: userId },
      select: {
        id: true,
        email: true,
        role: true,
        displayName: true,
        isActive: true,
        isEmailVerified: true,
        createdAt: true,
        updatedAt: true,
        lastLoginAt: true,
      },
    });

    if (!user || !user.isActive) return reply.code(404).send({ message: "User not found" });
    return reply.send(user);
  });

  const patchSchema = z.object({
    displayName: z.string().max(120).nullable().optional(),
  });

  app.patch("/me", { preHandler: app.requireAuth }, async (req, reply) => {
    const userId = req.user.sub;
    const body = patchSchema.parse(req.body);

    const existing = await prisma.user.findUnique({
      where: { id: userId },
      select: { isActive: true },
    });

    if (!existing || !existing.isActive) return reply.code(404).send({ message: "User not found" });

    const user = await prisma.user.update({
      where: { id: userId },
      data: {
        displayName: body.displayName === undefined ? undefined : body.displayName,
      },
      select: {
        id: true,
        email: true,
        displayName: true,
        updatedAt: true,
      },
    });

    return reply.send(user);
  });

  app.post("/me/password", { preHandler: app.requireAuth }, async (req, reply) => {
    const userId = req.user.sub;
    const sessionId = req.user.sessionId;
    const body = changePasswordSchema.parse(req.body);

    await changePassword({
      userId,
      currentPassword: body.currentPassword,
      newPassword: body.newPassword,
      currentSessionId: sessionId,
    });

    req.log.info({ userId }, "user.password_changed");
    return reply.send({ message: "Password updated" });
  });

  app.delete("/me/sessions", { preHandler: app.requireAuth }, async (req, reply) => {
    const userId = req.user.sub;
    await revokeAllSessions(userId);
    req.log.info({ userId }, "user.sessions_revoked");
    return reply.code(204).send();
  });

  app.delete("/me", { preHandler: app.requireAuth }, async (req, reply) => {
    const userId = req.user.sub;
    const body = deleteAccountSchema.parse(req.body);

    await deleteAccount(userId, body.password);
    req.log.info({ userId }, "user.deleted");
    return reply.code(204).send();
  });
};
