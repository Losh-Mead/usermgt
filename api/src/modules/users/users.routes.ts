import type { FastifyPluginAsync } from "fastify";
import { z } from "zod";
import { prisma } from "../../db/prisma";

export const userRoutes: FastifyPluginAsync = async (app) => {
  app.get("/me", { preHandler: app.requireAuth }, async (req, reply) => {
    const userId = req.user!.sub;

    const user = await prisma.user.findUnique({
      where: { id: userId },
      select: {
        id: true,
        email: true,
        displayName: true,
        isActive: true,
        isEmailVerified: true,
        createdAt: true,
        updatedAt: true,
        lastLoginAt: true,
      },
    });

    if (!user) return reply.code(404).send({ message: "User not found" });
    return reply.send(user);
  });

  const patchSchema = z.object({
    displayName: z.string().max(120).nullable().optional(),
  });

  app.patch("/me", { preHandler: app.requireAuth }, async (req, reply) => {
    const userId = req.user!.sub;
    const body = patchSchema.parse(req.body);

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
};
