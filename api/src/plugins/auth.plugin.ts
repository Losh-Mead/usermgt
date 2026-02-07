import fp from "fastify-plugin";
import type { FastifyPluginAsync } from "fastify";

export const authPlugin: FastifyPluginAsync = fp(async (app) => {
  app.decorate("requireAuth", async (req, reply) => {
    try {
      await req.jwtVerify();
    } catch {
      return reply.code(401).send({ message: "Invalid or missing token" });
    }
  });
});

declare module "fastify" {
  interface FastifyInstance {
    requireAuth: (req: any, reply: any) => Promise<void>;
  }
}
