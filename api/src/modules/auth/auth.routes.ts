import type { FastifyPluginAsync } from "fastify";
import { registerSchema, loginSchema, refreshSchema, logoutSchema } from "./auth.schemas";
import {
  accessTokenTtlSeconds,
  createUserAndSession,
  loginAndCreateSession,
  logoutSession,
  refreshSession,
} from "./auth.service";

export const authRoutes: FastifyPluginAsync = async (app) => {
  // Helper to issue access tokens
  const issueAccessToken = (userId: string) => {
    return app.jwt.sign(
      { },
      {
        sub: userId,
        expiresIn: accessTokenTtlSeconds(),
      }
    );
  };

  app.post("/auth/register", async (req, reply) => {
    const body = registerSchema.parse(req.body);

    try {
      const tokens = await createUserAndSession({
        email: body.email.toLowerCase(),
        password: body.password,
        displayName: body.displayName,
        issueAccessToken,
      });

      return reply.code(201).send(tokens);
    } catch (e: any) {
      const status = e?.statusCode ?? 500;
      return reply.code(status).send({ message: e?.message ?? "Server error" });
    }
  });

  app.post("/auth/login", async (req, reply) => {
    const body = loginSchema.parse(req.body);

    try {
      const tokens = await loginAndCreateSession({
        email: body.email.toLowerCase(),
        password: body.password,
        userAgent: req.headers["user-agent"],
        ipAddress: req.ip,
        issueAccessToken,
      });

      return reply.code(200).send(tokens);
    } catch (e: any) {
      const status = e?.statusCode ?? 500;
      return reply.code(status).send({ message: e?.message ?? "Server error" });
    }
  });

  app.post("/auth/refresh", async (req, reply) => {
    const body = refreshSchema.parse(req.body);

    try {
      const tokens = await refreshSession({
        refreshToken: body.refreshToken,
        issueAccessToken,
      });

      return reply.code(200).send(tokens);
    } catch (e: any) {
      const status = e?.statusCode ?? 500;
      return reply.code(status).send({ message: e?.message ?? "Server error" });
    }
  });

  app.post("/auth/logout", async (req, reply) => {
    const body = logoutSchema.parse(req.body);

    await logoutSession(body.refreshToken);
    return reply.code(204).send();
  });
};
