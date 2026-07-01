import { buildApp } from "../app";
import { prisma } from "../db/prisma";
import type { FastifyInstance } from "fastify";

export async function createApp(): Promise<FastifyInstance> {
  const app = buildApp();
  await app.ready();
  return app;
}

/** Register a user and return their tokens + userId from the DB. */
export async function registerUser(
  app: FastifyInstance,
  overrides: { email?: string; password?: string; displayName?: string } = {}
) {
  const email = overrides.email ?? "test@example.com";
  const password = overrides.password ?? "password123";

  const res = await app.inject({
    method: "POST",
    url: "/v1/auth/register",
    payload: { email, password, displayName: overrides.displayName },
  });

  const body = res.json();
  const user = await prisma.user.findUnique({ where: { email: email.toLowerCase() } });

  return { res, body, user: user!, password };
}

/** Log in and return tokens + the DB user row. */
export async function loginUser(
  app: FastifyInstance,
  email: string,
  password: string
) {
  const res = await app.inject({
    method: "POST",
    url: "/v1/auth/login",
    payload: { email, password },
  });
  const body = res.json();
  return { res, accessToken: body.accessToken as string, refreshToken: body.refreshToken as string };
}

/** Issue a valid JWT for a userId, bypassing the login flow. */
export function issueToken(
  app: FastifyInstance,
  userId: string,
  extra: { role?: string; sessionId?: string } = {}
): string {
  return (app as any).jwt.sign(
    { role: extra.role ?? "USER", sessionId: extra.sessionId ?? "fake-session-id" },
    { sub: userId, expiresIn: 900 }
  );
}

/** Issue an already-expired JWT. */
export function issueExpiredToken(app: FastifyInstance, userId: string): string {
  return (app as any).jwt.sign(
    { role: "USER", sessionId: "fake-session-id" },
    { sub: userId, expiresIn: -1 }
  );
}
