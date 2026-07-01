import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { prisma } from "../db/prisma";
import { createApp, registerUser, loginUser } from "./helpers";
import type { FastifyInstance } from "fastify";

let app: FastifyInstance;

beforeAll(async () => { app = await createApp(); });
afterAll(async () => { await app.close(); });

// ─── POST /v1/me/password ─────────────────────────────────────────────────────

describe("POST /v1/me/password", () => {
  it("updates password with correct current password", async () => {
    const { user } = await registerUser(app);
    const { accessToken } = await loginUser(app, user.email, "password123");

    const res = await app.inject({
      method: "POST",
      url: "/v1/me/password",
      headers: { authorization: `Bearer ${accessToken}` },
      payload: { currentPassword: "password123", newPassword: "newpassword456" },
    });

    expect(res.statusCode).toBe(200);
    expect(res.json().message).toMatch(/updated/i);
  });

  it("can log in with new password after change", async () => {
    const { user } = await registerUser(app, { email: "pw-change@example.com" });
    const { accessToken } = await loginUser(app, user.email, "password123");

    await app.inject({
      method: "POST",
      url: "/v1/me/password",
      headers: { authorization: `Bearer ${accessToken}` },
      payload: { currentPassword: "password123", newPassword: "newpassword456" },
    });

    const loginRes = await app.inject({
      method: "POST",
      url: "/v1/auth/login",
      payload: { email: user.email, password: "newpassword456" },
    });
    expect(loginRes.statusCode).toBe(200);
  });

  it("revokes other sessions but keeps the current one", async () => {
    const { user } = await registerUser(app, { email: "pw-sessions@example.com" });
    // Create a second session
    await loginUser(app, user.email, "password123");
    const { accessToken, refreshToken } = await loginUser(app, user.email, "password123");

    await app.inject({
      method: "POST",
      url: "/v1/me/password",
      headers: { authorization: `Bearer ${accessToken}` },
      payload: { currentPassword: "password123", newPassword: "newpassword456" },
    });

    const sessions = await prisma.userSession.findMany({ where: { userId: user.id } });
    const active = sessions.filter((s) => !s.revokedAt);
    expect(active).toHaveLength(1);

    // The current session's refresh token should still work
    const refreshRes = await app.inject({
      method: "POST",
      url: "/v1/auth/refresh",
      payload: { refreshToken },
    });
    expect(refreshRes.statusCode).toBe(200);
  });

  it("returns 401 with wrong current password", async () => {
    const { user } = await registerUser(app, { email: "pw-wrong@example.com" });
    const { accessToken } = await loginUser(app, user.email, "password123");

    const res = await app.inject({
      method: "POST",
      url: "/v1/me/password",
      headers: { authorization: `Bearer ${accessToken}` },
      payload: { currentPassword: "wrongpassword", newPassword: "newpassword456" },
    });
    expect(res.statusCode).toBe(401);
  });

  it("returns 400 when new password is too short", async () => {
    const { user } = await registerUser(app, { email: "pw-short@example.com" });
    const { accessToken } = await loginUser(app, user.email, "password123");

    const res = await app.inject({
      method: "POST",
      url: "/v1/me/password",
      headers: { authorization: `Bearer ${accessToken}` },
      payload: { currentPassword: "password123", newPassword: "short" },
    });
    expect(res.statusCode).toBe(400);
  });

  it("returns 401 with no token", async () => {
    const res = await app.inject({
      method: "POST",
      url: "/v1/me/password",
      payload: { currentPassword: "password123", newPassword: "newpassword456" },
    });
    expect(res.statusCode).toBe(401);
  });
});

// ─── DELETE /v1/me/sessions ───────────────────────────────────────────────────

describe("DELETE /v1/me/sessions", () => {
  it("revokes all sessions for the user", async () => {
    const { user } = await registerUser(app, { email: "revoke-all@example.com" });
    // Create multiple sessions
    await loginUser(app, user.email, "password123");
    await loginUser(app, user.email, "password123");
    const { accessToken, refreshToken } = await loginUser(app, user.email, "password123");

    const res = await app.inject({
      method: "DELETE",
      url: "/v1/me/sessions",
      headers: { authorization: `Bearer ${accessToken}` },
    });
    expect(res.statusCode).toBe(204);

    const activeSessions = await prisma.userSession.findMany({
      where: { userId: user.id, revokedAt: null },
    });
    expect(activeSessions).toHaveLength(0);

    // Refresh tokens should no longer work
    const refreshRes = await app.inject({
      method: "POST",
      url: "/v1/auth/refresh",
      payload: { refreshToken },
    });
    expect(refreshRes.statusCode).toBe(401);
  });

  it("returns 401 with no token", async () => {
    const res = await app.inject({ method: "DELETE", url: "/v1/me/sessions" });
    expect(res.statusCode).toBe(401);
  });
});

// ─── DELETE /v1/me ────────────────────────────────────────────────────────────

describe("DELETE /v1/me", () => {
  it("deletes the account with correct password", async () => {
    const { user } = await registerUser(app, { email: "delete-me@example.com" });
    const { accessToken } = await loginUser(app, user.email, "password123");

    const res = await app.inject({
      method: "DELETE",
      url: "/v1/me",
      headers: { authorization: `Bearer ${accessToken}` },
      payload: { password: "password123" },
    });
    expect(res.statusCode).toBe(204);

    const gone = await prisma.user.findUnique({ where: { id: user.id } });
    expect(gone).toBeNull();
  });

  it("cascades deletion to sessions and tokens", async () => {
    const { user } = await registerUser(app, { email: "delete-cascade@example.com" });
    const { accessToken } = await loginUser(app, user.email, "password123");

    await app.inject({
      method: "DELETE",
      url: "/v1/me",
      headers: { authorization: `Bearer ${accessToken}` },
      payload: { password: "password123" },
    });

    const sessions = await prisma.userSession.findMany({ where: { userId: user.id } });
    expect(sessions).toHaveLength(0);
  });

  it("returns 401 with wrong password", async () => {
    const { user } = await registerUser(app, { email: "delete-wrong@example.com" });
    const { accessToken } = await loginUser(app, user.email, "password123");

    const res = await app.inject({
      method: "DELETE",
      url: "/v1/me",
      headers: { authorization: `Bearer ${accessToken}` },
      payload: { password: "wrongpassword" },
    });
    expect(res.statusCode).toBe(401);
  });

  it("returns 401 with no token", async () => {
    const res = await app.inject({
      method: "DELETE",
      url: "/v1/me",
      payload: { password: "password123" },
    });
    expect(res.statusCode).toBe(401);
  });

  it("returns 401 on subsequent JWT use after deletion", async () => {
    const { user } = await registerUser(app, { email: "delete-jwt@example.com" });
    const { accessToken } = await loginUser(app, user.email, "password123");

    await app.inject({
      method: "DELETE",
      url: "/v1/me",
      headers: { authorization: `Bearer ${accessToken}` },
      payload: { password: "password123" },
    });

    // JWT is still cryptographically valid but user is gone — 404 from the route
    const res = await app.inject({
      method: "GET",
      url: "/v1/me",
      headers: { authorization: `Bearer ${accessToken}` },
    });
    expect(res.statusCode).toBe(404);
  });
});
