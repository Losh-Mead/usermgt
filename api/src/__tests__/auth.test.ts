import { describe, it, expect, beforeAll, afterAll, vi } from "vitest";
import { prisma } from "../db/prisma";
import { createApp, registerUser } from "./helpers";
import type { FastifyInstance } from "fastify";
import { sendVerificationEmail, sendPasswordResetEmail } from "../utils/email";

let app: FastifyInstance;

beforeAll(async () => { app = await createApp(); });
afterAll(async () => { await app.close(); });

// ─── Register ───────────────────────────────────────────────────────────────

describe("POST /v1/auth/register", () => {
  it("returns 201 with tokens on valid input", async () => {
    const { res, body } = await registerUser(app);
    expect(res.statusCode).toBe(201);
    expect(body).toHaveProperty("accessToken");
    expect(body).toHaveProperty("refreshToken");
  });

  it("creates user with isEmailVerified=false and isActive=true", async () => {
    const { user } = await registerUser(app);
    expect(user.isEmailVerified).toBe(false);
    expect(user.isActive).toBe(true);
    expect(user.passwordHash).not.toBe("password123");
  });

  it("creates a VerificationToken for email confirmation", async () => {
    const { user } = await registerUser(app);
    const token = await prisma.verificationToken.findFirst({ where: { userId: user.id, type: "EMAIL_VERIFY" } });
    expect(token).not.toBeNull();
    expect(token!.usedAt).toBeNull();
  });

  it("fires sendVerificationEmail", async () => {
    await registerUser(app);
    expect(sendVerificationEmail).toHaveBeenCalledOnce();
  });

  it("returns 409 on duplicate email", async () => {
    await registerUser(app);
    const { res, body } = await registerUser(app);
    expect(res.statusCode).toBe(409);
    expect(body.message).toMatch(/already registered/i);
  });

  it("is case-insensitive on email (stores lowercase)", async () => {
    const { user } = await registerUser(app, { email: "Upper@Example.COM" });
    expect(user.email).toBe("upper@example.com");
  });

  it("returns 400 on invalid email format", async () => {
    const res = await app.inject({
      method: "POST",
      url: "/v1/auth/register",
      payload: { email: "not-an-email", password: "password123" },
    });
    expect(res.statusCode).toBe(400);
  });

  it("returns 400 when password is too short", async () => {
    const res = await app.inject({
      method: "POST",
      url: "/v1/auth/register",
      payload: { email: "test@example.com", password: "short" },
    });
    expect(res.statusCode).toBe(400);
  });
});

// ─── Login ───────────────────────────────────────────────────────────────────

describe("POST /v1/auth/login", () => {
  it("returns 200 with tokens on correct credentials", async () => {
    await registerUser(app);
    const res = await app.inject({
      method: "POST",
      url: "/v1/auth/login",
      payload: { email: "test@example.com", password: "password123" },
    });
    expect(res.statusCode).toBe(200);
    expect(res.json()).toHaveProperty("accessToken");
    expect(res.json()).toHaveProperty("refreshToken");
  });

  it("updates lastLoginAt on successful login", async () => {
    await registerUser(app);
    await app.inject({
      method: "POST",
      url: "/v1/auth/login",
      payload: { email: "test@example.com", password: "password123" },
    });
    const user = await prisma.user.findUnique({ where: { email: "test@example.com" } });
    expect(user!.lastLoginAt).not.toBeNull();
  });

  it("returns 401 on wrong password with generic message", async () => {
    await registerUser(app);
    const res = await app.inject({
      method: "POST",
      url: "/v1/auth/login",
      payload: { email: "test@example.com", password: "wrongpassword" },
    });
    expect(res.statusCode).toBe(401);
    expect(res.json().message).toBe("Invalid credentials");
  });

  it("returns 401 on non-existent email with same message as wrong password", async () => {
    const res = await app.inject({
      method: "POST",
      url: "/v1/auth/login",
      payload: { email: "nobody@example.com", password: "password123" },
    });
    expect(res.statusCode).toBe(401);
    expect(res.json().message).toBe("Invalid credentials");
  });

  it("returns 401 for inactive accounts", async () => {
    const { user } = await registerUser(app);
    await prisma.user.update({ where: { id: user.id }, data: { isActive: false } });

    const res = await app.inject({
      method: "POST",
      url: "/v1/auth/login",
      payload: { email: "test@example.com", password: "password123" },
    });
    expect(res.statusCode).toBe(401);
  });
});

// ─── Refresh ─────────────────────────────────────────────────────────────────

describe("POST /v1/auth/refresh", () => {
  it("returns 200 with a new token pair", async () => {
    const { body: reg } = await registerUser(app);
    const res = await app.inject({
      method: "POST",
      url: "/v1/auth/refresh",
      payload: { refreshToken: reg.refreshToken },
    });
    expect(res.statusCode).toBe(200);
    expect(res.json()).toHaveProperty("accessToken");
    expect(res.json().refreshToken).not.toBe(reg.refreshToken);
  });

  it("rejects the same token a second time (rotation)", async () => {
    const { body: reg } = await registerUser(app);
    await app.inject({
      method: "POST",
      url: "/v1/auth/refresh",
      payload: { refreshToken: reg.refreshToken },
    });
    const res2 = await app.inject({
      method: "POST",
      url: "/v1/auth/refresh",
      payload: { refreshToken: reg.refreshToken },
    });
    expect(res2.statusCode).toBe(401);
  });

  it("rejects an expired refresh token", async () => {
    const { body: reg, user } = await registerUser(app);
    await prisma.userSession.updateMany({
      where: { userId: user.id },
      data: { expiresAt: new Date(Date.now() - 1000) },
    });
    const res = await app.inject({
      method: "POST",
      url: "/v1/auth/refresh",
      payload: { refreshToken: reg.refreshToken },
    });
    expect(res.statusCode).toBe(401);
  });

  it("rejects a revoked session token", async () => {
    const { body: reg, user } = await registerUser(app);
    await prisma.userSession.updateMany({
      where: { userId: user.id },
      data: { revokedAt: new Date() },
    });
    const res = await app.inject({
      method: "POST",
      url: "/v1/auth/refresh",
      payload: { refreshToken: reg.refreshToken },
    });
    expect(res.statusCode).toBe(401);
  });

  it("returns 401 for malformed token", async () => {
    const res = await app.inject({
      method: "POST",
      url: "/v1/auth/refresh",
      payload: { refreshToken: "not.a.valid.token" },
    });
    expect(res.statusCode).toBe(401);
  });
});

// ─── Logout ──────────────────────────────────────────────────────────────────

describe("POST /v1/auth/logout", () => {
  it("returns 204 and marks session revoked", async () => {
    const { body: reg, user } = await registerUser(app);
    const res = await app.inject({
      method: "POST",
      url: "/v1/auth/logout",
      payload: { refreshToken: reg.refreshToken },
    });
    expect(res.statusCode).toBe(204);

    const session = await prisma.userSession.findFirst({ where: { userId: user.id } });
    expect(session!.revokedAt).not.toBeNull();
  });

  it("returns 204 for a garbage token (idempotent)", async () => {
    const res = await app.inject({
      method: "POST",
      url: "/v1/auth/logout",
      payload: { refreshToken: "completely.garbage.token.value.here" },
    });
    expect(res.statusCode).toBe(204);
  });

  it("refresh token is rejected after logout", async () => {
    const { body: reg } = await registerUser(app);
    await app.inject({
      method: "POST",
      url: "/v1/auth/logout",
      payload: { refreshToken: reg.refreshToken },
    });
    const res = await app.inject({
      method: "POST",
      url: "/v1/auth/refresh",
      payload: { refreshToken: reg.refreshToken },
    });
    expect(res.statusCode).toBe(401);
  });
});

// ─── Email verification ───────────────────────────────────────────────────────

describe("POST /v1/auth/verify-email", () => {
  async function getVerifyToken(userId: string): Promise<string> {
    // Read the raw token by pulling from mock call args
    const calls = vi.mocked(sendVerificationEmail).mock.calls;
    const lastCall = calls[calls.length - 1];
    return lastCall[1]; // second arg is the raw token
  }

  it("sets isEmailVerified=true with a valid token", async () => {
    const { user } = await registerUser(app);
    const rawToken = await getVerifyToken(user.id);

    const res = await app.inject({
      method: "POST",
      url: "/v1/auth/verify-email",
      payload: { token: rawToken },
    });
    expect(res.statusCode).toBe(200);

    const updated = await prisma.user.findUnique({ where: { id: user.id } });
    expect(updated!.isEmailVerified).toBe(true);
  });

  it("returns 400 when token is already used", async () => {
    const { user } = await registerUser(app);
    const rawToken = await getVerifyToken(user.id);

    await app.inject({ method: "POST", url: "/v1/auth/verify-email", payload: { token: rawToken } });
    const res2 = await app.inject({ method: "POST", url: "/v1/auth/verify-email", payload: { token: rawToken } });
    expect(res2.statusCode).toBe(400);
  });

  it("returns 400 for an expired token", async () => {
    const { user } = await registerUser(app);
    await prisma.verificationToken.updateMany({
      where: { userId: user.id, type: "EMAIL_VERIFY" },
      data: { expiresAt: new Date(Date.now() - 1000) },
    });
    const rawToken = await getVerifyToken(user.id);
    const res = await app.inject({ method: "POST", url: "/v1/auth/verify-email", payload: { token: rawToken } });
    expect(res.statusCode).toBe(400);
  });

  it("returns 400 for a garbage token", async () => {
    const res = await app.inject({
      method: "POST",
      url: "/v1/auth/verify-email",
      payload: { token: "completelyfaketoken1234567890ab" },
    });
    expect(res.statusCode).toBe(400);
  });
});

// ─── Forgot / reset password ─────────────────────────────────────────────────

describe("POST /v1/auth/forgot-password", () => {
  it("returns 200 and creates a reset token for a registered email", async () => {
    const { user } = await registerUser(app);
    const res = await app.inject({
      method: "POST",
      url: "/v1/auth/forgot-password",
      payload: { email: "test@example.com" },
    });
    expect(res.statusCode).toBe(200);
    const token = await prisma.verificationToken.findFirst({ where: { userId: user.id, type: "PASSWORD_RESET" } });
    expect(token).not.toBeNull();
  });

  it("returns 200 for an unregistered email but creates no token", async () => {
    const before = await prisma.verificationToken.count();
    const res = await app.inject({
      method: "POST",
      url: "/v1/auth/forgot-password",
      payload: { email: "nobody@example.com" },
    });
    expect(res.statusCode).toBe(200);
    const after = await prisma.verificationToken.count();
    expect(after).toBe(before);
  });

  it("invalidates the previous reset token when a second is requested", async () => {
    const { user } = await registerUser(app);

    await app.inject({ method: "POST", url: "/v1/auth/forgot-password", payload: { email: "test@example.com" } });
    const first = await prisma.verificationToken.findFirst({ where: { userId: user.id, type: "PASSWORD_RESET" }, orderBy: { createdAt: "asc" } });

    await app.inject({ method: "POST", url: "/v1/auth/forgot-password", payload: { email: "test@example.com" } });
    const firstRefetched = await prisma.verificationToken.findUnique({ where: { id: first!.id } });

    expect(firstRefetched!.usedAt).not.toBeNull();
  });
});

// ─── Account lockout ─────────────────────────────────────────────────────────

describe("POST /v1/auth/login — account lockout", () => {
  async function failLogin(email: string, n: number) {
    for (let i = 0; i < n; i++) {
      await app.inject({
        method: "POST",
        url: "/v1/auth/login",
        payload: { email, password: "wrongpassword" },
      });
    }
  }

  it("allows login after fewer than 5 failures", async () => {
    const { user } = await registerUser(app, { email: "lockout-under@example.com" });
    await failLogin(user.email, 4);

    const res = await app.inject({
      method: "POST",
      url: "/v1/auth/login",
      payload: { email: user.email, password: "password123" },
    });
    expect(res.statusCode).toBe(200);
  });

  it("locks account after 5 failures with generic error message", async () => {
    const { user } = await registerUser(app, { email: "lockout-5@example.com" });
    await failLogin(user.email, 5);

    const res = await app.inject({
      method: "POST",
      url: "/v1/auth/login",
      payload: { email: user.email, password: "password123" },
    });
    expect(res.statusCode).toBe(401);
    expect(res.json().message).toBe("Invalid credentials"); // same message — doesn't reveal lock

    const dbUser = await prisma.user.findUnique({ where: { id: user.id } });
    expect(dbUser!.lockedUntil).not.toBeNull();
    expect(dbUser!.lockedUntil!.getTime()).toBeGreaterThan(Date.now() + 10 * 60 * 1000); // > 10 min away
  });

  it("sets a 1-hour lock once failedLoginAttempts reaches 10", async () => {
    const { user } = await registerUser(app, { email: "lockout-10@example.com" });
    // Simulate 9 prior failures (as if the 15-min lock expired and attacks resumed)
    await prisma.user.update({ where: { id: user.id }, data: { failedLoginAttempts: 9 } });

    await app.inject({
      method: "POST",
      url: "/v1/auth/login",
      payload: { email: user.email, password: "wrongpassword" },
    });

    const dbUser = await prisma.user.findUnique({ where: { id: user.id } });
    expect(dbUser!.lockedUntil!.getTime()).toBeGreaterThan(Date.now() + 50 * 60 * 1000); // > 50 min away
  });

  it("resets failure counter and lock on successful login", async () => {
    const { user } = await registerUser(app, { email: "lockout-reset@example.com" });
    await failLogin(user.email, 3);

    await app.inject({
      method: "POST",
      url: "/v1/auth/login",
      payload: { email: user.email, password: "password123" },
    });

    const dbUser = await prisma.user.findUnique({ where: { id: user.id } });
    expect(dbUser!.failedLoginAttempts).toBe(0);
    expect(dbUser!.lockedUntil).toBeNull();
  });

  it("allows login again once the lock expires", async () => {
    const { user } = await registerUser(app, { email: "lockout-expired@example.com" });
    // Set an already-expired lock
    await prisma.user.update({
      where: { id: user.id },
      data: { failedLoginAttempts: 5, lockedUntil: new Date(Date.now() - 1000) },
    });

    const res = await app.inject({
      method: "POST",
      url: "/v1/auth/login",
      payload: { email: user.email, password: "password123" },
    });
    expect(res.statusCode).toBe(200);
  });
});

// ─── Token introspection ─────────────────────────────────────────────────────

describe("POST /v1/auth/introspect", () => {
  it("returns active=true with claims for a valid token", async () => {
    const { body } = await registerUser(app, { email: "introspect-valid@example.com" });

    const res = await app.inject({
      method: "POST",
      url: "/v1/auth/introspect",
      payload: { token: body.accessToken },
    });
    expect(res.statusCode).toBe(200);
    const json = res.json();
    expect(json.active).toBe(true);
    expect(json.role).toBe("USER");
    expect(json.isEmailVerified).toBe(false);
    expect(json).toHaveProperty("sub");
    expect(json).toHaveProperty("exp");
  });

  it("returns active=false for a deactivated user's token", async () => {
    const { user, body } = await registerUser(app, { email: "introspect-inactive@example.com" });
    await prisma.user.update({ where: { id: user.id }, data: { isActive: false } });

    const res = await app.inject({
      method: "POST",
      url: "/v1/auth/introspect",
      payload: { token: body.accessToken },
    });
    expect(res.statusCode).toBe(200);
    expect(res.json()).toEqual({ active: false });
  });

  it("returns active=false for a tampered token", async () => {
    const { body } = await registerUser(app, { email: "introspect-tampered@example.com" });
    const tampered = body.accessToken.slice(0, -5) + "XXXXX";

    const res = await app.inject({
      method: "POST",
      url: "/v1/auth/introspect",
      payload: { token: tampered },
    });
    expect(res.statusCode).toBe(200);
    expect(res.json()).toEqual({ active: false });
  });

  it("returns active=false for a malformed string", async () => {
    const res = await app.inject({
      method: "POST",
      url: "/v1/auth/introspect",
      payload: { token: "not.a.real.jwt.value" },
    });
    expect(res.statusCode).toBe(200);
    expect(res.json()).toEqual({ active: false });
  });

  it("reflects isEmailVerified=true after verification", async () => {
    const { user, body } = await registerUser(app, { email: "introspect-verified@example.com" });
    await prisma.user.update({ where: { id: user.id }, data: { isEmailVerified: true } });

    const res = await app.inject({
      method: "POST",
      url: "/v1/auth/introspect",
      payload: { token: body.accessToken },
    });
    expect(res.json().isEmailVerified).toBe(true);
  });

  it("returns 400 when token field is missing", async () => {
    const res = await app.inject({
      method: "POST",
      url: "/v1/auth/introspect",
      payload: {},
    });
    expect(res.statusCode).toBe(400);
  });
});

// ─── Forgot / reset password ─────────────────────────────────────────────────

describe("POST /v1/auth/reset-password", () => {
  async function getResetToken(): Promise<string> {
    const calls = vi.mocked(sendPasswordResetEmail).mock.calls;
    return calls[calls.length - 1][1];
  }

  it("changes the password and revokes all sessions", async () => {
    const { user, body: reg } = await registerUser(app);
    await app.inject({ method: "POST", url: "/v1/auth/forgot-password", payload: { email: "test@example.com" } });
    const rawToken = await getResetToken();

    const res = await app.inject({
      method: "POST",
      url: "/v1/auth/reset-password",
      payload: { token: rawToken, password: "newpassword456" },
    });
    expect(res.statusCode).toBe(200);

    // old session revoked
    const session = await prisma.userSession.findFirst({ where: { userId: user.id } });
    expect(session!.revokedAt).not.toBeNull();

    // old refresh token rejected
    const refreshRes = await app.inject({
      method: "POST",
      url: "/v1/auth/refresh",
      payload: { refreshToken: reg.refreshToken },
    });
    expect(refreshRes.statusCode).toBe(401);

    // can log in with new password
    const loginRes = await app.inject({
      method: "POST",
      url: "/v1/auth/login",
      payload: { email: "test@example.com", password: "newpassword456" },
    });
    expect(loginRes.statusCode).toBe(200);
  });

  it("returns 400 for an expired reset token", async () => {
    const { user } = await registerUser(app);
    await app.inject({ method: "POST", url: "/v1/auth/forgot-password", payload: { email: "test@example.com" } });
    await prisma.verificationToken.updateMany({
      where: { userId: user.id, type: "PASSWORD_RESET" },
      data: { expiresAt: new Date(Date.now() - 1000) },
    });
    const rawToken = await getResetToken();
    const res = await app.inject({ method: "POST", url: "/v1/auth/reset-password", payload: { token: rawToken, password: "newpassword456" } });
    expect(res.statusCode).toBe(400);
  });

  it("returns 400 when token is already used", async () => {
    await registerUser(app);
    await app.inject({ method: "POST", url: "/v1/auth/forgot-password", payload: { email: "test@example.com" } });
    const rawToken = await getResetToken();

    await app.inject({ method: "POST", url: "/v1/auth/reset-password", payload: { token: rawToken, password: "newpassword456" } });
    const res2 = await app.inject({ method: "POST", url: "/v1/auth/reset-password", payload: { token: rawToken, password: "anotherpass789" } });
    expect(res2.statusCode).toBe(400);
  });
});
