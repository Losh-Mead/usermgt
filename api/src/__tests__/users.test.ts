import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { prisma } from "../db/prisma";
import { createApp, registerUser, issueToken, issueExpiredToken } from "./helpers";
import type { FastifyInstance } from "fastify";

let app: FastifyInstance;

beforeAll(async () => { app = await createApp(); });
afterAll(async () => { await app.close(); });

// ─── GET /v1/me ──────────────────────────────────────────────────────────────

describe("GET /v1/me", () => {
  it("returns the user profile with a valid JWT", async () => {
    const { user } = await registerUser(app);
    const token = issueToken(app, user.id);

    const res = await app.inject({
      method: "GET",
      url: "/v1/me",
      headers: { authorization: `Bearer ${token}` },
    });

    expect(res.statusCode).toBe(200);
    const body = res.json();
    expect(body.id).toBe(user.id);
    expect(body.email).toBe(user.email);
    expect(body).not.toHaveProperty("passwordHash");
  });

  it("returns 401 with no Authorization header", async () => {
    const res = await app.inject({ method: "GET", url: "/v1/me" });
    expect(res.statusCode).toBe(401);
  });

  it("returns 401 with an expired JWT", async () => {
    const { user } = await registerUser(app);
    const token = issueExpiredToken(app, user.id);

    const res = await app.inject({
      method: "GET",
      url: "/v1/me",
      headers: { authorization: `Bearer ${token}` },
    });
    expect(res.statusCode).toBe(401);
  });

  it("returns 401 with a tampered JWT", async () => {
    const { user } = await registerUser(app);
    const token = issueToken(app, user.id);
    const tampered = token.slice(0, -5) + "XXXXX";

    const res = await app.inject({
      method: "GET",
      url: "/v1/me",
      headers: { authorization: `Bearer ${tampered}` },
    });
    expect(res.statusCode).toBe(401);
  });

  it("returns 404 for a deactivated user", async () => {
    const { user } = await registerUser(app);
    await prisma.user.update({ where: { id: user.id }, data: { isActive: false } });
    const token = issueToken(app, user.id);

    const res = await app.inject({
      method: "GET",
      url: "/v1/me",
      headers: { authorization: `Bearer ${token}` },
    });
    expect(res.statusCode).toBe(404);
  });
});

// ─── PATCH /v1/me ────────────────────────────────────────────────────────────

describe("PATCH /v1/me", () => {
  it("updates displayName", async () => {
    const { user } = await registerUser(app);
    const token = issueToken(app, user.id);

    const res = await app.inject({
      method: "PATCH",
      url: "/v1/me",
      headers: { authorization: `Bearer ${token}` },
      payload: { displayName: "Updated Name" },
    });

    expect(res.statusCode).toBe(200);
    expect(res.json().displayName).toBe("Updated Name");
  });

  it("clears displayName when null is sent", async () => {
    const { user } = await registerUser(app, { displayName: "Initial Name" });
    const token = issueToken(app, user.id);

    const res = await app.inject({
      method: "PATCH",
      url: "/v1/me",
      headers: { authorization: `Bearer ${token}` },
      payload: { displayName: null },
    });

    expect(res.statusCode).toBe(200);
    expect(res.json().displayName).toBeNull();
  });

  it("returns 401 with no token", async () => {
    const res = await app.inject({ method: "PATCH", url: "/v1/me", payload: { displayName: "x" } });
    expect(res.statusCode).toBe(401);
  });

  it("returns 404 for a deactivated user", async () => {
    const { user } = await registerUser(app);
    await prisma.user.update({ where: { id: user.id }, data: { isActive: false } });
    const token = issueToken(app, user.id);

    const res = await app.inject({
      method: "PATCH",
      url: "/v1/me",
      headers: { authorization: `Bearer ${token}` },
      payload: { displayName: "Hacker" },
    });
    expect(res.statusCode).toBe(404);
  });

  it("returns 400 when displayName exceeds max length", async () => {
    const { user } = await registerUser(app);
    const token = issueToken(app, user.id);

    const res = await app.inject({
      method: "PATCH",
      url: "/v1/me",
      headers: { authorization: `Bearer ${token}` },
      payload: { displayName: "x".repeat(121) },
    });
    expect(res.statusCode).toBe(400);
  });
});
