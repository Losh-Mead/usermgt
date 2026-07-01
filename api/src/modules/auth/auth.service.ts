import { VerificationTokenType } from "@prisma/client";
import { prisma } from "../../db/prisma";
import { hashPassword, randomToken, sha256Base64Url, timingSafeStringEqual, verifyPassword } from "../../utils/crypto";
import { sendPasswordResetEmail, sendVerificationEmail } from "../../utils/email";

const EMAIL_VERIFY_TTL_HOURS = 24;
const PASSWORD_RESET_TTL_HOURS = 1;

function getAccessTtlSeconds(): number {
  return Math.max(1, Number(process.env.ACCESS_TOKEN_TTL_MINUTES ?? 15)) * 60;
}

function getRefreshTtlDays(): number {
  return Math.max(1, Number(process.env.REFRESH_TOKEN_TTL_DAYS ?? 30));
}

export type Tokens = { accessToken: string; refreshToken: string };

export async function createUserAndSession(args: {
  email: string;
  password: string;
  displayName?: string;
  issueAccessToken: (userId: string, role: string, sessionId: string) => string;
}): Promise<Tokens> {
  const { email, password, displayName, issueAccessToken } = args;

  const passwordHash = await hashPassword(password);

  let userId: string;
  try {
    const user = await prisma.user.create({
      data: { email, passwordHash, displayName: displayName ?? null },
      select: { id: true },
    });
    userId = user.id;
  } catch (e: any) {
    if (e?.code === "P2002") {
      throw Object.assign(new Error("Email already registered"), { statusCode: 409 });
    }
    throw e;
  }

  const { refreshToken, sessionId } = await createSessionForUser(userId, {});
  const accessToken = issueAccessToken(userId, "USER", sessionId);

  const rawVerifyToken = await createVerificationToken(userId, VerificationTokenType.EMAIL_VERIFY, EMAIL_VERIFY_TTL_HOURS);
  sendVerificationEmail(email, rawVerifyToken).catch((err) => {
    console.error("Failed to send verification email:", err);
  });

  return { accessToken, refreshToken };
}

const LOCKOUT_THRESHOLD_SOFT = 5;   // failures before 15-min lock
const LOCKOUT_THRESHOLD_HARD = 10;  // failures before 1-hour lock
const LOCKOUT_SOFT_MS = 15 * 60 * 1000;
const LOCKOUT_HARD_MS = 60 * 60 * 1000;

export async function loginAndCreateSession(args: {
  email: string;
  password: string;
  userAgent?: string;
  ipAddress?: string;
  issueAccessToken: (userId: string, role: string, sessionId: string) => string;
}): Promise<Tokens & { userId: string }> {
  const { email, password, issueAccessToken } = args;

  const user = await prisma.user.findUnique({
    where: { email },
    select: { id: true, passwordHash: true, isActive: true, role: true, failedLoginAttempts: true, lockedUntil: true },
  });

  // same error for not-found, inactive, and wrong password — prevents user enumeration
  if (!user) {
    throw Object.assign(new Error("Invalid credentials"), { statusCode: 401 });
  }

  // Lockout check (same generic error — don't reveal locked state to attacker)
  if (user.lockedUntil && user.lockedUntil > new Date()) {
    throw Object.assign(new Error("Invalid credentials"), { statusCode: 401 });
  }

  if (!user.isActive) {
    throw Object.assign(new Error("Invalid credentials"), { statusCode: 401 });
  }

  const ok = await verifyPassword(password, user.passwordHash);
  if (!ok) {
    const newCount = user.failedLoginAttempts + 1;
    const lockedUntil =
      newCount >= LOCKOUT_THRESHOLD_HARD ? new Date(Date.now() + LOCKOUT_HARD_MS) :
      newCount >= LOCKOUT_THRESHOLD_SOFT ? new Date(Date.now() + LOCKOUT_SOFT_MS) :
      undefined;
    await prisma.user.update({
      where: { id: user.id },
      data: { failedLoginAttempts: { increment: 1 }, ...(lockedUntil ? { lockedUntil } : {}) },
    });
    throw Object.assign(new Error("Invalid credentials"), { statusCode: 401 });
  }

  // Successful login — reset lockout state
  await prisma.user.update({
    where: { id: user.id },
    data: { lastLoginAt: new Date(), failedLoginAttempts: 0, lockedUntil: null },
  });

  const { refreshToken, sessionId } = await createSessionForUser(user.id, {
    userAgent: args.userAgent,
    ipAddress: args.ipAddress,
  });
  const accessToken = issueAccessToken(user.id, user.role, sessionId);

  return { accessToken, refreshToken, userId: user.id };
}

export async function refreshSession(args: {
  refreshToken: string;
  issueAccessToken: (userId: string, role: string, sessionId: string) => string;
}): Promise<Tokens> {
  const { refreshToken, issueAccessToken } = args;

  const parsed = parseRefreshToken(refreshToken);
  if (!parsed) throw Object.assign(new Error("Invalid refresh token"), { statusCode: 401 });

  const { sessionId, rawToken } = parsed;
  const tokenHash = sha256Base64Url(rawToken);

  const session = await prisma.userSession.findUnique({
    where: { id: sessionId },
    select: {
      id: true,
      userId: true,
      refreshHash: true,
      revokedAt: true,
      expiresAt: true,
      user: { select: { role: true } },
    },
  });

  if (!session || session.revokedAt || session.expiresAt.getTime() <= Date.now()) {
    throw Object.assign(new Error("Invalid refresh token"), { statusCode: 401 });
  }

  // Valid session ID but wrong token hash — the session exists but this token was already
  // rotated out. Revoke the session immediately: this is a strong signal of token theft.
  if (!timingSafeStringEqual(session.refreshHash, tokenHash)) {
    await prisma.userSession.update({
      where: { id: session.id },
      data: { revokedAt: new Date() },
    });
    throw Object.assign(new Error("Invalid refresh token"), { statusCode: 401 });
  }

  const newRaw = randomToken(48);
  const newHash = sha256Base64Url(newRaw);
  const newExpiresAt = new Date(Date.now() + getRefreshTtlDays() * 24 * 60 * 60 * 1000);

  await prisma.userSession.update({
    where: { id: session.id },
    data: { refreshHash: newHash, expiresAt: newExpiresAt },
  });

  const newRefreshToken = formatRefreshToken(session.id, newRaw);
  const accessToken = issueAccessToken(session.userId, session.user.role, session.id);

  return { accessToken, refreshToken: newRefreshToken };
}

export async function logoutSession(refreshToken: string): Promise<void> {
  const parsed = parseRefreshToken(refreshToken);
  if (!parsed) return;

  await prisma.userSession.updateMany({
    where: { id: parsed.sessionId, revokedAt: null },
    data: { revokedAt: new Date() },
  });
}

export async function verifyEmail(rawToken: string): Promise<{ userId: string }> {
  const record = await consumeVerificationToken(rawToken, VerificationTokenType.EMAIL_VERIFY);
  await prisma.user.update({
    where: { id: record.userId },
    data: { isEmailVerified: true },
  });
  return { userId: record.userId };
}

export async function requestPasswordReset(email: string): Promise<void> {
  const user = await prisma.user.findUnique({ where: { email }, select: { id: true } });
  if (!user) return; // don't reveal whether email exists

  // Invalidate any existing pending reset tokens before issuing a new one
  await prisma.verificationToken.updateMany({
    where: { userId: user.id, type: VerificationTokenType.PASSWORD_RESET, usedAt: null },
    data: { usedAt: new Date() },
  });

  const rawToken = await createVerificationToken(user.id, VerificationTokenType.PASSWORD_RESET, PASSWORD_RESET_TTL_HOURS);
  sendPasswordResetEmail(email, rawToken).catch((err) => {
    console.error("Failed to send password reset email:", err);
  });
}

export async function resetPassword(rawToken: string, newPassword: string): Promise<void> {
  const record = await consumeVerificationToken(rawToken, VerificationTokenType.PASSWORD_RESET);
  const passwordHash = await hashPassword(newPassword);
  await prisma.$transaction([
    prisma.user.update({ where: { id: record.userId }, data: { passwordHash } }),
    // revoke all active sessions so any stolen refresh tokens are immediately dead
    prisma.userSession.updateMany({
      where: { userId: record.userId, revokedAt: null },
      data: { revokedAt: new Date() },
    }),
  ]);
}

export async function changePassword(args: {
  userId: string;
  currentPassword: string;
  newPassword: string;
  currentSessionId: string;
}): Promise<void> {
  const user = await prisma.user.findUnique({
    where: { id: args.userId },
    select: { passwordHash: true, isActive: true },
  });

  if (!user || !user.isActive) {
    throw Object.assign(new Error("User not found"), { statusCode: 404 });
  }

  const ok = await verifyPassword(args.currentPassword, user.passwordHash);
  if (!ok) {
    throw Object.assign(new Error("Current password is incorrect"), { statusCode: 401 });
  }

  const newHash = await hashPassword(args.newPassword);
  await prisma.$transaction([
    prisma.user.update({ where: { id: args.userId }, data: { passwordHash: newHash } }),
    // Revoke all OTHER sessions — keep the current one so the user stays logged in
    prisma.userSession.updateMany({
      where: { userId: args.userId, id: { not: args.currentSessionId }, revokedAt: null },
      data: { revokedAt: new Date() },
    }),
  ]);
}

export async function revokeAllSessions(userId: string): Promise<void> {
  await prisma.userSession.updateMany({
    where: { userId, revokedAt: null },
    data: { revokedAt: new Date() },
  });
}

export async function deleteAccount(userId: string, password: string): Promise<void> {
  const user = await prisma.user.findUnique({
    where: { id: userId },
    select: { passwordHash: true, isActive: true },
  });

  if (!user || !user.isActive) {
    throw Object.assign(new Error("User not found"), { statusCode: 404 });
  }

  const ok = await verifyPassword(password, user.passwordHash);
  if (!ok) {
    throw Object.assign(new Error("Invalid password"), { statusCode: 401 });
  }

  // Cascade in schema handles sessions + verificationTokens
  await prisma.user.delete({ where: { id: userId } });
}

const MAX_SESSIONS_PER_USER = 10;

async function createSessionForUser(
  userId: string,
  meta: { userAgent?: string; ipAddress?: string }
): Promise<{ refreshToken: string; sessionId: string }> {
  // Enforce per-user session cap — evict the oldest session(s) if at the limit
  const activeSessions = await prisma.userSession.findMany({
    where: { userId, revokedAt: null, expiresAt: { gt: new Date() } },
    orderBy: { createdAt: "asc" },
    select: { id: true },
  });
  if (activeSessions.length >= MAX_SESSIONS_PER_USER) {
    const evict = activeSessions.slice(0, activeSessions.length - MAX_SESSIONS_PER_USER + 1);
    await prisma.userSession.updateMany({
      where: { id: { in: evict.map((s) => s.id) } },
      data: { revokedAt: new Date() },
    });
  }

  const raw = randomToken(48);
  const hash = sha256Base64Url(raw);
  const expiresAt = new Date(Date.now() + getRefreshTtlDays() * 24 * 60 * 60 * 1000);

  const session = await prisma.userSession.create({
    data: {
      userId,
      refreshHash: hash,
      expiresAt,
      userAgent: meta.userAgent ?? null,
      ipAddress: meta.ipAddress ?? null,
    },
    select: { id: true },
  });

  return { refreshToken: formatRefreshToken(session.id, raw), sessionId: session.id };
}

function formatRefreshToken(sessionId: string, raw: string): string {
  return `${sessionId}.${raw}`;
}

function parseRefreshToken(rt: string): { sessionId: string; rawToken: string } | null {
  const idx = rt.indexOf(".");
  if (idx <= 0) return null;
  const sessionId = rt.slice(0, idx);
  const rawToken = rt.slice(idx + 1);
  if (!sessionId || !rawToken) return null;
  return { sessionId, rawToken };
}

async function createVerificationToken(
  userId: string,
  type: VerificationTokenType,
  ttlHours: number
): Promise<string> {
  const raw = randomToken(32);
  const tokenHash = sha256Base64Url(raw);
  const expiresAt = new Date(Date.now() + ttlHours * 60 * 60 * 1000);
  await prisma.verificationToken.create({ data: { userId, tokenHash, type, expiresAt } });
  return raw;
}

async function consumeVerificationToken(
  rawToken: string,
  type: VerificationTokenType
): Promise<{ userId: string }> {
  const tokenHash = sha256Base64Url(rawToken);
  const now = new Date();

  // Atomic mark-as-used — prevents two concurrent requests from both succeeding
  const { count } = await prisma.verificationToken.updateMany({
    where: { tokenHash, type, usedAt: null, expiresAt: { gt: now } },
    data: { usedAt: now },
  });

  if (count === 0) {
    throw Object.assign(new Error("Invalid or expired token"), { statusCode: 400 });
  }

  const record = await prisma.verificationToken.findFirst({
    where: { tokenHash, type },
    select: { userId: true },
  });

  return { userId: record!.userId };
}

export function accessTokenTtlSeconds(): number {
  return getAccessTtlSeconds();
}

export type IntrospectResult =
  | { active: false }
  | { active: true; sub: string; role: string; sessionId: string; isEmailVerified: boolean; exp: number };

export async function introspectToken(
  token: string,
  jwtVerify: (t: string) => { sub: string; role: string; sessionId: string; exp: number }
): Promise<IntrospectResult> {
  let payload: { sub: string; role: string; sessionId: string; exp: number };
  try {
    payload = jwtVerify(token);
  } catch {
    return { active: false };
  }

  const user = await prisma.user.findUnique({
    where: { id: payload.sub },
    select: { isActive: true, isEmailVerified: true },
  });

  if (!user || !user.isActive) return { active: false };

  return {
    active: true,
    sub: payload.sub,
    role: payload.role,
    sessionId: payload.sessionId,
    isEmailVerified: user.isEmailVerified,
    exp: payload.exp,
  };
}
