import { prisma } from "../../db/prisma";
import { hashPassword, randomToken, sha256Base64Url, verifyPassword } from "../../utils/crypto";

function getAccessTtlSeconds(): number {
  const minutes = Number(process.env.ACCESS_TOKEN_TTL_MINUTES ?? 15);
  return Math.max(1, minutes) * 60;
}

function getRefreshTtlDays(): number {
  const days = Number(process.env.REFRESH_TOKEN_TTL_DAYS ?? 30);
  return Math.max(1, days);
}

export type Tokens = { accessToken: string; refreshToken: string };

export async function createUserAndSession(args: {
  email: string;
  password: string;
  displayName?: string;
  issueAccessToken: (userId: string) => string;
}): Promise<Tokens> {
  const { email, password, displayName, issueAccessToken } = args;

  const existing = await prisma.user.findUnique({ where: { email } });
  if (existing) {
    throw Object.assign(new Error("Email already registered"), { statusCode: 409 });
  }

  const passwordHash = await hashPassword(password);

  const user = await prisma.user.create({
    data: { email, passwordHash, displayName: displayName ?? null },
    select: { id: true },
  });

  const { refreshToken } = await createSessionForUser(user.id);
  const accessToken = issueAccessToken(user.id);

  return { accessToken, refreshToken };
}

export async function loginAndCreateSession(args: {
  email: string;
  password: string;
  userAgent?: string;
  ipAddress?: string;
  issueAccessToken: (userId: string) => string;
}): Promise<Tokens> {
  const { email, password, issueAccessToken } = args;

  const user = await prisma.user.findUnique({
    where: { email },
    select: { id: true, passwordHash: true, isActive: true },
  });

  // same error for not-found vs wrong password
  if (!user || !user.isActive) {
    throw Object.assign(new Error("Invalid credentials"), { statusCode: 401 });
  }

  const ok = await verifyPassword(password, user.passwordHash);
  if (!ok) {
    throw Object.assign(new Error("Invalid credentials"), { statusCode: 401 });
  }

  await prisma.user.update({
    where: { id: user.id },
    data: { lastLoginAt: new Date() },
  });

  const { refreshToken } = await createSessionForUser(user.id);
  const accessToken = issueAccessToken(user.id);

  return { accessToken, refreshToken };
}

export async function refreshSession(args: {
  refreshToken: string;
  issueAccessToken: (userId: string) => string;
}): Promise<Tokens> {
  const { refreshToken, issueAccessToken } = args;

  const parsed = parseRefreshToken(refreshToken);
  if (!parsed) throw Object.assign(new Error("Invalid refresh token"), { statusCode: 401 });

  const { sessionId, rawToken } = parsed;
  const tokenHash = sha256Base64Url(rawToken);

  const session = await prisma.userSession.findUnique({
    where: { id: sessionId },
    select: { id: true, userId: true, refreshHash: true, revokedAt: true, expiresAt: true },
  });

  if (
    !session ||
    session.revokedAt ||
    session.expiresAt.getTime() <= Date.now() ||
    session.refreshHash !== tokenHash
  ) {
    throw Object.assign(new Error("Invalid refresh token"), { statusCode: 401 });
  }

  // rotate refresh token
  const newRaw = randomToken(48);
  const newHash = sha256Base64Url(newRaw);
  const newExpiresAt = new Date(Date.now() + getRefreshTtlDays() * 24 * 60 * 60 * 1000);

  await prisma.userSession.update({
    where: { id: session.id },
    data: { refreshHash: newHash, expiresAt: newExpiresAt },
  });

  const newRefreshToken = formatRefreshToken(session.id, newRaw);
  const accessToken = issueAccessToken(session.userId);

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

async function createSessionForUser(userId: string): Promise<{ refreshToken: string }> {
  const raw = randomToken(48);
  const hash = sha256Base64Url(raw);
  const expiresAt = new Date(Date.now() + getRefreshTtlDays() * 24 * 60 * 60 * 1000);

  const session = await prisma.userSession.create({
    data: {
      userId,
      refreshHash: hash,
      expiresAt,
    },
    select: { id: true },
  });

  return { refreshToken: formatRefreshToken(session.id, raw) };
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

export function accessTokenTtlSeconds(): number {
  return getAccessTtlSeconds();
}
