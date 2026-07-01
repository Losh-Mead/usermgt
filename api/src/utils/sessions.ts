import { prisma } from "../db/prisma";

const REVOKED_RETENTION_DAYS = 30;

export async function purgeExpiredSessions(): Promise<number> {
  const revokedCutoff = new Date(Date.now() - REVOKED_RETENTION_DAYS * 24 * 60 * 60 * 1000);
  const { count } = await prisma.userSession.deleteMany({
    where: {
      OR: [
        { expiresAt: { lt: new Date() } },
        { revokedAt: { lt: revokedCutoff } },
      ],
    },
  });
  return count;
}
