import { vi, beforeEach, afterAll } from "vitest";
import { prisma } from "../db/prisma";

// Mock email so tests never attempt real SMTP
vi.mock("../utils/email", () => ({
  sendVerificationEmail: vi.fn().mockResolvedValue(undefined),
  sendPasswordResetEmail: vi.fn().mockResolvedValue(undefined),
}));

beforeEach(async () => {
  vi.clearAllMocks();
  // Delete in FK-safe order
  await prisma.verificationToken.deleteMany();
  await prisma.userSession.deleteMany();
  await prisma.user.deleteMany();
});

afterAll(async () => {
  await prisma.$disconnect();
});
