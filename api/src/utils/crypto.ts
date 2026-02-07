import bcrypt from "bcrypt";
import crypto from "crypto";

export async function hashPassword(password: string): Promise<string> {
  // bcrypt cost 12 is a reasonable baseline
  return bcrypt.hash(password, 12);
}

export async function verifyPassword(password: string, passwordHash: string): Promise<boolean> {
  return bcrypt.compare(password, passwordHash);
}

export function randomToken(bytes = 32): string {
  return crypto.randomBytes(bytes).toString("base64url");
}

export function sha256Base64Url(input: string): string {
  return crypto.createHash("sha256").update(input).digest("base64url");
}
