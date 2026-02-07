import { z } from "zod";

export const registerSchema = z.object({
  email: z.string().email().max(320),
  password: z.string().min(8).max(200),
  displayName: z.string().max(120).optional(),
});

export const loginSchema = z.object({
  email: z.string().email().max(320),
  password: z.string().min(1).max(200),
});

export const refreshSchema = z.object({
  refreshToken: z.string().min(10),
});

export const logoutSchema = z.object({
  refreshToken: z.string().min(10),
});
