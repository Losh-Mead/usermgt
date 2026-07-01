import Fastify from "fastify";
import helmet from "@fastify/helmet";
import jwt from "@fastify/jwt";
import cookie from "@fastify/cookie";
import cors from "@fastify/cors";
import rateLimit from "@fastify/rate-limit";
import swagger from "@fastify/swagger";
import swaggerUi from "@fastify/swagger-ui";
import { ZodError } from "zod";
import { authPlugin } from "./plugins/auth.plugin";
import { authRoutes } from "./modules/auth/auth.routes";
import { userRoutes } from "./modules/users/users.routes";
import { prisma } from "./db/prisma";

export function buildApp() {
  const app = Fastify({ logger: true });

  app.register(helmet, {
    contentSecurityPolicy: false,    // API — no HTML served
    crossOriginEmbedderPolicy: false, // not serving cross-origin resources
  });

  app.register(cookie);

  app.register(cors, {
    origin: process.env.CORS_ORIGINS ? process.env.CORS_ORIGINS.split(",") : false,
    credentials: true,
  });

  // Rate limiting is disabled in test mode so tests don't accumulate counts across runs
  if (process.env.NODE_ENV !== "test") {
    app.register(rateLimit, {
      global: false,
      max: 100,
      timeWindow: "1 minute",
    });
  }

  const jwtOptions: Parameters<typeof jwt>[1] = {
    secret: process.env.JWT_ACCESS_SECRET!,
  };
  if (process.env.JWT_AUDIENCE) {
    jwtOptions.sign = { aud: process.env.JWT_AUDIENCE };
    jwtOptions.verify = { allowedAud: process.env.JWT_AUDIENCE };
  }
  app.register(jwt, jwtOptions);

  app.setErrorHandler((err, _req, reply) => {
    if (err instanceof ZodError) {
      return reply.code(400).send({
        message: "Validation error",
        errors: err.issues.map((issue) => ({ path: issue.path.join("."), message: issue.message })),
      });
    }
    const e = err as { statusCode?: number; message?: string };
    return reply.code(e.statusCode ?? 500).send({ message: e.message ?? "Server error" });
  });

  app.get("/health", async (_req, reply) => {
    try {
      await prisma.$queryRaw`SELECT 1`;
      return reply.send({ ok: true });
    } catch {
      return reply.code(503).send({ ok: false, error: "Database unavailable" });
    }
  });

  if (process.env.NODE_ENV !== "production") {
    app.register(swagger, {
      openapi: {
        info: { title: "Auth API", version: "1.0.0" },
        components: {
          securitySchemes: {
            bearerAuth: { type: "http", scheme: "bearer", bearerFormat: "JWT" },
          },
        },
      },
    });
    app.register(swaggerUi, { routePrefix: "/docs" });
  }

  // Auth guard
  app.register(authPlugin);

  // v1 routes
  app.register(async (v1) => {
    v1.register(authRoutes);
    v1.register(userRoutes);
  }, { prefix: "/v1" });

  return app;
}
