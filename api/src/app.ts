import Fastify from "fastify";
import jwt from "@fastify/jwt";
import cookie from "@fastify/cookie";
import { authPlugin } from "./plugins/auth.plugin";
import { authRoutes } from "./modules/auth/auth.routes";
import { userRoutes } from "./modules/users/users.routes";

export function buildApp() {
  const app = Fastify({ logger: true });

  app.register(cookie);

  app.register(jwt, {
    secret: process.env.JWT_ACCESS_SECRET || "dev_access_secret",
  });

  app.get("/health", async () => ({ ok: true }));

  // Auth guard
  app.register(authPlugin);

  // v1 routes
  app.register(async (v1) => {
    v1.register(authRoutes);
    v1.register(userRoutes);
  }, { prefix: "/v1" });

  return app;
}
