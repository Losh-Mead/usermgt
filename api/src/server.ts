import Fastify from "fastify";
import jwt from "@fastify/jwt";
import cookie from "@fastify/cookie";
import { PrismaClient } from "@prisma/client";

const prisma = new PrismaClient();

async function main() {
  const app = Fastify({ logger: true });

  app.register(cookie);
  app.register(jwt, { secret: process.env.JWT_ACCESS_SECRET || "dev_secret" });

  app.get("/health", async () => ({ ok: true }));

  app.get("/db", async () => {
    const count = await prisma.user.count();
    return { users: count };
  });

  const port = Number(process.env.PORT || 3000);
  await app.listen({ port, host: "0.0.0.0" });
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
