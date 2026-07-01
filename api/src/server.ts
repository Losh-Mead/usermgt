import { buildApp } from "./app";
import { purgeExpiredSessions } from "./utils/sessions";

const REQUIRED_ENV = ["JWT_ACCESS_SECRET", "DATABASE_URL", "APP_URL", "JWT_AUDIENCE"] as const;

function validateEnv() {
  const missing = REQUIRED_ENV.filter((k) => !process.env[k]);
  if (missing.length) {
    console.error(`Missing required environment variables: ${missing.join(", ")}`);
    process.exit(1);
  }
  if ((process.env.JWT_ACCESS_SECRET?.length ?? 0) < 32) {
    console.error("JWT_ACCESS_SECRET must be at least 32 characters");
    process.exit(1);
  }
}

async function main() {
  validateEnv();
  const app = buildApp();
  const port = Number(process.env.PORT || 3000);

  await app.listen({ port, host: "0.0.0.0" });

  const PURGE_INTERVAL_MS = 6 * 60 * 60 * 1000; // every 6 hours
  setInterval(async () => {
    const count = await purgeExpiredSessions();
    if (count > 0) app.log.info({ count }, "Purged expired sessions");
  }, PURGE_INTERVAL_MS).unref();
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
