import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    environment: "node",
    globals: true,
    setupFiles: ["src/__tests__/setup.ts"],
    env: {
      NODE_ENV: "test",
      JWT_ACCESS_SECRET: "test_secret_long_enough_for_hs256_algorithm_testing",
      DATABASE_URL: "postgresql://app:app_password@localhost:5432/usermgt",
      APP_URL: "http://localhost:3000",
      SMTP_HOST: "localhost",
      SMTP_PORT: "1025",
      SMTP_USER: "test",
      SMTP_PASS: "test",
      SMTP_FROM: "test@example.com",
    },
    // Serial execution prevents test files from sharing DB state concurrently
    fileParallelism: false,
    testTimeout: 15000,
  },
});
