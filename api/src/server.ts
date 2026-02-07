import { buildApp } from "./app";

async function main() {
  const app = buildApp();
  const port = Number(process.env.PORT || 3000);

  await app.listen({ port, host: "0.0.0.0" });
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
