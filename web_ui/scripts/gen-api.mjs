import { spawnSync } from "node:child_process";
import { existsSync, readFileSync } from "node:fs";
import { resolve } from "node:path";

function loadDotEnvValue(key) {
  for (const candidate of [resolve(process.cwd(), ".env"), resolve(process.cwd(), "..", ".env")]) {
    if (!existsSync(candidate)) {
      continue;
    }
    const lines = readFileSync(candidate, "utf-8").split(/\r?\n/);
    for (const line of lines) {
      const trimmed = line.trim();
      if (!trimmed || trimmed.startsWith("#")) {
        continue;
      }
      const separator = trimmed.indexOf("=");
      if (separator <= 0) {
        continue;
      }
      const name = trimmed.slice(0, separator).trim();
      if (name !== key) {
        continue;
      }
      const rawValue = trimmed.slice(separator + 1).trim();
      return rawValue.replace(/^['"]|['"]$/g, "");
    }
  }
  return "";
}

const baseUrl = (
  process.env.FORENSIA_API_BASE_URL ||
  loadDotEnvValue("FORENSIA_API_BASE_URL") ||
  "http://127.0.0.1:8000"
).replace(/\/+$/, "");
const schemaUrl = `${baseUrl}/openapi.json`;

const result = spawnSync(
  "npx",
  ["openapi-typescript", schemaUrl, "-o", "src/api/types.ts"],
  { stdio: "inherit", shell: true }
);

if (result.status !== 0) {
  process.exit(result.status ?? 1);
}
