import { defineConfig, loadEnv } from "vite";
import { svelte } from "@sveltejs/vite-plugin-svelte";
import path from "node:path";

export default defineConfig(({ mode }) => {
  const envDir = path.resolve(__dirname, "..");
  const env = loadEnv(mode, envDir, "");
  const apiBaseUrl = (env.FORENSIA_API_BASE_URL || "http://127.0.0.1:8000").replace(/\/+$/, "");

  return {
    envDir,
    plugins: [svelte()],
    server: {
      proxy: {
        "/api": apiBaseUrl,
        "/evidence": apiBaseUrl,
        "/openapi.json": apiBaseUrl
      }
    }
  };
});
