import { defineConfig, loadEnv } from "vite";
import { svelte } from "@sveltejs/vite-plugin-svelte";

export default defineConfig(({ mode }) => {
  const env = loadEnv(mode, process.cwd(), "");
  const apiBaseUrl = (env.FORENSIA_API_BASE_URL || "http://127.0.0.1:8000").replace(/\/+$/, "");

  return {
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
