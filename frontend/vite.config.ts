import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
export default defineConfig({
  plugins: [react()],
  base: "/workbench/",
  build: { outDir: "../app/static/workbench", emptyOutDir: true },
  server: {
    proxy: {
      "/ThreatKB": process.env.THREATKB_BACKEND_URL || "http://127.0.0.1:5080",
    },
  },
});
