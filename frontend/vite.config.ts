import react from "@vitejs/plugin-react";
import { defineConfig } from "vite";

// The dashboard talks to the local NetTriage API (nettriage serve) through this proxy.
export default defineConfig({
  plugins: [react()],
  server: { port: 5173, proxy: { "/api": { target: "http://127.0.0.1:8000", changeOrigin: false } } },
});
