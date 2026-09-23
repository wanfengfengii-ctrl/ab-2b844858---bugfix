import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// During `vite dev` API calls are proxied to the FastAPI server.
// The production build is served directly by FastAPI from the same origin.
export default defineConfig({
  plugins: [react()],
  server: {
    proxy: {
      "/api": "http://localhost:8000",
      "/health": "http://localhost:8000",
    },
  },
});
