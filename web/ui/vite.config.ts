import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// Backend used by `npm run dev` for /api (see README.md).
const backend = process.env.SURICONTROLLER_URL ?? "http://127.0.0.1:8080";

export default defineConfig({
  // Relative asset URLs so the UI works under any path prefix.
  base: "./",
  plugins: [react()],
  build: {
    outDir: "../dist",
    emptyOutDir: true,
    chunkSizeWarningLimit: 900,
    rollupOptions: {
      output: {
        manualChunks(id) {
          if (!id.includes("node_modules")) return undefined;
          if (/[\\/]node_modules[\\/](@codemirror|@lezer|@uiw|codemirror|crelt|style-mod|w3c-keyname)[\\/]/.test(id)) {
            return "codemirror";
          }
          if (/[\\/]node_modules[\\/]@mantine[\\/]/.test(id)) return "mantine";
          if (/[\\/]node_modules[\\/](react|react-dom|scheduler|react-router)[\\/]/.test(id)) return "react";
          return undefined;
        },
      },
    },
  },
  server: {
    proxy: {
      "/api": { target: backend, changeOrigin: false, ws: false },
    },
  },
});
