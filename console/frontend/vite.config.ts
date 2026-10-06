import { svelte } from '@sveltejs/vite-plugin-svelte';
import { defineConfig } from 'vitest/config';

// In development the API runs separately (python -m tbconsole serve) and Vite
// proxies /api to it, so the app and the API share an origin as they do in
// production, where the API serves the built app itself.
const api = process.env.TBCONSOLE_API ?? 'http://127.0.0.1:8710';

export default defineConfig({
  plugins: [svelte()],
  server: {
    port: 5710,
    proxy: { '/api': { target: api, changeOrigin: false } },
  },
  build: {
    outDir: '../backend/tbconsole/static',
    emptyOutDir: true,
    sourcemap: false,
    chunkSizeWarningLimit: 900,
  },
  test: {
    include: ['src/**/*.test.ts'],
  },
});
