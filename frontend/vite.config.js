import { defineConfig } from 'vite';

const backendTarget = process.env.BACKEND_TARGET || 'http://backend:8000';
const wsBackendTarget = backendTarget.replace(/^http/, 'ws');

export default defineConfig({
  root: '.',
  server: {
    host: '0.0.0.0',
    port: 5173,
    allowedHosts: 'all',
    proxy: {
      '/api/admin/ws': {
        target: wsBackendTarget,
        ws: true,
        changeOrigin: true,
      },
      '/api': {
        target: backendTarget,
        changeOrigin: true,
      },
      '/ws': {
        target: wsBackendTarget,
        ws: true,
      },
    },
  },
  build: {
    outDir: 'dist',
  },
});
