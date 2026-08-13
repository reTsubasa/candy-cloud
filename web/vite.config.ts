import { defineConfig } from 'vitest/config';
import { loadEnv } from 'vite';
import react from '@vitejs/plugin-react';

export default defineConfig(({ mode }) => {
  const environment = loadEnv(mode, '.', '');
  const cloudTarget = environment.CANDY_CLOUD_PROXY_TARGET ?? 'http://127.0.0.1:8080';
  const apiPrefix = environment.CANDY_CLOUD_PROXY_API_PREFIX ?? '';
  return {
    plugins: [react()],
    test: {
      environment: 'jsdom',
      setupFiles: './src/test-setup.ts',
    },
    server: {
      host: '127.0.0.1',
      port: 4173,
      proxy: {
        '/api': {
          target: cloudTarget,
          changeOrigin: true,
          rewrite: (path) => `${apiPrefix}${path.replace(/^\/api/, '')}`,
        },
        '/identity': {
          target: cloudTarget,
          changeOrigin: true,
        },
      },
    },
  };
});
