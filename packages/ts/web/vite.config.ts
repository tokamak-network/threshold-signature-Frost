import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import wasm from 'vite-plugin-wasm';
import topLevelAwait from 'vite-plugin-top-level-await';
import path from 'path';
import init from 'tokamak-frost-wasm';
// @ts-ignore - Importing from sibling package source
import { FServer } from '../ts-fserver/src/server.ts';

// https://vitejs.dev/config/
export default defineConfig({
  plugins: [
    react(),
    wasm(),
    topLevelAwait(),
    {
      name: 'configure-fserver',
      configureServer(server) {
        init().then(() => {
          console.log('WASM module initialized for FServer.');
          try {
            // Attach FServer to Vite's HTTP server at /frost-ws path
            new FServer({ server: server.httpServer!, path: '/frost-ws' });
          } catch (e) {
            console.error("Failed to start FServer:", e);
          }
        }).catch((e) => {
          console.error("Failed to initialize WASM for FServer:", e);
        });
      }
    }
  ],
  server: {
    fs: {
      allow: ['..'], // Allow serving files from parent directory (node_modules, related packages)
    },
  },
  optimizeDeps: {
    include: [
      '@noble/hashes/sha256',
      '@noble/hashes/sha512',
      '@noble/hashes/ripemd160',
      '@noble/hashes/hmac',
    ],
  },
  resolve: {
    alias: {
      '@noble/hashes': path.resolve(__dirname, '../../../node_modules/@noble/hashes'),
    },
  },
});
