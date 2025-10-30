import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import path from 'path';

// https://vitejs.dev/config/
export default defineConfig({
  plugins: [react()],
  server: {
    fs: {
      // Allow serving files from one level up (the 'wasm' directory)
      // to allow access to the 'pkg' directory.
      allow: ['..'],
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
      '@noble/hashes': path.resolve(__dirname, './node_modules/@noble/hashes'),
    },
  },
});
