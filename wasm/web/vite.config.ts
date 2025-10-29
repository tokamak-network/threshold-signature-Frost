import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

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
});
