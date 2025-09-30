import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import fs from 'fs';

export default defineConfig({
  root: './src',
  plugins: [react()],
  server: {
    host: '0.0.0.0', // Binds to all IPv4 interfaces
    port: process.env.PORT ? parseInt(process.env.PORT) : 5173,
    https: {
      key: fs.readFileSync('ssl/rmorin-key.pem'),
      cert: fs.readFileSync('ssl/rmorin.pem'),
    },
  },
});
