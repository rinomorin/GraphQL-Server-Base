import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

export default defineConfig({
  root: './src',
  plugins: [react()],
  "scripts" : {
    "dev": "vite"
  },
  server: {
    host: '0.0.0.0', // Binds to all IPv4 interfaces
    port: process.env.PORT ? parseInt(process.env.PORT) : 5173
  }
})
