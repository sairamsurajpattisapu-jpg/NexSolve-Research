import react from '@vitejs/plugin-react'
import { defineConfig } from 'vite'

// https://vite.dev/config/
export default defineConfig({
  plugins: [react()],
  server: {
    proxy: {
      '/api': 'http://127.0.0.1:8001',
      '/health': 'http://127.0.0.1:8001',
      '/ready': 'http://127.0.0.1:8001',
      '/jobs': 'http://127.0.0.1:8001',
    },
  },
  preview: {
    port: 5173,
    proxy: {
      '/api': 'http://127.0.0.1:8001',
      '/health': 'http://127.0.0.1:8001',
      '/ready': 'http://127.0.0.1:8001',
      '/jobs': 'http://127.0.0.1:8001',
    },
  },
})
