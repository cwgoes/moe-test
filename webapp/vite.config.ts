import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import wasm from 'vite-plugin-wasm'
import topLevelAwait from 'vite-plugin-top-level-await'

// https://vite.dev/config/
export default defineConfig({
  plugins: [
    react(),
    wasm(),
    topLevelAwait(),
  ],
  optimizeDeps: {
    exclude: ['masp-wasm'],
  },
  build: {
    rollupOptions: {
      // Externalize the WASM module since we load it at runtime
      external: ['/wasm/masp_wasm.js'],
    },
  },
})
