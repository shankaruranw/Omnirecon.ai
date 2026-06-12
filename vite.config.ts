import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import tailwindcss from '@tailwindcss/vite'
import { viteSingleFile } from 'vite-plugin-singlefile'

export default defineConfig({
  plugins: [react(), tailwindcss(), viteSingleFile()],
  define: {
    'process.env.VITE_API_BASE_URL':JSON.stringify(process.env.VITE_API_BASE_URL ||'https://omnirecon-ai-1.onrender.com')
  }
})
