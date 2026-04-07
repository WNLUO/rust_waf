/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{vue,js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        cyber: {
          bg: '#0a0a0a',
          surface: '#121212',
          border: '#2a2a2a',
          accent: '#7c3aed',
          success: '#00ffaa',
          error: '#ff3333',
          muted: '#888888',
        }
      },
      fontFamily: {
        mono: ['JetBrains Mono', 'Fira Code', 'monospace'],
        sans: ['Inter', 'SF Pro Display', 'system-ui', 'sans-serif'],
      },
      borderRadius: {
        'cyber': '4px',
      },
      boxShadow: {
        'cyber': '0 0 15px rgba(0, 255, 170, 0.1)',
        'cyber-error': '0 0 15px rgba(255, 51, 51, 0.1)',
      }
    },
  },
  plugins: [],
}
