/** @type {import('tailwindcss').Config} */
export default {
  content: ['./src/**/*.{astro,html,js,jsx,md,mdx,svelte,ts,tsx,vue}'],
  theme: {
    extend: {
      colors: {
        cyber: {
          dark: '#080c14',
          card: '#0f172a',
          cardHover: '#131e33',
          border: '#1e293b',
          borderHover: '#334155',
          indigo: '#6366f1',
          indigoHover: '#4f46e5',
          cyan: '#38bdf8',
          emerald: '#10b981',
          amber: '#f59e0b',
          crimson: '#ef4444',
          purple: '#a855f7',
          muted: '#94a3b8'
        }
      },
      fontFamily: {
        sans: ['"Red Hat Text"', 'ui-sans-serif', 'system-ui', 'sans-serif'],
        display: ['"Red Hat Display"', '"Red Hat Text"', 'ui-sans-serif', 'system-ui', 'sans-serif'],
        mono: ['"Red Hat Mono"', 'ui-monospace', 'SFMono-Regular', 'Menlo', 'Monaco', 'Consolas', 'monospace']
      }
    },
  },
  plugins: [],
}
