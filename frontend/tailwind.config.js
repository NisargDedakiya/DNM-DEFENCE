/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{js,jsx}'],
  theme: {
    extend: {
      colors: {
        base: '#0B0E14',
        panel: '#11151D',
        panel2: '#161B26',
        border: '#232A38',
        ink: '#E4E7EC',
        muted: '#8B93A3',
        signal: '#F5A623',
        critical: '#E5484D',
        high: '#F5793A',
        medium: '#F0C808',
        low: '#6B7280',
        good: '#33C481',
      },
      fontFamily: {
        sans: ['"IBM Plex Sans"', 'system-ui', 'sans-serif'],
        mono: ['"IBM Plex Mono"', 'monospace'],
      },
    },
  },
  plugins: [],
}
