/** @type {import('tailwindcss').Config} */
module.exports = {
  content: ["./index.html", "./src/**/*.{js,jsx,ts,tsx}"],
  theme: {
    fontFamily: {
      mono: ['"Space Mono"', '"Fira Code"', 'Courier New', 'monospace'],
      vt:   ['"VT323"', 'monospace'],
    },
    extend: {
      colors: {
        /* 90s PC Neubrutalism Palette */
        'retro-teal':    '#008080',
        'retro-beige':   '#EBE9D8',
        'retro-gray':    '#C0C0C0',
        'retro-white':   '#FFFFFF',
        'retro-black':   '#000000',
        
        'retro-blue':    '#000080',
        'retro-red':     '#FF0000',
        'retro-yellow':  '#FFCC00',
        'retro-green':   '#00FF00',
      },
      boxShadow: {
        /* Hard solid black offset shadows for neubrutalism */
        'mech':          '4px 4px 0px 0px rgba(0,0,0,1)',
        'mech-lg':       '6px 6px 0px 0px rgba(0,0,0,1)',
        'window':        '8px 8px 0px 0px rgba(0,0,0,1)',
        /* Pressed state — shadow collapses to zero */
        'pressed':       '0px 0px 0px 0px rgba(0,0,0,1)',
      },
      animation: {
        'cursor-blink': 'cursorBlink 1s step-end infinite',
        'pulse-dot':    'pulseDot 2s ease-in-out infinite',
      },
      keyframes: {
        cursorBlink: {
          '0%, 100%': { opacity: '1' },
          '50%':      { opacity: '0' },
        },
        pulseDot: {
          '0%, 100%': { opacity: '1',   transform: 'scale(1)' },
          '50%':      { opacity: '0.4', transform: 'scale(0.85)' },
        },
      },
    },
  },
  plugins: [],
}
