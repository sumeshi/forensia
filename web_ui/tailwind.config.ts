import type { Config } from "tailwindcss";

const config: Config = {
  content: ["./index.html", "./src/**/*.{svelte,ts}"],
  theme: {
    extend: {
      fontFamily: {
        mono: ['"JetBrains Mono"', '"IBM Plex Mono"', 'Consolas', 'monospace'],
      },
      colors: {
        mocha: {
          base: "#1e1e2e",
          mantle: "#181825",
          crust: "#11111b",
          text: "#cdd6f4",
          subtext0: "#a6adc8",
          subtext1: "#bac2de",
          overlay0: "#6c7086",
          overlay1: "#7f849c",
          overlay2: "#9399b2",
          surface0: "#313244",
          surface1: "#45475a",
          surface2: "#585b70",
          mauve: "#cba6f7",
          lavender: "#b4befe",
          blue: "#89b4fa",
          sky: "#89dceb",
          teal: "#94e2d5",
          green: "#a6e3a1",
          yellow: "#f9e2af",
          peach: "#fab387",
          maroon: "#eba0ac",
          red: "#f38ba8",
          pink: "#f5c2e7",
          flamingo: "#f2cdcd",
          rosewater: "#f5e0dc"
        },
        // Static hex (not CSS vars): Tailwind opacity modifiers (/40 etc.)
        // need alpha-capable color values. Revisit if a theme switch lands.
        semantic: {
          accent: "#b4befe",
          ok: "#a6e3a1",
          warn: "#f9e2af",
          danger: "#f38ba8",
          info: "#89b4fa",
          fg: "#cdd6f4",
          "fg-muted": "#a6adc8",
          "fg-faint": "#7f849c",
          bg: "#1e1e2e",
          "bg-raised": "#313244",
          "bg-inset": "#11111b",
        }
      }
    }
  },
  plugins: [require("@tailwindcss/typography"), require("@tailwindcss/forms")]
};

export default config;
