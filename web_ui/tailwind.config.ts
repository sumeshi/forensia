import type { Config } from "tailwindcss";

const config: Config = {
  content: ["./index.html", "./src/**/*.{svelte,ts}"],
  theme: {
    extend: {
      fontFamily: {
        mono: ['"JetBrains Mono"', '"IBM Plex Mono"', 'Consolas', 'monospace'],
      },
      colors: {
        // Near-black neutral ramp (page → cards → borders → text). The accent
        // hues below stay vivid for charts/status; the primary accent is a
        // single violet so the UI reads as one calm, dark surface.
        mocha: {
          base: "#0a0a0d",
          mantle: "#08080b",
          crust: "#060608",
          text: "#e8e8ef",
          subtext0: "#9a9aa8",
          subtext1: "#c2c2cd",
          overlay0: "#4f4f5a",
          overlay1: "#6b6b78",
          overlay2: "#8a8a98",
          surface0: "#18181f",
          surface1: "#2c2c38",
          surface2: "#3a3a47",
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
          accent: "#cba6f7",
          ok: "#a6e3a1",
          warn: "#f9e2af",
          danger: "#f38ba8",
          info: "#89b4fa",
          fg: "#e8e8ef",
          "fg-muted": "#9a9aa8",
          "fg-faint": "#62626e",
          bg: "#0a0a0d",
          "bg-raised": "#18181f",
          "bg-inset": "#060608",
        }
      }
    }
  },
  plugins: [require("@tailwindcss/typography"), require("@tailwindcss/forms")]
};

export default config;
