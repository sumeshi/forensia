import type { Config } from "tailwindcss";

const config: Config = {
  content: ["./index.html", "./src/**/*.{svelte,ts}"],
  theme: {
    extend: {
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
        }
      },
      boxShadow: {
        cockpit: "0 18px 48px rgba(0, 0, 0, 0.28)"
      }
    }
  },
  plugins: [require("@tailwindcss/typography"), require("@tailwindcss/forms")]
};

export default config;
