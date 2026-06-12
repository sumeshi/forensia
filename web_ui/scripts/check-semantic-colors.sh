#!/usr/bin/env bash
set -euo pipefail

# Check for raw mocha accent color classes that should have been migrated to semantic tokens.

errors=0

# Accent colors that should NOT appear in .svelte files
for color in mauve green peach blue red pink yellow teal sky lavender maroon sapphire flamingo rosewater; do
  for prefix in text bg border ring; do
    pattern="${prefix}-mocha-${color}"
    matches=$(grep -rn "${pattern}" --include="*.svelte" src/ 2>/dev/null || true)
    if [ -n "$matches" ]; then
      echo "ERROR: Found '${pattern}' in .svelte files:"
      echo "$matches"
      errors=$((errors + 1))
    fi
  done
done

if [ "$errors" -gt 0 ]; then
  echo "----------------------------------------"
  echo "FAILED: $errors raw mocha accent class patterns found."
  echo "Migrate them to semantic equivalents (e.g., text-semantic-ok, bg-semantic-danger)."
  exit 1
fi

echo "OK: No raw mocha accent color classes found in .svelte files."
exit 0
