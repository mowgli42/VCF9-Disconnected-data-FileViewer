#!/usr/bin/env bash
set -euo pipefail
root="${1:-.}"; fail=0
while IFS= read -r -d '' f; do
  rel="${f#"$root"/}"
  case "$rel" in .git/*|*/.git/*|node_modules/*|*/node_modules/*|build/*|*/build/*|deps/*|.venv/*|vendor/*) continue ;; esac
  base="$(basename "$f")"
  case "$base" in *-key.pem|*.key|id_rsa|id_dsa|id_ecdsa|id_ed25519) echo "KEY FILE: $rel"; fail=1; continue ;; esac
  if grep -qE --binary-files=without-match 'BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY' "$f" 2>/dev/null; then echo "PRIVATE KEY HEADER: $rel"; fail=1; fi
done < <(find "$root" -type f -print0)
if [[ "$fail" -ne 0 ]]; then echo "Secrets scan failed."; exit 1; fi
echo "Secrets scan clean (working tree)."
