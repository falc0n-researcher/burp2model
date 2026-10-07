#!/usr/bin/env bash
# Build the demo report from the bundled samples (no network).
# Usage: ./demo.sh [output-dir]
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
out="${1:-burp2model-out}"

run() { if command -v burp2model >/dev/null 2>&1; then burp2model "$@"; else python -m burp2model "$@"; fi; }

# A synthetic external-recon record, so the demo shows the infrastructure layer
# without touching the network. Real runs get this from `burp2model osint`.
mkdir -p "$out/shop"
cp "$here/samples/osint-sample.json" "$out/shop/osint.json"

run "$here/samples/burp-history-sample.xml"       -w shop --role user  --out "$out"
run "$here/samples/burp-history-admin-sample.xml" -w shop --role admin --out "$out"

report="$out/shop/report.html"
echo "wrote $report"

case "$(uname -s)" in
  Darwin) open "$report" ;;
  Linux)  xdg-open "$report" >/dev/null 2>&1 || true ;;
  *)      echo "open it in a browser: $report" ;;
esac
