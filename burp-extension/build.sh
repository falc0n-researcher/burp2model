#!/usr/bin/env bash
# Build burp2model.jar with the engine inside, for the platform you run this on.
# Needs Python 3.9+, pip, and a JDK 17+ with the Montoya API on the classpath (or gradle).
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
repo="$(dirname "$here")"
os="$(uname -s | tr '[:upper:]' '[:lower:]')"; case "$os" in darwin) os=macos ;; msys*|mingw*|cygwin*) os=windows ;; esac
arch="$(uname -m)"; case "$arch" in arm64|aarch64) arch=arm64 ;; *) arch=x64 ;; esac
dest="$here/src/main/resources/engine/$os-$arch"
work="$(mktemp -d)"
python3 -m venv "$work/v"
"$work/v/bin/pip" -q install "$repo" pyinstaller
printf 'import sys\nfrom burp2model.cli import main\nsys.exit(main())\n' > "$work/entry.py"
(cd "$work" && "$work/v/bin/pyinstaller" --onefile --name burp2model --collect-data burp2model --noconfirm --log-level WARN entry.py)
mkdir -p "$dest" && cp "$work"/dist/burp2model* "$dest/"
(cd "$here" && gradle jar)
echo "built $here/build/libs/burp2model.jar (engine for $os-$arch inside)"
