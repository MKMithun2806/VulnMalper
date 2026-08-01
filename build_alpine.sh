#!/usr/bin/env bash
# Build a self-contained Alpine Linux (musl) binary for VulnMalper using
# Nuitka. Must run on Alpine Linux (musl libc) — typically invoked inside
# the official `alpine` container, e.g. by the release workflow:
#
#   docker run --rm -v "$PWD":/work -w /work \
#     alpine:edge sh -c "apk add --no-cache python3 py3-pip gcc musl-dev python3-dev binutils curl ca-certificates && sh build_alpine.sh"
#
#   ./build_alpine.sh              # reads VERSION from vulnmalper.py
#   ./build_alpine.sh 7.3.6        # override version
#
# Output: dist/vulnmalper-v<version>-alpine-musl
set -euo pipefail
cd "$(dirname "$0")"

SCRIPT=vulnmalper.py
[ -f "$SCRIPT" ] || { echo "vulnmalper.py not found"; exit 1; }

VERSION="${1:-$(sed -n 's/^VERSION = "\([0-9.]*\)"/\1/p' "$SCRIPT")}"
[ -n "$VERSION" ] || { echo "could not determine version from $SCRIPT"; exit 1; }

# Refuse to run on glibc systems — the point is to produce a musl binary.
if ! ls /lib/ld-musl-*.so.1 >/dev/null 2>&1; then
  echo "ERROR: build_alpine.sh must run on Alpine Linux (musl)."
  echo "Run inside an Alpine container, e.g.:"
  echo "  docker run --rm -v \"\$PWD\":/work -w /work alpine:edge sh build_alpine.sh"
  exit 1
fi

echo ">> Building vulnmalper $VERSION for Alpine Linux (musl)"

command -v python3 >/dev/null 2>&1 || {
  echo "python3 missing. Install with: apk add python3 py3-pip gcc musl-dev python3-dev binutils curl ca-certificates"
  exit 1
}

# Nuitka refuses patchelf 0.18.0 (a known buggy release that breaks its
# binary patching). Every current Alpine repo ships 0.18.0, so when that
# version is present we build a working patchelf from source.
ensure_patchelf() {
  local cur=""
  if command -v patchelf >/dev/null 2>&1; then
    cur="$(patchelf --version 2>/dev/null | awk '{print $2}')"
  fi
  if [ -n "$cur" ] && [ "$cur" != "0.18.0" ]; then
    echo "[+] patchelf $cur OK"
    return 0
  fi
  echo "[+] patchelf '${cur:-missing}' not usable — building 0.17.2 from source..."
  apk add --no-cache build-base linux-headers autoconf automake libtool git >/dev/null
  rm -rf /tmp/patchelf-src
  git clone --quiet --depth 1 --branch 0.17.2 \
    https://github.com/NixOS/patchelf /tmp/patchelf-src
  (
    cd /tmp/patchelf-src \
      && ./bootstrap.sh \
      && ./configure --prefix=/usr >/dev/null \
      && make -s -j"$(nproc)" \
      && make install >/dev/null
  )
  rm -rf /tmp/patchelf-src
  echo "[+] patchelf built: $(patchelf --version)"
}

ensure_patchelf

mkdir -p dist

echo "[+] Creating virtual environment..."
python3 -m venv .venv-alpine

echo "[+] Installing build dependencies..."
.venv-alpine/bin/pip install --quiet --upgrade pip
.venv-alpine/bin/pip install --quiet "nuitka[onefile]"

echo "[+] Cleaning previous build artifacts..."
rm -rf vulnmalper.build vulnmalper.dist vulnmalper.onefile-build vulnmalper.bin

echo "[+] Compiling executable..."
.venv-alpine/bin/python -m nuitka \
  --onefile \
  --assume-yes-for-downloads \
  --output-filename=vulnmalper.bin \
  vulnmalper.py

OUT="dist/vulnmalper-v${VERSION}-alpine-musl"
mv vulnmalper.bin "$OUT"
chmod 0755 "$OUT"

rm -rf vulnmalper.build vulnmalper.dist vulnmalper.onefile-build

echo ">> Built: $OUT"
command -v file >/dev/null 2>&1 && file "$OUT" || true
