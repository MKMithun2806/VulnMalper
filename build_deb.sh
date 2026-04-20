#!/usr/bin/env bash
# Build a vulnmalper .deb from the repo. Run on any Debian/Ubuntu box.
#
#   ./build_deb.sh              # reads VERSION from vulnmalper.py
#   ./build_deb.sh 2.2.0        # override version
#
# Output: dist/vulnmalper_<version>_all.deb
set -euo pipefail
cd "$(dirname "$0")"

SCRIPT=vulnmalper.py
[ -f "$SCRIPT" ] || { echo "vulnmalper.py not found"; exit 1; }

VERSION="${1:-$(grep -Po 'VERSION\s*=\s*"\K[0-9.]+' "$SCRIPT")}"
echo ">> Building vulnmalper $VERSION"

command -v dpkg-deb >/dev/null 2>&1 || {
  echo "dpkg-deb missing. Install with:  sudo apt install dpkg-dev"; exit 1; }

ROOT="$(mktemp -d)"
trap 'rm -rf "$ROOT"' EXIT

install -d -m 0755 "$ROOT/DEBIAN" \
  "$ROOT/usr/bin" "$ROOT/usr/lib/vulnmalper" \
  "$ROOT/usr/share/doc/vulnmalper" "$ROOT/usr/share/man/man1" \
  "$ROOT/usr/share/bash-completion/completions"

install -m 0644 "$SCRIPT" "$ROOT/usr/lib/vulnmalper/vulnmalper.py"
[ -f README.md ] && install -m 0644 README.md "$ROOT/usr/share/doc/vulnmalper/README.md"

cat > "$ROOT/usr/bin/vulnmalper" << 'EOF'
#!/bin/sh
exec /usr/bin/python3 /usr/lib/vulnmalper/vulnmalper.py "$@"
EOF
chmod 0755 "$ROOT/usr/bin/vulnmalper"

cat > "$ROOT/usr/share/doc/vulnmalper/copyright" << 'EOF'
Format: https://www.debian.org/doc/packaging-manuals/copyright-format/1.0/
Upstream-Name: vulnmalper
Files: *
Copyright: 2026 VulnMalper contributors
License: MIT
EOF

TMPCHG=$(mktemp)
cat > "$TMPCHG" << EOF
vulnmalper ($VERSION) unstable; urgency=medium

  * Release $VERSION.

 -- VulnMalper <noreply@localhost>  $(date -R)
EOF
gzip -9n -c "$TMPCHG" > "$ROOT/usr/share/doc/vulnmalper/changelog.Debian.gz"
rm -f "$TMPCHG"

TMPMAN=$(mktemp)
cat > "$TMPMAN" << 'EOF'
.TH VULNMALPER 1 "2026" "vulnmalper" "User Commands"
.SH NAME
vulnmalper \- vulnerability pipeline for NetMalper graphs
.SH SYNOPSIS
.B vulnmalper
.I input.json
[\fB\-\-out\fR \fIname\fR]
[\fB\-\-runner\fR auto|local|docker]
[\fB\-\-only\fR \fItools\fR]
[\fB\-\-severity\fR info|low|medium|high|critical]
[\fB\-\-threads\fR \fIN\fR]
.SH DESCRIPTION
VulnMalper consumes a NetMalper JSON graph and orchestrates a 3-phase scan:
fingerprint (httpx, whatweb, wafw00f), scan (testssl.sh, nikto, nuclei, wapiti),
verify (sqlmap on curated endpoints only). Any missing tool is transparently
run via its official Docker image. Output is a single Markdown report.
.SH SEE ALSO
netmalper(1), nuclei(1), nikto(1), sqlmap(1), wapiti(1), testssl.sh(1)
EOF
gzip -9n -c "$TMPMAN" > "$ROOT/usr/share/man/man1/vulnmalper.1.gz"
rm -f "$TMPMAN"

cat > "$ROOT/usr/share/bash-completion/completions/vulnmalper" << 'EOF'
_vulnmalper() {
    local cur prev opts
    COMPREPLY=()
    cur="${COMP_WORDS[COMP_CWORD]}"
    prev="${COMP_WORDS[COMP_CWORD-1]}"
    opts="--out --only --runner --severity --threads --max-targets
          --httpx-timeout --whatweb-timeout --wafw00f-timeout --testssl-timeout
          --nikto-timeout --nuclei-timeout --wapiti-timeout --sqlmap-timeout -h --help"
    case "$prev" in
      --runner)   COMPREPLY=( $(compgen -W "auto local docker" -- "$cur") ); return ;;
      --severity) COMPREPLY=( $(compgen -W "info low medium high critical" -- "$cur") ); return ;;
      --only)     COMPREPLY=( $(compgen -W "httpx whatweb wafw00f testssl nikto nuclei wapiti sqlmap" -- "$cur") ); return ;;
    esac
    if [[ "$cur" == -* ]]; then
      COMPREPLY=( $(compgen -W "$opts" -- "$cur") )
    else
      COMPREPLY=( $(compgen -f -X '!*.json' -- "$cur") )
    fi
}
complete -F _vulnmalper vulnmalper
EOF

cat > "$ROOT/DEBIAN/postinst" << 'EOF'
#!/bin/sh
set -e
if [ "$1" = "configure" ]; then
cat << 'MSG'

  VulnMalper installed. Try:    vulnmalper <netmalper_graph.json>
  Man page:                     man vulnmalper
  Force Docker-only mode:       --runner docker
  Any missing scanner will be pulled as its official Docker image.

MSG
fi
exit 0
EOF
chmod 0755 "$ROOT/DEBIAN/postinst"

INSTALLED_SIZE=$(du -sk "$ROOT/usr" | awk '{print $1}')
cat > "$ROOT/DEBIAN/control" << EOF
Package: vulnmalper
Version: $VERSION
Section: admin
Priority: optional
Architecture: all
Depends: python3 (>= 3.9)
Recommends: docker.io | docker-ce | podman
Suggests: nikto, sqlmap, whatweb, wafw00f, wapiti, testssl.sh
Maintainer: VulnMalper <noreply@localhost>
Installed-Size: $INSTALLED_SIZE
Homepage: https://github.com/MKMithun2806
Description: Vulnerability pipeline for NetMalper graphs
 Consumes NetMalper JSON and orchestrates an 8-tool pipeline:
  .
  1. Fingerprint (httpx, whatweb, wafw00f)
  2. Scan        (testssl.sh on 443/8443, nikto on 80/443/8080/8443,
                  nuclei, wapiti)
  3. Verify      (sqlmap — only on upstream-flagged endpoints)
  .
 Missing tools auto-fallback to their official Docker images.
 Produces a clean Markdown report and a colored console summary.
EOF

mkdir -p dist
OUT="dist/vulnmalper_${VERSION}_all.deb"
fakeroot_cmd=""
command -v fakeroot >/dev/null 2>&1 && fakeroot_cmd="fakeroot"
$fakeroot_cmd dpkg-deb --build "$ROOT" "$OUT"
echo ">> Built: $OUT"
dpkg-deb --info "$OUT" | sed -n '1,15p'
