# Installing VulnMalper

This guide covers every supported way to install and run VulnMalper, on any
platform and from any distribution channel.

**Requirements**

- Python 3.9 or newer for the source / `uv` / `pip` routes.
- `docker` (Engine or Desktop) only if you want the automatic Docker fallback
  for missing scanners — VulnMalper itself has zero runtime dependencies.

---

## 1. Install with `uv` (recommended)

[`uv`](https://docs.astral.sh/uv/) is the fastest Python package manager.

Install `uv` (if you don't have it yet):

```bash
curl -LsSf https://astral.sh/uv/install.sh | sh
# or: pip install uv
```

### From PyPI

```bash
uv tool install vulnmalper
```

### From GitHub

```bash
uv tool install git+https://github.com/MKMithun2806/VulnMalper
```

### From a local clone

```bash
git clone https://github.com/MKMithun2806/VulnMalper
cd VulnMalper
uv tool install .
```

All three install a `vulnmalper` executable on your `PATH`:

```bash
vulnmalper --help
```

To update a `uv`-managed install:

```bash
uv tool upgrade vulnmalper
```

To uninstall:

```bash
uv tool uninstall vulnmalper
```

---

## 2. Install with `pip`

```bash
pip install vulnmalper
```

Or in a dedicated virtual environment:

```bash
python -m venv .venv
.venv/bin/pip install vulnmalper
.venv/bin/vulnmalper --help
```

Upgrade:

```bash
pip install --upgrade vulnmalper
```

---

## 3. Debian / Ubuntu (.deb)

Each [GitHub release](https://github.com/MKMithun2806/VulnMalper/releases)
attaches `vulnmalper_<version>_all.deb`.

### Install the prebuilt package

```bash
URL=$(curl -s https://api.github.com/repos/MKMithun2806/VulnMalper/releases/latest \
  | grep browser_download_url | grep .deb | cut -d '"' -f 4)
curl -L -o vulnmalper.deb "$URL"
sudo apt install -y ./vulnmalper.deb
rm vulnmalper.deb
```

This installs the `vulnmalper` command, a man page, and bash completion.

### Build it yourself

Needs `dpkg-dev` (and `fakeroot`, used automatically when present):

```bash
git clone https://github.com/MKMithun2806/VulnMalper
cd VulnMalper
sudo apt install -y dpkg-dev
./build_deb.sh                 # version is read from vulnmalper.py
# or: ./build_deb.sh 8.1.0     # to pin a version
sudo apt install -y ./dist/vulnmalper_*_all.deb
```

The build does **not** require root: it uses `fakeroot` when available and
`dpkg-deb --root-owner-group` otherwise.

### Uninstall

```bash
sudo apt remove -y vulnmalper
```

---

## 4. Alpine Linux (musl)

Each release attaches a self-contained one-file binary,
`vulnmalper-v<version>-alpine-musl`, statically bundled with its Python
runtime.

### Install the prebuilt binary

```bash
wget -O /usr/local/bin/vulnmalper \
  https://github.com/MKMithun2806/VulnMalper/releases/latest/download/vulnmalper-v8.1.0-alpine-musl
chmod +x /usr/local/bin/vulnmalper
vulnmalper --help
```

(Replace `8.1.0` with the version of the release you want.)

### Build it yourself

`build_alpine.sh` builds a Nuitka `--onefile` binary inside the official
Alpine container:

```bash
git clone https://github.com/MKMithun2806/VulnMalper
cd VulnMalper
docker run --rm -v "$PWD":/work -w /work \
  alpine:3.21 sh -c "apk add --no-cache python3 py3-pip gcc musl-dev python3-dev binutils curl ca-certificates >/dev/null 2>&1 && sh build_alpine.sh"
ls -lh dist/vulnmalper-v*-alpine-musl
```

The binary is musl-linked, so it runs on Alpine and any other musl-based
distro without needing Python installed.

---

## 5. Docker

VulnMalper itself has no official image, but it is designed to run inside
containers — and when you install it anywhere, missing scanners are pulled
automatically as their **official Docker images** (nuclei, httpx, nikto,
wapiti, sqlmap, etc.), so only Docker Engine is required:

```bash
# Any distro: engine is enough — scanners come via Docker
curl -fsSL https://get.docker.com | sh
sudo systemctl enable --now docker
```

### Run VulnMalper inside a container

Pick a base image and install via `uv`, `pip`, or the prebuilt artifacts:

```bash
# Python image (uv route)
docker run --rm -v "$PWD":/work -w /work \
  -v /var/run/docker.sock:/var/run/docker.sock \
  python:3.12-slim sh -c "pip install vulnmalper && vulnmalper --help"
```

```bash
# Alpine image (musl binary route)
docker run --rm -v "$PWD":/work -w /work \
  -v /var/run/docker.sock:/var/run/docker.sock \
  alpine:3.21 sh -c "wget -O /usr/local/bin/vulnmalper https://github.com/MKMithun2806/VulnMalper/releases/latest/download/vulnmalper-v8.1.0-alpine-musl && chmod +x /usr/local/bin/vulnmalper && vulnmalper --help"
```

Mounting `/var/run/docker.sock` lets VulnMalper in the container reach the
host Docker daemon to pull the scanner images (see "Docker fallback" below).

### Docker fallback at runtime

Run VulnMalper normally and let it pick the runner:

```bash
vulnmalper targets.json            # --runner auto (default)
vulnmalper targets.json --runner docker   # force all tools via Docker
```

The first run may take a while as scanner images are pulled.

---

## 6. Windows

Install Nuitka, then build the EXE with `build_exe.ps1`:

```powershell
powershell -File build_exe.ps1
```

Or install with `pip` / `uv` directly:

```powershell
pip install vulnmalper
# or:  uv tool install vulnmalper
vulnmalper --help
```

---

## 7. From source (no install)

```bash
git clone https://github.com/MKMithun2806/VulnMalper
cd VulnMalper
./vulnmalper.py --help            # run the single file directly
```

The file is fully self-contained — zero runtime dependencies.

---

## 8. Verify the installation

```bash
vulnmalper --help                 # shows the CLI and tool list
vulnmalper examples/targets.json  # run a real scan against the sample graph
```

A successful run writes a Markdown report (default `report.md`) and prints a
console summary.

---

## 9. Optional: install local scanners

VulnMalper pulls official Docker images for any tool it can't find locally.
For fully local execution, install the tools yourself:

```bash
sudo apt install nikto sqlmap whatweb wafw00f
pip install wapiti3
# Go-based tools
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install github.com/projectdiscovery/katana/cmd/katana@latest
```

---

## Troubleshooting

| Problem | Fix |
| :--- | :--- |
| `docker: command not found` while using `--runner docker` | Install Docker Engine, or install the scanners locally. |
| Scanner images are large / slow to pull | Only the tools you actually run get pulled; run with `--only nuclei` etc. to limit. |
| `vulnmalper` not on `PATH` after `uv tool install` | Run `uv tool update-shell` or re-add `~/.local/bin`. |
| `.deb` build fails on an old dpkg | Install `fakeroot`: `sudo apt install -y fakeroot`. |
| Want to run all tools locally | See "Optional: install local scanners" above. |
