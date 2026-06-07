#!/usr/bin/env python3
"""
VulnMalper v7.3.6  —  Vulnerability pipeline for NetMalper graphs.

Pipeline:
    NetMalper JSON
        │
        ├── httpx       → all HTTP targets       (always — tech + status)
        ├── whatweb     → all HTTP targets       (always — tech stack)
        ├── wafw00f     → all HTTP targets       (always — detects WAF)
        ├── testssl.sh  → 443 / 8443 only        (TLS config bugs)
        ├── nikto       → 80 / 443 / 8080 / 8443 (web server misconfig)
        ├── nuclei      → all HTTP targets       (CVE / misconfig templates)
        ├── wapiti      → all HTTP targets       (active XSS/SSRF/RCE/XXE/LFI)
        └── sqlmap      → only injectable-looking endpoints surfaced by
                          NetMalper (query params) OR by nuclei/nikto
                          (forms, reflected params). No blind spray.

Tools run locally when present, else via their official Docker image
(auto-fallback, `--runner auto` by default).

Pairs with: https://github.com/MKMithun2806/NetMalper

Usage:
    python3 vulnmalper.py <netmalper_graph.json> [options]
"""
from __future__ import annotations

import argparse
import concurrent.futures
import base64
import csv
import ipaddress
import json
import os
import random
import shlex
import re
import shutil
import socket
import ssl
import subprocess
import sys
import tempfile
import time
import threading
import urllib.parse
import urllib.error
import urllib.request
import xml.etree.ElementTree as ET
import html.parser
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

VERSION = "7.3.6"

# Background warmup state for docker images and nuclei templates.
DOCKER_IMAGE_EVENTS: dict[str, threading.Event] = {}
DOCKER_IMAGE_RESULTS: dict[str, bool] = {}
NUCLEI_TEMPLATE_EVENT: Optional[threading.Event] = None
NUCLEI_TEMPLATE_RESULT: Optional[bool] = None
NUCLEI_TEMPLATE_LOCK = threading.RLock()
PHASE0_NMAP_EVENT: Optional[threading.Event] = None
PHASE0_NMAP_RESULT: Optional[bool] = None
PHASE0_NMAP_LOCK = threading.RLock()

# ── Stealth / polite-mode profile ───────────────────────────────────────────
# Realistic, current desktop browser User-Agents. One is picked per run (or
# per request when supported by the tool) so a noisy 8-tool pipeline doesn't
# advertise itself with a single tell-tale UA string. Pool widened in 2.6.2
# so per-request randomisation (httpx/nuclei/whatweb) doesn't cycle visibly.
BROWSER_UAS = [
    # Chrome 124 / Win11
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    # Chrome 122 / Win10
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    # Chrome 124 / macOS
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    # Edge 124 / Win11
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 Edg/124.0.0.0",
    # Edge 123 / Win10
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36 Edg/123.0.0.0",
    # Safari 17 / macOS
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 "
    "(KHTML, like Gecko) Version/17.4 Safari/605.1.15",
    # Safari 16 / macOS
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 "
    "(KHTML, like Gecko) Version/16.6 Safari/605.1.15",
    # Firefox 125 / Linux
    "Mozilla/5.0 (X11; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0",
    # Firefox 124 / Win10
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:124.0) Gecko/20100101 Firefox/124.0",
    # Chrome 124 / Android
    "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0.0.0 Mobile Safari/537.36",
]

# Plausible Referer pool — varies per request so every probe doesn't claim
# to be a Google click-through. Keep these to common entry points an actual
# browser session might originate from.
REFERER_POOL = [
    "https://www.google.com/",
    "https://duckduckgo.com/",
    "https://www.bing.com/",
    "https://news.ycombinator.com/",
    "https://github.com/",
    "https://stackoverflow.com/",
    "",  # direct-nav (no Referer at all)
]

# Accept-Language mix — some EN, some ES/DE/FR variants. WAFs that fingerprint
# on a fixed "en-US,en;q=0.9" string see less of a pattern this way.
ACCEPT_LANG_POOL = [
    "en-US,en;q=0.9",
    "en-GB,en;q=0.9,en-US;q=0.8",
    "en-US,en;q=0.8,es;q=0.6",
    "en-US,en;q=0.9,de;q=0.7",
    "fr-FR,fr;q=0.9,en;q=0.7",
    "en-US,en;q=0.9,ja;q=0.6",
]

@dataclass
class StealthProfile:
    """Centralised stealth/polite-mode knobs, plumbed into every tool."""
    polite:     bool = False        # global "be nice to the target" flag
    slow:       bool = False        # Nikto -Pause 1 + verbose, evades simple WAFs
    user_agent: Optional[str] = None  # explicit UA, else random per-run
    headers:    list[str] = field(default_factory=list)  # ["K: V", ...]
    rate_limit: int = 0             # nuclei -rl / wapiti -d cap (0 = tool default)
    delay_ms:   int = 0             # request spacing where supported
    headless:   bool = False        # nuclei -headless: render JS via Chromium
    jitter:     bool = True         # randomise timing + headers per request
    quiet:      bool = False        # nuclei: drop noisy/intrusive templates

    def pick_ua(self) -> str:
        return self.user_agent or random.choice(BROWSER_UAS)

    def default_headers(self) -> list[str]:
        """Browser-ish headers we add unless the user already specified one.

        With jitter on (the default), Referer / Accept-Language / DNT / a
        small subset of Sec-Fetch-* values are randomised PER CALL so two
        back-to-back probes don't carry an identical header fingerprint.
        WAFs (Cloudflare, Akamai, F5) hash on header order + value tuples;
        varying a few fields breaks naive signatures without looking weird.
        """
        have = {h.split(":",1)[0].strip().lower() for h in self.headers if ":" in h}
        out  = list(self.headers)

        ref = random.choice(REFERER_POOL) if self.jitter else "https://www.google.com/"
        lang = random.choice(ACCEPT_LANG_POOL) if self.jitter else "en-US,en;q=0.9"
        # Randomise DNT + Sec-Fetch-Site so we look like both fresh-tab and
        # cross-site nav traffic, not a robot that always claims one origin.
        sec_site = random.choice(["cross-site","same-origin","none"]) \
                   if self.jitter else "cross-site"
        dnt_val = random.choice(["1","0"]) if self.jitter else "1"

        candidate = [
            ("Accept",          "text/html,application/xhtml+xml,application/xml;"
                                "q=0.9,image/avif,image/webp,*/*;q=0.8"),
            ("Accept-Language", lang),
            ("Accept-Encoding", "gzip, deflate, br"),
            ("DNT",             dnt_val),
            ("Sec-Fetch-Site",  sec_site),
            ("Sec-Fetch-Mode",  "navigate"),
            ("Sec-Fetch-User",  "?1"),
            ("Sec-Fetch-Dest",  "document"),
            ("Upgrade-Insecure-Requests", "1"),
            ("Cache-Control",   random.choice(["max-age=0","no-cache"])
                                if self.jitter else "max-age=0"),
        ]
        if ref:  # skip Referer entirely on "direct nav" rolls
            candidate.append(("Referer", ref))

        for k, v in candidate:
            if k.lower() not in have:
                out.append(f"{k}: {v}")
        return out

    def polite_rl(self, default_rl: int) -> int:
        """Throttle a tool's req/sec when polite/slow is on."""
        if self.rate_limit > 0:
            return self.rate_limit
        if self.slow:   return min(default_rl, 5)
        if self.polite: return min(default_rl, 20)
        return default_rl

    def polite_delay(self, default_ms: int = 0) -> int:
        """Return a *base* per-request delay (ms). With jitter enabled, callers
        should treat this as the lower bound and add random spread (see
        ``jittered_delay``) so timing patterns aren't perfectly periodic."""
        if self.delay_ms > 0:    return self.delay_ms
        if self.slow:            return max(default_ms, 1000)
        if self.polite:          return max(default_ms, 250)
        return default_ms

    def jittered_delay(self, default_ms: int = 0) -> int:
        """Base delay + ±50% random spread. 0 in fast mode = no sleep."""
        base = self.polite_delay(default_ms)
        if base <= 0 or not self.jitter:
            return base
        # spread between 0.5x and 1.5x the base
        return int(base * random.uniform(0.5, 1.5))

    def sleep_jitter(self, default_ms: int = 0) -> None:
        """Used by orchestrator between tool launches per target — small
        random pause so an 8-tool fan-out doesn't hit the target in a clean
        burst pattern that scream-tests an IPS."""
        ms = self.jittered_delay(default_ms)
        if ms > 0:
            time.sleep(ms / 1000.0)

# Default profile (overwritten in main() once CLI args are parsed). Keeping
# a module-global keeps the per-tool runner signatures backward compatible.
STEALTH = StealthProfile()

@dataclass
class AuthProfile:
    user: Optional[str] = None
    password: Optional[str] = None
    cookie: Optional[str] = None
    authed_cookie: Optional[str] = None

AUTH = AuthProfile()

class ProxyPool:
    """Round-robin proxy rotator. Thread-safe."""
    def __init__(self, proxies: list[str]):
        self._all = proxies
        self._http = [p for p in proxies if p.startswith("http://") or p.startswith("https://")]
        self._idx = 0
        self._lock = threading.Lock()

    def next(self) -> Optional[str]:
        if not self._all:
            return None
        with self._lock:
            p = self._all[self._idx % len(self._all)]
            self._idx += 1
            return p

    def next_http_only(self) -> Optional[str]:
        if not self._http:
            return None
        with self._lock:
            p = self._http[self._idx % len(self._http)]
            self._idx += 1
            return p

    def __bool__(self):
        return bool(self._all)

PROXY_POOL: ProxyPool = ProxyPool([])

def _apply_proxy(cmd: list[str], proxy: Optional[str], tool: str) -> list[str]:
    if not proxy:
        return cmd
    flags: dict[str, list[str]] = {
        "httpx":       ["--http-proxy", proxy],
        "nuclei":      ["-proxy", proxy],
        "wapiti":      ["--proxy", proxy],
        "sqlmap":      ["--proxy", proxy],
        "nikto":       ["-useproxy", proxy],
        "ffuf":        ["-x", proxy],
        "feroxbuster": ["--proxy", proxy],
        "katana":      ["-proxy", proxy],
        "whatweb":     [f"--proxy={proxy}"],
    }
    return cmd + flags.get(tool, [])

SQLMAP_LEVEL: Optional[int] = None
SQLMAP_RISK: Optional[int] = None

def auth_present() -> bool:
    return bool((AUTH.user and AUTH.password) or AUTH.cookie)

def auth_mode_label() -> str:
    return "authenticated" if auth_present() else "unauthenticated"

def auth_cookie_value() -> str:
    return AUTH.cookie or ""

def auth_basic_header() -> Optional[str]:
    if not (AUTH.user and AUTH.password):
        return None
    raw = f"{AUTH.user}:{AUTH.password}".encode("utf-8")
    token = base64.b64encode(raw).decode("ascii")
    return f"Authorization: Basic {token}"

def auth_form_data() -> str:
    if not (AUTH.user and AUTH.password):
        return ""
    return f"username={urllib.parse.quote_plus(AUTH.user)}&password={urllib.parse.quote_plus(AUTH.password)}"

def merge_form_data(*parts: str) -> str:
    """Merge URL-encoded form/query strings without losing existing fields."""
    items: list[tuple[str, str]] = []
    for part in parts:
        if not part:
            continue
        try:
            items.extend(urllib.parse.parse_qsl(part, keep_blank_values=True))
        except Exception:
            continue
    if not items:
        return ""
    return urllib.parse.urlencode(items, doseq=True)

# ── Nuclei template hygiene ────────────────────────────────────────────────
# Tags that are noisy, intrusive, or already covered by another stage in
# this pipeline. Excluding them when --quiet (or --polite) is on cuts
# request volume by ~60-80% and avoids the obvious "nuclei default scan"
# fingerprint that every WAF vendor ships a rule for.
NOISY_NUCLEI_TAGS = [
    "dos",           # denial-of-service probes — never run uninvited
    "intrusive",     # writes / state-changing requests
    "fuzz", "fuzzing",
    "tech",          # tech-detect — already done by httpx + whatweb
    "favicon",       # ditto
    "ssl",           # already done by testssl.sh
    "network",       # we're scanning HTTP, not raw TCP services here
    "dns",           # NetMalper handled DNS upstream
    "miscellaneous",
    "honeypot",
]

# Templates that are pure noise on a typical bug-bounty / red-team scan and
# almost always trigger WAFs. Excluded under --quiet/--polite via -et glob.
NOISY_NUCLEI_TEMPLATE_GLOBS = [
    "http/exposures/configs/",      # ~600 templates, mostly false-positive heavy
    "http/miscellaneous/",
    "http/technologies/",           # tech-detect dupes
]

# ── ANSI colors ─────────────────────────────────────────────────────────────
class C:
    R   = "\033[0m"; B = "\033[1m"; DIM = "\033[2m"
    RD  = "\033[31m"; GN = "\033[32m"; YL = "\033[33m"
    BL  = "\033[34m"; MG = "\033[35m"; CY = "\033[36m"; GY = "\033[90m"
    BG_RD = "\033[41m"

def _supports_color() -> bool:
    return sys.stdout.isatty() and os.environ.get("NO_COLOR") is None

if not _supports_color():
    for k in list(vars(C)):
        if not k.startswith("_") and isinstance(getattr(C, k), str):
            setattr(C, k, "")

SEV_ORDER = {"critical":4, "high":3, "medium":2, "low":1, "info":0, "unknown":0}
SEV_BADGE = {
    "critical": C.BG_RD + C.B + " CRIT " + C.R,
    "high":     C.RD + C.B + " HIGH " + C.R,
    "medium":   C.YL + C.B + " MED  " + C.R,
    "low":      C.BL + " LOW  " + C.R,
    "info":     C.GY + " INFO " + C.R,
    "unknown":  C.GY + " ???? " + C.R,
}

def log(level: str, msg: str):
    tags = {
        "info": f"{C.CY}[*]{C.R}", "ok":   f"{C.GN}[+]{C.R}",
        "warn": f"{C.YL}[!]{C.R}", "err":  f"{C.RD}[x]{C.R}",
        "run":  f"{C.MG}[»]{C.R}", "skip": f"{C.GY}[~]{C.R}",
        "phase":f"{C.MG}{C.B}▶{C.R}",
    }
    print(f"{tags.get(level,'[?]')} {msg}", flush=True)

def banner():
    print(f"""{C.MG}{C.B}
 ╔══════════════════════════════════════════════════════╗
 ║   V u l n M a l p e r    v{VERSION}                       ║
 ║   fingerprint → scan → exploit-verify   pipeline     ║
 ║   httpx · whatweb · wafw00f · testssl · nikto        ║
 ║   nuclei · wapiti · sqlmap · ffuf · feroxbuster      ║
 ║   local OR docker, auto-fallback                     ║
 ╚══════════════════════════════════════════════════════╝{C.R}
""")

# ── Data classes ────────────────────────────────────────────────────────────
@dataclass
class Finding:
    target:    str
    tool:      str
    severity:  str
    title:     str
    detail:    str = ""
    reference: str = ""
    raw:       dict = field(default_factory=dict)
    def key(self): return (self.target, self.tool, self.title.lower())

@dataclass
class WebTarget:
    url:       str
    host:      str
    port:      int
    scheme:    str
    service:   str = "http"
    product:   str = ""
    has_query: bool = False
    src_node:  str = ""
    # filled in by fingerprinting phase:
    alive:     bool = False
    status:    Optional[int] = None
    tech:      list[str] = field(default_factory=list)
    waf:       Optional[str] = None
    crawl_new_endpoints: int = 0
    # injectable URLs discovered by upstream tools (nikto/nuclei) during scan:
    injectable: list[str] = field(default_factory=list)
    # flag to avoid recursive discovery loops
    discovered: bool = False
    # auto-mode strategy cache (set after Phase 1 when enabled)
    auto_strategy: Optional[str] = None
    auto_reason: str = ""
    # session cookie from a successful default-login finding; used for sqlmap
    authed_cookie: Optional[str] = None

@dataclass
class ServiceTarget:
    host:      str
    port:      int
    service:   str = ""
    product:   str = ""
    src_node:  str = ""
    crawl_new_endpoints: int = 0

    @property
    def component(self) -> str:
        return f"{self.host}:{self.port}"

# ── NetMalper graph parsing ─────────────────────────────────────────────────
WEB_SERVICES = {"http","https","http-proxy","https-alt","http-alt"}
WEB_PORTS    = {80,81,443,591,2082,2083,2086,2087,2095,2096,
                3000,5000,7001,7002,8000,8008,8080,8081,8088,
                8090,8443,8888,9000,9001,9090,9443}
NIKTO_PORTS  = {80,443,8080,8443}
TLS_PORTS    = {443,8443}
PHASE0_NMAP_IMAGE = "instrumentisto/nmap:latest"

def _best_hostname_for_ip(ip: str, cache: dict[str, str]) -> Optional[str]:
    return cache.get(ip)

def _normalize_url(url: str) -> str:
    """Robustly normalize a URL for deduplication and tool consistency."""
    try:
        p = urllib.parse.urlparse(url.strip())
        scheme = p.scheme.lower() or "http"
        netloc = p.netloc.lower()
        path = p.path or "/"
        # Ensure path starts with /
        if not path.startswith("/"):
            path = "/" + path
        # Normalize: remove redundant /., etc. but keep trailing / if it was there
        path = re.sub(r"/+", "/", path)
        query = p.query
        # Sort query params for stable normalization
        if query:
            qs = urllib.parse.parse_qsl(query, keep_blank_values=True)
            qs.sort()
            query = urllib.parse.urlencode(qs)
        return urllib.parse.urlunparse((scheme, netloc, path, "", query, ""))
    except Exception:
        return url.strip()

def _is_worth_scanning(url: str) -> bool:
    """Return False if the URL points to a static asset that doesn't need vulnerability scanning."""
    STATIC_EXTS = {
        ".css", ".js", ".png", ".jpg", ".jpeg", ".gif", ".ico", ".svg",
        ".woff", ".woff2", ".ttf", ".eot", ".pdf", ".mp4", ".mp3",
        ".wasm", ".map", ".json", ".xml", ".txt",
    }
    try:
        path = urllib.parse.urlparse(url).path.lower()
        ext = os.path.splitext(path)[1]
        return ext not in STATIC_EXTS
    except Exception:
        return True

def parse_netmalper(graph: dict):
    nodes = {n["id"]: n for n in graph.get("nodes", [])}
    meta  = graph.get("meta", {})
    targets: dict[str, WebTarget] = {}
    services: dict[tuple[str, int, str], ServiceTarget] = {}

    # Pre-compute IP-to-hostname mapping to avoid O(N^2) DNS lookups
    ip_to_host: dict[str, str] = {}
    for n in nodes.values():
        if n["type"] in ("sub", "root", "cname"):
            fqdn = n["data"].get("fqdn") or n.get("label")
            if not fqdn:
                continue
            try:
                # Short timeout for DNS resolution
                ip = socket.gethostbyname(fqdn)
                if ip:
                    ip_to_host[ip] = fqdn
            except Exception:
                continue

    for n in nodes.values():
        if n["type"] != "endpoint": continue
        url = n["data"].get("url")
        if not url: continue
        # Normalize URL while preserving trailing slashes if present
        normalized_url = _normalize_url(url)
        p = urllib.parse.urlparse(normalized_url)
        port = p.port or (443 if p.scheme == "https" else 80)
        targets.setdefault(normalized_url, WebTarget(
            url=normalized_url, host=p.hostname or "", port=port, scheme=p.scheme,
            service=p.scheme, has_query=bool(p.query), src_node=n["id"],
        ))

    for n in nodes.values():
        if n["type"] != "port": continue
        d = n["data"]
        port_raw = d.get("port")
        if port_raw is None: continue
        try:
            port = int(port_raw)
        except (ValueError, TypeError):
            continue
        svc = (d.get("service") or "").lower()
        host = d.get("host") or ""
        if not host: continue
        
        looks_web = svc in WEB_SERVICES or port in WEB_PORTS or "http" in svc
        if not looks_web: continue
        scheme = "https" if (svc == "https" or port in (443,8443,9443)) else "http"
        host_label = _best_hostname_for_ip(host, ip_to_host) or host
        url = f"{scheme}://{host_label}" + (f":{port}" if port not in (80,443) else "") + "/"
        # Normalize URL while preserving trailing slashes if present
        normalized_url = _normalize_url(url)
        p = urllib.parse.urlparse(normalized_url)
        targets.setdefault(normalized_url, WebTarget(
            url=normalized_url, host=host_label, port=p.port or port, scheme=scheme,
            service=svc or scheme, product=d.get("product",""),
            src_node=n["id"],
        ))

    for n in nodes.values():
        if n["type"] != "port":
            continue
        d = n["data"]
        port_raw = d.get("port")
        if port_raw is None: continue
        try:
            port = int(port_raw)
        except (ValueError, TypeError):
            continue
        svc = (d.get("service") or "").lower()
        host = d.get("host") or ""
        if not host:
            continue
        looks_web = svc in WEB_SERVICES or port in WEB_PORTS or "http" in svc
        if looks_web:
            continue
        host_label = _best_hostname_for_ip(host, ip_to_host) or host
        key = (host_label, port, svc)
        services.setdefault(key, ServiceTarget(
            host=host_label,
            port=port,
            service=svc or "unknown",
            product=d.get("product", ""),
            src_node=n["id"],
        ))
    return list(targets.values()), list(services.values()), meta

# ── Runner layer (local + docker) ───────────────────────────────────────────
ALL_TOOLS = ["httpx","whatweb","wafw00f","testssl","nikto",
             "nuclei","wapiti","sqlmap","ffuf","feroxbuster", "katana"]

DOCKER_IMAGES = {
    "httpx":   "projectdiscovery/httpx:latest",
    "whatweb": "ghcr.io/mkmithun2806/whatweb:latest",
    "wafw00f": "ghcr.io/mkmithun2806/wafw00f:latest",
    "testssl": "ghcr.io/mkmithun2806/testssl.sh:latest",
    "nikto":   "ghcr.io/sullo/nikto:latest",
    "nuclei":  "ghcr.io/mkmithun2806/nuclei:latest",
    "wapiti":  "ghcr.io/mkmithun2806/wapiti:latest",
    "sqlmap":  "ghcr.io/mkmithun2806/sqlmap:latest",
    "ffuf":    "ghcr.io/mkmithun2806/ffuf:latest",
    "feroxbuster": "ghcr.io/mkmithun2806/feroxbuster:latest",
    "katana": "ghcr.io/mkmithun2806/katana:latest",
}
# Some tools publish their binary under a different name inside the image:
DOCKER_ENTRYPOINTS = {
    # "testssl" image has /bin/bash entrypoint; we'll prepend the script name.
    # All others have sensible default entrypoints.
}
LOCAL_BINARIES = {
    "httpx":   "httpx",
    "whatweb": "whatweb",
    "wafw00f": "wafw00f",
    "testssl": "testssl.sh",
    "nikto":   "nikto",
    "nuclei":  "nuclei",
    "wapiti":  "wapiti",
    "sqlmap":  "sqlmap",
    "ffuf":    "ffuf",
    "feroxbuster": "feroxbuster",
    "katana": "katana",
}

def have(cmd: str) -> bool:
    return shutil.which(cmd) is not None

def _docker_env() -> dict:
    """Env to hand to docker subprocesses so sudo'd runs still see the
    real user's docker config (creds + context). Without this, running
    `sudo vulnmalper` makes docker look at /root/.docker which usually
    has no auth and no `desktop-linux` context, breaking all pulls.

    Also falls back to the local Unix socket when no DOCKER_HOST is
    set, because WSL2 + Docker Desktop users often have a broken
    `desktop-linux` named-pipe context (yields
    "Failed to initialize: protocol not available")."""
    env = os.environ.copy()
    sudo_user = os.environ.get("SUDO_USER") or os.environ.get("DOAS_USER")
    if sudo_user:
        try:
            pwd = subprocess.run(
                ["getent", "passwd", sudo_user],
                capture_output=True, text=True, timeout=4,
            )
            if pwd.returncode == 0:
                home_dir = pwd.stdout.strip().split(":")[5]
                if home_dir and os.path.isdir(home_dir):
                    env["HOME"] = home_dir
                    env.setdefault("USER", sudo_user)
                    cfg_candidates = [
                        os.path.join(home_dir, ".docker"),
                        os.path.join(home_dir, ".local", "share", "docker"),
                    ]
                    for c in cfg_candidates:
                        if os.path.isdir(c):
                            env.setdefault("DOCKER_CONFIG", c)
                            break
        except Exception:
            pass
    if "DOCKER_HOST" not in env and os.path.exists("/var/run/docker.sock"):
        env["DOCKER_HOST"] = "unix:///var/run/docker.sock"
    return env

def docker_available() -> bool:
    if not have("docker"): return False
    try:
        p = subprocess.run(["docker","info"], capture_output=True, text=True,
                           timeout=15, env=_docker_env())
        return p.returncode == 0
    except Exception:
        return False

@dataclass
class ToolPlan:
    name:   str
    runner: str
    image:  Optional[str] = None

def plan_tools(runner_pref: str) -> dict[str, Optional[ToolPlan]]:
    docker_ok = docker_available()
    out: dict[str, Optional[ToolPlan]] = {}
    for name in ALL_TOOLS:
        bin_name  = LOCAL_BINARIES[name]
        local_ok  = have(bin_name)
        plan: Optional[ToolPlan] = None
        if runner_pref == "local":
            if local_ok: plan = ToolPlan(name, "local")
        elif runner_pref == "docker":
            if docker_ok: plan = ToolPlan(name, "docker", DOCKER_IMAGES[name])
        else:  # auto
            if local_ok:
                plan = ToolPlan(name, "local")
            elif docker_ok:
                plan = ToolPlan(name, "docker", DOCKER_IMAGES[name])
        out[name] = plan
    return out

def _image_candidates(image: str) -> list[str]:
    """Return alternative image refs to try for a configured image.
    The user may have pulled a private namespace under a slightly
    different prefix (e.g. `ghcr.io/me/foo` vs `docker.io/me/foo` vs
    just `me/foo`)."""
    seen, out = set(), []
    for ref in [image,
                image.replace("ghcr.io/", ""),
                image.replace("ghcr.io/", "docker.io/"),
                image.split("/", 1)[-1] if "/" in image else image]:
        if ref and ref not in seen:
            seen.add(ref)
            out.append(ref)
    return out

def ensure_docker_image(image: str, quiet: bool = False):
    env = _docker_env()
    for candidate in _image_candidates(image):
        try:
            subprocess.run(["docker", "image", "inspect", candidate],
                           capture_output=True, text=True, timeout=10,
                           env=env, check=True)
            return True
        except subprocess.TimeoutExpired:
            if not quiet:
                log("warn", f"docker image inspect timed out for {candidate} after 10s")
            return False
        except subprocess.CalledProcessError:
            pass
        except Exception:
            return False

    if not quiet:
        log("info", f"Pulling docker image: {image}")
    for attempt, timeout in ((1, 120), (2, 300)):
        for candidate in _image_candidates(image):
            try:
                subprocess.run(["docker", "pull", candidate],
                               capture_output=True, text=True, timeout=timeout,
                               env=env, check=True)
                return True
            except subprocess.TimeoutExpired:
                log("warn", f"docker pull {candidate} timed out ({timeout}s), retrying...")
                break
            except subprocess.CalledProcessError as e:
                details = _coerce_subprocess_text(
                    getattr(e, "stderr", "")) or _coerce_subprocess_text(
                    getattr(e, "stdout", ""))
                details = details.strip().splitlines()
                snippet = details[-1] if details else ""
                if attempt == 1:
                    log("warn",
                        f"docker pull {candidate} failed ({snippet or 'unknown error'}), retrying...")
                continue
            except Exception as e:
                log("err", f"docker pull {candidate} error: {e}")
                return False
    log("err", f"docker pull {image} failed; tried {len(_image_candidates(image))} tag(s). "
              f"Run `docker images` as the real user (or `docker login ghcr.io`) and try again.")
    return False

def warm_docker_images(plans: dict[str, Optional["ToolPlan"]]):
    """Start background pulls for docker images used by this run."""
    for name, plan in plans.items():
        if not plan or plan.runner != "docker" or name in DOCKER_IMAGE_EVENTS:
            continue
        event = threading.Event()
        DOCKER_IMAGE_EVENTS[name] = event

        def _worker(tool_name=name, image=plan.image, done=event):
            ok = ensure_docker_image(image)
            DOCKER_IMAGE_RESULTS[tool_name] = ok
            done.set()

        threading.Thread(target=_worker, daemon=True).start()

def wait_for_docker_image(plan: ToolPlan) -> bool:
    """Block until the background pull for a docker image has finished."""
    event = DOCKER_IMAGE_EVENTS.get(plan.name)
    if event is None:
        return ensure_docker_image(plan.image)
    event.wait()
    return DOCKER_IMAGE_RESULTS.get(plan.name, False)

def warm_nuclei_templates(plan: Optional[ToolPlan]):
    """Start a one-time nuclei template refresh in the background."""
    global NUCLEI_TEMPLATE_EVENT
    if not plan or plan.runner != "docker":
        return
    with NUCLEI_TEMPLATE_LOCK:
        if NUCLEI_TEMPLATE_EVENT is not None:
            return
        event = threading.Event()
        NUCLEI_TEMPLATE_EVENT = event

        def _worker():
            global NUCLEI_TEMPLATE_RESULT
            try:
                template_dir = os.path.expanduser("~/.cache/vulnmalper/nuclei-templates")
                try:
                    os.makedirs(template_dir, exist_ok=True)
                except Exception:
                    template_dir = os.path.join(tempfile.gettempdir(), f"vulnmalper_nuclei_{os.getuid()}")
                    os.makedirs(template_dir, exist_ok=True)

                log("info", "Refreshing Nuclei templates in background...")
                cmd = build_cmd(plan, ["-update-templates", "-silent"], mounts=[(template_dir, "/root/nuclei-templates")])
                rc, out, err = _run(cmd, 300)
                if rc != 0:
                    log("warn", f"Nuclei template refresh failed (rc={rc}), retrying...")
                    rc2, out2, err2 = _run(cmd, 300)
                    NUCLEI_TEMPLATE_RESULT = (rc2 == 0)
                    if rc2 == 0:
                        msg = out2.strip() or err2.strip() or "done"
                        log("ok", f"Nuclei templates refreshed: {msg}")
                    else:
                        log("warn", "Nuclei templates refresh failed twice; scans will continue")
                else:
                    NUCLEI_TEMPLATE_RESULT = True
                    msg = out.strip() or err.strip() or "done"
                    log("ok", f"Nuclei templates refreshed: {msg}")
            except Exception as e:
                NUCLEI_TEMPLATE_RESULT = False
                log("warn", f"Nuclei template refresh errored: {e}")
            finally:
                event.set()

        threading.Thread(target=_worker, daemon=True).start()

def ensure_nuclei_templates(plan: Optional[ToolPlan]):
    """Wait for the nuclei template refresh, starting it if needed."""
    global NUCLEI_TEMPLATE_EVENT
    if not plan or plan.runner != "docker":
        return True
    with NUCLEI_TEMPLATE_LOCK:
        if NUCLEI_TEMPLATE_EVENT is None:
            warm_nuclei_templates(plan)
    event = NUCLEI_TEMPLATE_EVENT
    if event is None:
        return True
    event.wait()
    return bool(NUCLEI_TEMPLATE_RESULT)

def _nuclei_template_mount() -> tuple[str, str]:
    """Return the host/container mount used for nuclei template persistence."""
    template_dir = _nuclei_template_host_dir()
    return (template_dir, "/root/nuclei-templates")

def _nuclei_template_host_dir() -> str:
    """Return the host directory used to persist nuclei templates."""
    template_dir = os.path.expanduser("~/.cache/vulnmalper/nuclei-templates")
    try:
        os.makedirs(template_dir, exist_ok=True)
    except Exception:
        # Fall back to a user-specific temp dir if the cache path is not writable.
        template_dir = os.path.join(tempfile.gettempdir(), f"vulnmalper_nuclei_{os.getuid()}")
        os.makedirs(template_dir, exist_ok=True)
    return template_dir

def _ensure_nuclei_templates_ready(plan: Optional[ToolPlan], target: str) -> bool:
    """Wait for nuclei templates to finish refreshing and verify they exist."""
    if not plan or plan.runner != "docker":
        return True

    ok = ensure_nuclei_templates(plan)
    if not ok:
        log("warn", "nuclei: template update was incomplete/failed, using existing or default set")

    template_dir = _nuclei_template_host_dir()
    try:
        tmpl_path = Path(template_dir)
        tmpl_count = sum(1 for _ in tmpl_path.rglob("*.yaml"))
        if tmpl_count < 100:
            log("warn", f"nuclei: only {tmpl_count} templates found, waiting...")
            time.sleep(5)
            tmpl_count = sum(1 for _ in tmpl_path.rglob("*.yaml"))
        if tmpl_count < 100:
            log("err", f"nuclei: template dir empty after wait, skipping {target}")
            return False
        log("info", f"nuclei: {tmpl_count} templates ready")
    except Exception as e:
        log("warn", f"nuclei: template readiness check failed for {target}: {e}")
        return False
    return True

def warm_phase0_nmap_image():
    """Background-pull the Phase 0 nmap image when Docker fallback is needed."""
    global PHASE0_NMAP_EVENT
    with PHASE0_NMAP_LOCK:
        if PHASE0_NMAP_EVENT is not None:
            return
        event = threading.Event()
        PHASE0_NMAP_EVENT = event

        def _worker():
            global PHASE0_NMAP_RESULT
            try:
                PHASE0_NMAP_RESULT = ensure_docker_image(PHASE0_NMAP_IMAGE)
            except Exception:
                PHASE0_NMAP_RESULT = False
            finally:
                event.set()

        threading.Thread(target=_worker, daemon=True).start()

def wait_for_phase0_nmap_image() -> bool:
    event = PHASE0_NMAP_EVENT
    if event is None:
        warm_phase0_nmap_image()
        event = PHASE0_NMAP_EVENT
    if event is None:
        return False
    event.wait()
    return bool(PHASE0_NMAP_RESULT)

def _coerce_subprocess_text(value: object) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return str(value)

def _format_cmd(cmd: list[str]) -> str:
    try:
        return shlex.join(str(part) for part in cmd)
    except Exception:
        return " ".join(str(part) for part in cmd)

def _run(cmd, timeout, stdin_data: Optional[str] = None):
    cmd_text = _format_cmd(cmd)
    try:
        p = subprocess.run(cmd, input=stdin_data, capture_output=True,
                           text=True, timeout=timeout)
        return p.returncode, p.stdout, p.stderr
    except subprocess.TimeoutExpired as e:
        stdout = _coerce_subprocess_text(getattr(e, "stdout", ""))
        stderr = _coerce_subprocess_text(getattr(e, "stderr", ""))
        parts = [f"timeout after {timeout}s"]
        if cmd_text:
            parts.append(f"while running: {cmd_text}")
        if stderr.strip():
            parts.append("stderr: " + stderr.strip())
        if stdout.strip():
            parts.append("stdout: " + stdout.strip())
        return 124, stdout, "\n".join(parts)
    except FileNotFoundError as e:
        return 127, "", f"{cmd_text}: {e}" if cmd_text else str(e)
    except Exception as e:
        return 1, "", f"{cmd_text}: {e}" if cmd_text else str(e)

def _first_human_line(text: str) -> str:
    """Return the first non-empty, non-JSON-looking line from a blob."""
    for raw in (text or "").splitlines():
        line = raw.strip()
        if not line:
            continue
        if line.startswith("{") or line.startswith("["):
            continue
        return line
    return ""

def _summarize_nuclei_stats(text: str) -> str:
    """Turn nuclei progress snapshots into a compact one-line summary."""
    latest: dict[str, object] = {}
    for raw in (text or "").splitlines():
        line = raw.strip()
        if not line:
            continue
        if not line.startswith("{"):
            continue
        try:
            payload = json.loads(line)
        except Exception:
            continue
        if isinstance(payload, dict):
            latest = payload

    if not latest:
        return _first_human_line(text)

    preferred = ("duration", "requests", "matched", "errors", "rps", "percent")
    bits = [f"{key}={latest[key]}" for key in preferred if key in latest]
    if bits:
        return "nuclei stats: " + " ".join(bits)

    return _first_human_line(text)

def _load_json_document(text: str):
    """Parse a JSON document, with a line-by-line fallback for tool output."""
    blob = (text or "").strip()
    if not blob:
        return None
    try:
        return json.loads(blob)
    except Exception:
        pass
    for raw in blob.splitlines():
        line = raw.strip()
        if not line or not line.startswith(("{", "[")):
            continue
        try:
            return json.loads(line)
        except Exception:
            continue
    return None

def _iter_wapiti_vulnerabilities(payload):
    """Yield (category, item) pairs from a wapiti JSON payload."""
    if isinstance(payload, dict):
        vulns = payload.get("vulnerabilities", payload)
    else:
        vulns = payload

    if isinstance(vulns, dict):
        items_iter = vulns.items()
    elif isinstance(vulns, list):
        items_iter = enumerate(vulns)
    else:
        return

    for category, items in items_iter:
        if isinstance(items, dict):
            items = [items]
        elif not isinstance(items, list):
            continue
        for item in items:
            if isinstance(item, dict):
                yield str(category), item

def _same_netloc(candidate: str, base: str) -> bool:
    """True when both URLs resolve to the same network location."""
    try:
        c = urllib.parse.urlparse(candidate)
        b = urllib.parse.urlparse(base)
        return bool(c.netloc) and c.netloc == b.netloc
    except Exception:
        return False

def _looks_like_advisory_path(path: str) -> bool:
    """Reject path fragments that are clearly embedded absolute URLs."""
    try:
        frag = path.lstrip("/")
        first_seg = frag.split("/", 1)[0]
        return "/" in frag and "." in first_seg
    except Exception:
        return False

def build_cmd(plan: ToolPlan, tool_args: list[str],
              mounts: Optional[list[tuple[str,str]]] = None,
              extra_docker: Optional[list[str]] = None,
              local_binary: Optional[str] = None) -> list[str]:
    """Build the final subprocess command for either runner."""
    if plan.runner == "local":
        return [local_binary or LOCAL_BINARIES[plan.name]] + tool_args
    wait_for_docker_image(plan)
    docker = ["docker","run","--rm","-i","--network","host"]
    if mounts:
        for host, container in mounts:
            os.makedirs(host, exist_ok=True)
            docker += ["-v", f"{host}:{container}"]
    if extra_docker:
        docker += extra_docker
    docker += [plan.image]
    return docker + tool_args

def ensure_wordlist(name: str, url: str) -> str:
    """Download a wordlist to /tmp/vulnmalper_wordlists if missing."""
    folder = "/tmp/vulnmalper_wordlists"
    os.makedirs(folder, exist_ok=True)
    path = os.path.join(folder, name)
    if os.path.exists(path) and os.path.getsize(path) > 0:
        return path
    log("info", f"Downloading wordlist: {name} ...")
    try:
        urllib.request.urlretrieve(url, path)
        return path
    except Exception as e:
        log("err", f"Failed to download wordlist {name}: {e}")
        return ""

# ────────────────────────────────────────────────────────────────────────────
#  PHASE 1 — FINGERPRINTING (always runs on every HTTP target)
# ────────────────────────────────────────────────────────────────────────────
def run_httpx(targets: list[WebTarget], plan: ToolPlan, timeout: int, stealth: StealthProfile):
    """Probe alive + fingerprint tech/server/status for every target."""
    if not targets:
        return []
    urls = "\n".join(t.url for t in targets)
    args = ["-silent","-json","-l","-","-nc","-no-color","-timeout","10",
            "-tech-detect","-status-code","-title","-server","-follow-redirects"]
    base_args = list(args)
    # Stealth: random browser UA + extra (jittered) headers on every probe.
    args += ["-H", f"User-Agent: {stealth.pick_ua()}"]
    for h in stealth.default_headers():
        args += ["-H", h]
    # Lower rate when polite/slow; httpx -rate-limit is per-second.
    rl = stealth.polite_rl(150)
    args += ["-rate-limit", str(rl)]
    # Cap parallel fan-out so a 50-target graph doesn't burst-probe.
    if stealth.polite or stealth.slow:
        args += ["-threads", "10" if stealth.slow else "25"]
    by_url = {t.url: t for t in targets}
    findings: list[Finding] = []

    def _parse_httpx_output(out: str):
        for line in out.splitlines():
            line = line.strip()
            if not line.startswith("{"): continue
            try: j = json.loads(line)
            except Exception: continue
            u = j.get("url") or j.get("input") or ""
            t = by_url.get(u)
            # some httpx builds normalize trailing slashes etc.
            if not t:
                for k, v in by_url.items():
                    if k.rstrip("/") == u.rstrip("/"): t = v; break
            if not t: continue
            t.alive  = True
            t.status = j.get("status_code") or j.get("status-code")
            techs    = j.get("tech") or j.get("technologies") or []
            if isinstance(techs, list): t.tech = [str(x) for x in techs]
            server   = j.get("webserver") or j.get("server") or ""
            title    = j.get("title") or ""
            detail_parts = []
            if server: detail_parts.append(f"server={server}")
            if t.tech: detail_parts.append("tech=" + ", ".join(t.tech))
            if title:  detail_parts.append(f"title={title[:80]}")
            findings.append(Finding(
                target=t.url, tool="httpx", severity="info",
                title=f"Alive ({t.status}) — {server or 'unknown server'}",
                detail=" · ".join(detail_parts), raw=j,
            ))

    proxy = PROXY_POOL.next()
    args = _apply_proxy(args, proxy, "httpx")
    cmd  = build_cmd(plan, args)
    rc, out, err = _run(cmd, timeout, stdin_data=urls)
    _parse_httpx_output(out)
    if targets and not findings:
        log("warn", "httpx returned 0 results, falling back to direct probing")
        single_args = base_args[:2] + base_args[4:]
        for t in targets:
            _fb_args = _apply_proxy(single_args + ["-u", t.url], PROXY_POOL.next(), "httpx")
            cmd = build_cmd(plan, _fb_args)
            rc, out, err = _run(cmd, timeout)
            _parse_httpx_output(out)
    return findings

def run_whatweb(t: WebTarget, plan: ToolPlan, timeout: int, stealth: StealthProfile):
    args = ["--color=never","--log-json=-","-a","1",
            "--user-agent", stealth.pick_ua()]
    for h in stealth.default_headers():
        args += ["--header", h]
    args.append(t.url)
    proxy = PROXY_POOL.next()
    args = _apply_proxy(args, proxy, "whatweb")
    cmd = build_cmd(plan, args)
    rc, out, err = _run(cmd, timeout)
    findings: list[Finding] = []
    for line in out.splitlines():
        line = line.strip()
        if not line.startswith("["): continue
        try: arr = json.loads(line)
        except Exception: continue
        for entry in arr if isinstance(arr, list) else [arr]:
            plugins = entry.get("plugins") or {}
            names = []
            for pname, pdata in plugins.items():
                versions = (pdata or {}).get("version") or []
                if versions:
                    names.append(f"{pname} {versions[0]}")
                else:
                    names.append(pname)
            for n in names:
                if n and n not in t.tech:
                    t.tech.append(n)
            if names:
                findings.append(Finding(
                    target=t.url, tool="whatweb", severity="info",
                    title=f"Tech: {', '.join(names[:8])}" + (" …" if len(names) > 8 else ""),
                    detail=", ".join(names), raw=entry,
                ))
    return findings

def run_wafw00f(t: WebTarget, plan: ToolPlan, timeout: int, stealth: StealthProfile):
    host_dir = f"/tmp/vulnmalper_waf_{abs(hash(t.url))}"
    os.makedirs(host_dir, exist_ok=True)
    out_name = "waf.json"
    ua = stealth.pick_ua()
    if plan.runner == "docker":
        container_dir = "/wrk"
        out_path = f"{container_dir}/{out_name}"
        args = ["-U", ua, t.url, "-a", "-o", out_path, "-f", "json"]
        cmd = build_cmd(plan, args, mounts=[(host_dir, container_dir)])
    else:
        out_path = os.path.join(host_dir, out_name)
        args = ["-U", ua, t.url, "-a", "-o", out_path, "-f", "json"]
        cmd = build_cmd(plan, args)
    rc, out, err = _run(cmd, timeout)
    findings: list[Finding] = []
    host_out = os.path.join(host_dir, out_name)
    detected_waf = None
    if os.path.exists(host_out):
        try:
            with open(host_out) as f:
                data = json.load(f)
            entries = data if isinstance(data, list) else [data]
            for e in entries:
                if e.get("detected") and e.get("firewall"):
                    detected_waf = e.get("firewall")
                    break
        except Exception: pass
    else:
        # fallback: parse "[+] The site X is behind Y WAF"
        m = re.search(r"behind\s+(.+?)\s+WAF", out, re.I)
        if m: detected_waf = m.group(1).strip()
    if detected_waf:
        t.waf = detected_waf
        findings.append(Finding(
            target=t.url, tool="wafw00f", severity="info",
            title=f"WAF detected: {detected_waf}",
            detail=f"Scanners downstream (sqlmap, wapiti) may be throttled or blocked by {detected_waf}.",
        ))
    else:
        findings.append(Finding(
            target=t.url, tool="wafw00f", severity="info",
            title="No WAF detected", detail="",
        ))
    shutil.rmtree(host_dir, ignore_errors=True)
    return findings

# ────────────────────────────────────────────────────────────────────────────
#  PHASE 2 — SCANNING
# ────────────────────────────────────────────────────────────────────────────
def run_testssl(t: WebTarget, plan: ToolPlan, timeout: int):
    """Only called on TLS ports (443/8443)."""
    host_dir = f"/tmp/vulnmalper_tls_{abs(hash(t.url))}"
    os.makedirs(host_dir, exist_ok=True)
    target = f"{t.host}:{t.port}"
    out_name = "tls.json"
    if plan.runner == "docker":
        container_dir = "/wrk"
        args = ["--quiet","--color","0","--jsonfile",
                f"{container_dir}/{out_name}", target]
        cmd = build_cmd(plan, args, mounts=[(host_dir, container_dir)])
    else:
        args = ["--quiet","--color","0","--jsonfile",
                os.path.join(host_dir, out_name), target]
        cmd = build_cmd(plan, args)
    rc, out, err = _run(cmd, timeout)
    findings: list[Finding] = []
    host_out = os.path.join(host_dir, out_name)
    sev_map = {"OK":"info","INFO":"info","LOW":"low","MEDIUM":"medium",
               "HIGH":"high","CRITICAL":"critical","WARN":"low"}
    if os.path.exists(host_out):
        try:
            with open(host_out) as f:
                data = json.load(f)
            entries = data if isinstance(data, list) else data.get("scanResult", [])
            for e in entries:
                sev_raw = (e.get("severity") or "").upper()
                sev = sev_map.get(sev_raw, "info")
                if sev == "info": continue  # keep noise down
                findings.append(Finding(
                    target=t.url, tool="testssl", severity=sev,
                    title=e.get("id") or "TLS finding",
                    detail=e.get("finding") or "",
                    reference=e.get("cve") or e.get("cwe") or "",
                    raw=e,
                ))
        except Exception as ex:
            log("warn", f"testssl JSON parse failed: {ex}")
    shutil.rmtree(host_dir, ignore_errors=True)
    return findings

NIKTO_SEV_HINTS = [
    (re.compile(r"\b(rce|remote code|sql injection|sqli|shell upload|directory traversal)\b", re.I), "high"),
    (re.compile(r"\b(xss|csrf|open redirect|file inclusion|lfi|rfi|exposed)\b", re.I), "medium"),
    (re.compile(r"\b(missing|outdated|deprecated|default|insecure header)\b", re.I), "low"),
]
def _classify_nikto(text):
    for pat, sev in NIKTO_SEV_HINTS:
        if pat.search(text): return sev
    return "info"

# Findings already covered better by other tools — drop to reduce report noise.
# (X-Frame-Options / clickjacking is also reported by wapiti & nuclei templates.)
NIKTO_NOISE_RE = re.compile(
    r"("
    r"anti[- ]clickjacking.*X-Frame-Options"
    r"|X-Frame-Options.*not present"
    r"|X-Content-Type-Options.*not (set|present)"
    r"|Strict-Transport-Security.*not (defined|set)"
    r"|Content-Security-Policy.*not (defined|set|present)"
    r"|uncommon header .* by the target"
    r"|Cookie .* created without the (httponly|secure) flag"
    r")",
    re.I,
)

# ── Nikto capability cache ─────────────────────────────────────────────────
# Different nikto builds have wildly different option sets:
#   * Ubuntu/Debian apt ships 2.1.6 (2014):  no -Add-header, no -nointeractive,
#                                            no -maxtime in seconds form,
#                                            -host wants a hostname (not URL).
#   * ghcr.io/sullo/nikto docker image is current 2.5.0+: full option set.
#   * Newest from-source builds (2.6.0):     -Add-header, -nointeractive,
#                                            -host accepts full URL.
# We probe `nikto -Help` ONCE per binary and cache which options are
# supported, then build the command line accordingly. Anything not on the
# binary's help screen is silently dropped instead of triggering the
# "Unknown option, exiting in 0.1s" failure mode.
_NIKTO_CAPS_CACHE: dict[str, dict] = {}

def _nikto_capabilities(plan: ToolPlan) -> dict:
    """Run `nikto -Help` once and cache which CLI options this build accepts."""
    key = f"{plan.runner}:{plan.image or LOCAL_BINARIES['nikto']}"
    if key in _NIKTO_CAPS_CACHE:
        return _NIKTO_CAPS_CACHE[key]
    cmd = build_cmd(plan, ["-Help"])
    rc, out, err = _run(cmd, timeout=20)
    help_text = (out or "") + "\n" + (err or "")
    # Some builds print -Version before the help table — that's fine, we
    # only care which option names appear anywhere in the text.
    def has(opt: str) -> bool:
        # Match e.g. "-Add-header" but not "-Add-headerless"
        return bool(re.search(rf"(?<!\w){re.escape(opt)}(?!\w)", help_text))
    caps = {
        "version_text":   (re.search(r"Nikto\s+v?([\d.]+)", help_text) or [None,"unknown"])[1],
        "add_header":     has("-Add-header"),
        "request_header": has("-RequestHeader"),  # legacy
        "id_flag":        has("-id"),
        "cookie_flag":    has("-cookie"),
        "useragent_flag": has("-useragent") or has("-Useragent"),
        "nointeractive":  has("-nointeractive"),
        "ask":            has("-ask"),
        "maxtime":        has("-maxtime"),
        "tuning":         has("-Tuning"),
        "display":        has("-Display"),
        "format_flag":    has("-Format"),
        "output_flag":    has("-output") or has("-o"),
        "host_flag":      has("-host") or has("-h"),
        "ssl_flag":       has("-ssl"),
        "port_flag":      has("-port") or has("-p"),
        "root_flag":      has("-root"),
        "pause":          has("-Pause"),
        # If help failed entirely, assume modern (don't cripple the run).
        "help_ok":        bool(help_text.strip()),
    }
    if not caps["help_ok"]:
        # Couldn't even probe — assume modern 2.5.0+ defaults.
        caps.update({"add_header": True, "nointeractive": True, "ask": True,
                     "maxtime": True, "tuning": True, "display": True,
                     "format_flag": True, "output_flag": True,
                     "host_flag": True, "ssl_flag": True, "port_flag": True,
                     "root_flag": True, "pause": True, "useragent_flag": True,
                     "id_flag": True, "cookie_flag": True})
    _NIKTO_CAPS_CACHE[key] = caps
    return caps


def run_nikto(t: WebTarget, plan: ToolPlan, timeout: int, stealth: StealthProfile):
    """Run nikto and parse its '+ ...' output lines.

    Built straight off the official option list at
    https://github.com/sullo/nikto/wiki/Annotated-Option-List, but adapts
    to legacy 2.1.6 (Ubuntu apt) which is missing several flags. We probe
    `nikto -Help` once per binary and only emit options it actually
    accepts — silently dropping anything else, instead of getting the
    "unknown option → exit 0.1s, 0 findings" failure mode.

    URL handling:
      We split t.url into -h <host> -port <N> [-ssl] [-root <path>]. This
      form is accepted by *every* nikto version since 2.1.x. Passing a
      full URL to -host worked in 2.6.0 but blew up on Ubuntu's 2.1.6.

    Output capture:
      Belt-and-braces: we write to -output FILE *and* capture stdout/stderr.
      Whichever has the '+ ' lines, we parse. Some old builds only print
      to stdout, others only to file.
    """
    caps = _nikto_capabilities(plan)

    # ── Decompose URL into host/port/ssl/root (works on every nikto) ────
    p = urllib.parse.urlparse(t.url)
    host = p.hostname or t.host
    port = p.port or (443 if p.scheme == "https" else 80)
    is_ssl = (p.scheme == "https")
    root_path = p.path or "/"
    if root_path == "/" or not root_path:
        root_path = ""  # no -root needed

    # ── Output file — always a unique, writable /tmp path ────────────────
    host_dir = tempfile.mkdtemp(prefix="vulnmalper_nikto_", dir="/tmp")
    os.chmod(host_dir, 0o777)  # docker user inside image is non-root
    out_name = f"nikto_{int(time.time() * 1000)}_{os.getpid()}.txt"
    if plan.runner == "docker":
        container_dir = "/wrk"
        out_path = f"{container_dir}/{out_name}"
    else:
        out_path = os.path.join(host_dir, out_name)

    # ── Build command, gated on capabilities ─────────────────────────────
    args: list[str] = []
    if caps["host_flag"]:
        args += ["-h", host, "-port", str(port)]
        if is_ssl and caps["ssl_flag"]:
            args += ["-ssl"]
        if root_path and caps["root_flag"]:
            args += ["-root", root_path]
    else:
        # absolute fallback — should never trigger, every nikto has -h
        args += [t.url]

    if AUTH.user and AUTH.password and caps.get("id_flag"):
        args += ["-id", f"{AUTH.user}:{AUTH.password}"]
    if AUTH.cookie and caps.get("cookie_flag"):
        args += ["-cookie", AUTH.cookie]

    if caps["ask"]:
        args += ["-ask", "no"]
    if caps["nointeractive"]:
        args += ["-nointeractive"]
    if caps["output_flag"]:
        args += ["-output", out_path]
    # -Format derived from extension on every build, so we omit it.
    # It's safer NOT to pass -Format than to pass an unsupported value.
    if caps["maxtime"]:
        if stealth.slow:
            maxtime = min(timeout, 570)
        elif stealth.headless:
            maxtime = min(timeout, 1200)
        else:
            maxtime = min(timeout, 900)
        maxtime = max(60, maxtime)
        args += ["-maxtime", f"{maxtime}s"]
    if caps["tuning"]:
        # 1=interesting files, 2=misconfig, 3=info disclosure,
        # b=software ID, c=remote source inclusion. Skip 4(XSS),
        # 5/7(LFI/RFI), 6(DoS), 8(RCE) — wapiti/nuclei cover those better.
        args += ["-Tuning", "123bc"]
    if caps["useragent_flag"]:
        args += ["-useragent", stealth.pick_ua()]
    if caps["display"]:
        # V = verbose. Without it, some builds emit nothing on stdout.
        args += ["-Display", "V"]
    if stealth.slow and caps["pause"]:
        args += ["-Pause", "1"]

    # Custom headers — only on builds that actually support them.
    if caps["add_header"]:
        for h in stealth.default_headers():
            args += ["-Add-header", h]
    elif caps["request_header"]:
        for h in stealth.default_headers():
            args += ["-RequestHeader", h]
    # else: legacy 2.1.6 — silently skip. Better than a hard exit.

    proxy = PROXY_POOL.next_http_only()
    args = _apply_proxy(args, proxy, "nikto")
    if plan.runner == "docker":
        cmd = build_cmd(plan, args, mounts=[(host_dir, container_dir)])
    else:
        cmd = build_cmd(plan, args)

    log("info", f"   nikto v{caps['version_text']} "
                f"({sum(1 for k,v in caps.items() if v is True)} caps detected)")
    t0 = time.time()
    rc, out, err = _run(cmd, timeout + 30)
    elapsed = time.time() - t0

    # Combine: file output (most reliable) + stdout + stderr.
    file_text = ""
    host_file = os.path.join(host_dir, out_name)
    if os.path.exists(host_file):
        try:
            with open(host_file, errors="replace") as fh:
                file_text = fh.read()
        except Exception as ex:
            log("warn", f"nikto could not read {host_file}: {ex}")
    text = "\n".join(x for x in (file_text, out, err) if x)

    # Diagnostic: a healthy nikto run is >5s. <2s + tiny output = it bailed.
    # Surface the actual command + first error line so the user can debug.
    line_count = sum(1 for ln in text.splitlines() if ln.strip())
    if elapsed < 2.0 and line_count < 15:
        snippet = " | ".join(
            ln.strip() for ln in text.splitlines() if ln.strip()
        )[:300] or "no output"
        log("warn", f"nikto bailed in {elapsed:.1f}s rc={rc}: {snippet}")
        log("warn", f"   cmd: {' '.join(cmd)}")

    # Lines we never want to treat as findings (banner/metadata/progress).
    SKIP_PREFIXES = (
        "Target IP", "Target Hostname", "Target Host", "Target Port",
        "Start Time", "End Time", "Server:", "Host:", "Hostname:",
        "No CGI Directories", "Site link", "SSL Info", "Root page",
        "Allowed HTTP Methods",
        "0 host(s) tested", "1 host(s) tested",
    )
    # Also skip "NNNN requests: ... item(s) reported" summary line.
    SUMMARY_RE = re.compile(r"^\d+\s+requests:\s+\d+\s+error", re.I)
    seen: set[str] = set()
    findings: list[Finding] = []
    for line in text.splitlines():
        line = line.rstrip()
        if not line.startswith("+ "):
            continue
        msg = line[2:].strip()
        if not msg or msg.startswith(SKIP_PREFIXES):
            continue
        if SUMMARY_RE.match(msg):
            continue
        # Strip duplicate-with-wapiti / always-the-same headers noise
        if NIKTO_NOISE_RE.search(msg):
            continue
        # Drop redundant OSVDB-prefixed dupes when the same body already
        # appeared without the OSVDB tag.
        if msg.startswith("OSVDB-"):
            tail = msg.split(":", 1)[-1].strip()
            if tail and tail[:200] in seen:
                continue
        # Dedupe identical advisory lines.
        key = msg[:200]
        if key in seen:
            continue
        seen.add(key)
        findings.append(Finding(
            target=t.url, tool="nikto",
            severity=_classify_nikto(msg),
            title=msg[:140], detail=msg,
        ))
        # Feed sqlmap: any flagged URL/path with a query string is a candidate.
        for tok in msg.replace(":", " ").split():
            tok = tok.rstrip(".,);")
            if tok.startswith(("http://", "https://")) and "?" in tok:
                parsed = urllib.parse.urlparse(tok)
                base = urllib.parse.urlparse(t.url)
                if parsed.netloc and parsed.netloc != base.netloc:
                    continue
                cand = tok
            elif tok.startswith("/") and "?" in tok:
                path_part = tok.split("?", 1)[0].lstrip("/")
                first_seg = path_part.split("/", 1)[0]
                if "/" in path_part and "." in first_seg:
                    continue
                cand = t.url.rstrip("/") + tok
            else:
                continue
            if cand not in t.injectable:
                t.injectable.append(cand)
        # Also extract any parameter-like patterns (e.g., ?id=, ?query=) from nikto msgs
        param_patterns = re.findall(r'\?(\w+)=', msg)
        for param in param_patterns:
            url_with_param = t.url.rstrip("/") + "?" + param + "=1"
            if url_with_param not in t.injectable:
                t.injectable.append(url_with_param)
    shutil.rmtree(host_dir, ignore_errors=True)
    return findings

def run_nuclei(targets: list[WebTarget], plan: ToolPlan, severity: str, timeout: Optional[int], stealth: StealthProfile, auth: AuthProfile):
    """
    Run nuclei on a list of URLs for a single host.
    """
    if not targets:
        return []

    sev_chain = ["info","low","medium","high","critical"]
    keep = sev_chain[max(0, sev_chain.index(severity)):] if severity in sev_chain else sev_chain
    rl = stealth.polite_rl(150)
    
    host_dir = tempfile.mkdtemp(prefix="vulnmalper_nuclei_", dir="/tmp")
    os.chmod(host_dir, 0o777)
    targets_file = os.path.join(host_dir, "targets.txt")
    target_urls = [t.url for t in targets]
    with open(targets_file, "w") as f:
        for u in target_urls: f.write(f"{u}\n")

    args = ["-l", targets_file if plan.runner != "docker" else "/wrk/targets.txt", 
            "-jsonl","-silent","-nc",
            "-severity", ",".join(keep),
            "-exclude-tags", "fuzzing,dos,helpers",
            "-timeout","15","-retries","2","-rl",str(rl),
            "-H", f"User-Agent: {stealth.pick_ua()}"]
    
    if any(t.url.startswith("http://") for t in targets):
        args += ["-ept", "ssl,dns"]
    args += ["-retries", "2", "-mhe", "30"]
    
    # Prefer a session cookie obtained from a successful default-login finding
    # so nuclei can reach authenticated surfaces when available.
    cookie_val = getattr(auth, "authed_cookie", None) or auth.cookie or auth_cookie_value()
    if cookie_val: args += ["-H", f"Cookie: {cookie_val}"]
    if auth.user and auth.password:
        args += ["--auth-credential", f"{auth.user}%{auth.password}", "--auth-method", "post"]

    for h in stealth.default_headers():
        args += ["-H", h]

    # Handle template persistence for Docker
    nuclei_mounts = []
    if plan.runner == "docker":
        template_dir = _nuclei_template_host_dir()
        if not _ensure_nuclei_templates_ready(plan, targets[0].url):
            return []
        nuclei_mounts.append((template_dir, "/root/nuclei-templates"))
        nuclei_mounts.append((host_dir, "/wrk"))

    # Stealth options
    if stealth.polite or stealth.slow or stealth.quiet:
        args += ["-bs", "1", "-c", "5" if stealth.slow else "10", 
                 "-rate-limit-duration", "5s" if stealth.slow else "2s"]
    if stealth.quiet or stealth.polite or stealth.slow:
        args += ["-etags", ",".join(NOISY_NUCLEI_TAGS)]
        for glob in NOISY_NUCLEI_TEMPLATE_GLOBS: args += ["-et", glob]
    if stealth.headless:
        args += ["-headless", "-page-timeout", "20"]
        if plan.runner == "docker": args += ["-system-chrome"]

    proxy = PROXY_POOL.next()
    args = _apply_proxy(args, proxy, "nuclei")
    cmd = build_cmd(plan, args, mounts=nuclei_mounts)

    log("run", f"nuclei batch ({len(targets)} targets) → {targets[0].url[:40]}...")
    rc, out, err = _run(cmd, timeout)
    findings: list[Finding] = []
    INJ_TAGS = {"sqli","sql-injection","injection","xss","ssti","lfi","rfi"}
    
    if rc == 0:
        if out:
            lines = [l for l in out.strip().splitlines() if l.startswith("{")]
            log("info", f"nuclei: got {len(lines)} JSON results")
        else:
            log("info", "nuclei completed successfully (0 findings)")
            if err:
                stats = _summarize_nuclei_stats(err)
                if stats: log("info", f"    {stats}")
    else:
        log("warn", f"nuclei failed rc={rc}")

    for line in out.splitlines():
        line = line.strip()
        if not line.startswith("{"): continue
        try: j = json.loads(line)
        except Exception: continue
        info = j.get("info", {})
        sev  = (info.get("severity") or "unknown").lower()
        matched = j.get("matched-at") or targets[0].url
        findings.append(Finding(
            target=matched, tool="nuclei", severity=sev,
            title=info.get("name") or j.get("template-id") or "nuclei finding",
            detail=(info.get("description") or "").strip(),
            reference=", ".join(info.get("reference") or []),
            raw=j,
        ))
        # If this is a default-login finding, extract the session cookie from
        # the response headers and attach it to matching WebTarget instances so
        # sqlmap can reach authenticated surfaces in Phase 3.
        tags = info.get("tags") or []
        template_id = j.get("template-id") or ""
        is_default_login = (
            "default-login" in tags
            or "default-credentials" in tags
            or "default-login" in template_id
        )
        if is_default_login:
            resp_headers = j.get("response") or ""
            cookie = None
            for hdr_line in resp_headers.splitlines():
                if hdr_line.lower().startswith("set-cookie:"):
                    cookie = hdr_line.split(":", 1)[1].strip().split(";")[0]
                    break
            if not cookie:
                # nuclei sometimes puts extracted values in extracted-results
                extracted = j.get("extracted-results") or []
                if extracted:
                    cookie = extracted[0]
            if cookie:
                log("info", f"nuclei: default-login cookie captured for {matched}: {cookie[:40]}...")
                for wt in targets:
                    if _same_netloc(matched, wt.url):
                        wt.authed_cookie = cookie
    shutil.rmtree(host_dir, ignore_errors=True)
    return findings

WAPITI_SEV_MAP = {1:"low",2:"medium",3:"high",4:"critical",0:"info",
                  "Low":"low","Medium":"medium","High":"high",
                  "Critical":"critical","Informational":"info"}

# Wapiti 3.2.10 module list. Source of truth:
# https://github.com/wapiti-scanner/wapiti/tree/master/wapitiCore/attack (mod_*.py)
# Dropped names that are NOT in 3.2.10: cookieflags, csp, headers, blindsqli,
# brute_login, takeover (renamed in 3.x). `timesql` IS still a real module in
# 3.2.10 (it is the time-based complement to error-based `sql`).
WAPITI_MODULES_REQUESTED = (
    "backup,brute_login_form,buster,cms,crlf,csrf,exec,file,htaccess,htp,ldap,"
    "log4shell,methods,nikto,permanentxss,redirect,shellshock,spring4shell,sql,"
    "ssl,ssrf,subdomaintakeover,takeover,timesql,upload,wapp,xss,xxe"
)

# Cache of "what modules does THIS wapiti image actually expose", keyed
# by image ref. Populated lazily on first wapiti run, then reused.
WAPITI_VALID_MODULES: Optional[set[str]] = None
WAPITI_VALID_MODULES_IMAGE: Optional[str] = None

def _wapiti_valid_modules(image: Optional[str]) -> set[str]:
    """Ask the wapiti image for `--list-modules` and parse the names. Cached."""
    global WAPITI_VALID_MODULES, WAPITI_VALID_MODULES_IMAGE
    if not image:
        return set()
    if WAPITI_VALID_MODULES is not None and WAPITI_VALID_MODULES_IMAGE == image:
        return WAPITI_VALID_MODULES
    WAPITI_VALID_MODULES = set()
    WAPITI_VALID_MODULES_IMAGE = image
    try:
        p = subprocess.run(
            ["docker", "run", "--rm", "--network", "host", image, "--list-modules"],
            capture_output=True, text=True, timeout=60, env=_docker_env(),
        )
        # Format:
        #   [*] Available modules:
        #           backup
        #                   Uncover backup files on the web server.
        #           brute_login_form
        #                   ...
        for ln in (p.stdout or "").splitlines():
            stripped = ln.strip()
            if not stripped or stripped.startswith("[*]") or " " in stripped:
                continue
            WAPITI_VALID_MODULES.add(stripped)
        if not WAPITI_VALID_MODULES:
            log("warn", f"wapiti --list-modules returned no module names; "
                       f"stdout={len(p.stdout)}B stderr={len(p.stderr)}B")
    except subprocess.TimeoutExpired:
        log("warn", f"wapiti --list-modules timed out for {image}")
    except Exception as e:
        log("warn", f"wapiti --list-modules failed: {e}")
    return WAPITI_VALID_MODULES

def _wapiti_filter_modules(requested_csv: str, image: Optional[str]) -> str:
    """Return `requested_csv` filtered against the image's actual module set.
    Falls back to wapiti's built-in `common` keyword if everything was dropped."""
    requested = [m.strip() for m in requested_csv.split(",") if m.strip()]
    valid = _wapiti_valid_modules(image)
    if not valid:
        return requested_csv  # trust ourselves if the probe failed
    keep   = [m for m in requested if m in valid]
    dropped = [m for m in requested if m not in valid]
    if dropped:
        log("info", f"wapiti: image {image} does not expose {dropped}; "
                   f"running {len(keep)}/{len(requested)} requested modules")
    return ",".join(keep) if keep else "common"

def run_wapiti(t: WebTarget, plan: ToolPlan, timeout: int, stealth: StealthProfile):
    host_dir = f"/tmp/vulnmalper_wapiti_{abs(hash(t.url))}"
    os.makedirs(host_dir, exist_ok=True)
    report = "report.json"
    scope = "page" if t.discovered else "folder"

    # level: 1 = only attack params actually present in URLs/forms
    #        2 = also inject into bare URLs (better for sparse homepages
    #            like testasp.vulnweb.com where most URLs are static).
    # Stealth/quiet mode stays at 1 to avoid amplifying traffic;
    # balanced, aggressive, and plain (no stealth flag) all use 2.
    level = 1 if stealth.quiet else 2

    # Wapiti 3.2.10 flag set (verified from `wapiti --help` in
    # ghcr.io/mkmithun2806/wapiti:latest). Note the short forms only:
    #   -A = user agent,  -H = header,  -t = per-request timeout,
    #   -m/--module, --verify-ssl {0,1}, --max-scan-time, -s/--start
    # The long forms --user-agent, --header, --start do NOT exist in 3.2.10.
    extra = ["-A", stealth.pick_ua()]
    for h in stealth.default_headers():
        extra += ["-H", h]

    extra += [
        "--scope", scope,
        "--max-links-per-page", "100",
        "-t", "10",                 # per-request timeout (s)
        "--verify-ssl", "0",        # wapiti 3.2.10 valid; accepts {0,1}
    ]

    # Seed with upstream-discovered endpoints so wapiti
    # doesn't start blind on sparse homepages
    for seed in (t.injectable or [])[:15]:
        if not seed.startswith(("http://", "https://")):
            continue
        if not _same_netloc(seed, t.url):
            continue
        extra += ["-s", seed]

    if stealth.headless:
        extra += ["--scope", "domain"]

    # Full wapiti 3.x attack module set, filtered against the actual
    # `--list-modules` output of the image. `--base` does NOT exist in
    # 3.2.10 (`-u` is the base).
    modules_csv = _wapiti_filter_modules(WAPITI_MODULES_REQUESTED, plan.image)
    extra += ["--module", modules_csv]

    if AUTH.user and AUTH.password:
        # wapiti 3.2.10 takes --auth-user/--auth-password/--auth-method,
        # not --auth-credential (the latter is a 2.x flag).
        extra += ["--auth-user", AUTH.user,
                  "--auth-password", AUTH.password,
                  "--auth-method", "post"]
    if getattr(t, "authed_cookie", None):
        extra += ["-C", t.authed_cookie]   # 3.2.10: -C COOKIE_VALUE, not --cookie
    elif AUTH.cookie:
        extra += ["-C", AUTH.cookie]   # 3.2.10: -C COOKIE_VALUE, not --cookie

    base_args = ["-u", t.url, "-f", "json",
                 "--flush-session", "--level", str(level),
                 "--max-scan-time", str(min(timeout, 1200)),
                 "-v", "1",                  # progress to stdout: "N URLs scanned"
                 "--color"]                  # disable ANSI escape codes
    proxy = PROXY_POOL.next()
    extra = _apply_proxy(extra, proxy, "wapiti")
    if plan.runner == "docker":
        container_dir = "/wrk"
        out_arg = f"{container_dir}/{report}"
        cmd = build_cmd(plan, base_args + ["-o", out_arg] + extra,
                        mounts=[(host_dir, container_dir)])
    else:
        cmd = build_cmd(plan,
                        base_args + ["-o", os.path.join(host_dir, report)] + extra)
    log("info", f"wapiti cmd: {' '.join(cmd[:8])}... (level={level}, scope={scope})")
    rc, out, err = _run(cmd, timeout + 30)

    # Persist the full wapiti output (banner is ~416B and swamps the
    # 5-line snippet). Always keep the log; don't put it in host_dir
    # because that gets rmtree'd below.
    log_path = f"/tmp/vulnmalper_wapiti_{abs(hash(t.url))}.log"
    try:
        with open(log_path, "w") as _f:
            _f.write(f"$ {' '.join(cmd)}\n--- rc={rc} ---\n--- stdout ({len(out)}B) ---\n{out}\n"
                     f"--- stderr ({len(err)}B) ---\n{err}\n")
    except Exception:
        pass

    # Surface a few progress lines so a slow-but-alive run is visibly
    # alive instead of looking hung. Pick lines containing "URLs scanned"
    # or percentage markers.
    progress = [ln.strip() for ln in out.splitlines()
                if "URLs scanned" in ln or "scan progress" in ln.lower()
                or "crawling" in ln.lower() or "%" in ln]
    for ln in progress[-3:]:
        if ln and ln != "[*] You are lucky! Full moon tonight.":
            log("info", f"wapiti: {ln}")

    # Find the actual error line(s) in the noisy banner. Argparse
    # failures look like "unrecognized arguments: --foo" or
    # "the following arguments are required: -u" or just "usage:".
    blob = (err + "\n" + out)
    error_lines = [ln.strip() for ln in blob.splitlines()
                   if any(k in ln.lower() for k in
                          ("unrecognized", "error:", "usage:", "no such",
                           "invalid", "required:", "ambiguous",
                           "argument --", "unknown"))]
    # Drop banner-art duplicates.
    seen, dedup = set(), []
    for ln in error_lines:
        if ln and ln not in seen:
            seen.add(ln); dedup.append(ln)
    error_lines = dedup[:8]

    host_out = os.path.join(host_dir, report)
    if rc != 0:
        log("warn", f"wapiti exit {rc} for {t.url}")
        if error_lines:
            for ln in error_lines:
                log("warn", f"  wapiti: {ln}")
        else:
            tail = (err or out).strip().splitlines()[-5:]
            for ln in tail:
                if ln.strip():
                    log("warn", f"  wapiti: {ln.strip()}")
        log("warn", f"  full wapiti log: {log_path}")

    findings: list[Finding] = []
    payload = None
    if os.path.exists(host_out):
        try:
            with open(host_out) as f:
                data = json.load(f)
            payload = data
        except Exception as e:
            log("warn", f"wapiti JSON parse failed for {t.url}: {e}")
    if payload is None:
        payload = _load_json_document(out) or _load_json_document(err)

    if payload is not None:
        for category, it in _iter_wapiti_vulnerabilities(payload):
            lvl = it.get("level", it.get("severity", 0))
            sev = WAPITI_SEV_MAP.get(lvl, "unknown")
            info_ = it.get("info") or it.get("description") or ""
            method = it.get("method") or ""
            path   = it.get("path") or ""
            param  = it.get("parameter") or it.get("parameter_name") or ""
            full_url = urllib.parse.urljoin(t.url, path)
            findings.append(Finding(
                target=full_url, tool="wapiti", severity=sev,
                title=f"{category}" + (f" on `{param}`" if param else ""),
                detail=(f"{method} {path}\n{info_}").strip(),
                raw=it,
            ))
            # If wapiti cracked a login form, pull the session cookie out of
            # the finding detail and store it on the target for sqlmap.
            if "brute_login" in category.lower() or "default" in category.lower():
                cookie = it.get("set-cookie") or it.get("cookie") or it.get("session")
                if not cookie:
                    # Some wapiti versions embed it in the info string as
                    # "Cookie: ..." or a token containing the session value.
                    for tok in (info_ or "").split():
                        low = tok.lower()
                        if low.startswith("cookie:"):
                            cookie = tok.split(":", 1)[1].strip().rstrip(",;")
                            break
                        if "=" in tok and "session" in low:
                            cookie = tok.strip().rstrip(",;")
                            break
                if cookie:
                    log("info", f"wapiti: default-login cookie captured for {full_url}: {cookie[:40]}...")
                    t.authed_cookie = cookie
            # Add URLs with parameters to injectable for sqlmap testing.
            # Include SQLi, XSS, and any other parameter-based vulnerabilities.
            if not _same_netloc(full_url, t.url):
                continue
            if param and "?" not in full_url:
                injectable_url = full_url + "?" + param + "=1"
            elif param:
                injectable_url = full_url + "&" + param + "=1"
            else:
                injectable_url = full_url
            if injectable_url not in t.injectable:
                t.injectable.append(injectable_url)

    if not findings:
        log("warn",
            f"wapiti produced no findings for {t.url} "
            f"(rc={rc}, host_out_exists={os.path.exists(host_out)}, "
            f"out={len(out)}B, err={len(err)}B, scope={scope}, level={level}, "
            f"log={log_path})")

    shutil.rmtree(host_dir, ignore_errors=True)
    return findings

def run_feroxbuster(t: WebTarget, plan: ToolPlan, timeout: int) -> tuple[list[Finding], list[str]]:
    """Discover new directories. Returns (findings, new_urls)."""
    wl_url = "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/common.txt"
    wl_path = ensure_wordlist("common.txt", wl_url)
    if not wl_path: return [], []

    host_dir = f"/tmp/vulnmalper_ferox_{abs(hash(t.url))}"
    os.makedirs(host_dir, exist_ok=True)
    report = "ferox.txt"
    
    args = ["-u", t.url, "-w", f"/wl/{os.path.basename(wl_path)}" if plan.runner == "docker" else wl_path,
            "-d", "2", "--silent", "-o", f"/wrk/{report}" if plan.runner == "docker" else os.path.join(host_dir, report)]
    proxy = PROXY_POOL.next()
    args = _apply_proxy(args, proxy, "feroxbuster")
    
    if plan.runner == "docker":
        docker = ["docker","run","--rm","-i","--network","host",
                  "-v", f"{host_dir}:/wrk", "-v", f"{os.path.dirname(wl_path)}:/wl",
                  plan.image]
        cmd = docker + args
    else:
        cmd = [LOCAL_BINARIES["feroxbuster"]] + args

    rc, out, err = _run(cmd, timeout)
    new_urls = []
    findings = []
    host_report = os.path.join(host_dir, report)
    if os.path.exists(host_report):
        with open(host_report) as f:
            for line in f:
                parts = line.split()
                if len(parts) >= 5 and parts[0] == "200":
                    url = parts[-1]
                    if url.rstrip("/") != t.url.rstrip("/"):
                        new_urls.append(url)
                        findings.append(Finding(
                            target=t.url, tool="feroxbuster", severity="info",
                            title=f"Discovered directory: {url}",
                            detail=f"Found via feroxbuster recursive scan.\nFull path: {url}",
                        ))
    shutil.rmtree(host_dir, ignore_errors=True)
    return findings, list(set(new_urls))

def run_ffuf(t: WebTarget, plan: ToolPlan, timeout: int) -> tuple[list[Finding], list[str]]:
    """Fuzz for specific files/configs. Returns (findings, new_urls)."""
    wl_url = "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/raft-small-files.txt"
    wl_path = ensure_wordlist("raft-small-files.txt", wl_url)
    if not wl_path: return [], []

    host_dir = f"/tmp/vulnmalper_ffuf_{abs(hash(t.url))}"
    os.makedirs(host_dir, exist_ok=True)
    report = "ffuf.json"

    target_url = t.url.rstrip("/") + "/FUZZ"
    args = ["-u", target_url, "-w", f"/wl/{os.path.basename(wl_path)}" if plan.runner == "docker" else wl_path,
            "-mc", "200", "-of", "json", "-o", f"/wrk/{report}" if plan.runner == "docker" else os.path.join(host_dir, report),
            "-s"]
    proxy = PROXY_POOL.next()
    args = _apply_proxy(args, proxy, "ffuf")
    
    if plan.runner == "docker":
        docker = ["docker","run","--rm","-i","--network","host",
                  "-v", f"{host_dir}:/wrk", "-v", f"{os.path.dirname(wl_path)}:/wl",
                  plan.image]
        cmd = docker + args
    else:
        cmd = [LOCAL_BINARIES["ffuf"]] + args

    rc, out, err = _run(cmd, timeout)
    new_urls = []
    findings = []
    host_report = os.path.join(host_dir, report)
    if os.path.exists(host_report):
        try:
            with open(host_report) as f:
                data = json.load(f)
                for res in data.get("results", []):
                    u = res.get("url")
                    new_urls.append(u)
                    findings.append(Finding(
                        target=t.url, tool="ffuf", severity="info",
                        title=f"Discovered file: {u}",
                        detail=f"Found via ffuf config fuzzing.\nFull path: {u}",
                        raw=res
                    ))
        except Exception: pass
    shutil.rmtree(host_dir, ignore_errors=True)
    return findings, list(set(new_urls))

SERVICE_SCAN_PLANS: dict[int, dict] = {
    21:   {"service": "ftp",        "scheme": "ftp",         "nuclei_tags": ("ftp",),          "nmap_scripts": ("ftp-anon", "ftp-vuln*"), "nuclei": True,  "nmap": True},
    22:   {"service": "ssh",        "scheme": "ssh",         "nuclei_tags": ("ssh",),          "nmap_scripts": (),                      "nuclei": True,  "nmap": False},
    139:  {"service": "smb",        "scheme": "",            "nuclei_tags": (),                "nmap_scripts": ("smb-vuln*", "smb-enum-shares", "smb-enum-users"), "nuclei": False, "nmap": True},
    445:  {"service": "smb",        "scheme": "",            "nuclei_tags": (),                "nmap_scripts": ("smb-vuln*", "smb-enum-shares", "smb-enum-users"), "nmap": True},
    3306: {"service": "mysql",      "scheme": "mysql",       "nuclei_tags": ("mysql",),        "nmap_scripts": ("mysql-vuln*", "mysql-empty-password"), "nuclei": True,  "nmap": True},
    5432: {"service": "postgresql", "scheme": "postgresql",  "nuclei_tags": ("postgresql",),   "nmap_scripts": ("pgsql-brute",), "nuclei": True,  "nmap": True},
    6379: {"service": "redis",      "scheme": "redis",       "nuclei_tags": ("redis",),        "nmap_scripts": (),                      "nuclei": True,  "nmap": False},
    27017: {"service": "mongodb",   "scheme": "mongodb",     "nuclei_tags": ("mongodb",),      "nmap_scripts": (),                      "nuclei": True,  "nmap": False},
    3389: {"service": "rdp",        "scheme": "",            "nuclei_tags": (),                "nmap_scripts": ("rdp-vuln-ms12-020", "rdp-enum-encryption"), "nuclei": False, "nmap": True},
    9200: {"service": "elasticsearch", "scheme": "http",    "nuclei_tags": ("elasticsearch",),"nmap_scripts": (),                      "nuclei": True,  "nmap": False},
    2049: {"service": "nfs",        "scheme": "",            "nuclei_tags": (),                "nmap_scripts": ("nfs-showmount", "nfs-ls"), "nuclei": False, "nmap": True},
    5900: {"service": "vnc",        "scheme": "vnc",         "nuclei_tags": ("vnc",),          "nmap_scripts": ("vnc-info", "vnc-brute"), "nuclei": True,  "nmap": True},
}

def _service_target_url(asset: ServiceTarget) -> str:
    spec = SERVICE_SCAN_PLANS.get(asset.port, {})
    scheme = spec.get("scheme") or (asset.service if asset.service in {"ssh", "ftp", "mysql", "postgresql", "redis", "mongodb", "vnc"} else "http")
    if scheme == "http" and asset.port == 9200:
        scheme = "http"
    return f"{scheme}://{asset.host}:{asset.port}"

def _service_scan_tags(asset: ServiceTarget) -> list[str]:
    spec = SERVICE_SCAN_PLANS.get(asset.port, {})
    return list(spec.get("nuclei_tags") or [])

def _nmap_severity(script_id: str, output: str) -> str:
    sid = (script_id or "").lower()
    text = f"{script_id} {output}".lower()
    if any(tok in sid for tok in ("vuln", "brute")):
        return "high"
    if any(tok in text for tok in ("empty password", "unauth", "unauthorized", "default credential")):
        return "high"
    if any(tok in sid for tok in ("enum", "info", "showmount", "ls")):
        return "medium"
    return "low"

def _collect_json_urls(blob) -> list[str]:
    urls: list[str] = []
    if isinstance(blob, dict):
        for key in ("url", "link", "href", "endpoint", "request", "source_url"):
            val = blob.get(key)
            if isinstance(val, str) and val.startswith(("http://", "https://")):
                urls.append(val)
        for value in blob.values():
            urls.extend(_collect_json_urls(value))
    elif isinstance(blob, list):
        for item in blob:
            urls.extend(_collect_json_urls(item))
    elif isinstance(blob, str) and blob.startswith(("http://", "https://")):
        urls.append(blob)
    return urls

def run_crawler(t: WebTarget, plan: Optional[ToolPlan], timeout: int, stealth: StealthProfile) -> list[str]:
    """Best-effort crawl with katana. Supports local or docker via ToolPlan."""
    if not plan:
        return []
    # katana equivalent: -u for url, -d for depth, -c for concurrency, -jc for JS crawl, -json for JSON, -nc for no-color
    args = ["-u", t.url, "-d", "3", "-c", "10", "-jc", "-json", "-nc", "-H", f"User-Agent: {stealth.pick_ua()}"]
    if stealth.headless:
        args.append("-hl")
    proxy = PROXY_POOL.next()
    args = _apply_proxy(args, proxy, "katana")
    cmd = build_cmd(plan, args)
    rc, out, err = _run(cmd, timeout)
    if rc != 0 or not out:
        return []
    urls: list[str] = []
    # Try parsing whole output as JSON array
    try:
        blob = json.loads(out)
        urls.extend(_collect_json_urls(blob))
    except Exception:
        pass
    # Also try line-by-line (NDJSON)
    for line in out.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            blob = json.loads(line)
        except Exception:
            try:
                blob = json.loads(line.strip(","))
            except Exception:
                continue
        urls.extend(_collect_json_urls(blob))
    return list(set(urls))

def _normalize_discovered_url(u: str) -> str:
    try:
        n = _normalize_url(u)
        # strip trailing /. that ffuf sometimes returns
        if n.endswith("/."):
            n = n[:-2] + "/"
        return n
    except Exception:
        return u

def run_nmap_nse(asset: ServiceTarget, scripts: tuple[str, ...], timeout: int) -> list[Finding]:
    if not scripts:
        return []
    script_arg = ",".join(scripts)
    local_nmap = have("nmap")
    cmd: list[str]
    if local_nmap:
        cmd = ["nmap", "--script", script_arg, "-p", str(asset.port), asset.host, "-oX", "-"]
    else:
        if not have("docker"):
            return []
        if not wait_for_phase0_nmap_image():
            return []
        cmd = [
            "docker", "run", "--rm", "--network", "host", PHASE0_NMAP_IMAGE,
            "--script", script_arg, "-p", str(asset.port), asset.host, "-oX", "-",
        ]
    rc, out, err = _run(cmd, timeout)
    if rc not in (0, 1) or not out.strip():
        return []
    findings: list[Finding] = []
    try:
        root = ET.fromstring(out)
    except Exception:
        return []
    for host_el in root.findall("host"):
        for port_el in host_el.findall("./ports/port"):
            state_el = port_el.find("state")
            if state_el is not None and (state_el.attrib.get("state") or "").lower() != "open":
                continue
            portid = port_el.attrib.get("portid") or str(asset.port)
            for script_el in port_el.findall("script"):
                sid = script_el.attrib.get("id") or "nmap-script"
                output = script_el.attrib.get("output") or ""
                if not output:
                    parts = []
                    for elem in script_el.iter():
                        if elem is script_el:
                            continue
                        text = (elem.text or "").strip()
                        if text:
                            parts.append(text)
                    output = "\n".join(parts)
                findings.append(Finding(
                    target=f"{asset.host}:{portid}",
                    tool="nmap",
                    severity=_nmap_severity(sid, output),
                    title=sid,
                    detail=output or f"NSE script {sid} reported on port {portid}",
                    reference=f"nmap NSE: {sid}",
                    raw={"script": sid, "port": portid, "service": asset.service},
                ))
    return findings

def run_service_nuclei(asset: ServiceTarget, plan: ToolPlan, timeout: int, severity: str, stealth: StealthProfile) -> list[Finding]:
    tags = _service_scan_tags(asset)
    if not tags:
        return []
    sev_chain = ["info","low","medium","high","critical"]
    keep = sev_chain[max(0, sev_chain.index(severity)):] if severity in sev_chain else sev_chain
    rl = stealth.polite_rl(50)
    url = _service_target_url(asset)
    args = ["-u", url, "-jsonl", "-silent", "-nc",
            "-tags", ",".join(tags),
            "-severity", ",".join(keep),
            "-exclude-tags", "fuzzing,dos,helpers",
            "-timeout", "10", "-rl", str(rl),
            "-H", f"User-Agent: {stealth.pick_ua()}"]
    for h in stealth.default_headers():
        args += ["-H", h]
    if auth_basic_header():
        args += ["-H", auth_basic_header()]
    if auth_cookie_value():
        args += ["-H", f"Cookie: {auth_cookie_value()}"]
    nuclei_mount = None
    if plan.runner == "docker":
        nuclei_mount = _nuclei_template_mount()
        if not _ensure_nuclei_templates_ready(plan, f"{asset.host}:{asset.port}"):
            return []
    proxy = PROXY_POOL.next()
    args = _apply_proxy(args, proxy, "nuclei")
    cmd = build_cmd(plan, args, mounts=[nuclei_mount] if nuclei_mount else None)
    rc, out, err = _run(cmd, timeout)
    findings: list[Finding] = []
    for line in out.splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            j = json.loads(line)
        except Exception:
            continue
        info = j.get("info", {})
        findings.append(Finding(
            target=f"{asset.host}:{asset.port}",
            tool="nuclei",
            severity=(info.get("severity") or "unknown").lower(),
            title=info.get("name") or j.get("template-id") or "nuclei finding",
            detail=(info.get("description") or "").strip(),
            reference=", ".join(info.get("reference") or []),
            raw=j,
        ))
    return findings

def run_phase0_service_scan(service_targets: list[ServiceTarget], plans: dict[str, Optional[ToolPlan]], stealth: StealthProfile, timeout: int = 300, nuclei_timeout: Optional[int] = 300, severity: str = "low") -> list[Finding]:
    findings: list[Finding] = []
    if not service_targets:
        return findings
    log("info", f"Service scan: {len(service_targets)} non-web service(s) queued")
    if not have("nmap") and have("docker"):
        warm_phase0_nmap_image()
    service_plans = [s for s in service_targets if s.port in SERVICE_SCAN_PLANS]
    for asset in service_plans:
        spec = SERVICE_SCAN_PLANS.get(asset.port, {})
        if spec.get("nuclei") and plans.get("nuclei"):
            findings.extend(run_service_nuclei(asset, plans["nuclei"], nuclei_timeout, severity, stealth))
        if spec.get("nmap"):
            findings.extend(run_nmap_nse(asset, tuple(spec.get("nmap_scripts") or ()), timeout))
    return findings

# ────────────────────────────────────────────────────────────────────────────
#  PHASE 2.5 — ACTIVE SERVICE CHAINING
#
#  When a fingerprint reveals a known service on a "telltale" port, we don't
#  just hand the URL to nuclei and pray — we *think* about what that service
#  exposes and hit those endpoints directly. e.g. seeing :9090 should make
#  the scanner say "that's Prometheus, let me try /api/v1/status/config".
#
#  Each playbook entry = (probe_path, severity_if_200, finding_title).
# ────────────────────────────────────────────────────────────────────────────
SERVICE_CHAIN_PLAYBOOKS: dict[int, dict] = {
    9090: {
        "name": "Prometheus",
        "fingerprints": ("prometheus", "Prometheus Time Series"),
        "probes": [
            ("/api/v1/status/config",   "high",   "Prometheus config exposed (secrets/scrape targets)"),
            ("/api/v1/status/flags",    "medium", "Prometheus runtime flags exposed"),
            ("/api/v1/targets",         "medium", "Prometheus scrape targets exposed"),
            ("/api/v1/status/buildinfo","low",    "Prometheus build info exposed"),
            ("/metrics",                "low",    "Prometheus self-metrics exposed"),
        ],
    },
    9093: {
        "name": "Alertmanager",
        "fingerprints": ("alertmanager",),
        "probes": [
            ("/api/v2/status",          "medium", "Alertmanager status exposed"),
            ("/api/v2/alerts",          "medium", "Alertmanager alerts exposed"),
        ],
    },
    9200: {
        "name": "Elasticsearch",
        "fingerprints": ("elasticsearch", "lucene_version"),
        "probes": [
            ("/_cluster/health",   "medium",   "Elasticsearch cluster health exposed"),
            ("/_cat/indices",      "high",     "Elasticsearch indices listing exposed"),
            ("/_nodes",            "high",     "Elasticsearch node info exposed"),
        ],
    },
    5601: {
        "name": "Kibana",
        "fingerprints": ("kibana",),
        "probes": [
            ("/api/status",        "medium", "Kibana status endpoint exposed"),
            ("/app/kibana",        "low",    "Kibana UI reachable"),
        ],
    },
    8500: {
        "name": "Consul",
        "fingerprints": ("consul",),
        "probes": [
            ("/v1/status/leader",  "medium",   "Consul cluster leader exposed"),
            ("/v1/agent/self",     "high",     "Consul agent self info exposed"),
            ("/v1/kv/?recurse",    "critical", "Consul KV store exposed (read all)"),
        ],
    },
    2375: {
        "name": "Docker API (TCP)",
        "fingerprints": ("docker",),
        "probes": [
            ("/version",         "high",     "Docker API /version reachable (likely unauthenticated)"),
            ("/containers/json", "critical", "Docker API container listing exposed"),
        ],
    },
    15672: {
        "name": "RabbitMQ Mgmt",
        "fingerprints": ("rabbitmq",),
        "probes": [
            ("/api/overview", "medium", "RabbitMQ management API exposed"),
            ("/api/vhosts",   "high",   "RabbitMQ vhosts listing exposed"),
        ],
    },
    8161: {
        "name": "ActiveMQ Console",
        "fingerprints": ("activemq",),
        "probes": [("/admin/", "medium", "ActiveMQ admin console reachable")],
    },
    8086: {
        "name": "InfluxDB",
        "fingerprints": ("influxdb",),
        "probes": [
            ("/ping",      "low",  "InfluxDB ping endpoint exposed"),
            ("/debug/vars","high", "InfluxDB debug vars exposed"),
        ],
    },
    3000: {
        "name": "Grafana",
        "fingerprints": ("grafana",),
        "probes": [
            ("/api/health",         "low",      "Grafana health endpoint reachable"),
            ("/api/datasources",    "high",     "Grafana datasources exposed (auth bypass?)"),
            ("/api/admin/settings", "critical", "Grafana admin settings exposed"),
        ],
    },
    5984: {
        "name": "CouchDB",
        "fingerprints": ("couchdb",),
        "probes": [
            ("/_all_dbs",   "high",   "CouchDB database listing exposed"),
            ("/_utils/",    "medium", "CouchDB Fauxton UI reachable"),
        ],
    },
}

def _http_probe(url: str, stealth: StealthProfile, timeout: int = 10) -> tuple[int, str]:
    """Tiny stdlib HTTP GET — avoids pulling `requests` just for chaining.
    Returns (status_code, body_first_4kb). status=0 on connection failure."""
    headers = {"User-Agent": stealth.pick_ua()}
    for h in stealth.default_headers():
        if ":" in h:
            k, v = h.split(":", 1)
            headers[k.strip()] = v.strip()
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    req = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
            return r.status, r.read(4096).decode("utf-8", errors="replace")
    except urllib.error.HTTPError as e:
        try:    body = e.read(4096).decode("utf-8", errors="replace")
        except Exception: body = ""
        return e.code, body
    except Exception:
        return 0, ""

def _tcp_probe(host: str, port: int, timeout: int = 4) -> bool:
    """Best-effort TCP liveness probe for hosts that don't answer HTTP cleanly."""
    if not host or not port:
        return False
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except Exception:
        return False

def discover_forms(url: str, stealth: StealthProfile) -> list[dict]:
    """Fetch a page and extract all forms with real field names and action URLs."""

    class FormParser(html.parser.HTMLParser):
        def __init__(self):
            super().__init__()
            self.forms = []
            self.current_form = None

        def handle_starttag(self, tag, attrs):
            attrs = dict(attrs)
            if tag == "form":
                self.current_form = {
                    "action": attrs.get("action", ""),
                    "method": attrs.get("method", "get").lower(),
                    "fields": {}
                }
            elif tag == "input" and self.current_form is not None:
                name = attrs.get("name")
                val = attrs.get("value", "test")
                typ = attrs.get("type", "text").lower()
                if name and typ not in ("submit", "button", "image", "reset", "hidden"):
                    self.current_form["fields"][name] = val or "test"
            elif tag == "textarea" and self.current_form is not None:
                name = attrs.get("name")
                if name:
                    self.current_form["fields"][name] = "test"
            elif tag == "select" and self.current_form is not None:
                name = attrs.get("name")
                if name:
                    self.current_form["fields"][name] = "1"

        def handle_endtag(self, tag):
            if tag == "form" and self.current_form:
                if self.current_form["fields"]:
                    self.forms.append(self.current_form)
                self.current_form = None

    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    req = urllib.request.Request(url, headers={"User-Agent": stealth.pick_ua()})
    try:
        with urllib.request.urlopen(req, timeout=10, context=ctx) as r:
            body = r.read(50000).decode("utf-8", errors="replace")
    except Exception:
        return []

    parser = FormParser()
    try:
        parser.feed(body)
    except Exception:
        return []
    return parser.forms


def build_sqlmap_targets(t: "WebTarget", stealth: StealthProfile) -> list[tuple[str, str, str]]:
    """
    Returns list of (url, post_data, method).
    Discovers real form fields rather than guessing param names.
    """
    targets: list[tuple[str, str, str]] = []
    seen: set[str] = set()

    forms = discover_forms(t.url, stealth)
    for form in forms:
        action = form["action"].strip()
        if action.startswith("http"):
            action_url = action
        elif action.startswith("/"):
            action_url = f"{t.scheme}://{t.host}{action}"
        elif action in ("", "#"):
            action_url = t.url
        else:
            action_url = t.url.rstrip("/") + "/" + action

        parsed_action = urllib.parse.urlparse(action_url)
        parsed_base = urllib.parse.urlparse(t.url)
        if parsed_action.netloc and parsed_action.netloc != parsed_base.netloc:
            continue

        method = form["method"]
        post_data = urllib.parse.urlencode(form["fields"]) if method == "post" else ""
        get_suffix = ("?" + urllib.parse.urlencode(form["fields"])) if method == "get" and form["fields"] else ""
        final_url = action_url + get_suffix

        key = f"{final_url}|{post_data}"
        if key not in seen:
            seen.add(key)
            targets.append((final_url, post_data, method))

    # Add upstream-flagged injectable URLs (from nuclei/nikto) with value=1
    for u in t.injectable:
        if "?" not in u:
            continue
        if urllib.parse.urlparse(u).netloc and not _same_netloc(u, t.url):
            continue
        # Ensure params have a value
        base, qs = u.split("?", 1)
        fixed_qs = "&".join(
            (p if "=" in p and p.split("=", 1)[1] else p.split("=")[0] + "=1")
            for p in qs.split("&") if p
        )
        fixed_url = base + "?" + fixed_qs
        key = f"{fixed_url}|"
        if key not in seen:
            seen.add(key)
            targets.append((fixed_url, "", "get"))

    return targets

def confirm_target_liveness(t: WebTarget, stealth: StealthProfile) -> bool:
    """Double-check a target before considering it dead.

    Strategy:
      1) Retry HTTP probe on the exact URL twice.
      2) If still no HTTP response, try a raw TCP connect to host:port.
    """
    # Two HTTP attempts (covers transient resets/timeouts).
    for _ in range(2):
        status, _ = _http_probe(t.url, stealth, timeout=8)
        if status > 0:
            t.alive = True
            if t.status is None:
                t.status = status
            return True
        time.sleep(0.35)
    # HTTP can fail behind odd middleware; a successful TCP connect means
    # the service is up enough to keep in scope for downstream tools.
    if _tcp_probe(t.host, t.port, timeout=4):
        t.alive = True
        return True
    return False

# ────────────────────────────────────────────────────────────────────────────
#  AUTO MODE — smart strategy detection (per-target)
# ────────────────────────────────────────────────────────────────────────────
# When the user runs `vulnmalper graph.json` with ZERO stealth flags, we
# auto-pick a per-target strategy based on Phase-1 evidence:
#
#   WAF / CDN detected   →  STEALTH   (be quiet, low rate, jittered delays)
#   private RFC1918 host →  AGGRESSIVE (lab/internal — full toolchain)
#   otherwise            →  BALANCED  (moderate rate + delay, most tools on)
#
# WAF/CDN signal wins over private-IP signal (a private IP fronted by a
# reverse proxy still trips perimeter alarms — better safe than sorry).
#
# We ONLY toggle EXISTING StealthProfile fields. No new CLI surface.

# Response headers that strongly imply a CDN / WAF edge in front of the
# origin. Lower-cased for case-insensitive matching.
WAF_CDN_HEADERS = {
    "cf-ray":            "Cloudflare",
    "cf-cache-status":   "Cloudflare",
    "x-vercel-id":       "Vercel",
    "x-vercel-cache":    "Vercel",
    "x-amz-cf-id":       "AWS CloudFront",
    "x-amz-cf-pop":      "AWS CloudFront",
    "x-akamai-request-id": "Akamai",
    "x-akamai-transformed": "Akamai",
    "x-sucuri-id":       "Sucuri",
    "x-sucuri-cache":    "Sucuri",
    "x-fastly-request-id": "Fastly",
    "x-served-by":       "Fastly/Varnish",
    "x-cdn":             "Generic CDN",
    "x-azure-ref":       "Azure Front Door",
    "x-iinfo":           "Imperva Incapsula",
    "x-cdn-provider":    "Generic CDN",
}
# Tokens we look for in `Server:` header values.
WAF_CDN_SERVER_TOKENS = {
    "cloudflare": "Cloudflare", "akamai": "Akamai", "sucuri": "Sucuri",
    "imperva": "Imperva", "incapsula": "Imperva Incapsula",
    "varnish": "Varnish/Fastly", "vercel": "Vercel",
    "cloudfront": "AWS CloudFront", "fastly": "Fastly",
    "awselb": "AWS ELB", "azurefd": "Azure Front Door",
}
# Tokens we look for inside the WhatWeb / httpx `tech` list.
WAF_CDN_TECH_TOKENS = {
    "cloudflare", "akamai", "fastly", "vercel", "sucuri", "imperva",
    "incapsula", "cloudfront", "azure cdn", "aws elb", "stackpath",
}

def _probe_response_headers(url: str, stealth: StealthProfile, timeout: int = 6) -> dict:
    """Single GET, return the response headers as a lowercased dict.
    Uses the active stealth headers so we look like a normal browser to
    the WAF too — otherwise a curl-shaped probe might itself flag us."""
    headers = {"User-Agent": stealth.pick_ua()}
    for h in stealth.default_headers():
        if ":" in h:
            k, v = h.split(":", 1)
            headers[k.strip()] = v.strip()
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    req = urllib.request.Request(url, headers=headers, method="GET")
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
            return {k.lower(): v for k, v in r.headers.items()}
    except urllib.error.HTTPError as e:
        # Even error responses (403/406/etc.) carry CDN headers — that's
        # actually the most useful case for WAF detection.
        try:    return {k.lower(): v for k, v in e.headers.items()}
        except Exception: return {}
    except Exception:
        return {}

def _is_private_host(host: str) -> bool:
    """True if `host` resolves to (or already is) an RFC1918 / loopback /
    link-local / CGNAT / IPv6 unique-local address. CGNAT (100.64/10) is
    included because internal labs and Tailscale use it heavily."""
    if not host:
        return False
    candidates: list[str] = []
    # Direct IP literal?
    try:
        ipaddress.ip_address(host)
        candidates.append(host)
    except ValueError:
        # Hostname → resolve. Best-effort, short timeout via socket default.
        try:
            for fam, _, _, _, sockaddr in socket.getaddrinfo(host, None):
                if fam in (socket.AF_INET, socket.AF_INET6):
                    candidates.append(sockaddr[0])
        except Exception:
            return False
    for ip_str in candidates:
        try:
            ip = ipaddress.ip_address(ip_str)
        except ValueError:
            continue
        if ip.is_private or ip.is_loopback or ip.is_link_local:
            return True
        # CGNAT: 100.64.0.0/10 — RFC6598
        if isinstance(ip, ipaddress.IPv4Address) and ip in ipaddress.ip_network("100.64.0.0/10"):
            return True
    return False

# Host-level WAF detection cache to avoid redundant probes on the same host.
WAF_CACHE: dict[str, Optional[str]] = {}
WAF_CACHE_LOCK = threading.Lock()

def detect_strategy(t: WebTarget, stealth: StealthProfile) -> tuple[str, str]:
    """Inspect a finished-Phase-1 target and pick its strategy.
    Returns (strategy_name, human_readable_reason).

    Precedence:
      1. WAF/CDN signal (wafw00f result, tech tokens, response headers)
      2. Private/internal IP → aggressive
      3. Default → balanced
    """
    # ── 1. WAF/CDN — strongest signal, wins over everything ───────────
    if t.waf:
        with WAF_CACHE_LOCK:
            WAF_CACHE[t.host] = t.waf
        return "stealth", f"WAF detected by wafw00f ({t.waf})"
    
    # Check host-level cache first
    with WAF_CACHE_LOCK:
        if t.host in WAF_CACHE and WAF_CACHE[t.host]:
            t.waf = WAF_CACHE[t.host]
            return "stealth", f"WAF detected previously on this host ({t.waf})"

    tech_blob = " ".join((x or "").lower() for x in (t.tech or []))
    for tok in WAF_CDN_TECH_TOKENS:
        if tok in tech_blob:
            with WAF_CACHE_LOCK:
                WAF_CACHE[t.host] = tok
            return "stealth", f"CDN/WAF tech fingerprint ({tok})"

    # Cheap header sniff — single GET, ignored on failure.
    hdrs = _probe_response_headers(t.url, stealth)
    for h, vendor in WAF_CDN_HEADERS.items():
        if h in hdrs:
            with WAF_CACHE_LOCK:
                WAF_CACHE[t.host] = vendor
            return "stealth", f"edge header `{h}` → {vendor}"
    server = (hdrs.get("server") or "").lower()
    for tok, vendor in WAF_CDN_SERVER_TOKENS.items():
        if tok in server:
            with WAF_CACHE_LOCK:
                WAF_CACHE[t.host] = vendor
            return "stealth", f"Server: {vendor}"
    
    # Cache "no WAF" for this host to skip future probes
    with WAF_CACHE_LOCK:
        if t.host not in WAF_CACHE:
            WAF_CACHE[t.host] = None

    # ── 2. Private / internal IP → aggressive ─────────────────────────
    if _is_private_host(t.host):
        return "aggressive", f"private/internal host ({t.host})"
    # ── 3. Default ────────────────────────────────────────────────────
    return "balanced", "public host, no WAF/CDN signal"

def build_auto_profile(strategy: str, base: StealthProfile) -> StealthProfile:
    """Return a NEW StealthProfile tuned for the given strategy.
    We only flip EXISTING knobs (no new fields, no new CLI flags)."""
    # Carry over things the user can't conceptually set in auto mode but
    # that we still want stable across the run (jitter on, fresh UA pool).
    if strategy == "stealth":
        return StealthProfile(
            polite=True, slow=False,
            user_agent=None, headers=list(base.headers),
            rate_limit=20,        # nuclei -rl, wapiti -d cap
            delay_ms=600,         # base; jittered_delay() spreads ±50%
            headless=base.headless,
            jitter=True,
            quiet=True,           # drop noisy nuclei templates
        )
    if strategy == "aggressive":
        return StealthProfile(
            polite=False, slow=False,
            user_agent=None, headers=list(base.headers),
            rate_limit=0,         # tool defaults — no throttle
            delay_ms=0,
            headless=base.headless,
            jitter=True,          # keep header jitter even when fast
            quiet=False,          # full template set
        )
    # balanced
    return StealthProfile(
        polite=False, slow=False,
        user_agent=None, headers=list(base.headers),
        rate_limit=40,            # moderate
        delay_ms=200,
        headless=base.headless,
        jitter=True,
        quiet=False,
    )

def _user_supplied_stealth_flags(args) -> bool:
    """True if the user touched ANY stealth knob on the CLI. In that case
    we disable auto-mode entirely (per the user's chosen override policy:
    explicit flags fully override auto)."""
    return bool(
        args.polite or args.slow or args.quiet or args.headless
        or args.no_jitter or args.user_agent or args.header
        or args.rate_limit or args.delay_ms
    )

_AUTO_BANNER_COLORS = {
    "stealth":    lambda: f"{C.CY}STEALTH{C.R}",
    "aggressive": lambda: f"{C.RD}AGGRESSIVE{C.R}",
    "balanced":   lambda: f"{C.GN}BALANCED{C.R}",
}

def _format_auto_banner(t: WebTarget, strategy: str, reason: str,
                        prof: StealthProfile) -> str:
    """One-liner explaining what auto-mode picked and why, for this target."""
    label = _AUTO_BANNER_COLORS[strategy]()
    knobs = []
    knobs.append(f"quiet={'on' if prof.quiet else 'off'}")
    knobs.append(f"rl={prof.rate_limit or 'default'}")
    knobs.append(f"delay={prof.delay_ms or 0}ms"
                 + ("±jitter" if prof.jitter and prof.delay_ms else ""))
    return (f"{C.MG}[auto]{C.R} {t.url} → {label}  "
            f"({C.GY}{reason}{C.R})  ·  " + " · ".join(knobs))

def _ensure_auto_strategy(t: WebTarget, stealth: StealthProfile) -> tuple[str, str]:
    """Resolve and cache auto strategy/reason once per target."""
    if t.auto_strategy and t.auto_reason:
        return t.auto_strategy, t.auto_reason
    strategy, reason = detect_strategy(t, stealth)
    t.auto_strategy = strategy
    t.auto_reason = reason
    return strategy, reason

def run_service_chain(t: WebTarget, stealth: StealthProfile, timeout: int = 15) -> list[Finding]:
    """If t looks like a known service (by port + tech fingerprint), run its
    targeted probe playbook. This is *active reasoning*: the scanner says
    "that's Prometheus on 9090, let me hit /api/v1/status/config" instead of
    waiting for a generic template to catch it."""
    play = SERVICE_CHAIN_PLAYBOOKS.get(t.port)
    if not play:
        return []
    haystack = " ".join([
        (t.product or ""), " ".join(t.tech or []), (t.service or ""),
    ]).lower()
    fps = play.get("fingerprints") or ()
    confirmed = any(fp.lower() in haystack for fp in fps) if fps else False

    findings: list[Finding] = []
    base = t.url.rstrip("/")
    if confirmed:
        log("info", f"   ↪ {C.B}{play['name']}{C.R} confirmed on {t.url} — "
                    f"running {len(play['probes'])} targeted probe(s)")
    else:
        log("info", f"   ↪ port {t.port} matches {C.B}{play['name']}{C.R} — "
                    f"probing blind ({len(play['probes'])} endpoint(s))")

    for path, sev, title in play["probes"]:
        url = base + path
        status, body = _http_probe(url, stealth, timeout=timeout)
        if status == 0:
            continue
        if 200 <= status < 300:
            ev = f"GET {url}\nHTTP/1.1 {status}\n\n{body[:1500]}".strip()
            findings.append(Finding(
                target=url, tool=f"chain:{play['name'].lower().split()[0]}",
                severity=sev, title=title, detail=ev,
                reference=f"Service chain probe — port {t.port} ({play['name']})",
            ))
            log("ok", f"     {SEV_BADGE[sev]} {title} → HTTP {status}")
            if "?" in path and url not in t.injectable:
                t.injectable.append(url)
    return findings

# ── PHASE 3 — VERIFY (sqlmap, only on endpoints upstream flagged)
# ────────────────────────────────────────────────────────────────────────────
def run_sqlmap(url: str, plan: ToolPlan, timeout: int, stealth: StealthProfile, auth: AuthProfile,
               post_data: str = "", waf_detected: bool = False):
    """
    Run sqlmap on a single target.
    """
    host_dir = tempfile.mkdtemp(prefix="vulnmalper_sqlmap_", dir="/tmp")
    os.chmod(host_dir, 0o777)
    ua = stealth.pick_ua()
    
    # ── Auto-tuning: level/risk based on strategy ────────────────────────
    if SQLMAP_LEVEL is not None:
        level = SQLMAP_LEVEL
    else:
        if stealth.slow or stealth.polite: level = 1
        elif not stealth.jitter:           level = 5
        else:                              level = 4

    if SQLMAP_RISK is not None:
        risk = SQLMAP_RISK
    else:
        if stealth.slow or stealth.polite: risk = 1
        elif not stealth.jitter:           risk = 3
        else:                              risk = 2

    extra = ["--level", str(level), "--risk", str(risk), "--random-agent"]

    if waf_detected:
        extra += ["--tamper", "between,charencode,space2comment,randomcase,apostrophemask,base64encode,multiplespaces,unionalltounion",
                  "--hex", "--no-cast"]
    else:
        extra += ["--tamper", "between,space2comment"]

    cookie_val = getattr(auth, "authed_cookie", None) or auth.cookie or auth_cookie_value()
    if cookie_val:
        extra += ["--cookie", cookie_val]

    hdrs = stealth.default_headers()
    if hdrs:
        extra += ["--headers", "\n".join(hdrs)]

    # POST data + auth merge
    form_data = post_data or ""
    if auth.user and auth.password:
        form_data = merge_form_data(form_data, auth_form_data()) # Still uses global helper
    if form_data:
        extra += ["--data", form_data]

    extra += ["--technique", "BEUSTQ", "--batch", "--non-interactive"]

    if stealth.polite or stealth.slow:
        d = max(1, int(stealth.polite_delay(500) / 1000))
        extra += ["--delay", str(d), "--safe-freq", "5"]
    else:
        extra += ["--delay", "0", "--safe-freq", "3"]

    proxy = PROXY_POOL.next()
    extra = _apply_proxy(extra, proxy, "sqlmap")
    if plan.runner == "docker":
        container_dir = "/wrk"
        args = ["-u", url, "--disable-coloring", "--output-dir", container_dir, "--timeout", "30"] + extra
        cmd = build_cmd(plan, args, mounts=[(host_dir, container_dir)])
    else:
        args = ["-u", url, "--disable-coloring", "--output-dir", host_dir, "--timeout", "30"] + extra
        cmd = build_cmd(plan, args)

    log("run", f"sqlmap → {url[:60]}...")
    rc, out, err = _run(cmd, timeout)
    return _parse_sqlmap_results(host_dir, out, err, [url])

def run_sqlmap_batch(urls: list[str], plan: ToolPlan, timeout: int, stealth: StealthProfile, auth: AuthProfile,
                     waf_detected: bool = False):
    """
    Run sqlmap on a list of GET URLs for a single host.
    """
    if not urls: return []
    host_dir = tempfile.mkdtemp(prefix="vulnmalper_sqlmap_batch_", dir="/tmp")
    os.chmod(host_dir, 0o777)
    
    targets_file = os.path.join(host_dir, "targets.txt")
    with open(targets_file, "w") as f:
        for u in urls: f.write(f"{u}\n")

    ua = stealth.pick_ua()
    
    # Auto-tuning (re-used logic)
    level = SQLMAP_LEVEL if SQLMAP_LEVEL is not None else (1 if (stealth.slow or stealth.polite) else 5 if not stealth.jitter else 4)
    risk  = SQLMAP_RISK  if SQLMAP_RISK  is not None else (1 if (stealth.slow or stealth.polite) else 3 if not stealth.jitter else 2)

    extra = ["--level", str(level), "--risk", str(risk), "--random-agent", "--batch", "--non-interactive"]
    if waf_detected:
        extra += ["--tamper", "between,charencode,space2comment,randomcase,apostrophemask,base64encode,multiplespaces,unionalltounion",
                  "--hex", "--no-cast"]
    else:
        extra += ["--tamper", "between,space2comment"]

    cookie_val = getattr(auth, "authed_cookie", None) or auth.cookie or auth_cookie_value()
    if cookie_val: extra += ["--cookie", cookie_val]
    hdrs = stealth.default_headers()
    if hdrs: extra += ["--headers", "\n".join(hdrs)]

    proxy = PROXY_POOL.next()
    extra = _apply_proxy(extra, proxy, "sqlmap")
    if plan.runner == "docker":
        container_dir = "/wrk"
        args = ["-m", f"{container_dir}/targets.txt", "--disable-coloring", "--output-dir", container_dir] + extra
        cmd = build_cmd(plan, args, mounts=[(host_dir, container_dir)])
    else:
        args = ["-m", targets_file, "--disable-coloring", "--output-dir", host_dir] + extra
        cmd = build_cmd(plan, args)

    log("run", f"sqlmap batch ({len(urls)} urls) → {urls[0][:40]}...")
    rc, out, err = _run(cmd, timeout)
    return _parse_sqlmap_results(host_dir, out, err, urls)

def _parse_sqlmap_results(host_dir: str, out: str, err: str, targets: list[str]) -> list[Finding]:
    findings: list[Finding] = []
    text = out + "\n" + err
    blocks = re.findall(
        r"Parameter:\s*(.+?)\n\s*Type:\s*(.+?)\n\s*Title:\s*(.+?)\n\s*Payload:\s*(.+?)(?:\n\s*\n|\Z)",
        text, re.S,
    )
    for param, typ, title, payload in blocks:
        findings.append(Finding(
            target=targets[0], 
            tool="sqlmap", severity="critical",
            title=f"SQL Injection ({typ.strip()}) on `{param.strip()}`",
            detail=f"Title: {title.strip()}\nPayload: {payload.strip()}",
            reference="https://owasp.org/www-community/attacks/SQL_Injection",
        ))

    for root, dirs, files in os.walk(host_dir):
        if "log" in files:
            log_path = os.path.join(root, "log")
            if os.path.getsize(log_path) > 0:
                with open(log_path, "r") as f: log_content = f.read()
                dbms_match = re.search(r"back-end DBMS: (.+)", log_content)
                dbms_info = f" (DBMS: {dbms_match.group(1).strip()})" if dbms_match else ""
                if not findings:
                    findings.append(Finding(
                        target=targets[0], tool="sqlmap", severity="critical",
                        title=f"SQL Injection Detected{dbms_info}",
                        detail="sqlmap confirmed injectable. Check logs for details.",
                        reference="https://owasp.org/www-community/attacks/SQL_Injection",
                    ))
                elif dbms_info:
                    for f in findings:
                        if "DBMS:" not in f.title: f.title += dbms_info
    shutil.rmtree(host_dir, ignore_errors=True)
    return findings

# ── Reporting ───────────────────────────────────────────────────────────────
def _summary(findings):
    by_sev, by_tool = {}, {}
    for f in findings:
        by_sev[f.severity] = by_sev.get(f.severity, 0) + 1
        by_tool[f.tool]    = by_tool.get(f.tool, 0) + 1
    return {"total": len(findings), "by_severity": by_sev, "by_tool": by_tool}

def render_console(findings, targets, meta, duration, runner_map):
    seen, uniq = set(), []
    for f in findings:
        k = f.key()
        if k in seen: continue
        seen.add(k); uniq.append(f)
    uniq.sort(key=lambda f: -SEV_ORDER.get(f.severity, 0))
    service_findings = [f for f in uniq if _is_service_target_label(f.target)]
    web_findings = [f for f in uniq if not _is_service_target_label(f.target)]

    counts, by_tool = {}, {}
    for f in uniq:
        counts[f.severity] = counts.get(f.severity, 0) + 1
        by_tool[f.tool]    = by_tool.get(f.tool, 0) + 1

    line = C.GY + "─" * 64 + C.R
    print(); print(line)
    print(f"  {C.B}{C.MG}VulnMalper Report{C.R}  ·  source: {C.CY}{meta.get('target','?')}{C.R}")
    print(line)
    print(f"  Auth mode           : {C.B}{auth_mode_label()}{C.R}")
    print(f"  Web targets scanned : {C.B}{len(targets)}{C.R}")
    if service_findings:
        print(f"  Service findings    : {C.B}{len(service_findings)}{C.R}")
    print(f"  Total findings      : {C.B}{len(uniq)}{C.R}  (raw: {len(findings)})")
    print(f"  Duration            : {C.B}{duration:.1f}s{C.R}")
    print(f"  Tools used          : {C.B}{', '.join(by_tool) or 'none'}{C.R}")
    print()
    print(f"  {C.B}Severity breakdown{C.R}")
    for sev in ("critical","high","medium","low","info"):
        n = counts.get(sev, 0); bar = "█" * min(n, 40)
        col = {"critical":C.RD,"high":C.RD,"medium":C.YL,"low":C.BL,"info":C.GY}[sev]
        print(f"    {SEV_BADGE[sev]} {n:>3}  {col}{bar}{C.R}")
    print(line)
    print(f"  {C.B}Per-target fingerprint{C.R}")
    for t in targets:
        tags = []
        if t.alive: tags.append(f"{C.GN}alive {t.status}{C.R}")
        else:       tags.append(f"{C.RD}dead{C.R}")
        if t.tech:  tags.append(f"tech=[{', '.join(t.tech[:4])}{'…' if len(t.tech)>4 else ''}]")
        if t.waf:   tags.append(f"{C.YL}WAF={t.waf}{C.R}")
        if t.injectable: tags.append(f"{C.MG}injectable×{len(t.injectable)}{C.R}")
        tags.append(f"Crawl: {t.crawl_new_endpoints} new endpoints discovered")
        print(f"    {C.CY}{t.url:<55}{C.R}  " + " · ".join(tags))
    print(line)

    if service_findings:
        print(f"  {C.B}Service Vulnerabilities{C.R}")
        by_service: dict[str, list[Finding]] = {}
        for f in service_findings:
            by_service.setdefault(f.target, []).append(f)
        for comp, fs in sorted(by_service.items(), key=lambda kv: (-max(SEV_ORDER.get(f.severity, 0) for f in kv[1]), kv[0])):
            print(f"    {C.CY}{comp}{C.R} ({len(fs)})")
            for f in sorted(fs, key=lambda f: (-SEV_ORDER.get(f.severity, 0), f.tool, f.title.lower()))[:8]:
                print(f"      {SEV_BADGE[f.severity]} {C.DIM}[{f.tool}]{C.R} {f.title}")
        print(line)

    if not web_findings:
        if not service_findings:
            print(f"  {C.GN}No vulnerabilities detected. Clean run.{C.R}")
        print(line)
        return

    by_target: dict[str,list[Finding]] = {}
    for f in web_findings: by_target.setdefault(f.target.split("?")[0], []).append(f)
    for tgt, fs in by_target.items():
        print()
        print(f"  {C.B}{C.CY}● {tgt}{C.R}  {C.GY}({len(fs)} findings){C.R}")
        for f in fs[:30]:
            print(f"    {SEV_BADGE[f.severity]} {C.DIM}[{f.tool}]{C.R} {f.title}")
            if f.detail and f.detail != f.title:
                first = f.detail.strip().splitlines()[0][:140]
                print(f"        {C.GY}{first}{C.R}")
            if f.reference:
                print(f"        {C.GY}↳ {f.reference[:140]}{C.R}")
        if len(fs) > 30:
            print(f"    {C.GY}… and {len(fs)-30} more (see report file){C.R}")
    print(); print(line)


# ── Markdown helpers ───────────────────────────────────────────────────────
_SEV_SHIELD = {
    "critical": "https://img.shields.io/badge/CRITICAL-8B0000?style=flat-square",
    "high":     "https://img.shields.io/badge/HIGH-D7263D?style=flat-square",
    "medium":   "https://img.shields.io/badge/MEDIUM-F46036?style=flat-square",
    "low":      "https://img.shields.io/badge/LOW-2E86AB?style=flat-square",
    "info":     "https://img.shields.io/badge/INFO-6C757D?style=flat-square",
    "unknown":  "https://img.shields.io/badge/UNKNOWN-444?style=flat-square",
}
_SEV_EMOJI = {
    "critical":"🔴","high":"🟠","medium":"🟡","low":"🔵","info":"⚪","unknown":"⚫",
}

def _slug(s: str) -> str:
    s = re.sub(r"https?://", "", s)
    s = re.sub(r"[^A-Za-z0-9]+", "-", s).strip("-").lower()
    return s[:80] or "target"

def _is_service_target_label(label: str) -> bool:
    return bool(re.fullmatch(r"[^/]+:\d+", label or ""))

def _md_escape(s: str) -> str:
    return (s or "").replace("|", "\\|").replace("\n", " ").strip()

def _sev_badge(sev: str) -> str:
    """Plain text badge - works everywhere including Obsidian.
    Uses emoji + text for maximum compatibility."""
    sev = (sev or "unknown").lower()
    emoji = _SEV_EMOJI.get(sev, "⚫")
    return f"{emoji} {sev.upper()}"

def _fence(text: str, lang: str = "") -> str:
    text = text.rstrip()
    # pick a fence longer than any backtick run inside
    longest = 0; run = 0
    for ch in text:
        if ch == "`":
            run += 1; longest = max(longest, run)
        else:
            run = 0
    fence = "`" * max(3, longest + 1)
    return f"{fence}{lang}\n{text}\n{fence}"

def write_json_export(path, findings, targets, meta, duration, runner_map):
    """Pretty, single-file JSON export of the entire scan.

    Structure:
      {
        "vulnmalper": { version, generated_utc, source_target, duration_s,
                        runner_map, totals: {findings, targets, alive, with_waf} },
        "summary":    { by_severity, by_tool, risk_score, risk_label },
        "hosts":      [ { url, host, port, scheme, alive, status, tech, waf,
                          injectable, finding_count, by_severity, findings:[...] } ],
        "findings":   [ ...flat list, deduped... ]
      }
    """
    # Dedupe findings (same key as console renderer).
    seen, uniq = set(), []
    for f in findings:
        k = f.key()
        if k in seen: continue
        seen.add(k); uniq.append(f)

    summary = _summary(uniq)
    bs = summary["by_severity"]
    crit, high, med, low = (bs.get(k, 0) for k in ("critical","high","medium","low"))
    risk = min(100, crit*25 + high*10 + med*4 + low*1)
    if   risk >= 75: risk_label = "CRITICAL EXPOSURE"
    elif risk >= 40: risk_label = "HIGH RISK"
    elif risk >= 15: risk_label = "MODERATE RISK"
    elif risk >  0:  risk_label = "LOW RISK"
    else:            risk_label = "NO ISSUES SURFACED"

    def _f2dict(f: Finding) -> dict:
        return {
            "tool":      f.tool,
            "severity":  f.severity,
            "title":     f.title,
            "target":    f.target,
            "detail":    f.detail,
            "reference": f.reference,
        }

    # Group findings per host (key = URL without query, matches MD report).
    by_host: dict[str, list[Finding]] = {}
    for f in uniq:
        by_host.setdefault(f.target.split("?")[0], []).append(f)

    hosts_out = []
    for t in targets:
        key = t.url.split("?")[0]
        host_fs = by_host.get(key, [])
        host_sev: dict[str, int] = {}
        for f in host_fs:
            host_sev[f.severity] = host_sev.get(f.severity, 0) + 1
        hosts_out.append({
            "url":           t.url,
            "host":          t.host,
            "port":          t.port,
            "scheme":        t.scheme,
            "service":       t.service,
            "product":       t.product,
            "alive":         t.alive,
            "status":        t.status,
            "tech":          list(t.tech),
            "waf":           t.waf,
            "injectable":    list(t.injectable),
            "crawl_new_endpoints": t.crawl_new_endpoints,
            "finding_count": len(host_fs),
            "by_severity":   host_sev,
            "findings":      [_f2dict(f) for f in sorted(
                host_fs,
                key=lambda f: (-SEV_ORDER.get(f.severity, 0), f.tool, f.title.lower())
            )],
        })

    payload = {
        "vulnmalper": {
            "version":        VERSION,
            "generated_utc":  datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
            "source_target":  meta.get("target", "?"),
            "duration_s":     round(duration, 2),
            "auth_mode":      auth_mode_label(),
            "runner_map":     runner_map,
            "totals": {
                "findings": len(uniq),
                "raw_findings": len(findings),
                "targets":  len(targets),
                "alive":    sum(1 for t in targets if t.alive),
                "with_waf": sum(1 for t in targets if t.waf),
            },
        },
        "summary": {
            "by_severity": summary["by_severity"],
            "by_tool":     summary["by_tool"],
            "risk_score":  risk,
            "risk_label":  risk_label,
        },
        "hosts":    hosts_out,
        "findings": [_f2dict(f) for f in sorted(
            uniq,
            key=lambda f: (-SEV_ORDER.get(f.severity, 0), f.target, f.tool, f.title.lower())
        )],
    }
    with open(path, "w") as fh:
        json.dump(payload, fh, indent=2, sort_keys=False, default=str)

def write_markdown(path, findings, targets, meta, duration, runner_map):
    summary = _summary(findings)
    total = summary["total"]
    bs    = summary["by_severity"]
    crit, high, med, low, info = (bs.get(k,0) for k in ("critical","high","medium","low","info"))

    # Risk score: weighted, capped at 100
    risk = min(100, crit*25 + high*10 + med*4 + low*1)
    if   risk >= 75: risk_label = "🔴 CRITICAL EXPOSURE"
    elif risk >= 40: risk_label = "🟠 HIGH RISK"
    elif risk >= 15: risk_label = "🟡 MODERATE RISK"
    elif risk >  0:  risk_label = "🔵 LOW RISK"
    else:            risk_label = "🟢 NO ISSUES SURFACED"

    target_name = meta.get("target","?")
    gen_iso     = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    alive_n     = sum(1 for t in targets if t.alive)
    waf_n       = sum(1 for t in targets if t.waf)

    runner_line = " · ".join(
        f"`{k}`→{('🟢' if v=='local' else '🐳' if v=='docker' else '⚫')} {v}"
        for k,v in runner_map.items()
    )
    service_findings = [f for f in findings if _is_service_target_label(f.target)]
    web_findings = [f for f in findings if not _is_service_target_label(f.target)]

    L: list[str] = []
    # ── Header ────────────────────────────────────────────────────────────
    L += [
        f"# 🛡️  VulnMalper Report",
        "",
        f"> **Target:** `{target_name}` | **Generated:** {gen_iso} | **Engine:** VulnMalper v{VERSION}",
        f"> **Auth mode:** `{auth_mode_label()}`",
        "",
        f"> {risk_label} | **{total}** findings across **{alive_n}/{len(targets)}** alive targets | scan took **{duration:.1f}s**",
        "",
        "---",
        "",
    ]

    if service_findings:
        by_service: dict[str, list[Finding]] = {}
        for f in service_findings:
            by_service.setdefault(f.target, []).append(f)
        L += [
            "## 🔧 Service Vulnerabilities",
            "",
            "| Component | Severity | Tool | Title |",
            "|---|---|---|---|",
        ]
        for comp, fs in sorted(by_service.items(), key=lambda kv: (-max(SEV_ORDER.get(f.severity, 0) for f in kv[1]), kv[0])):
            for f in sorted(fs, key=lambda f: (-SEV_ORDER.get(f.severity, 0), f.tool, f.title.lower())):
                L.append(f"| `{comp}` | {_SEV_EMOJI.get(f.severity,'⚫')} **{f.severity.upper()}** | `{f.tool}` | {_md_escape(f.title)[:160]} |")
        L += ["", "---", ""]

    # ── Table of contents ────────────────────────────────────────────────
    L += ["## 🧭 Table of Contents", ""]
    toc_entries = [
        "- [Target Fingerprints](#-target-fingerprints)",
        "- [Findings](#-findings)",
        "- [Scan Metadata](#-scan-metadata)",
    ]
    if service_findings:
        toc_entries.insert(0, "- [Service Vulnerabilities](#-service-vulnerabilities)")
    L += toc_entries
    by_target: dict[str,list[Finding]] = {}
    for f in web_findings:
        by_target.setdefault(f.target.split("?")[0], []).append(f)
    # stable ordering: targets with most-severe findings first
    def _max_sev(fs): return max((SEV_ORDER.get(f.severity,0) for f in fs), default=0)
    ordered_targets = sorted(by_target.items(), key=lambda kv: (-_max_sev(kv[1]), -len(kv[1])))
    for tgt, fs in ordered_targets:
        sev_max = max(fs, key=lambda f: SEV_ORDER.get(f.severity,0)).severity
        L.append(f"  - [{_SEV_EMOJI.get(sev_max,'⚫')} `{tgt}` _({len(fs)})_](#target-{_slug(tgt)})")
    L.append("")

    # ── Target fingerprint cards ─────────────────────────────────────────
    L += ["---", "", "## 🔍 Target Fingerprints", ""]
    for t in targets:
        status_emoji = "🟢" if t.alive else "🔴"
        waf_str  = f"🛡️ {t.waf}" if t.waf else "—"
        tech_str = ", ".join(f"`{x}`" for x in t.tech[:6]) or "—"
        inj_str  = f"⚠️ {len(t.injectable)} candidate(s)" if t.injectable else "—"
        L += [
            f'<details markdown="1"><summary><b>{status_emoji} <code>{t.url}</code></b> '
            f"| <code>{t.scheme}/{t.port}</code> "
            f"| status: <b>{t.status or 'n/a'}</b></summary>",
            "",
            "| Field | Value |",
            "|---|---|",
            f"| Host | `{t.host}` |",
            f"| Port / Scheme | `{t.port}` / `{t.scheme}` |",
            f"| Service | `{t.service}` |",
            f"| Product | `{t.product or '—'}` |",
            f"| HTTP Status | `{t.status or 'n/a'}` |",
            f"| Detected Tech | {tech_str} |",
            f"| WAF | {waf_str} |",
            f"| Injectable Endpoints | {inj_str} |",
            f"| Crawl | `{t.crawl_new_endpoints}` new endpoints discovered |",
            "",
            "</details>",
            "",
        ]

    # ── Findings ─────────────────────────────────────────────────────────
    L += ["---", "", "## 🎯 Findings", ""]
    if not web_findings:
        if not service_findings:
            L += ["_No findings reported by any tool._", ""]
    else:
        for tgt, fs in ordered_targets:
            fs.sort(key=lambda f: (-SEV_ORDER.get(f.severity, 0), f.tool, f.title.lower()))
            sev_counts = {s: sum(1 for f in fs if f.severity == s)
                          for s in ("critical","high","medium","low","info")}
            sev_chips = " ".join(
                f"{_SEV_EMOJI[s]}`{n}`" for s,n in sev_counts.items() if n
            ) or "—"

            L += [
                f'<a id="target-{_slug(tgt)}"></a>',
                f"### 🌐 `{tgt}`",
                "",
                f"**{len(fs)} finding(s)** | {sev_chips}",
                "",
                "#### Summary",
                "",
                "| # | Severity | Tool | Title |",
                "|--:|:--------:|:----:|------|",
            ]
            for i, f in enumerate(fs, 1):
                L.append(
                    f"| {i} | {_SEV_EMOJI.get(f.severity,'⚫')} **{f.severity.upper()}** "
                    f"| `{f.tool}` | {_md_escape(f.title)[:160]} |"
                )
            L += ["", "#### Detailed Findings", ""]
            for i, f in enumerate(fs, 1):
                title = _md_escape(f.title)[:120]
                L += [
                    f'<details markdown="1"><summary>'
                    f"<b>#{i}</b> {_SEV_EMOJI.get(f.severity,'⚫')} "
                    f"{_sev_badge(f.severity)} "
                    f"<code>{f.tool}</code> — {title}"
                    f"</summary>",
                    "",
                    "| | |",
                    "|---|---|",
                    f"| **Severity** | {_SEV_EMOJI.get(f.severity,'⚫')} `{f.severity.upper()}` |",
                    f"| **Tool** | `{f.tool}` |",
                    f"| **Target** | `{f.target}` |",
                ]
                if f.reference:
                    L.append(f"| **Reference** | {f.reference} |")
                L.append("")
                if f.detail:
                    L += ["**Evidence:**", "", _fence(f.detail), ""]
                else:
                    L += ["_No additional evidence captured._", ""]
                L += ["</details>", ""]
            L += ["---", ""]

    # ── Footer ───────────────────────────────────────────────────────────
    L += [
        "## ⚙️ Scan Metadata",
        "",
        "| Field | Value |",
        "|---|---|",
        f"| VulnMalper version | `v{VERSION}` |",
        f"| Source NetMalper target | `{target_name}` |",
        f"| Generated (UTC) | `{gen_iso}` |",
        f"| Total scan duration | `{duration:.1f}s` |",
        f"| Tools dispatched | {runner_line} |",
        "",
        "---",
        "_Report generated by **VulnMalper** — pipelines NetMalper recon into nikto, nuclei, sqlmap, wapiti, testssl, httpx, whatweb & wafw00f._",
        "",
    ]
    with open(path, "w") as f: f.write("\n".join(L))

# ── Main pipeline ──────────────────────────────────────────────────────────
def _phase(label: str):
    print()
    log("phase", f"{C.B}{label}{C.R}")

def main():
    ap = argparse.ArgumentParser(
        prog="vulnmalper",
        description="Vulnerability pipeline for NetMalper graphs.",
    )
    ap.add_argument("input", help="NetMalper JSON graph")
    ap.add_argument("--out", default=None)
    ap.add_argument("--only", default="",
                    help=f"Comma list restricting stages: {','.join(ALL_TOOLS)}")
    ap.add_argument("--runner", default="auto", choices=["auto","local","docker"])
    ap.add_argument("--severity", default="low",
                    choices=["info","low","medium","high","critical"],
                    help="Minimum severity for nuclei (default: low)")
    ap.add_argument("--threads", type=int, default=3,
                    help="Parallel per-target workers in scan phase")
    ap.add_argument("--max-targets", type=int, default=0)
    ap.add_argument("--httpx-timeout",    type=int, default=120)
    ap.add_argument("--whatweb-timeout",  type=int, default=120)
    ap.add_argument("--wafw00f-timeout",  type=int, default=120)
    ap.add_argument("--testssl-timeout",  type=int, default=600)
    ap.add_argument("--nikto-timeout",    type=int, default=600)
    ap.add_argument("--nuclei-timeout",   type=int, default=86400)
    ap.add_argument("--wapiti-timeout",   type=int, default=1200)
    ap.add_argument("--sqlmap-timeout",   type=int, default=900)
    ap.add_argument("--ffuf-timeout",     type=int, default=600)
    ap.add_argument("--feroxbuster-timeout", type=int, default=900)
    ap.add_argument("--katana-timeout", type=int, default=600)
    ap.add_argument("--nmap-timeout",   type=int, default=300)
    ap.add_argument("--sqlmap-level", type=int, default=None,
                    help="Override sqlmap --level (default: 3 normal, 1 stealth)")
    ap.add_argument("--sqlmap-risk", type=int, default=None,
                    help="Override sqlmap --risk (default: 2 normal, 1 stealth)")
    ap.add_argument("--auth-user", default=None, help="Username for authenticated scanning.")
    ap.add_argument("--auth-pass", default=None, help="Password for authenticated scanning.")
    ap.add_argument("--auth-cookie", default=None, help='Session cookie in "NAME=VALUE" form.')
    ap.add_argument(
        "--proxy-file", default=None, metavar="FILE",
        help="File with one proxy per line (http://host:port or socks5://host:port). "
             "2-15 proxies; rotated round-robin across tool launches."
    )

    # ── Stealth / polite-mode flags ─────────────────────────────────────
    sg = ap.add_argument_group("stealth / polite-mode",
        "Reduce request rate, randomise headers, and avoid IPS triggers. "
        "Recommended when running through proxychains against production.")
    sg.add_argument("--polite", action="store_true",
        help="Polite mode: cap req/sec, add ~250ms delays, browser headers.")
    sg.add_argument("--slow", action="store_true",
        help="Slow mode: very low req/sec, ~1s delays, Nikto -Pause 1. "
             "Use against WAF-protected / rate-limited targets.")
    sg.add_argument("--user-agent", default=None,
        help="Pin a single User-Agent. Default: random per-run from a "
             "pool of current Chrome/Safari/Edge/Firefox UAs.")
    sg.add_argument("--header", action="append", default=[],
        metavar="K: V",
        help="Extra HTTP header sent by every tool that supports it. "
             "Repeatable. e.g. --header 'X-Forwarded-For: 1.2.3.4'")
    sg.add_argument("--rate-limit", type=int, default=0,
        help="Hard cap on req/sec for nuclei/httpx (0 = tool default).")
    sg.add_argument("--delay-ms", type=int, default=0,
        help="Min ms between requests for tools that support it.")
    sg.add_argument("--headless", action="store_true",
        help="Render JavaScript: enables nuclei -headless (Chromium) so "
             "SPA-only endpoints (e.g. Juice Shop's /rest/user/login) get "
             "discovered, and feeds them to wapiti as seed URLs. NB: "
             "lynx is text-only and CAN'T run JS — this uses Chromium "
             "via nuclei's bundled headless engine.")
    sg.add_argument("--quiet", action="store_true",
        help="Smarter probing: drop noisy nuclei tags (dos/intrusive/fuzz/"
             "tech/ssl/dns) and exposure-config globs. Cuts ~60-80%% of "
             "request volume and the 'nuclei default scan' WAF fingerprint. "
             "Implied by --polite/--slow.")
    sg.add_argument("--no-jitter", action="store_true",
        help="Disable per-request randomisation of timing + headers. "
             "Default is jitter ON: Referer, Accept-Language, DNT, "
             "Sec-Fetch-Site, Cache-Control rotate per call, and delays "
             "are spread ~50%% so timing isn't perfectly periodic.")

    # ── Long-scan / no-timeout flag ─────────────────────────────────────
    ap.add_argument("--no-timeout", nargs="?", const="__ALL__", default=None,
        metavar="TOOLS[=SECONDS]",
        help="Give tools a very long runtime budget. "
             "Bare `--no-timeout` lifts the cap on ALL tools (default 21600s = 6h each). "
             "Pass a comma-separated list to target specific tools, e.g. "
             "`--no-timeout nuclei,sqlmap`. "
             "Append `=SECONDS` to set a custom value, e.g. "
             "`--no-timeout=7200` (all tools, 2h) or "
             "`--no-timeout nuclei,nikto=10800` (those two, 3h). "
             "Valid tool names: httpx, whatweb, wafw00f, testssl, nikto, "
             "nuclei, wapiti, sqlmap, ffuf, feroxbuster, katana, nmap.")

    ap.add_argument("--addtimeout", action="store_true",
        help="Enable process-level timeout for nuclei (uses --nuclei-timeout, default 86400s). "
             "By default, nuclei runs without a process-level timeout.")

    # ── JSON export flag ───────────────────────────────────────────────
    ap.add_argument("--export-json", nargs="?", const="__AUTO__", default=None,
        metavar="PATH",
        help="Also write a single pretty JSON file with per-host summaries "
             "and the full deduped findings list. Bare `--export-json` writes "
             "next to the .md report (same basename, .json extension). "
             "Pass a path to override, e.g. `--export-json /tmp/scan.json`.")

    args = ap.parse_args()

    # Activate the stealth profile BEFORE any tool runs.
    global STEALTH, AUTH, SQLMAP_LEVEL, SQLMAP_RISK, PROXY_POOL
    STEALTH = StealthProfile(
        polite     = args.polite or args.slow,
        slow       = args.slow,
        user_agent = args.user_agent,
        headers    = list(args.header or []),
        rate_limit = args.rate_limit,
        delay_ms   = args.delay_ms,
        headless   = args.headless,
        jitter     = not args.no_jitter,
        quiet      = args.quiet or args.polite or args.slow,
    )
    AUTH = AuthProfile(user=args.auth_user, password=args.auth_pass, cookie=args.auth_cookie)
    SQLMAP_LEVEL = args.sqlmap_level
    SQLMAP_RISK = args.sqlmap_risk
    if args.proxy_file:
        _raw: list[str] = []
        with open(args.proxy_file) as _pf:
            for _ln in _pf:
                _ln = _ln.strip()
                if _ln and not _ln.startswith("#"):
                    _raw.append(_ln)
        if not (2 <= len(_raw) <= 15):
            log("err", f"--proxy-file must contain 2-15 proxies, got {len(_raw)}")
            sys.exit(2)
        PROXY_POOL = ProxyPool(_raw)
        _hc = len(PROXY_POOL._http)
        log("info", f"proxy pool: {len(_raw)} proxies ({_hc} HTTP, {len(_raw)-_hc} SOCKS5)")
        if not PROXY_POOL._http:
            log("warn", "no HTTP proxies in pool - nikto will run unproxied")

    if PROXY_POOL:
        _ps = 2.5
        for _attr in ("httpx_timeout","whatweb_timeout","wafw00f_timeout","nikto_timeout",
                      "nuclei_timeout","wapiti_timeout","sqlmap_timeout","ffuf_timeout",
                      "feroxbuster_timeout","katana_timeout"):
            setattr(args, _attr, int(getattr(args, _attr) * _ps))
        log("info", "proxy pool active - all timeouts scaled x2.5")

    banner()
    # Surface the active stealth profile so the user knows what's on.
    if STEALTH.slow or STEALTH.polite or STEALTH.user_agent or STEALTH.headers \
            or STEALTH.rate_limit or STEALTH.delay_ms or STEALTH.headless \
            or STEALTH.quiet or not STEALTH.jitter:
        bits = []
        if STEALTH.slow:        bits.append(f"{C.YL}SLOW{C.R}")
        elif STEALTH.polite:    bits.append(f"{C.CY}POLITE{C.R}")
        if STEALTH.rate_limit:  bits.append(f"rl={STEALTH.rate_limit}/s")
        if STEALTH.delay_ms:    bits.append(f"delay={STEALTH.delay_ms}ms")
        if STEALTH.user_agent:  bits.append("UA=pinned")
        else:                   bits.append("UA=random/run")
        if STEALTH.headers:     bits.append(f"+{len(STEALTH.headers)} hdr")
        if STEALTH.headless:    bits.append(f"{C.MG}HEADLESS{C.R}")
        if STEALTH.quiet:       bits.append(f"{C.GN}QUIET{C.R}")
        bits.append("jitter=" + ("on" if STEALTH.jitter else "off"))
        log("info", "Stealth profile: " + " · ".join(bits))

    # ── Auto mode ──────────────────────────────────────────────────────
    # If the user supplied ZERO stealth knobs, enable auto-mode: the scan
    # worker will pick a per-target strategy (stealth/aggressive/balanced)
    # from Phase-1 evidence and swap STEALTH for the duration of that
    # target's tools. Explicit flags fully override auto.
    auto_mode = not _user_supplied_stealth_flags(args)
    if auto_mode:
        log("info", f"{C.MG}[auto]{C.R} ON — strategy chosen per-target after "
                    "Phase 1 (WAF/CDN→stealth, private IP→aggressive, "
                    "else→balanced). Pass any --polite/--quiet/--rate-limit/"
                    "etc. to disable.")

    in_path = Path(args.input)
    if not in_path.exists():
        log("err", f"Input file not found: {in_path}"); sys.exit(2)
    try:
        with open(in_path) as f: graph = json.load(f)
    except Exception as e:
        log("err", f"Failed to read NetMalper JSON: {e}"); sys.exit(2)

    targets, service_targets, meta = parse_netmalper(graph)
    log("info", f"Loaded NetMalper graph for {C.B}{meta.get('target','?')}{C.R} "
                f"({len(graph.get('nodes',[]))} nodes)")
    if not targets and not service_targets:
        log("warn", "No scan targets discovered. Nothing to scan."); sys.exit(0)
    if not targets and service_targets:
        log("info", f"Web targets absent, but {len(service_targets)} service target(s) found for Phase 0")
    if args.max_targets and len(targets) > args.max_targets:
        log("warn", f"Capping {len(targets)} → {args.max_targets} targets")
        targets = targets[:args.max_targets]

    # Seed injectable URLs from NetMalper's endpoint findings (already has ?params)
    for t in targets:
        if t.has_query and t.url not in t.injectable:
            t.injectable.append(t.url)

    plans = plan_tools(args.runner)
    only  = {x.strip().lower() for x in args.only.split(",") if x.strip()}
    if only:
        for name in list(plans):
            if name not in only: plans[name] = None
        log("info", f"Restricted to: {', '.join(sorted(only))}")

    parts = []
    for name in ALL_TOOLS:
        p = plans.get(name)
        parts.append(f"{name}:{C.RD}off{C.R}" if p is None
                     else f"{name}:{C.GN}{p.runner}{C.R}")
    log("info", "Tool plan: " + "  ".join(parts))

    log("info", "Warming docker images in background where needed")
    warm_docker_images(plans)
    warm_nuclei_templates(plans["nuclei"])
    if service_targets and not have("nmap") and have("docker"):
        warm_phase0_nmap_image()
    runner_map = {k: (v.runner if v else "off") for k, v in plans.items()}

    timeouts = {
        "httpx": args.httpx_timeout, "whatweb": args.whatweb_timeout,
        "wafw00f": args.wafw00f_timeout, "testssl": args.testssl_timeout,
        "nikto": args.nikto_timeout, "nuclei": args.nuclei_timeout if args.addtimeout else None,
        "wapiti": args.wapiti_timeout, "sqlmap": args.sqlmap_timeout,
        "ffuf": args.ffuf_timeout, "feroxbuster": args.feroxbuster_timeout,
        "katana": args.katana_timeout, "nmap": args.nmap_timeout,
    }

    # Disable aggressive fuzzers if ANY stealth/polite flags are set
    if STEALTH.polite or STEALTH.slow or STEALTH.quiet or not STEALTH.jitter:
        if plans["ffuf"] or plans["feroxbuster"]:
            log("warn", "Stealth/Polite mode active — disabling aggressive fuzzers (ffuf, feroxbuster)")
            plans["ffuf"] = None
            plans["feroxbuster"] = None

    # ── --no-timeout: extend per-tool runtime budgets ──────────────────────
    if args.no_timeout is not None:
        raw = args.no_timeout
        # Split optional "=SECONDS" suffix.
        secs = 21600   # 6h default
        tool_part = raw
        if "=" in raw:
            tool_part, _, sec_str = raw.rpartition("=")
            try:
                secs = max(60, int(sec_str))
            except ValueError:
                log("warn", f"--no-timeout: bad seconds '{sec_str}', using {secs}s")
            if not tool_part:
                tool_part = "__ALL__"
        valid = set(timeouts.keys())
        if tool_part == "__ALL__":
            picked = sorted(valid)
        else:
            picked = [t.strip().lower() for t in tool_part.split(",") if t.strip()]
            unknown = [t for t in picked if t not in valid]
            if unknown:
                log("warn", f"--no-timeout: unknown tool(s) {unknown}, "
                            f"valid: {sorted(valid)}")
            picked = [t for t in picked if t in valid]
        for t in picked:
            timeouts[t] = secs
        if picked:
            log("info", f"--no-timeout active: {', '.join(picked)} "
                        f"→ {secs}s ({secs//60}min) each")

    all_findings: list[Finding] = []
    t0 = time.time()
    if service_targets:
        _phase("Phase 0 — Service Vulnerability Scanning")
        log("info", f"🔧 Service scan — {len(service_targets)} non-web services found")
        service_findings = run_phase0_service_scan(
            service_targets,
            plans,
            STEALTH,
            timeout=timeouts["nmap"],
            nuclei_timeout=timeouts["nuclei"],
            severity=args.severity,
        )
        all_findings.extend(service_findings)

    # ── PHASE 1: fingerprint ───────────────────────────────────────────────
    _phase("Phase 1 — Fingerprinting (httpx, whatweb, wafw00f)")

    if plans["httpx"]:
        log("run", f"httpx ({plans['httpx'].runner}) on {len(targets)} target(s)")
        fs = run_httpx(targets, plans["httpx"], timeouts["httpx"], STEALTH)
        log("ok", f"  httpx → {len(fs)} findings")
        all_findings.extend(fs)
    else:
        log("skip", "httpx unavailable — marking all targets as alive (no tech data)")
        for t in targets: t.alive = True

    def _fp_worker(t: WebTarget):
        out: list[Finding] = []
        if plans["whatweb"]:
            out.extend(run_whatweb(t, plans["whatweb"], timeouts["whatweb"], STEALTH))
        if plans["wafw00f"]:
            out.extend(run_wafw00f(t, plans["wafw00f"], timeouts["wafw00f"], STEALTH))
        return out

    if plans["whatweb"] or plans["wafw00f"]:
        alive = [t for t in targets if t.alive]
        log("run", f"whatweb/wafw00f on {len(alive)} alive target(s)")
        with concurrent.futures.ThreadPoolExecutor(max_workers=args.threads) as ex:
            for fs in ex.map(_fp_worker, alive):
                all_findings.extend(fs)

    # Before we classify a target as dead, do one last explicit recheck.
    dead_candidates = [t for t in targets if not t.alive]
    if dead_candidates:
        revived = 0
        log("info", f"Rechecking {len(dead_candidates)} target(s) that looked dead...")
        for t in dead_candidates:
            if confirm_target_liveness(t, STEALTH):
                revived += 1
                all_findings.append(Finding(
                    target=t.url, tool="liveness-check", severity="info",
                    title=f"Target responded on recheck ({t.status or 'tcp-open'})",
                    detail="Initial fingerprint missed this host; revived before scan phases.",
                ))
        if revived:
            log("ok", f"Liveness recheck revived {revived} target(s)")
            # Backfill tech/WAF on revived targets before deeper scans.
            revived_targets = [t for t in targets if t.alive and not t.tech and not t.waf]
            if revived_targets and (plans["whatweb"] or plans["wafw00f"]):
                with concurrent.futures.ThreadPoolExecutor(max_workers=args.threads) as ex:
                    for fs in ex.map(_fp_worker, revived_targets):
                        all_findings.extend(fs)

    # ── PHASE 1.5: crawl + discovery ──────────────────────────────────────
    DISCOVERY_TECHS = {"api", "rest", "node.js", "php", "asp.net", "java",
                       "python", "go", "ruby", "django", "flask", "laravel", "express"}
    alive_for_discovery = [t for t in targets if t.alive and not t.discovered]
    if alive_for_discovery:
        crawl_candidates = [t for t in alive_for_discovery
                            if any(dt in " ".join(t.tech).lower() for dt in DISCOVERY_TECHS)
                            or t.status in (200, 403)]
    else:
        crawl_candidates = []

    if crawl_candidates:
        _phase("Phase 1.5 — Crawl discovery (katana)")
        discovered_targets: list[WebTarget] = []
        existing_urls = {_normalize_discovered_url(t.url) for t in targets}

        def _register_discovered_urls(source: WebTarget, urls: list[str]) -> list[WebTarget]:
            new_targets: list[WebTarget] = []
            existing_urls_lower = {u.lower() for u in existing_urls}
            for u in urls:
                normalized_url = _normalize_discovered_url(u)
                if not normalized_url or normalized_url.lower() in existing_urls_lower:
                    continue
                existing_urls.add(normalized_url)
                existing_urls_lower.add(normalized_url.lower())
                p = urllib.parse.urlparse(normalized_url)
                new_targets.append(WebTarget(
                    url=normalized_url,
                    host=p.hostname or "",
                    port=p.port or (443 if p.scheme == "https" else 80),
                    scheme=p.scheme,
                    alive=True,
                    discovered=True,
                ))
            source.crawl_new_endpoints += len(new_targets)
            return new_targets

        def _crawl_worker(t: WebTarget):
            if auto_mode:
                strategy, reason = _ensure_auto_strategy(t, STEALTH)
                if strategy == "stealth":
                    log("skip", f"crawl → {t.url} skipped in auto stealth mode ({reason})")
                    return []
            urls = run_crawler(t, plans.get("katana"), min(timeouts.get("katana", 600), 600), STEALTH)
            if not urls:
                return []
            log("run", f"katana crawl → {t.url} ({len(urls)} raw url(s))")
            return _register_discovered_urls(t, urls)

        with concurrent.futures.ThreadPoolExecutor(max_workers=args.threads) as ex:
            for new_targets in ex.map(_crawl_worker, crawl_candidates):
                discovered_targets.extend(new_targets)

        if discovered_targets:
            log("ok", f"Discovered {len(discovered_targets)} crawl endpoint(s); fingerprinting new targets")
            targets.extend(discovered_targets)
            if plans["httpx"]:
                log("run", f"httpx fingerprinting {len(discovered_targets)} crawled target(s)")
                fs = run_httpx(discovered_targets, plans["httpx"], timeouts["httpx"], STEALTH)
                all_findings.extend(fs)
            with concurrent.futures.ThreadPoolExecutor(max_workers=args.threads) as ex:
                for fs in ex.map(_fp_worker, discovered_targets):
                    all_findings.extend(fs)

    discovery_enabled = plans["ffuf"] or plans["feroxbuster"]
    if discovery_enabled:
        _phase("Phase 1.5 — Discovery (feroxbuster, ffuf)")
        discovered_targets = []
        
        def _discovery_worker(t: WebTarget):
            new_targets = []
            local_findings = []
            if auto_mode:
                # Auto mode picks strategy per target. If this target is
                # classified as stealth, skip aggressive discovery fuzzers.
                strategy, reason = _ensure_auto_strategy(t, STEALTH)
                if strategy == "stealth":
                    log("skip", f"discovery → {t.url} skipped in auto stealth mode ({reason})")
                    return [], []
            
            # Skip non-scannable assets
            if not _is_worth_scanning(t.url):
                return [], []

            # Trigger logic: Status 200/403 OR Tech match
            tech_match = any(dt in " ".join(t.tech).lower() for dt in DISCOVERY_TECHS)
            status_match = t.status in (200, 403)
            
            if not (tech_match or status_match):
                return [], []

            if plans["feroxbuster"]:
                log("run", f"feroxbuster discovery → {t.url}")
                fs, urls = run_feroxbuster(t, plans["feroxbuster"], timeouts["feroxbuster"])
                local_findings.extend(fs)
                for u in urls:
                    # Normalize URL
                    normalized_url = _normalize_url(u)
                    p = urllib.parse.urlparse(normalized_url)
                    new_targets.append(WebTarget(
                        url=normalized_url, host=p.hostname or "", port=p.port or (443 if p.scheme == "https" else 80),
                        scheme=p.scheme, alive=True, discovered=True
                    ))
            
            if plans["ffuf"]:
                log("run", f"ffuf config discovery → {t.url}")
                fs, urls = run_ffuf(t, plans["ffuf"], timeouts["ffuf"])
                local_findings.extend(fs)
                for u in urls:
                    # Normalize URL
                    normalized_url = _normalize_url(u)
                    p = urllib.parse.urlparse(normalized_url)
                    new_targets.append(WebTarget(
                        url=normalized_url, host=p.hostname or "", port=p.port or (443 if p.scheme == "https" else 80),
                        scheme=p.scheme, alive=True, discovered=True
                    ))
            return local_findings, new_targets

        alive = [t for t in targets if t.alive and not t.discovered]
        if alive:
            log("info", f"Running discovery on {len(alive)} candidate(s) based on tech/status triggers")
            with concurrent.futures.ThreadPoolExecutor(max_workers=args.threads) as ex:
                for fs, results in ex.map(_discovery_worker, alive):
                    all_findings.extend(fs)
                    discovered_targets.extend(results)
        
        if discovered_targets:
            seen_urls_lower = {_normalize_discovered_url(t.url).lower() for t in targets}
            unique_new: dict[str, WebTarget] = {}
            for nt in discovered_targets:
                normalized_url = _normalize_discovered_url(nt.url)
                if not normalized_url or normalized_url.lower() in seen_urls_lower:
                    continue
                seen_urls_lower.add(normalized_url.lower())
                unique_new[normalized_url] = nt

            new_list = list(unique_new.values())
            if new_list:
                log("ok", f"Discovered {len(new_list)} new targets! Adding to full stack scan pool.")
                targets.extend(new_list)
                # For newly discovered targets, run a quick fingerprint.
                if plans["httpx"]:
                    log("run", f"httpx fingerprinting {len(new_list)} new target(s)")
                    fs = run_httpx(new_list, plans["httpx"], timeouts["httpx"], STEALTH)
                    all_findings.extend(fs)
                
                # whatweb/wafw00f for new targets
                with concurrent.futures.ThreadPoolExecutor(max_workers=args.threads) as ex:
                    for fs in ex.map(_fp_worker, new_list):
                        all_findings.extend(fs)

    # ── PHASE 2: scan ──────────────────────────────────────────────────────
    _phase("Phase 2 — Scanning (nuclei, wapiti, testssl, nikto)")

    # Snapshot the user-configured stealth profile so per-target auto-mode
    # swaps can always restore it cleanly between targets.
    base_stealth = STEALTH

    # Group targets by netloc for nuclei batching
    targets_by_host: dict[str, list[WebTarget]] = {}
    for t in targets:
        if not t.alive: continue
        host = urllib.parse.urlparse(t.url).netloc
        targets_by_host.setdefault(host, []).append(t)

    def _scan_host_worker(host_targets: list[WebTarget]):
        if not host_targets: return []
        out: list[Finding] = []
        
        # Pick a lead target for auto-strategy (or use base)
        lead = host_targets[0]
        local_stealth = base_stealth
        if auto_mode:
            strategy, reason = _ensure_auto_strategy(lead, base_stealth)
            local_stealth = build_auto_profile(strategy, base_stealth)
            log("info", _format_auto_banner(lead, strategy, reason, local_stealth))
        
        # ── 1. Batch Nuclei
        if plans["nuclei"]:
            scannable = [t for t in host_targets if _is_worth_scanning(t.url)]
            if scannable:
                fs = run_nuclei(scannable, plans["nuclei"], args.severity, timeouts["nuclei"], local_stealth, AUTH)
                out.extend(fs)
                # Feed back injectable endpoints to WebTarget objects
                for f in fs:
                    if "?" in f.target:
                        for t in host_targets:
                            if t.url == f.target:
                                if f.target not in t.injectable: t.injectable.append(f.target)
                local_stealth.sleep_jitter()

        # ── 2. Other tools (still per-target for now as they don't batch well)
        for t in host_targets:
            # testssl
            if plans["testssl"] and t.scheme == "https" and t.port in TLS_PORTS:
                log("run", f"testssl ({plans['testssl'].runner}) → {t.url}")
                tt = time.time()
                fs = run_testssl(t, plans["testssl"], timeouts["testssl"])
                log("ok" if fs else "skip", f"  testssl {round(time.time()-tt,1)}s — {len(fs)} findings")
                out.extend(fs)
                local_stealth.sleep_jitter()
            
            # nikto
            if plans["nikto"] and t.scheme in ("http", "https") and t.port in NIKTO_PORTS and not t.discovered:
                log("run", f"nikto ({plans['nikto'].runner}) → {t.url}")
                tt = time.time()
                fs = run_nikto(t, plans["nikto"], timeouts["nikto"], local_stealth)
                log("ok" if fs else "skip", f"  nikto {round(time.time()-tt,1)}s — {len(fs)} findings")
                out.extend(fs)
            
            # wapiti
            if plans["wapiti"]:
                log("run", f"wapiti ({plans['wapiti'].runner}) → {t.url}")
                tt = time.time()
                fs = run_wapiti(t, plans["wapiti"], timeouts["wapiti"], local_stealth)
                log("ok" if fs else "skip", f"  wapiti {round(time.time()-tt,1)}s — {len(fs)} findings")
                out.extend(fs)
                local_stealth.sleep_jitter()
        return out

    if args.threads <= 1:
        for host_targets in targets_by_host.values(): all_findings.extend(_scan_host_worker(host_targets))
    else:
        with concurrent.futures.ThreadPoolExecutor(max_workers=args.threads) as ex:
            for fs in ex.map(_scan_host_worker, list(targets_by_host.values())):
                all_findings.extend(fs)

    # ── PHASE 2.5: active service chaining ────────────────────────────────
    # No external tool — we hit known endpoints ourselves and reason about
    # what the responses mean. Cheap, offline, and catches the "obvious"
    # exposures every pentester checks first.
    chainable = [t for t in targets if t.alive and t.port in SERVICE_CHAIN_PLAYBOOKS]
    if auto_mode:
        filtered: list[WebTarget] = []
        for t in chainable:
            strategy, reason = _ensure_auto_strategy(t, base_stealth)
            if strategy == "stealth":
                log("skip", f"chain → {t.url} skipped in auto stealth mode ({reason})")
                continue
            filtered.append(t)
        chainable = filtered
    if chainable:
        _phase("Phase 2.5 — Active service chaining (Prometheus, Consul, "
               "Grafana, Docker API, …)")
        log("info", f"{len(chainable)} target(s) match a known service playbook")
        for t in chainable:
            # Re-resolve strategy to get correct profile for _http_probe
            local_stealth = base_stealth
            if auto_mode:
                strategy, reason = _ensure_auto_strategy(t, base_stealth)
                local_stealth = build_auto_profile(strategy, base_stealth)
            log("run", f"chain → {t.url}  (port {t.port})")
            all_findings.extend(run_service_chain(t, local_stealth))

    # ── PHASE 3: sqlmap verification on curated endpoints ──────────────────
    _phase("Phase 3 — Verifying SQLi candidates (sqlmap)")

    # Group GET targets by host for batching; POST targets run individually.
    sqli_get_by_host: dict[str, list[tuple[str, StealthProfile, bool, AuthProfile]]] = {}
    sqli_post_queue: list[tuple[str, str, StealthProfile, bool, AuthProfile]] = []
    seen_sqli: set[str] = set()

    for t in targets:
        local_stealth = base_stealth
        if auto_mode:
            strategy, reason = _ensure_auto_strategy(t, base_stealth)
            if strategy == "stealth":
                if t.injectable or t.alive:
                    log("skip", f"sqlmap on {t.url} skipped — auto stealth ({reason})")
                continue
            local_stealth = build_auto_profile(strategy, base_stealth)

        # Skip non-scannable assets
        if not _is_worth_scanning(t.url):
            continue

        target_auth = AUTH
        if t.authed_cookie:
            target_auth = AuthProfile(
                user=AUTH.user, password=AUTH.password,
                cookie=AUTH.cookie, authed_cookie=t.authed_cookie
            )
            if not AUTH.cookie:
                log("info", f"sqlmap: using authed session cookie for {t.url}")

        for url, post_data, method in build_sqlmap_targets(t, local_stealth):
            key = f"{url}|{post_data}"
            if key not in seen_sqli:
                seen_sqli.add(key)
                if post_data:
                    sqli_post_queue.append((url, post_data, local_stealth, bool(t.waf), target_auth))
                else:
                    host = urllib.parse.urlparse(url).netloc
                    sqli_get_by_host.setdefault(host, []).append((url, local_stealth, bool(t.waf), target_auth))

    if not plans["sqlmap"]:
        log("skip", "sqlmap unavailable — skipping phase 3")
    elif not sqli_get_by_host and not sqli_post_queue:
        log("skip", "No injectable endpoints found by form discovery or upstream tools")
    else:
        # ── 1. Batch GET targets
        def _sqli_get_worker(host_targets):
            urls = [u for u, s, w, a in host_targets]
            # Use stealth/waf/auth from the first target in the batch. If any
            # target in the batch has a captured login cookie, prefer it.
            _, stealth, waf, auth = host_targets[0]
            for _, _, _, candidate_auth in host_targets:
                if getattr(candidate_auth, "authed_cookie", None):
                    auth = candidate_auth
                    break
            return run_sqlmap_batch(urls, plans["sqlmap"], timeouts["sqlmap"], stealth, auth, waf_detected=waf)

        # ── 2. Individual POST targets
        def _sqli_post_worker(item):
            url, post_data, stealth, waf, auth = item
            return run_sqlmap(url, plans["sqlmap"], timeouts["sqlmap"], stealth, auth, post_data=post_data, waf_detected=waf)

        if args.threads <= 1:
            for host, host_targets in sqli_get_by_host.items():
                all_findings.extend(_sqli_get_worker(host_targets))
            for item in sqli_post_queue:
                all_findings.extend(_sqli_post_worker(item))
        else:
            with concurrent.futures.ThreadPoolExecutor(max_workers=min(args.threads, 3)) as ex:
                # Run GET batches
                for fs in ex.map(_sqli_get_worker, list(sqli_get_by_host.values())):
                    all_findings.extend(fs)
                # Run POST targets
                for fs in ex.map(_sqli_post_worker, sqli_post_queue):
                    all_findings.extend(fs)

    duration = time.time() - t0

    base = args.out
    if not base:
        stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        safe  = re.sub(r"[^A-Za-z0-9_.-]+", "_", meta.get("target","target"))
        base  = f"vulnmalper_{safe}_{stamp}"
    write_markdown(base + ".md", all_findings, targets, meta, duration, runner_map)

    render_console(all_findings, targets, meta, duration, runner_map)
    log("ok", f"Report written to {C.B}{base}.md{C.R}")

    # ── Optional JSON export ──────────────────────────────────────────────
    if args.export_json is not None:
        json_path = (base + ".json") if args.export_json == "__AUTO__" else args.export_json
        try:
            write_json_export(json_path, all_findings, targets, meta, duration, runner_map)
            log("ok", f"JSON export written to {C.B}{json_path}{C.R}")
        except Exception as e:
            log("err", f"JSON export failed: {e}")

if __name__ == "__main__":
    main()
