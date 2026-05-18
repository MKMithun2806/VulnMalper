#!/usr/bin/env python3
"""
VulnMalper v7.0.0  —  Vulnerability pipeline for NetMalper graphs.

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
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import threading
import urllib.parse
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

VERSION = "7.0.0"

# Background warmup state for docker images and nuclei templates.
DOCKER_IMAGE_EVENTS: dict[str, threading.Event] = {}
DOCKER_IMAGE_RESULTS: dict[str, bool] = {}
NUCLEI_TEMPLATE_EVENT: Optional[threading.Event] = None
NUCLEI_TEMPLATE_RESULT: Optional[bool] = None
NUCLEI_TEMPLATE_LOCK = threading.RLock()
PHASE0_NMAP_EVENT: Optional[threading.Event] = None
PHASE0_NMAP_RESULT: Optional[bool] = None
PHASE0_NMAP_LOCK = threading.RLock()
CRAWLER_IMAGE_EVENT: Optional[threading.Event] = None
CRAWLER_IMAGE_RESULT: Optional[bool] = None
CRAWLER_IMAGE_LOCK = threading.RLock()

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

AUTH = AuthProfile()
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

def _best_hostname_for_ip(ip: str, nodes: dict) -> Optional[str]:
    for n in nodes.values():
        if n["type"] in ("sub","root","cname"):
            fqdn = n["data"].get("fqdn") or n.get("label")
            if not fqdn: continue
            try:
                if socket.gethostbyname(fqdn) == ip: return fqdn
            except Exception: continue
    return None

def _normalize_url(url: str) -> str:
    """Normalize URL by removing trailing slashes and ensuring consistent format."""
    p = urllib.parse.urlparse(url)
    path = p.path.rstrip("/") or "/"
    return urllib.parse.urlunparse((p.scheme, p.netloc, path, p.params, p.query, p.fragment))

def parse_netmalper(graph: dict):
    nodes = {n["id"]: n for n in graph.get("nodes", [])}
    meta  = graph.get("meta", {})
    targets: dict[str, WebTarget] = {}
    services: dict[tuple[str, int, str], ServiceTarget] = {}

    for n in nodes.values():
        if n["type"] != "endpoint": continue
        url = n["data"].get("url")
        if not url: continue
        # Normalize URL to remove trailing slashes
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
        port = d.get("port"); svc = (d.get("service") or "").lower()
        host = d.get("host") or ""
        if not host or not port: continue
        looks_web = svc in WEB_SERVICES or port in WEB_PORTS or "http" in svc
        if not looks_web: continue
        scheme = "https" if (svc == "https" or port in (443,8443,9443)) else "http"
        host_label = _best_hostname_for_ip(host, nodes) or host
        url = f"{scheme}://{host_label}" + (f":{port}" if port not in (80,443) else "") + "/"
        # Normalize URL to remove trailing slashes
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
        port = d.get("port")
        svc = (d.get("service") or "").lower()
        host = d.get("host") or ""
        if not host or not port:
            continue
        looks_web = svc in WEB_SERVICES or port in WEB_PORTS or "http" in svc
        if looks_web:
            continue
        host_label = _best_hostname_for_ip(host, nodes) or host
        key = (host_label, int(port), svc)
        services.setdefault(key, ServiceTarget(
            host=host_label,
            port=int(port),
            service=svc or "unknown",
            product=d.get("product", ""),
            src_node=n["id"],
        ))
    return list(targets.values()), list(services.values()), meta

# ── Runner layer (local + docker) ───────────────────────────────────────────
ALL_TOOLS = ["httpx","whatweb","wafw00f","testssl","nikto",
             "nuclei","wapiti","sqlmap","ffuf","feroxbuster"]

DOCKER_IMAGES = {
    "httpx":   "projectdiscovery/httpx:latest",
    "whatweb": "secsi/whatweb:latest",
    "wafw00f": "secsi/wafw00f:latest",
    "testssl": "drwetter/testssl.sh:latest",
    "nikto":   "ghcr.io/sullo/nikto:latest",
    "nuclei":  "projectdiscovery/nuclei:latest",
    "wapiti":  "cyberwatch/wapiti:latest",
    "sqlmap":  "googlesky/sqlmap:latest",
    "ffuf":    "secsi/ffuf:latest",
    "feroxbuster": "epi052/feroxbuster",
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
}

def have(cmd: str) -> bool:
    return shutil.which(cmd) is not None

def docker_available() -> bool:
    if not have("docker"): return False
    try:
        p = subprocess.run(["docker","info"], capture_output=True, text=True, timeout=8)
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

def ensure_docker_image(image: str, quiet: bool = False):
    try:
        subprocess.run(["docker","image","inspect",image],
                       capture_output=True, timeout=10, check=True)
        return True
    except subprocess.CalledProcessError:
        if not quiet:
            log("info", f"Pulling docker image: {image}")
        try:
            subprocess.run(["docker","pull",image], timeout=600, check=True)
            return True
        except Exception as e:
            if not quiet:
                log("err", f"docker pull {image} failed: {e}")
            return False
    except Exception:
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
                cmd = build_cmd(plan, ["-update-templates"], mount=(template_dir, "/root/nuclei-templates"))
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

def warm_crawler_image():
    """Background-pull the gospider crawler image when crawling is enabled."""
    global CRAWLER_IMAGE_EVENT
    with CRAWLER_IMAGE_LOCK:
        if CRAWLER_IMAGE_EVENT is not None:
            return
        event = threading.Event()
        CRAWLER_IMAGE_EVENT = event

        def _worker():
            global CRAWLER_IMAGE_RESULT
            try:
                CRAWLER_IMAGE_RESULT = ensure_docker_image("jaeles-project/gospider", quiet=True)
            except Exception:
                CRAWLER_IMAGE_RESULT = False
            finally:
                event.set()

        threading.Thread(target=_worker, daemon=True).start()

def wait_for_crawler_image() -> bool:
    event = CRAWLER_IMAGE_EVENT
    if event is None:
        warm_crawler_image()
        event = CRAWLER_IMAGE_EVENT
    if event is None:
        return False
    event.wait()
    return bool(CRAWLER_IMAGE_RESULT)

def _run(cmd, timeout, stdin_data: Optional[str] = None):
    try:
        p = subprocess.run(cmd, input=stdin_data, capture_output=True,
                           text=True, timeout=timeout)
        return p.returncode, p.stdout, p.stderr
    except subprocess.TimeoutExpired:
        return 124, "", f"timeout after {timeout}s"
    except FileNotFoundError as e:
        return 127, "", str(e)
    except Exception as e:
        return 1, "", str(e)

def build_cmd(plan: ToolPlan, tool_args: list[str],
              mount: Optional[tuple[str,str]] = None,
              extra_docker: Optional[list[str]] = None,
              local_binary: Optional[str] = None) -> list[str]:
    """Build the final subprocess command for either runner."""
    if plan.runner == "local":
        return [local_binary or LOCAL_BINARIES[plan.name]] + tool_args
    wait_for_docker_image(plan)
    docker = ["docker","run","--rm","-i","--network","host"]
    if mount:
        host, container = mount
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
    import urllib.request
    try:
        urllib.request.urlretrieve(url, path)
        return path
    except Exception as e:
        log("err", f"Failed to download wordlist {name}: {e}")
        return ""

# ────────────────────────────────────────────────────────────────────────────
#  PHASE 1 — FINGERPRINTING (always runs on every HTTP target)
# ────────────────────────────────────────────────────────────────────────────
def run_httpx(targets: list[WebTarget], plan: ToolPlan, timeout: int):
    """Probe alive + fingerprint tech/server/status for every target."""
    if not targets:
        return []
    urls = "\n".join(t.url for t in targets)
    args = ["-silent","-json","-l","-","-nc","-no-color","-timeout","10",
            "-tech-detect","-status-code","-title","-server","-follow-redirects"]
    # Stealth: random browser UA + extra (jittered) headers on every probe.
    args += ["-H", f"User-Agent: {STEALTH.pick_ua()}"]
    for h in STEALTH.default_headers():
        args += ["-H", h]
    # Lower rate when polite/slow; httpx -rate-limit is per-second.
    rl = STEALTH.polite_rl(150)
    args += ["-rate-limit", str(rl)]
    # Cap parallel fan-out so a 50-target graph doesn't burst-probe.
    if STEALTH.polite or STEALTH.slow:
        args += ["-threads", "10" if STEALTH.slow else "25"]
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

    cmd  = build_cmd(plan, args)
    rc, out, err = _run(cmd, timeout, stdin_data=urls)
    _parse_httpx_output(out)
    if targets and not findings:
        log("warn", "httpx returned 0 results, falling back to direct probing")
        single_args = args[:2] + args[4:]
        for t in targets:
            cmd = build_cmd(plan, single_args + ["-u", t.url])
            rc, out, err = _run(cmd, timeout)
            _parse_httpx_output(out)
    return findings

def run_whatweb(t: WebTarget, plan: ToolPlan, timeout: int):
    args = ["--color=never","--log-json=-","-a","1",
            "--user-agent", STEALTH.pick_ua()]
    for h in STEALTH.default_headers():
        args += ["--header", h]
    args.append(t.url)
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

def run_wafw00f(t: WebTarget, plan: ToolPlan, timeout: int):
    host_dir = f"/tmp/vulnmalper_waf_{abs(hash(t.url))}"
    os.makedirs(host_dir, exist_ok=True)
    out_name = "waf.json"
    ua = STEALTH.pick_ua()
    if plan.runner == "docker":
        container_dir = "/wrk"
        out_path = f"{container_dir}/{out_name}"
        args = ["-U", ua, t.url, "-a", "-o", out_path, "-f", "json"]
        cmd = build_cmd(plan, args, mount=(host_dir, container_dir))
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
        cmd = build_cmd(plan, args, mount=(host_dir, container_dir))
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


def run_nikto(t: WebTarget, plan: ToolPlan, timeout: int):
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
        if STEALTH.slow:
            maxtime = min(timeout, 570)
        elif STEALTH.headless:
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
        args += ["-useragent", STEALTH.pick_ua()]
    if caps["display"]:
        # V = verbose. Without it, some builds emit nothing on stdout.
        args += ["-Display", "V"]
    if STEALTH.slow and caps["pause"]:
        args += ["-Pause", "1"]

    # Custom headers — only on builds that actually support them.
    if caps["add_header"]:
        for h in STEALTH.default_headers():
            args += ["-Add-header", h]
    elif caps["request_header"]:
        for h in STEALTH.default_headers():
            args += ["-RequestHeader", h]
    # else: legacy 2.1.6 — silently skip. Better than a hard exit.

    if plan.runner == "docker":
        cmd = build_cmd(plan, args, mount=(host_dir, container_dir))
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
                cand = tok
            elif tok.startswith("/") and "?" in tok:
                cand = t.url.rstrip("/") + tok
            else:
                continue
            if cand not in t.injectable:
                t.injectable.append(cand)
        # Also extract any parameter-like patterns (e.g., ?id=, ?query=) from nikto msgs
        param_patterns = re.findall(r'\?(\w+)=', msg)
        for param in param_patterns:
            url_with_param = t.url.rstrip("/") + "?" + param + "="
            if url_with_param not in t.injectable:
                t.injectable.append(url_with_param)
    shutil.rmtree(host_dir, ignore_errors=True)
    return findings

def run_nuclei(t: WebTarget, plan: ToolPlan, severity: str, timeout: int):
    sev_chain = ["info","low","medium","high","critical"]
    keep = sev_chain[max(0, sev_chain.index(severity)):] if severity in sev_chain else sev_chain
    rl = STEALTH.polite_rl(150)
    args = ["-u", t.url, "-jsonl","-silent","-nc",
            "-severity", ",".join(keep),
            "-tags", "cves,exposures,misconfiguration,vulnerabilities,default-logins,takeovers",
            "-exclude-tags", "fuzzing,dos,helpers",
            "-stats",
            "-timeout","10","-rl",str(rl),
            "-H", f"User-Agent: {STEALTH.pick_ua()}"]
    auth_hdr = auth_basic_header()
    if auth_hdr:
        args += ["-H", auth_hdr]
    if auth_cookie_value():
        args += ["-H", f"Cookie: {auth_cookie_value()}"]
    for h in STEALTH.default_headers():
        args += ["-H", h]

    # Handle template persistence for Docker
    nuclei_mount = None
    if plan.runner == "docker":
        # Use a user-specific path to avoid permission issues in /tmp
        # and ensure templates persist across reboots unlike /tmp.
        template_dir = os.path.expanduser("~/.cache/vulnmalper/nuclei-templates")
        try:
            os.makedirs(template_dir, exist_ok=True)
        except Exception:
            # Fallback to a user-specific temp dir if ~/.cache is not writable
            template_dir = os.path.join(tempfile.gettempdir(), f"vulnmalper_nuclei_{os.getuid()}")
            os.makedirs(template_dir, exist_ok=True)

        nuclei_mount = (template_dir, "/root/nuclei-templates")
        ensure_nuclei_templates(plan)

    # ── Stealth: smaller, smarter probing under --polite / --slow / --quiet
    # Default nuclei = 25 templates × 25 hosts in parallel = obvious burst.
    # We dial that down + spread requests across a wider window so the
    # per-second pattern doesn't scream "automated scanner".
    if STEALTH.polite or STEALTH.slow or STEALTH.quiet:
        # -bs (bulk-size) = parallel hosts/template; -c = parallel templates.
        # Single-target scan, so bs=1 just removes one redundant axis.
        args += ["-bs", "1"]
        args += ["-c", "5" if STEALTH.slow else "10"]
        # Spread the rate over a longer window so bursts smooth out.
        # nuclei -rate-limit-duration accepts Go duration: "2s","5s",...
        args += ["-rate-limit-duration", "5s" if STEALTH.slow else "2s"]
        # Skip a host if it 30x-errors before that, or we waste budget.
        args += ["-mhe", "10"]

    # ── Quiet template set: exclude noisy/intrusive tags + redundant globs.
    # The curated tag list above is the primary filter; these are extra
    # reductions when the user explicitly asked for quieter probing.
    if STEALTH.quiet or STEALTH.polite or STEALTH.slow:
        args += ["-etags", ",".join(NOISY_NUCLEI_TAGS)]
        for glob in NOISY_NUCLEI_TEMPLATE_GLOBS:
            args += ["-et", glob]
    # Headless: render JS so nuclei can hit SPA-only endpoints
    # (e.g. Juice Shop's /rest/user/login is only discoverable after the
    # Angular bundle boots). Requires Chromium on the host (or in the
    # nuclei docker image, which already ships it).
    if STEALTH.headless:
        args += ["-headless", "-page-timeout", "20"]
        # nuclei refuses headless+host-network unless you also pass these:
        if plan.runner == "docker":
            args += ["-system-chrome"]
    cmd = build_cmd(plan, args, mount=nuclei_mount)
    rc, out, err = _run(cmd, timeout)
    findings: list[Finding] = []
    INJ_TAGS = {"sqli","sql-injection","injection","xss","ssti","lfi","rfi"}
    
    # Debug: log nuclei output stats
    if out:
        lines = out.strip().splitlines()
        json_lines = [l for l in lines if l.startswith("{")]
        log("info", f"nuclei: got {len(json_lines)} JSON results from {t.url}")
    else:
        log("warn", f"nuclei: no output for {t.url} (rc={rc})")
        if err:
            log("warn", f"nuclei stderr: {err[:500]}")
    for line in out.splitlines():
        line = line.strip()
        if not line.startswith("{"): continue
        try: j = json.loads(line)
        except Exception: continue
        info = j.get("info", {})
        sev  = (info.get("severity") or "unknown").lower()
        tags = set(info.get("tags") or [])
        matched = j.get("matched-at") or t.url
        findings.append(Finding(
            target=matched, tool="nuclei", severity=sev,
            title=info.get("name") or j.get("template-id") or "nuclei finding",
            detail=(info.get("description") or "").strip(),
            reference=", ".join(info.get("reference") or []),
            raw=j,
        ))
        # Feed sqlmap when nuclei points at an injection-flavored URL w/ params.
        if (tags & INJ_TAGS) and "?" in matched and matched not in t.injectable:
            t.injectable.append(matched)
    if rc != 0 and not findings and err:
        log("warn", f"nuclei: {err.strip().splitlines()[-1] if err.strip() else 'no output'}")
    return findings

WAPITI_SEV_MAP = {1:"low",2:"medium",3:"high",4:"critical",0:"info",
                  "Low":"low","Medium":"medium","High":"high",
                  "Critical":"critical","Informational":"info"}

def run_wapiti(t: WebTarget, plan: ToolPlan, timeout: int):
    host_dir = f"/tmp/vulnmalper_wapiti_{abs(hash(t.url))}"
    os.makedirs(host_dir, exist_ok=True)
    report = "report.json"
    extra = ["-A", STEALTH.pick_ua()]
    for h in STEALTH.default_headers():
        extra += ["-H", h]
    # NOTE: Wapiti doesn't expose a true per-request delay flag. Do not map
    # STEALTH delay to `-t` (request timeout), that would silently change
    # timeout behavior instead of pacing.
    # Headless / SPA crawling: wapiti has no built-in headless browser
    # (NB: lynx is text-only, can't execute JS either — both are dead ends
    # for SPAs like Juice Shop). What we CAN do is bump scope to "domain"
    # and increase depth so wapiti follows every API call discovered by
    # nuclei's headless crawl (which feeds t.injectable upstream).
    if STEALTH.headless:
        extra += ["--scope", "domain", "-d", "5"]
        # Seed wapiti with API endpoints nuclei's headless run already found.
        for inj_url in t.injectable[:20]:
            extra += ["--start", inj_url]
    extra += ["--module", "csrf,xss,sql,xxe,redirect,ssrf,timesql,blindsql,wapp,nikto,htaccess,cookieflags,csp,headers,http_headers"]
    if AUTH.user and AUTH.password:
        extra += ["--auth-credential", f"{AUTH.user}%{AUTH.password}", "--auth-method", "post"]
    if AUTH.cookie:
        extra += ["--cookie", AUTH.cookie]
    if plan.runner == "docker":
        container_dir = "/wrk"
        args = ["-u", t.url, "-f","json","-o", f"{container_dir}/{report}",
                "--flush-session","--level","1",
                "--max-scan-time", str(min(timeout, 1200)), "-S","paranoid"] + extra
        cmd = build_cmd(plan, args, mount=(host_dir, container_dir))
    else:
        args = ["-u", t.url, "-f","json","-o", os.path.join(host_dir, report),
                "--flush-session","--level","1",
                "--max-scan-time", str(min(timeout, 1200)), "-S","paranoid"] + extra
        cmd = build_cmd(plan, args)
    rc, out, err = _run(cmd, timeout + 30)
    findings: list[Finding] = []
    host_out = os.path.join(host_dir, report)
    if os.path.exists(host_out):
        try:
            with open(host_out) as f: data = json.load(f)
            vulns = data.get("vulnerabilities", {}) or {}
            for category, items in vulns.items():
                for it in items or []:
                    lvl = it.get("level", it.get("severity", 0))
                    sev = WAPITI_SEV_MAP.get(lvl, "unknown")
                    info_ = it.get("info") or it.get("description") or ""
                    method = it.get("method") or ""
                    path   = it.get("path") or ""
                    param  = it.get("parameter") or it.get("parameter_name") or ""
                    full_url = t.url.rstrip("/") + path if path.startswith("/") else (path or t.url)
                    findings.append(Finding(
                        target=full_url, tool="wapiti", severity=sev,
                        title=f"{category}" + (f" on `{param}`" if param else ""),
                        detail=(f"{method} {path}\n{info_}").strip(),
                        raw=it,
                    ))
                    # Add URLs with parameters to injectable for sqlmap testing
                    # Include SQLi, XSS, and any other parameter-based vulnerabilities
                    if param and "?" not in full_url:
                        injectable_url = full_url + "?" + param + "="
                    elif param:
                        injectable_url = full_url + "&" + param + "="
                    else:
                        injectable_url = full_url
                    if injectable_url not in t.injectable:
                        t.injectable.append(injectable_url)
        except Exception as e:
            log("warn", f"wapiti JSON parse failed for {t.url}: {e}")
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
    
    args = ["-u", t.url, "-w", "/wl/wl.txt" if plan.runner == "docker" else wl_path,
            "-d", "2", "--silent", "-o", f"/wrk/{report}" if plan.runner == "docker" else os.path.join(host_dir, report)]
    
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
    args = ["-u", target_url, "-w", "/wl/wl.txt" if plan.runner == "docker" else wl_path,
            "-mc", "200", "-of", "json", "-o", f"/wrk/{report}" if plan.runner == "docker" else os.path.join(host_dir, report),
            "-s"]
    
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

def run_crawler(t: WebTarget, timeout: int) -> list[str]:
    """Best-effort crawl with gospider via Docker. Silent on failure."""
    if not have("docker"):
        return []
    if not wait_for_crawler_image():
        return []
    cmd = [
        "docker", "run", "--rm", "--network", "host", "jaeles-project/gospider",
        "-s", t.url, "-d", "3", "-c", "10", "--json", "-a", STEALTH.pick_ua(),
    ]
    rc, out, err = _run(cmd, timeout)
    if rc != 0 or not out:
        return []
    urls: list[str] = []
    try:
        blob = json.loads(out)
        urls.extend(_collect_json_urls(blob))
    except Exception:
        pass
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
    return urls

def _normalize_discovered_url(u: str) -> str:
    try:
        return _normalize_url(u)
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

def run_service_nuclei(asset: ServiceTarget, plan: ToolPlan, timeout: int) -> list[Finding]:
    tags = _service_scan_tags(asset)
    if not tags:
        return []
    rl = STEALTH.polite_rl(50)
    url = _service_target_url(asset)
    args = ["-u", url, "-jsonl", "-silent", "-nc",
            "-tags", ",".join(tags),
            "-exclude-tags", "fuzzing,dos,helpers",
            "-stats",
            "-timeout", "10", "-rl", str(rl),
            "-H", f"User-Agent: {STEALTH.pick_ua()}"]
    for h in STEALTH.default_headers():
        args += ["-H", h]
    if auth_basic_header():
        args += ["-H", auth_basic_header()]
    if auth_cookie_value():
        args += ["-H", f"Cookie: {auth_cookie_value()}"]
    cmd = build_cmd(plan, args)
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

def run_phase0_service_scan(service_targets: list[ServiceTarget], plans: dict[str, Optional[ToolPlan]], timeout: int = 300) -> list[Finding]:
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
            findings.extend(run_service_nuclei(asset, plans["nuclei"], timeout))
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

def _http_probe(url: str, timeout: int = 10) -> tuple[int, str]:
    """Tiny stdlib HTTP GET — avoids pulling `requests` just for chaining.
    Returns (status_code, body_first_4kb). status=0 on connection failure."""
    import urllib.request, urllib.error, ssl
    headers = {"User-Agent": STEALTH.pick_ua()}
    for h in STEALTH.default_headers():
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

def confirm_target_liveness(t: WebTarget) -> bool:
    """Double-check a target before considering it dead.

    Strategy:
      1) Retry HTTP probe on the exact URL twice.
      2) If still no HTTP response, try a raw TCP connect to host:port.
    """
    # Two HTTP attempts (covers transient resets/timeouts).
    for _ in range(2):
        status, _ = _http_probe(t.url, timeout=8)
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

def _probe_response_headers(url: str, timeout: int = 6) -> dict:
    """Single GET, return the response headers as a lowercased dict.
    Uses the active stealth headers so we look like a normal browser to
    the WAF too — otherwise a curl-shaped probe might itself flag us."""
    import urllib.request, urllib.error, ssl
    headers = {"User-Agent": STEALTH.pick_ua()}
    for h in STEALTH.default_headers():
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

def detect_strategy(t: WebTarget) -> tuple[str, str]:
    """Inspect a finished-Phase-1 target and pick its strategy.
    Returns (strategy_name, human_readable_reason).

    Precedence:
      1. WAF/CDN signal (wafw00f result, tech tokens, response headers)
      2. Private/internal IP → aggressive
      3. Default → balanced
    """
    # ── 1. WAF/CDN — strongest signal, wins over everything ───────────
    if t.waf:
        return "stealth", f"WAF detected by wafw00f ({t.waf})"
    tech_blob = " ".join((x or "").lower() for x in (t.tech or []))
    for tok in WAF_CDN_TECH_TOKENS:
        if tok in tech_blob:
            return "stealth", f"CDN/WAF tech fingerprint ({tok})"
    # Cheap header sniff — single GET, ignored on failure.
    hdrs = _probe_response_headers(t.url)
    for h, vendor in WAF_CDN_HEADERS.items():
        if h in hdrs:
            return "stealth", f"edge header `{h}` → {vendor}"
    server = (hdrs.get("server") or "").lower()
    for tok, vendor in WAF_CDN_SERVER_TOKENS.items():
        if tok in server:
            return "stealth", f"Server: {vendor}"
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
        rate_limit=60,            # moderate
        delay_ms=150,
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

def _ensure_auto_strategy(t: WebTarget) -> tuple[str, str]:
    """Resolve and cache auto strategy/reason once per target."""
    if t.auto_strategy and t.auto_reason:
        return t.auto_strategy, t.auto_reason
    strategy, reason = detect_strategy(t)
    t.auto_strategy = strategy
    t.auto_reason = reason
    return strategy, reason

def run_service_chain(t: WebTarget, timeout: int = 15) -> list[Finding]:
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
        status, body = _http_probe(url, timeout=timeout)
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

# ────────────────────────────────────────────────────────────────────────────
#  PHASE 3 — VERIFY (sqlmap, only on endpoints upstream flagged)
# ────────────────────────────────────────────────────────────────────────────
def run_sqlmap(url: str, plan: ToolPlan, timeout: int, post_data: str = "", cookie: str = ""):
    host_dir = f"/tmp/vulnmalper_sqlmap_{abs(hash(url))}"
    os.makedirs(host_dir, exist_ok=True)
    ua = STEALTH.pick_ua()
    stealth_sqlmap = STEALTH.polite or STEALTH.slow or STEALTH.quiet
    level = SQLMAP_LEVEL if SQLMAP_LEVEL is not None else (1 if stealth_sqlmap else 3)
    risk  = SQLMAP_RISK  if SQLMAP_RISK  is not None else (1 if stealth_sqlmap else 2)
    extra = ["--user-agent", ua, "--level", str(level), "--risk", str(risk)]

    # sqlmap accepts a single --headers="K1: V1\nK2: V2" string
    hdrs = STEALTH.default_headers()
    cookie_val = cookie or auth_cookie_value()

    # Add cookie header if provided
    if cookie_val:
        extra += ["--cookie", cookie_val]
        hdrs.append(f"Cookie: {cookie_val}")

    if hdrs:
        extra += ["--headers", "\n".join(hdrs)]

    # WAF evasion: enhanced tamper scripts for UNION, error-based, and blind SQLi
    tamper_scripts = [
        "between",           # SQL syntax alterations (greater/less than)
        "charencode",        # Character encoding
        "charunicodeencode", # Unicode encoding
        "space2comment",    # Comment replacement
        "lowercase",        # Keyword case variation
        "space2hash",       # Random space to HASH comment
        "space2dash",       # Random space to DASH comment
        "ifstring2iftag",  # IF string to IF tag
        "modsecurityversioned", # Versioned comment
        "xforwardedfor",   # X-Forwarded-For spoofing
    ]
    extra += ["--tamper", ",".join(tamper_scripts)]

    # PROJECT-WIDE EVASION: Use our pinned UA and other evasion headers
    # We explicitly EXCLUDE --random-agent because it would override our 
    # chosen UA with sqlmap's own internal (often outdated) pool.
    extra += ["--forms"]

    # Add POST data if provided for form-based SQLi, and merge auth creds
    # into the same body when they are supplied.
    form_data = post_data or ""
    if AUTH.user and AUTH.password:
        form_data = merge_form_data(form_data, auth_form_data())
    if form_data:
        extra += ["--data", form_data]

    # Blind SQLi specific: add time-delay for boolean-based detection
    if STEALTH.polite or STEALTH.slow:
        d = max(1, int(STEALTH.polite_delay(500) / 1000))
        extra += ["--delay", str(d), "--safe-freq", "5"]
    else:
        # Small delay even in aggressive mode to avoid instant WAF blocks
        extra += ["--delay", "0.5", "--safe-freq", "3"]

    # Enhanced techniques: include all SQLi types
    # B=Boolean-based blind, E=Error-based, U=Union, S=Stacked, T=Time-based, Q=Inline query
    extra += ["--technique", "BEUSTQ"]
    
    # For demo/vulnerable targets, be more aggressive
    # Skip smart mode, go straight to full scan
    extra += ["--smart"]  # Keep smart but combine with other options
    
    # No prompt for user interaction
    extra += ["--batch", "--non-interactive"]

    if plan.runner == "docker":
        container_dir = "/wrk"
        args = ["-u", url, "--disable-coloring",
                "--output-dir", container_dir,
                "--timeout","30","--retries","3"] + extra
        cmd = build_cmd(plan, args, mount=(host_dir, container_dir))
    else:
        args = ["-u", url, "--disable-coloring",
                "--output-dir", host_dir,
                "--timeout","30","--retries","3"] + extra
        cmd = build_cmd(plan, args)

    # Log the command for debugging
    log("run", f"sqlmap: {' '.join(cmd[:8])}...")

    rc, out, err = _run(cmd, timeout)
    findings: list[Finding] = []
    text = out + "\n" + err

    # Enhanced error detection and logging
    error_patterns = {
        "waf": r"(blocked|detected|waf|firewall|protection)",
        "timeout": r"(timeout|timed out)",
        "connection": r"(connection refused|reset|failed)",
        "rate_limit": r"(rate limit|too many requests)",
    }

    for pattern_name, pattern in error_patterns.items():
        if re.search(pattern, text, re.I):
            log("warn", f"sqlmap: {pattern_name} issue detected for {url}")

    # Extract SQLi findings with enhanced parsing
    blocks = re.findall(
        r"Parameter:\s*(.+?)\n\s*Type:\s*(.+?)\n\s*Title:\s*(.+?)\n\s*Payload:\s*(.+?)(?:\n\s*\n|\Z)",
        text, re.S,
    )
    for param, typ, title, payload in blocks:
        findings.append(Finding(
            target=url, tool="sqlmap", severity="critical",
            title=f"SQL Injection ({typ.strip()}) on `{param.strip()}`",
            detail=f"Title: {title.strip()}\nPayload: {payload.strip()}",
            reference="https://owasp.org/www-community/attacks/SQL_Injection",
        ))

    # Also capture findings from other sqlmap output formats
    # Extract "it looks like the back-end DBMS" type findings
    dbms_match = re.search(r"it looks like the back-end DBMS is '(.+?)'", text, re.I)
    if dbms_match:
        log("info", f"sqlmap: detected DBMS as {dbms_match.group(1)} for {url}")

    # Extract any "vulnerability(ies) found" message
    vuln_match = re.search(r"(\d+) vulnerability(?:ies)? found", text, re.I)
    if vuln_match and int(vuln_match.group(1)) > 0:
        log("ok", f"sqlmap: found {vuln_match.group(1)} vulnerability(ies) on {url}")

    if not findings:
        if "is not injectable" in text.lower():
            log("skip", f"sqlmap: no injectable params on {url}")
        elif "all parameters appear to be not injectable" in text.lower():
            log("skip", f"sqlmap: no injection point found in {url}")
        else:
            log("info", f"sqlmap: completed but no vulnerabilities found on {url}")

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
    ap.add_argument("--nuclei-timeout",   type=int, default=600)
    ap.add_argument("--wapiti-timeout",   type=int, default=1200)
    ap.add_argument("--sqlmap-timeout",   type=int, default=900)
    ap.add_argument("--ffuf-timeout",     type=int, default=600)
    ap.add_argument("--feroxbuster-timeout", type=int, default=900)
    ap.add_argument("--sqlmap-level", type=int, default=None,
                    help="Override sqlmap --level (default: 3 normal, 1 stealth)")
    ap.add_argument("--sqlmap-risk", type=int, default=None,
                    help="Override sqlmap --risk (default: 2 normal, 1 stealth)")
    ap.add_argument("--auth-user", default=None, help="Username for authenticated scanning.")
    ap.add_argument("--auth-pass", default=None, help="Password for authenticated scanning.")
    ap.add_argument("--auth-cookie", default=None, help='Session cookie in "NAME=VALUE" form.')

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
             "nuclei, wapiti, sqlmap, ffuf, feroxbuster.")

    # ── JSON export flag ───────────────────────────────────────────────
    ap.add_argument("--export-json", nargs="?", const="__AUTO__", default=None,
        metavar="PATH",
        help="Also write a single pretty JSON file with per-host summaries "
             "and the full deduped findings list. Bare `--export-json` writes "
             "next to the .md report (same basename, .json extension). "
             "Pass a path to override, e.g. `--export-json /tmp/scan.json`.")

    args = ap.parse_args()

    # Activate the stealth profile BEFORE any tool runs.
    global STEALTH, AUTH, SQLMAP_LEVEL, SQLMAP_RISK
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
        # Per-target STEALTH swaps mutate the module global; serialise scan
        # workers so two threads can't trample each other's profile.
        if args.threads > 1:
            log("warn", f"[auto] forcing --threads 1 (was {args.threads}) so "
                        "per-target stealth swaps stay coherent")
            args.threads = 1

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
    if targets:
        warm_crawler_image()
    if service_targets and not have("nmap") and have("docker"):
        warm_phase0_nmap_image()
    runner_map = {k: (v.runner if v else "off") for k, v in plans.items()}

    timeouts = {
        "httpx": args.httpx_timeout, "whatweb": args.whatweb_timeout,
        "wafw00f": args.wafw00f_timeout, "testssl": args.testssl_timeout,
        "nikto": args.nikto_timeout, "nuclei": args.nuclei_timeout,
        "wapiti": args.wapiti_timeout, "sqlmap": args.sqlmap_timeout,
        "ffuf": args.ffuf_timeout, "feroxbuster": args.feroxbuster_timeout,
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
    if service_targets:
        _phase("Phase 0 — Service Vulnerability Scanning")
        log("info", f"🔧 Service scan — {len(service_targets)} non-web services found")
        service_findings = run_phase0_service_scan(service_targets, plans, timeout=300)
        all_findings.extend(service_findings)

    t0 = time.time()

    # ── PHASE 1: fingerprint ───────────────────────────────────────────────
    _phase("Phase 1 — Fingerprinting (httpx, whatweb, wafw00f)")

    if plans["httpx"]:
        log("run", f"httpx ({plans['httpx'].runner}) on {len(targets)} target(s)")
        fs = run_httpx(targets, plans["httpx"], timeouts["httpx"])
        log("ok", f"  httpx → {len(fs)} findings")
        all_findings.extend(fs)
    else:
        log("skip", "httpx unavailable — marking all targets as alive (no tech data)")
        for t in targets: t.alive = True

    def _fp_worker(t: WebTarget):
        out: list[Finding] = []
        if plans["whatweb"]:
            out.extend(run_whatweb(t, plans["whatweb"], timeouts["whatweb"]))
        if plans["wafw00f"]:
            out.extend(run_wafw00f(t, plans["wafw00f"], timeouts["wafw00f"]))
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
            if confirm_target_liveness(t):
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
        _phase("Phase 1.5 — Crawl discovery (gospider)")
        discovered_targets: list[WebTarget] = []
        existing_urls = {_normalize_discovered_url(t.url) for t in targets}

        def _register_discovered_urls(source: WebTarget, urls: list[str]) -> list[WebTarget]:
            new_targets: list[WebTarget] = []
            for u in urls:
                normalized_url = _normalize_discovered_url(u)
                if not normalized_url or normalized_url in existing_urls:
                    continue
                existing_urls.add(normalized_url)
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
                strategy, reason = _ensure_auto_strategy(t)
                if strategy == "stealth":
                    log("skip", f"crawl → {t.url} skipped in auto stealth mode ({reason})")
                    return []
            urls = run_crawler(t, min(timeouts["feroxbuster"], 600))
            if not urls:
                return []
            log("run", f"gospider crawl → {t.url} ({len(urls)} raw url(s))")
            return _register_discovered_urls(t, urls)

        with concurrent.futures.ThreadPoolExecutor(max_workers=args.threads) as ex:
            for new_targets in ex.map(_crawl_worker, crawl_candidates):
                discovered_targets.extend(new_targets)

        if discovered_targets:
            log("ok", f"Discovered {len(discovered_targets)} crawl endpoint(s); fingerprinting new targets")
            targets.extend(discovered_targets)
            if plans["httpx"]:
                log("run", f"httpx fingerprinting {len(discovered_targets)} crawled target(s)")
                fs = run_httpx(discovered_targets, plans["httpx"], timeouts["httpx"])
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
                strategy, reason = _ensure_auto_strategy(t)
                if strategy == "stealth":
                    log("skip", f"discovery → {t.url} skipped in auto stealth mode ({reason})")
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
                    # Normalize URL to remove trailing slashes
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
                    # Normalize URL to remove trailing slashes
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
            seen_urls = {_normalize_discovered_url(t.url) for t in targets}
            unique_new: dict[str, WebTarget] = {}
            for nt in discovered_targets:
                normalized_url = _normalize_discovered_url(nt.url)
                if not normalized_url or normalized_url in seen_urls:
                    continue
                seen_urls.add(normalized_url)
                unique_new[normalized_url] = nt

            new_list = list(unique_new.values())
            if new_list:
                log("ok", f"Discovered {len(new_list)} new targets! Adding to full stack scan pool.")
                targets.extend(new_list)
                # For newly discovered targets, we might want to run Phase 1 (httpx/whatweb) on them too?
                # The user said "the full stack shud also scan whatewver ffuf or feroxbuster found".
                # Nikto/Nuclei/Wapiti are in Phase 2. So they will be scanned.
                # But they might need tech info. Let's run a quick fingerprint on them.
                if plans["httpx"]:
                    log("run", f"httpx fingerprinting {len(new_list)} new target(s)")
                    fs = run_httpx(new_list, plans["httpx"], timeouts["httpx"])
                    all_findings.extend(fs)
                
                # whatweb/wafw00f for new targets
                with concurrent.futures.ThreadPoolExecutor(max_workers=args.threads) as ex:
                    for fs in ex.map(_fp_worker, new_list):
                        all_findings.extend(fs)

    # ── PHASE 2: scan ──────────────────────────────────────────────────────
    _phase("Phase 2 — Scanning (testssl, nikto, nuclei, wapiti)")

    # Snapshot the user-configured stealth profile so per-target auto-mode
    # swaps can always restore it cleanly between targets.
    base_stealth = STEALTH

    def _scan_worker(t: WebTarget):
        global STEALTH
        out: list[Finding] = []
        if not t.alive:
            log("skip", f"{t.url} — dead/unreachable, skipping scan")
            return out
        # ── Auto-mode: pick a strategy for THIS target and swap STEALTH
        # for the duration of its tool runs. Restored in `finally` so a
        # tool exception can't leak the wrong profile into the next target.
        swapped = False
        if auto_mode:
            strategy, reason = _ensure_auto_strategy(t)
            new_prof = build_auto_profile(strategy, base_stealth)
            log("info", _format_auto_banner(t, strategy, reason, new_prof))
            STEALTH = new_prof
            swapped = True
        try:
            # testssl only for HTTPS (TLS) ports - check both port AND scheme
            if plans["testssl"] and t.scheme == "https" and t.port in TLS_PORTS:
                log("run", f"testssl ({plans['testssl'].runner}) → {t.url}")
                tt = time.time()
                fs = run_testssl(t, plans["testssl"], timeouts["testssl"])
                log("ok" if fs else "skip",
                    f"  testssl {round(time.time()-tt,1)}s — {len(fs)} findings")
                out.extend(fs)
                STEALTH.sleep_jitter()  # avoid burst pattern between tools
            # nikto only on HTTP/HTTPS ports with proper scheme check
            if plans["nikto"] and t.scheme in ("http", "https") and t.port in NIKTO_PORTS:
                log("run", f"nikto ({plans['nikto'].runner}) → {t.url}")
                tt = time.time()
                fs = run_nikto(t, plans["nikto"], timeouts["nikto"])
                log("ok" if fs else "skip",
                    f"  nikto {round(time.time()-tt,1)}s — {len(fs)} findings")
                out.extend(fs)
                STEALTH.sleep_jitter()
            # nuclei on all HTTP targets
            if plans["nuclei"]:
                log("run", f"nuclei ({plans['nuclei'].runner}) → {t.url}")
                tt = time.time()
                fs = run_nuclei(t, plans["nuclei"], args.severity, timeouts["nuclei"])
                log("ok" if fs else "skip",
                    f"  nuclei {round(time.time()-tt,1)}s — {len(fs)} findings")
                out.extend(fs)
                STEALTH.sleep_jitter()
            # wapiti — active app scanner, all HTTP targets
            if plans["wapiti"]:
                log("run", f"wapiti ({plans['wapiti'].runner}) → {t.url}")
                tt = time.time()
                fs = run_wapiti(t, plans["wapiti"], timeouts["wapiti"])
                log("ok" if fs else "skip",
                    f"  wapiti {round(time.time()-tt,1)}s — {len(fs)} findings")
                out.extend(fs)
            return out
        finally:
            if swapped:
                STEALTH = base_stealth

    if args.threads <= 1:
        for t in targets: all_findings.extend(_scan_worker(t))
    else:
        with concurrent.futures.ThreadPoolExecutor(max_workers=args.threads) as ex:
            for fs in ex.map(_scan_worker, targets):
                all_findings.extend(fs)

    # ── PHASE 2.5: active service chaining ────────────────────────────────
    # No external tool — we hit known endpoints ourselves and reason about
    # what the responses mean. Cheap, offline, and catches the "obvious"
    # exposures every pentester checks first.
    chainable = [t for t in targets if t.alive and t.port in SERVICE_CHAIN_PLAYBOOKS]
    if auto_mode:
        filtered: list[WebTarget] = []
        for t in chainable:
            strategy, reason = _ensure_auto_strategy(t)
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
            log("run", f"chain → {t.url}  (port {t.port})")
            all_findings.extend(run_service_chain(t))

    # ── PHASE 3: sqlmap verification on curated endpoints ──────────────────
    _phase("Phase 3 — Verifying SQLi candidates (sqlmap)")

    # Also scan all endpoints with query params even if Nuclei didn't flag them.
    # This is a fallback to catch SQLi that Nuclei templates might miss,
    # especially on standard patterns like login forms.
    for t in targets:
        if "?" in t.url and t.url not in t.injectable:
            t.injectable.append(t.url)

    # Try common parameters on likely vulnerable pages (JSP/PHP/ASP)
    COMMON_PARAMS = ["id", "query", "search", "user", "pass", "login", "name", "email", "q"]
    for t in targets:
        if any(t.url.endswith(ext) for ext in [".jsp", ".php", ".asp", ".aspx", ".do"]):
            for param in COMMON_PARAMS:
                url_with_param = t.url.rstrip("/") + "?" + param + "="
                if url_with_param not in t.injectable:
                    t.injectable.append(url_with_param)
    
    # Also try login forms with POST data - these are common SQLi targets
    # Try common login endpoints with POST data
    LOGIN_PARAMS = [
        ("/admin/doLogin", "username=admin&password="),
        ("/doLogin", "username=admin&password="),
        ("/login", "username=admin&password="),
        ("/auth", "username=admin&password="),
    ]
    for t in targets:
        for path, post_template in LOGIN_PARAMS:
            if path in t.url or t.url.endswith("/admin") or "login" in t.url:
                full_url = t.url.rstrip("/") + path if path.startswith("/") else t.url + path
                post_url = full_url + "?" + post_template.split("&")[0] + "="
                if post_url not in t.injectable:
                    t.injectable.append(post_url)

    sqli_queue: list[str] = []
    for t in targets:
        if auto_mode:
            strategy, reason = _ensure_auto_strategy(t)
            if strategy == "stealth":
                if t.injectable:
                    log("skip", f"sqlmap candidates on {t.url} skipped in auto stealth mode ({reason})")
                continue
        for u in t.injectable:
            # Normalize URL to remove trailing slashes for deduplication
            normalized_u = _normalize_url(u)
            if normalized_u not in sqli_queue:
                sqli_queue.append(normalized_u)

    if not plans["sqlmap"]:
        log("skip", "sqlmap unavailable — skipping phase 3")
    elif not sqli_queue:
        log("skip", "No injectable endpoints surfaced by upstream tools")
    else:
        log("info", f"{len(sqli_queue)} endpoint(s) flagged for sqlmap verification:")
        for u in sqli_queue: print(f"  {C.GY}•{C.R} {u}")
        def _sqli_worker(u):
            log("run", f"sqlmap ({plans['sqlmap'].runner}) → {u}")
            tt = time.time()
            # For POST forms, extract post_data from URL
            post_data = ""
            if "&" in u and "?" in u:
                # URL like http://host/admin/doLogin?username=admin&password=
                # Extract the query part as POST data
                query_part = u.split("?")[-1]
                post_data = query_part.replace("=", "=test&") + "test"
                u = u.split("?")[0]
            fs = run_sqlmap(u, plans["sqlmap"], timeouts["sqlmap"], post_data=post_data)
            log("ok" if fs else "skip",
                f"  sqlmap {round(time.time()-tt,1)}s — {len(fs)} findings")
            return fs
        if args.threads <= 1:
            for u in sqli_queue: all_findings.extend(_sqli_worker(u))
        else:
            with concurrent.futures.ThreadPoolExecutor(max_workers=min(args.threads,3)) as ex:
                for fs in ex.map(_sqli_worker, sqli_queue):
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
