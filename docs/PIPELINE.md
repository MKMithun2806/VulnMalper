# Pipeline

VulnMalper consumes a [NetMalper](https://github.com/MKMithun2806/NetMalper)
JSON graph and orchestrates a multi-stage audit. Each phase feeds its output
into the next, so later stages only ever act on evidence produced earlier.

## Phase 0 — Service scanning (non-web services)

Ports that do not look like web services are profiled with `nmap` and then
checked against `nuclei` service templates. This catches exposed databases,
messaging brokers, and administrative interfaces that a pure-HTTP pipeline
would miss.

## Phase 1 — Fingerprinting (every HTTP target)

- **httpx** — probes every target for liveness, status code, tech stack,
  server header, and title.
- **whatweb** — identifies the technology stack.
- **wafw00f** — detects WAF presence; downstream tools (e.g. sqlmap tamper
  scripts) adjust behavior when a WAF is found.
- **Liveness recheck** — targets that appear dead are probed once more
  before being dropped.

## Phase 1.5 — Discovery

- **katana** crawl discovery on tech/status-matched targets produces new
  endpoints that are fingerprinted and fed back into the scan pool.
- **ffuf / feroxbuster** content discovery maps hidden paths; newly
  discovered targets are fingerprinted and added to the full scan pool.
- Aggressive fuzzers are disabled when any stealth/polite flag is set.

## Phase 2 — Scanning

- **testssl.sh** — TLS configuration bugs (ports 443/8443 only).
- **nikto** — web server misconfigurations (ports 80/443/8080/8443).
- **nuclei** — CVE and misconfiguration templates, batched per host.
- **wapiti** — active fuzzing for XSS, SSRF, RCE, XXE, LFI.

Injectable-looking URLs discovered by `nuclei`, `nikto`, or form discovery are
recorded for Phase 3. Successful `nuclei` / `wapiti` login findings hand their
session cookie to Phase 3.

## Phase 2.5 — Active service chaining

Known internal services (Prometheus, Consul, Grafana, Docker API, ...) are
probed directly for the classic, easy-to-confirm exposures pentesters check
first. This stage is built into the pipeline and needs no external tool.

## Phase 3 — Verification (sqlmap)

`sqlmap` is run **only** on curated endpoints: targets that already carry
query parameters, forms, or reflective parameters surfaced by upstream
stages. No blind spraying. GET targets are batched per host; POST targets run
individually. Authenticated sessions and captured cookies are honored.

## Output

A single Markdown report is written with the deduped findings, per-target
summaries, and runtime metadata. The console shows a high-signal summary and
a `--export-json` flag writes a machine-readable JSON export.
