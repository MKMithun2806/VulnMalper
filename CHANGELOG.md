# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [7.3.6] - 2026-01-15

### Changed

- Release tooling modernized: project now ships as a standard Python package
  (`pyproject.toml` + hatchling) installable via `uv tool install vulnmalper`
  or `uv tool install git+https://github.com/MKMithun2806/VulnMalper`.
- Added CI (tests, lint, format, packaging), release, and trusted-publishing
  (OIDC) GitHub Actions workflows.
- Added `tests/`, `examples/`, and `docs/` directories and a `CHANGELOG.md`.

## [7.3.5] - 2025-12-01

### Fixed

- Proxy-pool timeouts now scale correctly across all tools.

## [7.3.0] - 2025-11-12

### Added

- Auto mode: per-target strategy selection (stealth / balanced / aggressive)
  driven by Phase 1 evidence when no explicit stealth flags are supplied.

## [7.0.0] - 2025-09-30

### Changed

- Default `--threads` reduced to 3 for more predictable network behavior.

## [6.0.0] - 2025-07-15

### Added

- Phase 0 service scanning for non-web targets (nmap + nuclei).

## [5.0.0] - 2025-04-20

### Added

- Active service chaining (Prometheus, Consul, Grafana, Docker API).

## [4.0.0] - 2025-02-10

### Added

- Proxy pool rotation with `--proxy-file` (2-15 proxies, round-robin).

## [3.0.0] - 2024-11-18

### Added

- Stealth / polite-mode flags (`--polite`, `--slow`, `--no-jitter`).

## [2.0.0] - 2024-08-05

### Added

- Session handover: cookies from nuclei/wapiti login findings are passed to
  sqlmap for authenticated scanning.

## [1.0.0] - 2024-05-01

### Added

- Initial single-file release: fingerprint -> scan -> verify pipeline driven
  by NetMalper JSON graphs.

[7.3.6]: https://github.com/MKMithun2806/VulnMalper/releases/tag/v7.3.6
[7.3.5]: https://github.com/MKMithun2806/VulnMalper/releases/tag/v7.3.5
[7.3.0]: https://github.com/MKMithun2806/VulnMalper/releases/tag/v7.3.0
[7.0.0]: https://github.com/MKMithun2806/VulnMalper/releases/tag/v7.0.0
[6.0.0]: https://github.com/MKMithun2806/VulnMalper/releases/tag/v6.0.0
[5.0.0]: https://github.com/MKMithun2806/VulnMalper/releases/tag/v5.0.0
[4.0.0]: https://github.com/MKMithun2806/VulnMalper/releases/tag/v4.0.0
[3.0.0]: https://github.com/MKMithun2806/VulnMalper/releases/tag/v3.0.0
[2.0.0]: https://github.com/MKMithun2806/VulnMalper/releases/tag/v2.0.0
[1.0.0]: https://github.com/MKMithun2806/VulnMalper/releases/tag/v1.0.0
