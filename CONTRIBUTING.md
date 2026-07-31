# Contributing to VulnMalper

Thanks for your interest in contributing! This guide covers how to set up a
development environment, run the checks, and open a pull request.

## Project design constraints

VulnMalper is intentionally a **single-file CLI** (`vulnmalper.py`, ~4k lines)
with zero runtime dependencies beyond the Python standard library.

When contributing, please respect these constraints:

- **Do not** split `vulnmalper.py` into modules.
- **Do not** move it out of the repository root.
- **Do not** change existing CLI arguments, output, or logging behavior.
- **Do not** add runtime dependencies.

This keeps the project easy to audit and compatible with `uv tool install`
and direct execution (`python3 vulnmalper.py`).

## Development environment

We use [uv](https://docs.astral.sh/uv/) for dependency management. If you do
not have it yet:

```bash
curl -LsSf https://astral.sh/uv/install.sh | sh
```

Clone and set up:

```bash
git clone https://github.com/MKMithun2806/VulnMalper
cd VulnMalper
uv sync
```

`uv sync` creates a virtual environment, installs the package in editable
mode, and installs the `dev` dependency group (pytest, ruff).

## Running the checks

Before pushing, run the full local suite:

```bash
uv sync --locked
uv run pytest                      # tests
uv run ruff check .                # lint
uv run ruff format --check .       # formatting
uv run python vulnmalper.py --help # smoke test
```

The CI pipeline (`/.github/workflows/ci.yml`) runs exactly these steps on
Python 3.9 and 3.13. A pull request must pass all of them.

Note: `vulnmalper.py` is excluded from ruff lint/format checks on purpose —
it is legacy code that must remain untouched. New Python files (e.g. under
`tests/`) are fully checked.

## Manual testing

VulnMalper orchestrates external tools (`httpx`, `nuclei`, `sqlmap`, ...).
You can test with any subset using `--only` and `--runner`:

```bash
uv run python vulnmalper.py examples/targets.json --only httpx --runner local
```

See `examples/targets.json` for a sample NetMalper graph and the README for
the full flag reference.

## Writing tests

Tests live in `tests/`. They must be **offline-safe**: they run in CI on a
clean runner, so they cannot depend on network access or external scanners.

Useful things to test:

- `parse_netmalper()` with a hand-built graph (endpoint and port nodes).
- URL normalization helpers (`_normalize_url`, `_is_worth_scanning`).
- The `vulnmalper` console script / `vulnmalper.py --help`.

## Opening a pull request

- Keep changes focused; one logical change per PR.
- Run the checks above and paste their output if relevant.
- Use the pull request template and fill in the checklist.
- Update `README.md` and `CHANGELOG.md` when behavior or usage changes.
- Never commit secrets, credentials, or real target data.

## Release process (maintainers)

Releases are driven by version tags:

1. Bump the version in `vulnmalper.py` (`VERSION = "x.y.z"`). The package
   version is read from this file automatically.
2. Update `CHANGELOG.md`.
3. Push a `v<version>` tag (e.g. `v7.3.6`). The `release` workflow builds
   distributions, uploads artifacts, and creates a GitHub Release.
4. Creating the Release triggers the `publish` workflow, which publishes the
   package to PyPI using trusted publishing (no API tokens).

## Code of conduct

By participating you agree to abide by the project's
[Code of Conduct](CODE_OF_CONDUCT.md).
