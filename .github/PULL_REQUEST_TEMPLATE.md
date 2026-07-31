## Description

<!-- Provide a summary of the change and the problem it solves. Reference any related issues. -->

Closes #<issue>

## Type of change

- [ ] Bug fix
- [ ] New feature
- [ ] Documentation update
- [ ] CI / packaging / tooling
- [ ] Other (describe)

## Design constraints

VulnMalper is a single-file CLI. Please confirm the change respects this:

- [ ] `vulnmalper.py` was not split into modules
- [ ] Existing CLI arguments and outputs were not changed
- [ ] Existing logging behavior was not changed

## Testing

<!-- Describe how you tested the change. Run at least the minimal suite: -->

```bash
uv sync
uv run pytest
uv run ruff check .
uv run ruff format --check .
uv run python vulnmalper.py --help
```

## Checklist

- [ ] I have run the test, lint, and format checks above
- [ ] I have updated the documentation (README, CHANGELOG) if needed
- [ ] I have not committed secrets or credentials
