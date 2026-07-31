# Security Policy

## Supported versions

Only the latest release receives security updates. Backporting to older
versions is done on a case-by-case basis.

| Version | Supported          |
| :------ | :----------------- |
| latest  | :white_check_mark: |
| < latest | :x:               |

## Reporting a vulnerability

Please **do not open a public issue** for security vulnerabilities. Instead,
report privately via GitHub's Security Advisories:

- <https://github.com/MKMithun2806/VulnMalper/security/advisories/new>

If you cannot use the advisory workflow, email the maintainers privately
(reach out through a GitHub account listed as a repository maintainer).

Please include, where possible:

- The affected version.
- A description of the vulnerability and its impact.
- Steps to reproduce (redacted of any sensitive data).
- Any proposed fix.

You should receive an acknowledgement within 3 business days. We will keep
you informed of the fix and disclosure timeline.

## Disclosure policy

- Vulnerabilities are disclosed after a fix is released and tested.
- We ask reporters to keep details confidential until public disclosure.
- Contributors who report valid security issues will be acknowledged (with
  their consent) in the release notes.

## Security considerations for users

VulnMalper is an active security scanner. Running it against systems you do
not own or lack written authorization to test may be illegal in your
jurisdiction. You are solely responsible for ensuring you have permission to
scan every target in your NetMalper graph.

- External tools are fetched from their official Docker images when not
  installed locally. Verify image provenance before use in sensitive
  environments.
- Proxy lists, credentials (`--auth-user`, `--auth-pass`, `--auth-cookie`)
  and reports may contain sensitive data. Store and share them carefully.
