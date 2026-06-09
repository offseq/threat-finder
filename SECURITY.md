# Security Policy

## Reporting a vulnerability

Please report security issues privately rather than opening a public issue.

- Preferred: GitHub **Security Advisories** ("Report a vulnerability" on the
  Security tab of this repository).
- Or email **security@offseq.com**.

Please include reproduction steps and the affected version (`threat-finder
--version`). We aim to acknowledge reports within a few business days.

## Scope notes

This tool runs locally, often as root, to discover services and query the OffSeq
API. Relevant hardening already in place:

- Version probing only ever executes an **absolute path to a real file** with a
  sanitized environment (`env_clear`, minimal `PATH`, no stdin) — closing
  PATH-hijack code execution.
- The package database is preferred over executing a service to read its version.
- The API key is stored `0600` in a `0700` directory and is never placed in a
  child process's environment or argv.

Findings about these areas — or any way to get code execution, leak the API key,
or produce false-negative "no vulnerabilities" results — are in scope.
