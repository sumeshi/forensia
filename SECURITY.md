# Security Policy

forensia is intended for sensitive incident-response evidence. Treat case inputs,
case directories, generated reports, `ai_logs/`, and memory files as confidential.

## Supported versions

This project is pre-1.0. Security fixes target the current `main` branch until a
release policy is published.

## Reporting a vulnerability

Please open a GitHub issue with a minimal, sanitized reproduction. Do **not**
attach real forensic artifacts, logs, tokens, customer names, hostnames, or other
sensitive evidence. If a report requires private coordination, first open an
issue requesting a private disclosure channel without including exploit details.

## Handling sensitive data

- Do not commit `.env`, case directories, generated `reports/`, `ai_logs/`,
  DuckDB databases, raw EVTX/MFT/Prefetch artifacts, mail stores, disk images, or
  other customer/user data.
- The tracked `.env.example` is safe to copy and edit locally.
- forensia does not require a cloud LLM. If `LLM_BASE_URL` points to a remote
  service, prompts may include case-derived summaries and evidence snippets; use
  a local/offline endpoint for sensitive investigations.
- Benchmark references to CFReDS/NIST data are public training data and are not
  a substitute for reviewing your own case outputs before publication.
