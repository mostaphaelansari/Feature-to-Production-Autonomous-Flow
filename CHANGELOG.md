# Changelog

## 0.2.0

Rewrite of the prototype into an installable tool. Breaking: the
`semantic_from_diff.py` / `risk_engine` / `enforce_policy.py` stages and their
JSON contracts are replaced by a single `diffguard` command and report format.

### Added
- `diffguard` CLI (`scan`, `gate`, `rules`) and the `diffguard-scan` package.
- 26 rules covering secrets, injection, code execution, TLS and crypto misuse,
  access-control bypasses, insecure configuration, and **removed** safety
  controls (auth checks, CSRF, password hashing, validation, hardening).
- AST-based checks for Python (multi-line calls, no matches inside strings).
- Sensitive-area detection driven by paths and whole-word identifiers.
- Configuration in `pyproject.toml` / `.diffguard.toml`: thresholds, excludes,
  per-path ignores, severity overrides, custom areas, suggested reviewers.
- Inline suppressions: `# diffguard: ignore[DG203]`.
- Output formats: text, JSON (with schema), Markdown, SARIF, GitHub annotations.
- Secret values are masked in every report format.
- GitHub Action, pre-commit hook, GitLab CI job, PyPI release workflow.

### Fixed
- Prose and identifiers no longer trigger risk (`author` → auth, `rapid` → api).
- Vulnerabilities that the keyword prototype auto-approved (hardcoded keys, SQL
  injection, `eval`, TLS verification off, removed password hashing) are now flagged.

## 0.1.0

Hackathon prototype: keyword-based semantic analysis, weighted risk score and a
three-stage GitLab pipeline.
