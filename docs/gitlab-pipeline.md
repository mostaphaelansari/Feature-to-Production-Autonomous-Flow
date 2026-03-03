# GitLab Pipeline

This project uses a merge-request-only pipeline in `.gitlab-ci.yml`.

## Stages

1. **analyze** — generate `mr.diff` and `semantic-analysis.json`
2. **score** — run risk engine to produce `risk-assessment.json`
3. **enforce** — convert risk actions to `action-plan.json` and fail on high risk

## Blocking behavior

- `risk_level=high` causes `policy_enforcer` to exit with non-zero status.
- In GitLab, this blocks merge when "Pipelines must succeed" is enabled.

## Artifacts

| Stage | Output |
|---|---|
| analyze | `mr.diff`, `semantic-analysis.json` |
| score | `risk-assessment.json` |
| enforce | `action-plan.json` |

## Security: `POLICY_REF` hardening

> **REQUIRED FOR PRODUCTION.** Without `POLICY_REF`, all scripts run from
> the MR branch, meaning an MR author can modify gate logic to approve
> their own changes.

### How it works

Set `POLICY_REF` to a **protected branch or tag** (e.g., `main` or `v1.0.0`)
in your GitLab CI/CD variables. When set:

- **analyze** checks out `scripts/semantic_from_diff.py` from the protected ref
- **score** checks out `src/risk_engine/`, `src/contracts.py` from the protected ref
- **enforce** checks out `scripts/enforce_policy.py`, `src/contracts.py`, `contracts/` from the protected ref

This ensures MR authors **cannot tamper** with any part of the gating pipeline.

### Setup

1. Go to **Settings → CI/CD → Variables** in your GitLab project
2. Add variable: `POLICY_REF` = `main` (or your protected branch/tag)
3. Mark it as **Protected** so only protected branches can override it
4. Enable **"Pipelines must succeed"** in merge request settings

### Development mode

Leave `POLICY_REF` empty to run all scripts from the MR branch. This is
convenient for local development but **not secure for production**.

## Dependencies

The pipeline installs `jsonschema` in `before_script` to enable fail-closed
contract validation at every stage boundary. If `jsonschema` is missing,
the pipeline will crash rather than silently skip validation.
