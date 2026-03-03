# GitLab Pipeline

This project uses a merge-request-only pipeline in `.gitlab-ci.yml`.

## Stages
1. `analyze`: generate `mr.diff` and `semantic-analysis.json`
2. `score`: run risk engine to produce `risk-assessment.json`
3. `enforce`: convert risk actions to `action-plan.json` and fail on high risk

## Blocking behavior
- `risk_level=high` causes `policy_enforcer` to exit with non-zero status.
- In GitLab, this blocks merge when "Pipelines must succeed" is enabled.

## Artifacts
- `mr.diff`
- `semantic-analysis.json`
- `risk-assessment.json`
- `action-plan.json`

