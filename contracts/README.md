# Contracts

JSON Schemas used by the Diff-First pipeline.

## Files
- `semantic-analysis.schema.json`: output of semantic diff analyzer
- `risk-assessment.schema.json`: output of risk scoring engine
- `action-plan.schema.json`: actionable decision payload for CI/CD automation

## Contract flow
1. Semantic analyzer emits payload valid against `semantic-analysis.schema.json`.
2. Risk engine consumes semantic payload and emits `risk-assessment.schema.json`.
3. Action module consumes risk payload and emits `action-plan.schema.json`.

