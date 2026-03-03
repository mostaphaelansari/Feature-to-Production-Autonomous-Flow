# Diff-First Autonomous Review & Risk Agent

Scaffold in progress.

## Current Scope
- [x] 1. Project structure
- [x] 2. JSON contracts
- [x] 3. Rule engine
- [x] 4. GitLab CI pipeline
- [x] 5. Demo fixtures and tests

## Structure
- `src/semantic_diff`: semantic diff analyzer agent
- `src/risk_engine`: risk scoring and thresholding
- `src/actions`: action modules (approve/block/tag)
- `src/security_regression`: targeted security checks
- `src/architecture_drift`: boundary/circular dependency checks
- `src/deployment_predictor`: deploy sensitivity tagging
- `src/contracts.py`: JSON Schema validation at pipeline boundaries
- `contracts`: JSON schemas and typed contracts
- `fixtures/diffs`: sample unified diffs for demos/tests
- `tests`: unit/integration tests
- `scripts`: local runner and utility scripts
- `docs`: architecture, scoring, and demo scripts

## Getting started
```bash
pip install -e ".[dev]"
pytest tests/ -v
```
