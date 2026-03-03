# Risk Engine

Rule-based scoring engine that consumes semantic diff output and emits a
`risk-assessment` payload.

## Inputs
- Semantic payload following `contracts/semantic-analysis.schema.json`

## Output
- Risk payload following `contracts/risk-assessment.schema.json`

## Run
```powershell
python -m src.risk_engine.cli --input path\\to\\semantic.json
```

