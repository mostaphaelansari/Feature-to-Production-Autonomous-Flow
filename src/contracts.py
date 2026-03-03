"""Validate JSON payloads against contract schemas.

Used at pipeline boundaries to ensure data integrity between stages.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import jsonschema

CONTRACTS_DIR = Path(__file__).resolve().parents[1] / "contracts"

SCHEMAS = {
    "semantic": CONTRACTS_DIR / "semantic-analysis.schema.json",
    "risk": CONTRACTS_DIR / "risk-assessment.schema.json",
    "action": CONTRACTS_DIR / "action-plan.schema.json",
}


def _load_schema(name: str) -> dict[str, Any]:
    path = SCHEMAS[name]
    return json.loads(path.read_text(encoding="utf-8"))


def validate_payload(payload: dict[str, Any], schema_name: str) -> None:
    """Validate *payload* against the named contract schema.

    Args:
        payload: The JSON-decoded dict to validate.
        schema_name: One of ``"semantic"``, ``"risk"``, or ``"action"``.

    Raises:
        jsonschema.ValidationError: If the payload violates the schema.
        KeyError: If *schema_name* is not recognised.
    """
    schema = _load_schema(schema_name)
    jsonschema.validate(instance=payload, schema=schema)
