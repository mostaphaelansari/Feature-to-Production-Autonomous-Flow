"""CLI for the risk engine - computes risk assessment from semantic analysis."""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from .engine import evaluate_risk
from src.contracts import validate_payload


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Compute risk assessment from semantic analysis JSON."
    )
    parser.add_argument(
        "--input",
        required=True,
        type=Path,
        help="Path to semantic analysis JSON file.",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=None,
        help="Optional output path for risk assessment JSON. Defaults to stdout.",
    )
    parser.add_argument(
        "--skip-validation",
        action="store_true",
        default=False,
        help="Skip JSON schema validation (NOT recommended in CI).",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    semantic_payload = json.loads(args.input.read_text(encoding="utf-8"))

    if not args.skip_validation:
        validate_payload(semantic_payload, "semantic")

    assessment = evaluate_risk(semantic_payload)

    if args.output:
        args.output.write_text(
            json.dumps(assessment, indent=2, ensure_ascii=True) + "\n",
            encoding="utf-8",
        )
        return

    print(json.dumps(assessment, indent=2, ensure_ascii=True))


if __name__ == "__main__":
    main()
