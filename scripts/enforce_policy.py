"""Enforce MR policy from risk assessment."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

# Add project root to path for imports
_ROOT = Path(__file__).resolve().parents[1]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from src.contracts import validate_payload


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Enforce MR policy from risk assessment."
    )
    parser.add_argument(
        "--assessment",
        required=True,
        type=Path,
        help="Path to risk assessment JSON.",
    )
    parser.add_argument(
        "--action-plan",
        required=True,
        type=Path,
        help="Path to output action plan JSON.",
    )
    parser.add_argument(
        "--skip-validation",
        action="store_true",
        default=False,
        help="Skip JSON schema validation (NOT recommended in CI).",
    )
    return parser.parse_args()


def to_action_plan(assessment: dict) -> dict:
    """Convert a risk assessment into an executable action plan."""
    actions = assessment.get("recommended_actions", [])
    if "block_merge" in actions:
        decision = "blocked_pending_security"
    elif "tag_domain_expert" in actions:
        decision = "approved_with_reviewers"
    else:
        decision = "approved"

    raw_actions: list[dict] = []
    for action in actions:
        if action == "auto_approve":
            raw_actions.append({"type": "AUTO_APPROVE", "params": {}})
        elif action == "tag_domain_expert":
            raw_actions.append(
                {"type": "REQUEST_REVIEWERS", "params": {"group": "domain-experts"}}
            )
        elif action == "run_enhanced_tests":
            raw_actions.append(
                {"type": "RUN_PIPELINE_STAGE", "params": {"stage": "enhanced_tests"}}
            )
        elif action == "generate_additional_tests":
            raw_actions.append({"type": "GENERATE_TESTS", "params": {}})
        elif action == "require_security_review":
            raw_actions.append(
                {"type": "REQUEST_REVIEWERS", "params": {"group": "security-team"}}
            )
        elif action == "block_merge":
            raw_actions.append({"type": "BLOCK_MERGE", "params": {}})
        elif action == "enforce_canary":
            raw_actions.append(
                {"type": "SET_DEPLOYMENT_MODE", "params": {"mode": "canary"}}
            )

    # Deduplicate by action type - merge REQUEST_REVIEWERS groups
    seen: dict[str, dict] = {}
    mapped_actions: list[dict] = []
    for act in raw_actions:
        key = act["type"]
        if key in seen:
            if key == "REQUEST_REVIEWERS":
                existing = seen[key]["params"]
                new_group = act["params"].get("group", "")
                old_group = existing.get("group", "")
                if new_group and new_group != old_group:
                    existing["groups"] = existing.pop("group", [old_group])
                    if isinstance(existing["groups"], str):
                        existing["groups"] = [existing["groups"]]
                    existing["groups"].append(new_group)
        else:
            seen[key] = act
            mapped_actions.append(act)

    return {
        "mr_id": assessment.get("mr_id", "unknown-mr"),
        "decision": decision,
        "actions": mapped_actions or [{"type": "RUN_PIPELINE_STAGE", "params": {}}],
    }


def main() -> None:
    args = parse_args()
    assessment = json.loads(args.assessment.read_text(encoding="utf-8"))

    if not args.skip_validation:
        validate_payload(assessment, "risk")

    action_plan = to_action_plan(assessment)

    if not args.skip_validation:
        validate_payload(action_plan, "action")

    args.action_plan.write_text(
        json.dumps(action_plan, indent=2, ensure_ascii=True) + "\n", encoding="utf-8"
    )

    risk_level = assessment.get("risk_level")
    risk_score = assessment.get("risk_score")
    print(f"Risk level: {risk_level} (score={risk_score})")
    print(f"Recommended actions: {assessment.get('recommended_actions', [])}")

    if risk_level == "high":
        raise SystemExit(1)


if __name__ == "__main__":
    main()
