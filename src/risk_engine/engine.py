from __future__ import annotations

from typing import Any


HIGH_DELTA_LINES = 300
MEDIUM_DELTA_LINES = 120

BASE_WEIGHTS = {
    "AUTH_CODE_MODIFIED": 30,
    "PAYMENT_LOGIC_TOUCHED": 30,
    "DB_MIGRATION_DETECTED": 25,
    "VALIDATION_REMOVED": 25,
    "CONCURRENCY_CHANGED": 20,
    "SECURITY_SENSITIVE_EDIT": 25,
    "ARCHITECTURE_DRIFT": 20,
    "CONFIG_CHANGE": 10,
}

ARCHITECTURE_KEYWORDS = (
    "cross-layer",
    "circular",
    "service boundary",
    "layer violation",
    "architecture drift",
)


def _has_architecture_drift(semantic: dict[str, Any]) -> bool:
    notes = semantic.get("behavioral_impact", {}).get("notes", [])
    notes_text = " ".join(str(note).lower() for note in notes)
    return any(keyword in notes_text for keyword in ARCHITECTURE_KEYWORDS)


def _has_config_change(semantic: dict[str, Any]) -> bool:
    if "configuration" in semantic.get("risk_areas", []):
        return True
    for file_change in semantic.get("files_changed", []):
        if "config_change" in file_change.get("change_types", []):
            return True
    return False


def _large_delta_weight(total_delta: int) -> int:
    if total_delta >= HIGH_DELTA_LINES:
        return 15
    if total_delta >= MEDIUM_DELTA_LINES:
        return 8
    return 2


def _recommended_actions(score: int, security_sensitive: bool) -> list[str]:
    if score < 30:
        return ["auto_approve"]
    if score <= 70:
        actions = ["tag_domain_expert", "run_enhanced_tests"]
        if security_sensitive:
            actions.append("require_security_review")
        return actions
    return [
        "block_merge",
        "require_security_review",
        "generate_additional_tests",
        "enforce_canary",
    ]


def evaluate_risk(semantic: dict[str, Any]) -> dict[str, Any]:
    """Compute risk score and recommended actions from semantic diff output."""
    signals = semantic.get("signals", {})
    categories = set(semantic.get("change_categories", []))
    risk_areas = set(semantic.get("risk_areas", []))

    total_added = int(signals.get("total_added", 0))
    total_removed = int(signals.get("total_removed", 0))
    total_delta = total_added + total_removed

    reason_weights: dict[str, int] = {
        "LARGE_DELTA": _large_delta_weight(total_delta),
    }

    if signals.get("auth_touched"):
        reason_weights["AUTH_CODE_MODIFIED"] = BASE_WEIGHTS["AUTH_CODE_MODIFIED"]
    if signals.get("payment_touched"):
        reason_weights["PAYMENT_LOGIC_TOUCHED"] = BASE_WEIGHTS["PAYMENT_LOGIC_TOUCHED"]
    if signals.get("db_migration_detected"):
        reason_weights["DB_MIGRATION_DETECTED"] = BASE_WEIGHTS["DB_MIGRATION_DETECTED"]
    if signals.get("validation_removed"):
        reason_weights["VALIDATION_REMOVED"] = BASE_WEIGHTS["VALIDATION_REMOVED"]
    if signals.get("concurrency_logic_changed"):
        reason_weights["CONCURRENCY_CHANGED"] = BASE_WEIGHTS["CONCURRENCY_CHANGED"]

    security_sensitive = (
        "security_sensitive" in categories or "security" in risk_areas
    )
    if security_sensitive:
        reason_weights["SECURITY_SENSITIVE_EDIT"] = BASE_WEIGHTS["SECURITY_SENSITIVE_EDIT"]

    if _has_architecture_drift(semantic):
        reason_weights["ARCHITECTURE_DRIFT"] = BASE_WEIGHTS["ARCHITECTURE_DRIFT"]

    if _has_config_change(semantic):
        reason_weights["CONFIG_CHANGE"] = BASE_WEIGHTS["CONFIG_CHANGE"]

    score = min(sum(reason_weights.values()), 100)

    if score < 30:
        level = "low"
        bucket = "lt_30"
    elif score <= 70:
        level = "medium"
        bucket = "between_30_70"
    else:
        level = "high"
        bucket = "gt_70"

    return {
        "mr_id": semantic.get("mr", {}).get("id", "unknown-mr"),
        "risk_score": score,
        "risk_level": level,
        "threshold_bucket": bucket,
        "reason_codes": list(reason_weights.keys()),
        "weights": [
            {"reason_code": code, "weight": weight}
            for code, weight in reason_weights.items()
        ],
        "recommended_actions": _recommended_actions(score, security_sensitive),
    }

