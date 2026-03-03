"""Tests for schema validation and edge cases."""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

from src.contracts import validate_payload
from src.risk_engine.engine import evaluate_risk

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "fixtures"
CONTRACTS = ROOT / "contracts"


# ── Schema validation tests ──────────────────────────────────────

class TestSchemaValidation:
    """Validate fixture samples against their contract schemas."""

    def test_semantic_fixture_valid(self):
        payload = json.loads(
            (FIXTURES / "semantic-sample.json").read_text(encoding="utf-8")
        )
        validate_payload(payload, "semantic")  # should not raise

    def test_risk_fixture_valid(self):
        payload = json.loads(
            (FIXTURES / "risk-sample.json").read_text(encoding="utf-8")
        )
        validate_payload(payload, "risk")  # should not raise

    def test_action_fixture_valid(self):
        payload = json.loads(
            (FIXTURES / "action-plan-sample.json").read_text(encoding="utf-8")
        )
        validate_payload(payload, "action")  # should not raise


class TestSchemaRejection:
    """Ensure malformed payloads are rejected."""

    def test_empty_object_rejected_semantic(self):
        with pytest.raises(Exception):
            validate_payload({}, "semantic")

    def test_missing_mr_id_rejected_risk(self):
        with pytest.raises(Exception):
            validate_payload(
                {"risk_score": 50, "risk_level": "medium"},
                "risk",
            )

    def test_invalid_risk_level_rejected(self):
        with pytest.raises(Exception):
            validate_payload(
                {
                    "mr_id": "1",
                    "risk_score": 50,
                    "risk_level": "extreme",  # not in enum
                    "threshold_bucket": "lt_30",
                    "reason_codes": ["LARGE_DELTA"],
                    "weights": [],
                    "recommended_actions": ["auto_approve"],
                },
                "risk",
            )

    def test_extra_fields_rejected_semantic(self):
        """additionalProperties: false should reject unknown keys."""
        payload = json.loads(
            (FIXTURES / "semantic-sample.json").read_text(encoding="utf-8")
        )
        payload["unknown_field"] = "bad"
        with pytest.raises(Exception):
            validate_payload(payload, "semantic")


# ── Edge-case engine tests ───────────────────────────────────────

class TestEdgeCases:
    """Cover inputs the happy-path tests miss."""

    def test_empty_signals(self):
        """Engine should not crash on missing signals."""
        result = evaluate_risk({
            "mr": {"id": "edge-1"},
            "signals": {},
            "change_categories": [],
            "risk_areas": [],
            "files_changed": [],
            "behavioral_impact": {"level": "low", "notes": []},
        })
        assert result["risk_score"] >= 0
        assert result["risk_level"] in ("low", "medium", "high")

    def test_missing_mr_section(self):
        """Engine should fall back to 'unknown-mr' when mr is absent."""
        result = evaluate_risk({
            "signals": {
                "auth_touched": False,
                "payment_touched": False,
                "db_migration_detected": False,
                "concurrency_logic_changed": False,
                "validation_removed": False,
                "total_added": 0,
                "total_removed": 0,
            },
            "change_categories": [],
            "risk_areas": [],
            "files_changed": [],
            "behavioral_impact": {"level": "low", "notes": []},
        })
        assert result["mr_id"] == "unknown-mr"

    def test_zero_delta(self):
        """Zero lines changed should still produce valid output."""
        result = evaluate_risk({
            "mr": {"id": "zero"},
            "signals": {
                "auth_touched": False,
                "payment_touched": False,
                "db_migration_detected": False,
                "concurrency_logic_changed": False,
                "validation_removed": False,
                "total_added": 0,
                "total_removed": 0,
            },
            "change_categories": [],
            "risk_areas": [],
            "files_changed": [],
            "behavioral_impact": {"level": "low", "notes": []},
        })
        assert result["risk_score"] == 2  # LARGE_DELTA minimum weight
        assert result["risk_level"] == "low"


# ── Diff parser edge-case tests ──────────────────────────────────

class TestDiffParser:
    """Test semantic_from_diff.py with edge-case diffs."""

    def _run_parser(self, diff_content: str, tmp_path: Path) -> dict:
        diff_file = tmp_path / "test.diff"
        output_file = tmp_path / "output.json"
        diff_file.write_text(diff_content, encoding="utf-8")
        result = subprocess.run(
            [
                sys.executable,
                str(ROOT / "scripts" / "semantic_from_diff.py"),
                "--diff", str(diff_file),
                "--output", str(output_file),
            ],
            capture_output=True,
            text=True,
            cwd=str(ROOT),
        )
        assert result.returncode == 0, f"Parser failed: {result.stderr}"
        return json.loads(output_file.read_text(encoding="utf-8"))

    def test_empty_diff(self, tmp_path):
        payload = self._run_parser("", tmp_path)
        assert payload["files_changed"][0]["path"] == "unknown"
        assert payload["signals"]["total_added"] == 0

    def test_rename_diff(self, tmp_path):
        diff = (
            "diff --git a/old.py b/new.py\n"
            "similarity index 100%\n"
            "rename from old.py\n"
            "rename to new.py\n"
        )
        payload = self._run_parser(diff, tmp_path)
        assert payload["files_changed"][0]["status"] == "renamed"

    def test_validation_removed_only_on_removed_lines(self, tmp_path):
        """Adding a 'validate' function should NOT trigger validation_removed."""
        diff = (
            "diff --git a/src/app.py b/src/app.py\n"
            "--- a/src/app.py\n"
            "+++ b/src/app.py\n"
            "@@ -1,0 +1,2 @@\n"
            "+def validate_input(data):\n"
            "+    return True\n"
        )
        payload = self._run_parser(diff, tmp_path)
        assert payload["signals"]["validation_removed"] is False

    def test_validation_removed_when_actually_removed(self, tmp_path):
        """Removing a 'validate' call SHOULD trigger validation_removed."""
        diff = (
            "diff --git a/src/app.py b/src/app.py\n"
            "--- a/src/app.py\n"
            "+++ b/src/app.py\n"
            "@@ -1,2 +1,0 @@\n"
            "-def validate_input(data):\n"
            "-    return True\n"
        )
        payload = self._run_parser(diff, tmp_path)
        assert payload["signals"]["validation_removed"] is True

    def test_binary_diff_no_crash(self, tmp_path):
        """Binary diff should not crash the parser."""
        diff = (
            "diff --git a/image.png b/image.png\n"
            "new file mode 100644\n"
            "Binary files /dev/null and b/image.png differ\n"
        )
        payload = self._run_parser(diff, tmp_path)
        assert len(payload["files_changed"]) >= 1
