"""Tests for the risk engine."""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

from src.risk_engine.engine import evaluate_risk


ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "fixtures"


# ── Helpers ──────────────────────────────────────────────────────

def _minimal_semantic(**overrides) -> dict:
    """Return a valid semantic payload with sensible defaults."""
    base = {
        "mr": {
            "id": "test-mr",
            "repository": "test/repo",
            "branch": "feat/test",
            "commit_sha": "abc1234",
        },
        "summary": "Test payload.",
        "files_changed": [
            {
                "path": "src/example.py",
                "status": "modified",
                "language": "python",
                "lines_added": 5,
                "lines_removed": 2,
                "change_types": ["modified_logic"],
                "sensitive": False,
            }
        ],
        "risk_areas": [],
        "change_categories": [],
        "signals": {
            "auth_touched": False,
            "payment_touched": False,
            "db_migration_detected": False,
            "concurrency_logic_changed": False,
            "validation_removed": False,
            "total_added": 5,
            "total_removed": 2,
        },
        "behavioral_impact": {"level": "low", "notes": []},
    }
    base.update(overrides)
    return base


# ── Low-risk path ────────────────────────────────────────────────

class TestLowRisk:
    def test_auto_approve(self):
        result = evaluate_risk(_minimal_semantic())
        assert result["risk_score"] < 30
        assert result["risk_level"] == "low"
        assert result["threshold_bucket"] == "lt_30"
        assert "auto_approve" in result["recommended_actions"]

    def test_mr_id_forwarded(self):
        result = evaluate_risk(_minimal_semantic())
        assert result["mr_id"] == "test-mr"


# ── Medium-risk path ─────────────────────────────────────────────

class TestMediumRisk:
    def test_auth_touched(self):
        sem = _minimal_semantic(
            signals={
                "auth_touched": True,
                "payment_touched": False,
                "db_migration_detected": False,
                "concurrency_logic_changed": False,
                "validation_removed": False,
                "total_added": 10,
                "total_removed": 5,
            },
        )
        result = evaluate_risk(sem)
        assert 30 <= result["risk_score"] <= 70
        assert result["risk_level"] == "medium"
        assert "tag_domain_expert" in result["recommended_actions"]
        assert "AUTH_CODE_MODIFIED" in result["reason_codes"]

    def test_no_security_review_without_security_flag(self):
        sem = _minimal_semantic(
            signals={
                "auth_touched": True,
                "payment_touched": False,
                "db_migration_detected": False,
                "concurrency_logic_changed": False,
                "validation_removed": False,
                "total_added": 10,
                "total_removed": 5,
            },
        )
        result = evaluate_risk(sem)
        assert "require_security_review" not in result["recommended_actions"]

    def test_security_review_with_security_category(self):
        sem = _minimal_semantic(
            change_categories=["security_sensitive"],
            signals={
                "auth_touched": True,
                "payment_touched": False,
                "db_migration_detected": False,
                "concurrency_logic_changed": False,
                "validation_removed": False,
                "total_added": 10,
                "total_removed": 5,
            },
        )
        result = evaluate_risk(sem)
        assert "require_security_review" in result["recommended_actions"]


# ── High-risk path ───────────────────────────────────────────────

class TestHighRisk:
    def test_blocks_merge(self):
        sem = _minimal_semantic(
            risk_areas=["authentication", "payment", "database", "security"],
            change_categories=["security_sensitive"],
            signals={
                "auth_touched": True,
                "payment_touched": True,
                "db_migration_detected": True,
                "concurrency_logic_changed": False,
                "validation_removed": True,
                "total_added": 400,
                "total_removed": 100,
            },
        )
        result = evaluate_risk(sem)
        assert result["risk_score"] > 70
        assert result["risk_level"] == "high"
        assert result["threshold_bucket"] == "gt_70"
        assert "block_merge" in result["recommended_actions"]

    def test_score_capped_at_100(self):
        sem = _minimal_semantic(
            risk_areas=["authentication", "security", "configuration"],
            change_categories=["security_sensitive"],
            signals={
                "auth_touched": True,
                "payment_touched": True,
                "db_migration_detected": True,
                "concurrency_logic_changed": True,
                "validation_removed": True,
                "total_added": 500,
                "total_removed": 500,
            },
            behavioral_impact={
                "level": "high",
                "notes": ["architecture drift detected, circular dependency"],
            },
        )
        result = evaluate_risk(sem)
        assert result["risk_score"] == 100


# ── Helper function tests ────────────────────────────────────────

class TestLargeDeltaWeight:
    def test_small_delta(self):
        sem = _minimal_semantic()
        sem["signals"]["total_added"] = 10
        sem["signals"]["total_removed"] = 5
        result = evaluate_risk(sem)
        weights = {w["reason_code"]: w["weight"] for w in result["weights"]}
        assert weights["LARGE_DELTA"] == 2

    def test_medium_delta(self):
        sem = _minimal_semantic()
        sem["signals"]["total_added"] = 80
        sem["signals"]["total_removed"] = 50
        result = evaluate_risk(sem)
        weights = {w["reason_code"]: w["weight"] for w in result["weights"]}
        assert weights["LARGE_DELTA"] == 8

    def test_high_delta(self):
        sem = _minimal_semantic()
        sem["signals"]["total_added"] = 200
        sem["signals"]["total_removed"] = 150
        result = evaluate_risk(sem)
        weights = {w["reason_code"]: w["weight"] for w in result["weights"]}
        assert weights["LARGE_DELTA"] == 15


class TestArchitectureDrift:
    def test_detected_via_notes(self):
        sem = _minimal_semantic(
            behavioral_impact={
                "level": "medium",
                "notes": ["possible circular dependency in module graph"],
            },
        )
        result = evaluate_risk(sem)
        assert "ARCHITECTURE_DRIFT" in result["reason_codes"]

    def test_not_detected(self):
        sem = _minimal_semantic(
            behavioral_impact={"level": "low", "notes": ["minor refactor"]},
        )
        result = evaluate_risk(sem)
        assert "ARCHITECTURE_DRIFT" not in result["reason_codes"]


class TestConfigChange:
    def test_detected_via_risk_area(self):
        sem = _minimal_semantic(risk_areas=["configuration"])
        result = evaluate_risk(sem)
        assert "CONFIG_CHANGE" in result["reason_codes"]

    def test_detected_via_change_type(self):
        sem = _minimal_semantic()
        sem["files_changed"][0]["change_types"] = ["config_change"]
        result = evaluate_risk(sem)
        assert "CONFIG_CHANGE" in result["reason_codes"]


# ── CLI smoke test ───────────────────────────────────────────────

class TestCLI:
    def test_cli_stdout(self, tmp_path):
        payload = _minimal_semantic()
        input_file = tmp_path / "input.json"
        input_file.write_text(json.dumps(payload), encoding="utf-8")

        result = subprocess.run(
            [sys.executable, "-m", "src.risk_engine.cli", "--input", str(input_file)],
            capture_output=True,
            text=True,
            cwd=str(ROOT),
        )
        assert result.returncode == 0
        output = json.loads(result.stdout)
        assert "risk_score" in output
        assert "recommended_actions" in output

    def test_cli_file_output(self, tmp_path):
        payload = _minimal_semantic()
        input_file = tmp_path / "input.json"
        output_file = tmp_path / "output.json"
        input_file.write_text(json.dumps(payload), encoding="utf-8")

        result = subprocess.run(
            [
                sys.executable, "-m", "src.risk_engine.cli",
                "--input", str(input_file),
                "--output", str(output_file),
            ],
            capture_output=True,
            text=True,
            cwd=str(ROOT),
        )
        assert result.returncode == 0
        output = json.loads(output_file.read_text(encoding="utf-8"))
        assert output["risk_level"] in ("low", "medium", "high")


# ── Fixture validation ───────────────────────────────────────────

class TestFixtures:
    def test_semantic_fixture_produces_expected_risk(self):
        """Run the engine against the shipped semantic-sample.json fixture."""
        fixture = FIXTURES / "semantic-sample.json"
        if not fixture.exists():
            pytest.skip("semantic-sample.json fixture not found")
        payload = json.loads(fixture.read_text(encoding="utf-8"))
        result = evaluate_risk(payload)
        # The fixture has auth_touched + validation_removed + security_sensitive
        assert result["risk_score"] > 70
        assert result["risk_level"] == "high"
        assert "block_merge" in result["recommended_actions"]
