from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
DIFFS = ROOT / "fixtures" / "diffs"


def run_cmd(args: list[str], expect_code: int = 0) -> subprocess.CompletedProcess:
    proc = subprocess.run(
        args,
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    if proc.returncode != expect_code:
        raise AssertionError(
            f"Command failed.\nArgs: {args}\nExpected: {expect_code}\n"
            f"Actual: {proc.returncode}\nStdout:\n{proc.stdout}\nStderr:\n{proc.stderr}"
        )
    return proc


class DiffFirstFlowTests(unittest.TestCase):
    def _run_flow(self, diff_name: str, mr_id: str) -> tuple[dict, dict, int]:
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp = Path(tmp_dir)
            semantic_path = tmp / "semantic.json"
            risk_path = tmp / "risk.json"
            action_path = tmp / "action.json"

            run_cmd(
                [
                    sys.executable,
                    "scripts/semantic_from_diff.py",
                    "--diff",
                    str(DIFFS / diff_name),
                    "--output",
                    str(semantic_path),
                    "--mr-id",
                    mr_id,
                    "--repo",
                    "local/repo",
                    "--branch",
                    "feat/test",
                    "--sha",
                    "abcdef1",
                ]
            )
            run_cmd(
                [
                    sys.executable,
                    "-m",
                    "src.risk_engine.cli",
                    "--input",
                    str(semantic_path),
                    "--output",
                    str(risk_path),
                ]
            )

            risk = json.loads(risk_path.read_text(encoding="utf-8"))
            expected_policy_code = 1 if risk["risk_level"] == "high" else 0
            policy_proc = run_cmd(
                [
                    sys.executable,
                    "scripts/enforce_policy.py",
                    "--assessment",
                    str(risk_path),
                    "--action-plan",
                    str(action_path),
                ],
                expect_code=expected_policy_code,
            )
            action_plan = json.loads(action_path.read_text(encoding="utf-8"))
            return risk, action_plan, policy_proc.returncode

    def test_low_risk_diff_auto_approve(self) -> None:
        risk, action_plan, code = self._run_flow("low_cosmetic.diff", "101")
        self.assertEqual(risk["risk_level"], "low")
        self.assertLess(risk["risk_score"], 30)
        self.assertIn("auto_approve", risk["recommended_actions"])
        self.assertEqual(action_plan["decision"], "approved")
        self.assertEqual(code, 0)

    def test_medium_risk_diff_requests_reviewers(self) -> None:
        risk, action_plan, code = self._run_flow("medium_payment.diff", "102")
        self.assertEqual(risk["risk_level"], "medium")
        self.assertGreaterEqual(risk["risk_score"], 30)
        self.assertLessEqual(risk["risk_score"], 70)
        self.assertIn("tag_domain_expert", risk["recommended_actions"])
        self.assertIn("run_enhanced_tests", risk["recommended_actions"])
        self.assertEqual(action_plan["decision"], "approved_with_reviewers")
        self.assertEqual(code, 0)

    def test_high_risk_diff_blocks_merge(self) -> None:
        risk, action_plan, code = self._run_flow("high_auth.diff", "103")
        self.assertEqual(risk["risk_level"], "high")
        self.assertGreater(risk["risk_score"], 70)
        self.assertIn("block_merge", risk["recommended_actions"])
        self.assertEqual(action_plan["decision"], "blocked_pending_security")
        self.assertEqual(code, 1)


if __name__ == "__main__":
    unittest.main()

