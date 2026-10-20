from __future__ import annotations

from helpers import make_diff, rule_ids

from diffguard import Config, RiskLevel, Severity, scan
from diffguard.config import config_from_dict

EVAL = "return eval(request.args['expr'])"


def test_inline_suppression_all_and_specific():
    assert not scan(make_diff("a.py", added=[EVAL + "  # diffguard: ignore"])).findings
    assert not scan(make_diff("a.py", added=[EVAL + "  # diffguard: ignore[DG202]"])).findings
    assert scan(make_diff("a.py", added=[EVAL + "  # diffguard: ignore[DG101]"])).findings


def test_disable_and_per_path_ignores():
    cfg = config_from_dict({"disable": ["DG202"]})
    assert not scan(make_diff("a.py", added=[EVAL]), cfg).findings
    cfg = config_from_dict({"per-path-ignores": {"scripts/**": ["*"]}})
    assert not scan(make_diff("scripts/a.py", added=[EVAL]), cfg).findings
    assert scan(make_diff("src/a.py", added=[EVAL]), cfg).findings


def test_severity_override():
    cfg = config_from_dict({"severity": {"DG202": "low"}})
    (finding,) = scan(make_diff("a.py", added=[EVAL]), cfg).findings
    assert finding.severity == Severity.LOW


def test_excluded_paths_are_listed_but_not_scanned():
    report = scan(make_diff("node_modules/x/index.js", added=["eval(userInput)"]))
    assert not report.findings
    assert report.files[0].excluded


def test_moved_line_is_not_a_removal():
    diff = make_diff("views.py", removed=["@login_required"]) + make_diff(
        "views_v2.py", added=["@login_required"]
    )
    assert "DG601" not in rule_ids(scan(diff))


def test_deleting_a_whole_file_does_not_report_removed_controls():
    diff = make_diff("old_views.py", removed=["@login_required"], status="deleted")
    assert "DG601" not in rule_ids(scan(diff))


def test_docs_and_tests_do_not_raise_domains():
    diff = make_diff("docs/auth.md", added=["How login and payments work"]) + make_diff(
        "tests/test_login.py", added=["def test_login(): assert login()"]
    )
    report = scan(diff)
    assert report.domains == {}
    assert report.level == RiskLevel.LOW


def test_secrets_are_caught_in_docs_too():
    key = "ghp_" + "a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8"
    report = scan(make_diff("README.md", added=[f"export GH_TOKEN={key}"]))
    assert "DG102" in rule_ids(report)
    assert report.level == RiskLevel.HIGH


def test_domain_from_path_and_identifier():
    report = scan(make_diff("src/billing/charges.py", added=["x = 1"]))
    assert "payment" in report.domains
    report = scan(make_diff("src/users.py", added=["if bcrypt.checkpw(pw, user.hash):"]))
    assert "auth" in report.domains


def test_custom_domain_and_reviewers():
    cfg = config_from_dict(
        {
            "domains": {"pricing": {"paths": ["src/pricing/**"], "weight": 30}},
            "reviewers": {"pricing": ["@org/pricing"], "findings": ["@org/appsec"]},
        }
    )
    report = scan(make_diff("src/pricing/rules.py", added=["discount = 0.1"]), cfg)
    assert "pricing" in report.domains
    assert report.score == 30
    assert report.suggested_reviewers == ["@org/pricing"]
    report = scan(make_diff("src/a.py", added=[EVAL]), cfg)
    assert report.suggested_reviewers == ["@org/appsec"]


def test_minified_lines_are_skipped():
    line = "eval(x);" + "a" * 3000
    assert not scan(make_diff("app.js", added=[line])).findings


def test_large_change_raises_size_points():
    lines = [f"value_{i} = {i}" for i in range(900)]
    report = scan(make_diff("src/big.py", added=lines))
    assert any(r.code == "LARGE_CHANGE" for r in report.reasons)
    assert report.level == RiskLevel.MEDIUM


def test_default_config_is_used_when_none_given():
    assert scan("", None).level == RiskLevel.LOW
    assert scan("", Config()).score == 0
