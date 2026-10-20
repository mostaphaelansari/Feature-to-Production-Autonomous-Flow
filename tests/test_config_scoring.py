from __future__ import annotations

import pytest

from diffguard.config import Config, ConfigError, config_from_dict, load_config
from diffguard.models import DomainHit, Finding, RiskLevel, Severity
from diffguard.scoring import score


def _finding(severity: Severity, rule_id: str = "DG999") -> Finding:
    return Finding(rule_id, severity, "t", "m", "a.py", 1, "s", "added")


def test_pyproject_discovery(tmp_path):
    (tmp_path / "pyproject.toml").write_text(
        '[project]\nname = "x"\n[tool.diffguard]\nfail_on = "medium"\ndisable = ["DG303"]\n',
        encoding="utf-8",
    )
    cfg = load_config(root=tmp_path)
    assert cfg.fail_on == RiskLevel.MEDIUM
    assert cfg.disable == {"DG303"}


def test_standalone_file_wins_and_accepts_top_level_table(tmp_path):
    (tmp_path / "pyproject.toml").write_text('[tool.diffguard]\nfail-on = "low"\n', encoding="utf-8")
    (tmp_path / ".diffguard.toml").write_text('fail-on = "never"\n', encoding="utf-8")
    assert load_config(root=tmp_path).fail_on is None


def test_no_config_gives_defaults(tmp_path):
    cfg = load_config(root=tmp_path)
    assert cfg.fail_on == RiskLevel.HIGH and cfg.source is None


@pytest.mark.parametrize(
    "data, message",
    [
        ({"fail_onn": "high"}, "unknown option"),
        ({"disable": ["DG999"]}, "unknown rule id"),
        ({"thresholds": {"medium": 80, "high": 50}}, "thresholds"),
        ({"severity": {"DG202": "extreme"}}, "invalid Severity"),
        ({"domains": {"x": {"globs": []}}}, "unknown option"),
        ({"exclude": "vendor/**"}, "list of strings"),
    ],
)
def test_invalid_config_is_rejected(data, message):
    with pytest.raises(ConfigError, match=message):
        config_from_dict(data)


def test_explicit_missing_file_errors(tmp_path):
    with pytest.raises(ConfigError, match="not found"):
        load_config(tmp_path / "nope.toml")


def test_critical_finding_forces_high_even_below_threshold():
    cfg = config_from_dict({"thresholds": {"medium": 50, "high": 99}})
    total, level, _ = score([_finding(Severity.CRITICAL)], {}, 0, cfg)
    assert total == 70 and level == RiskLevel.HIGH


def test_high_finding_is_at_least_medium():
    cfg = config_from_dict({"thresholds": {"medium": 50, "high": 99}})
    _, level, _ = score([_finding(Severity.HIGH)], {}, 0, cfg)
    assert level == RiskLevel.MEDIUM


def test_same_rule_counts_once():
    total, _, reasons = score([_finding(Severity.MEDIUM)] * 5, {}, 0, Config())
    assert total == 20 and len(reasons) == 1 and "5 occurrences" in reasons[0].detail


def test_domains_and_score_cap():
    domains = {d: [DomainHit(d, "a.py", None, "path")] for d in ("auth", "payment", "database")}
    total, level, _ = score([_finding(Severity.CRITICAL)], domains, 1000, Config())
    assert total == 100 and level == RiskLevel.HIGH


def test_areas_and_size_alone_cap_at_medium():
    domains = {d: [DomainHit(d, "a.py", None, "path")] for d in ("auth", "payment", "database")}
    total, level, reasons = score([], domains, 5000, Config())
    assert total == 59 and level == RiskLevel.MEDIUM
    assert reasons[-1].code == "CAPPED"
    total, level, _ = score([_finding(Severity.LOW)], domains, 0, Config())
    assert level == RiskLevel.MEDIUM
    total, level, _ = score([_finding(Severity.MEDIUM)], domains, 0, Config())
    assert level == RiskLevel.HIGH


def test_zero_weight_domain_is_ignored():
    cfg = config_from_dict({"domains": {"configuration": {"weight": 0}}})
    domains = {"configuration": [DomainHit("configuration", "settings.py", None, "path")]}
    assert score([], domains, 0, cfg)[0] == 0
