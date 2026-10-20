from __future__ import annotations

import json
from pathlib import Path

import jsonschema
from helpers import make_diff

from diffguard import scan
from diffguard.report import MARKDOWN_MARKER, render, render_rules

ROOT = Path(__file__).resolve().parents[1]
SCHEMA = json.loads((ROOT / "schema" / "report-v1.schema.json").read_text(encoding="utf-8"))

RISKY = (
    make_diff("src/views.py", ["@csrf_exempt", "x = eval(data)"], ["@login_required"])
    + make_diff("src/auth/tokens.py", ['SECRET_KEY = "Zx9!aQ27mLp0Rt"'])
    + make_diff("docs/guide.md", ["How auth works"])
)


def test_json_report_matches_schema():
    for diff in (RISKY, "", make_diff("README.md", ["hi"])):
        jsonschema.validate(json.loads(render(scan(diff), "json")), SCHEMA)


def test_sarif_structure():
    sarif = json.loads(render(scan(RISKY), "sarif"))
    run = sarif["runs"][0]
    rule_ids = [r["id"] for r in run["tool"]["driver"]["rules"]]
    assert len(rule_ids) == len(set(rule_ids))
    for result in run["results"]:
        assert run["tool"]["driver"]["rules"][result["ruleIndex"]]["id"] == result["ruleId"]
        region = result["locations"][0]["physicalLocation"]["region"]
        assert region["startLine"] >= 1
        assert result["level"] in ("error", "warning", "note")


def test_markdown_has_marker_and_escapes_pipes():
    md = render(scan(make_diff("a.js", ["el.innerHTML = a || b"])), "markdown")
    assert md.startswith(MARKDOWN_MARKER)
    assert "a \\|\\| b" in md


def test_secrets_never_appear_in_any_format():
    for fmt in ("text", "json", "markdown", "sarif", "github"):
        assert "Zx9!aQ27mLp0Rt" not in render(scan(RISKY), fmt)


def test_github_annotations_escape_properties():
    out = render(scan(make_diff("we,ird:name.py", ["eval(x)"])), "github")
    assert out.startswith("::error file=we%2Cird%3Aname.py,line=1,")


def test_text_report_mentions_removed_lines():
    text = render(scan(RISKY), "text")
    assert "- @login_required" in text
    assert "HIGH" in text


def test_rules_docs_are_up_to_date():
    docs = (ROOT / "docs" / "rules.md").read_text(encoding="utf-8")
    assert docs == render_rules("markdown"), "run: diffguard rules --format markdown > docs/rules.md"
