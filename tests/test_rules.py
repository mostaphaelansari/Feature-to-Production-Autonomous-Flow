"""Every rule's documented examples must behave as documented."""
from __future__ import annotations

import pytest
from helpers import make_diff, rule_ids

from diffguard import scan
from diffguard.rules import RULES, redact

CASES = [
    pytest.param(rule, path, line, expected, id=f"{rule.id}-{'bad' if expected else 'good'}-{i}")
    for rule in RULES
    for expected, examples in ((True, rule.bad), (False, rule.good))
    for i, (path, line) in enumerate(examples)
]


@pytest.mark.parametrize(("rule", "path", "line", "expected"), CASES)
def test_rule_examples(rule, path, line, expected):
    if rule.side == "added":
        diff = make_diff(path, added=[line])
    else:
        diff = make_diff(path, added=["pass"], removed=[line])
    found = rule.id in rule_ids(scan(diff))
    assert found is expected, f"{rule.id} on {path!r}: {line!r}"


def test_every_rule_has_examples_both_ways():
    for rule in RULES:
        assert rule.bad, f"{rule.id} has no flagged example"
        assert rule.good, f"{rule.id} has no non-flagged example"


def test_rule_ids_unique_and_well_formed():
    ids = [rule.id for rule in RULES]
    assert len(ids) == len(set(ids))
    assert all(len(i) == 5 and i.startswith("DG") and i[2:].isdigit() for i in ids)


def test_redact_masks_long_tokens():
    masked = redact('API_KEY = "sk-live-9f8e7d6c"')
    assert "9f8e7d6c" not in masked
    assert "sk-l****" in masked


def test_secret_snippets_are_redacted_in_findings():
    report = scan(make_diff("src/db.py", added=['PASSWORD = "Tr0ub4dor&3xyz"']))
    (finding,) = [f for f in report.findings if f.rule_id == "DG103"]
    assert "Tr0ub4dor&3xyz" not in finding.snippet
