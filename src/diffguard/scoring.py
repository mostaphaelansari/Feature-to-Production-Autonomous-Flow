"""Turn findings, domains and change size into an explainable 0-100 score."""
from __future__ import annotations

from .config import Config
from .domains import CUSTOM_DOMAIN_WEIGHT
from .models import DomainHit, Finding, RiskLevel, ScoreReason, Severity

SEVERITY_POINTS = {
    Severity.LOW: 5,
    Severity.MEDIUM: 20,
    Severity.HIGH: 45,
    Severity.CRITICAL: 70,
}
SIZE_POINTS_MEDIUM = 10
SIZE_POINTS_LARGE = 25


def score(
    findings: list[Finding],
    domains: dict[str, list[DomainHit]],
    code_lines_changed: int,
    cfg: Config,
) -> tuple[int, RiskLevel, list[ScoreReason]]:
    reasons: list[ScoreReason] = []

    by_rule: dict[str, list[Finding]] = {}
    for finding in findings:
        by_rule.setdefault(finding.rule_id, []).append(finding)
    for rule_id, group in by_rule.items():
        worst = max(f.severity for f in group)
        count = f"{len(group)} occurrence{'s' if len(group) > 1 else ''}"
        reasons.append(
            ScoreReason(rule_id, SEVERITY_POINTS[worst], f"{group[0].title} ({worst}, {count})")
        )

    for domain, hits in domains.items():
        weight = cfg.domain_weights.get(domain, CUSTOM_DOMAIN_WEIGHT)
        if weight <= 0:
            continue
        files = len({h.path for h in hits})
        reasons.append(
            ScoreReason(
                f"DOMAIN_{domain.upper()}",
                weight,
                f"Touches {domain} ({files} file{'s' if files > 1 else ''})",
            )
        )

    size = f"{code_lines_changed} code lines changed"
    if code_lines_changed >= cfg.size_large:
        reasons.append(ScoreReason("LARGE_CHANGE", SIZE_POINTS_LARGE, size))
    elif code_lines_changed >= cfg.size_medium:
        reasons.append(ScoreReason("MEDIUM_CHANGE", SIZE_POINTS_MEDIUM, size))

    reasons.sort(key=lambda r: -r.points)
    total = min(sum(r.points for r in reasons), 100)
    worst = max((f.severity for f in findings), default=None)

    has_evidence = worst is not None and worst >= Severity.MEDIUM
    if total >= cfg.high_threshold and not has_evidence and worst != Severity.CRITICAL:
        # Blocking needs a concrete finding: areas and size alone only route review.
        capped = cfg.high_threshold - 1
        detail = "no medium+ finding; areas and size cap at medium"
        reasons.append(ScoreReason("CAPPED", capped - total, detail))
        total = capped

    if worst == Severity.CRITICAL or total >= cfg.high_threshold:
        level = RiskLevel.HIGH
    elif total >= cfg.medium_threshold or has_evidence:
        level = RiskLevel.MEDIUM
    else:
        level = RiskLevel.LOW
    return total, level, reasons
