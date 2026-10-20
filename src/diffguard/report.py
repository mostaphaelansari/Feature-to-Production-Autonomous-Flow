"""Render a :class:`Report` as text, JSON, Markdown, SARIF or GitHub annotations."""
from __future__ import annotations

import json

from . import __version__
from .models import Report, RiskLevel, Severity
from .rules import RULES, redact

FORMATS = ("text", "json", "markdown", "sarif", "github")
MARKDOWN_MARKER = "<!-- diffguard-report -->"
REPO_URL = "https://github.com/mostaphaelansari/Feature-to-Production-Autonomous-Flow"
_MAX_MARKDOWN_FINDINGS = 50

_ANSI = {
    RiskLevel.LOW: "\033[32m",
    RiskLevel.MEDIUM: "\033[33m",
    RiskLevel.HIGH: "\033[31m",
    Severity.LOW: "\033[36m",
    Severity.MEDIUM: "\033[33m",
    Severity.HIGH: "\033[31m",
    Severity.CRITICAL: "\033[1;31m",
}
_RESET = "\033[0m"
_LEVEL_ICON = {RiskLevel.LOW: "🟢", RiskLevel.MEDIUM: "🟡", RiskLevel.HIGH: "🔴"}
_SEVERITY_ICON = {
    Severity.LOW: "⚪",
    Severity.MEDIUM: "🟡",
    Severity.HIGH: "🟠",
    Severity.CRITICAL: "🔴",
}
_SARIF_LEVEL = {
    Severity.LOW: "note",
    Severity.MEDIUM: "warning",
    Severity.HIGH: "error",
    Severity.CRITICAL: "error",
}
_SECURITY_SEVERITY = {
    Severity.LOW: "3.0",
    Severity.MEDIUM: "5.5",
    Severity.HIGH: "8.0",
    Severity.CRITICAL: "9.5",
}


def render(report: Report, fmt: str, color: bool = False) -> str:
    renderer = {
        "text": lambda r: render_text(r, color),
        "json": render_json,
        "markdown": render_markdown,
        "sarif": render_sarif,
        "github": render_github,
    }[fmt]
    return renderer(report)


def render_json(report: Report) -> str:
    return json.dumps(report.to_dict(), indent=2) + "\n"


def _files(count: int) -> str:
    return f"{count} file{'' if count == 1 else 's'}"


def render_text(report: Report, color: bool = False) -> str:
    def paint(text: str, key) -> str:
        return f"{_ANSI[key]}{text}{_RESET}" if color else text

    stats = report.stats
    out = [
        f"DiffGuard: {paint(str(report.level).upper(), report.level)} risk "
        f"(score {report.score}/100) - {_files(stats['files'])}, "
        f"+{stats['added']}/-{stats['removed']} lines",
    ]
    if report.reasons:
        out.append("")
        out.append("Score breakdown:")
        for reason in report.reasons:
            out.append(f"  {reason.points:<+4d} {reason.code:<22} {reason.detail}")
    if report.findings:
        out.append("")
        out.append(f"Findings ({len(report.findings)}):")
        for f in report.findings:
            sev = paint(f"{str(f.severity).upper():<8}", f.severity)
            out.append(f"  {sev} {f.rule_id}  {f.path}:{f.line}  {f.title}")
            out.append(f"           {'-' if f.kind == 'removed' else '+'} {f.snippet}")
    if report.domains:
        out.append("")
        out.append("Sensitive areas: " + ", ".join(sorted(report.domains)))
    if report.suggested_reviewers:
        out.append("Suggested reviewers: " + ", ".join(report.suggested_reviewers))
    if not report.findings and not report.domains:
        out.append("No findings.")
    return "\n".join(out) + "\n"


def _md_escape(text: str) -> str:
    return text.replace("|", "\\|").replace("`", "'")


def render_markdown(report: Report) -> str:
    stats = report.stats
    out = [
        MARKDOWN_MARKER,
        f"## {_LEVEL_ICON[report.level]} DiffGuard: **{str(report.level).upper()}** risk "
        f"({report.score}/100)",
        "",
        f"{_files(stats['files'])} changed, +{stats['added']} / -{stats['removed']} lines.",
    ]
    if report.findings:
        out += ["", "### Findings", "", "| | Rule | Location | Issue |", "|---|---|---|---|"]
        for f in report.findings[:_MAX_MARKDOWN_FINDINGS]:
            where = f"`{f.path}:{f.line}`"
            issue = f"**{_md_escape(f.title)}**<br>`{_md_escape(f.snippet)}`"
            if f.kind == "removed":
                issue = "Removed: " + issue
            severity = f"{_SEVERITY_ICON[f.severity]} {f.severity}"
            out.append(f"| {severity} | {f.rule_id} | {where} | {issue} |")
        hidden = len(report.findings) - _MAX_MARKDOWN_FINDINGS
        if hidden > 0:
            out.append(f"\n_…and {hidden} more. See the JSON or SARIF report._")
    if report.reasons:
        out += ["", "<details><summary>Score breakdown</summary>", "", "| Points | Reason |",
                "|---|---|"]
        out += [f"| {r.points:+d} | `{r.code}` {_md_escape(r.detail)} |" for r in report.reasons]
        out += ["", "</details>"]
    if report.domains:
        areas = ", ".join(f"`{d}`" for d in sorted(report.domains))
        out += ["", f"**Sensitive areas touched:** {areas}"]
    if report.suggested_reviewers:
        out += ["", "**Suggested reviewers:** " + ", ".join(report.suggested_reviewers)]
    if not report.findings and not report.domains:
        out += ["", "No findings."]
    out += ["", f"<sub>[DiffGuard]({REPO_URL}) v{__version__}</sub>"]
    return "\n".join(out) + "\n"


def render_sarif(report: Report) -> str:
    used = {f.rule_id for f in report.findings}
    rules = [rule for rule in RULES if rule.id in used]
    index = {rule.id: i for i, rule in enumerate(rules)}
    sarif = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "DiffGuard",
                        "version": __version__,
                        "informationUri": REPO_URL,
                        "rules": [
                            {
                                "id": rule.id,
                                "name": rule.title.replace(" ", ""),
                                "shortDescription": {"text": rule.title},
                                "fullDescription": {"text": rule.description},
                                "help": {"text": rule.remediation},
                                "defaultConfiguration": {"level": _SARIF_LEVEL[rule.severity]},
                                "properties": {
                                    "security-severity": _SECURITY_SEVERITY[rule.severity],
                                    "tags": ["security"],
                                },
                            }
                            for rule in rules
                        ],
                    }
                },
                "results": [
                    {
                        "ruleId": f.rule_id,
                        "ruleIndex": index[f.rule_id],
                        "level": _SARIF_LEVEL[f.severity],
                        "message": {"text": f"{f.message} `{f.snippet}`"},
                        "locations": [
                            {
                                "physicalLocation": {
                                    "artifactLocation": {"uri": f.path},
                                    "region": {"startLine": f.line},
                                }
                            }
                        ],
                        "properties": {"kind": f.kind},
                    }
                    for f in report.findings
                ],
            }
        ],
    }
    return json.dumps(sarif, indent=2) + "\n"


def _gh_escape(text: str, prop: bool = False) -> str:
    text = text.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")
    if prop:
        text = text.replace(":", "%3A").replace(",", "%2C")
    return text


def render_github(report: Report) -> str:
    """GitHub Actions workflow commands: findings show up inline on the PR diff."""
    command = {
        Severity.LOW: "notice",
        Severity.MEDIUM: "warning",
        Severity.HIGH: "error",
        Severity.CRITICAL: "error",
    }
    out = []
    for f in report.findings:
        title = _gh_escape(f"{f.rule_id} {f.title}", prop=True)
        message = _gh_escape(f.message if f.kind == "added" else f"{f.message} Was: {f.snippet}")
        out.append(
            f"::{command[f.severity]} file={_gh_escape(f.path, prop=True)},line={f.line},"
            f"title={title}::{message}"
        )
    out.append(f"DiffGuard: {str(report.level).upper()} risk (score {report.score}/100)")
    return "\n".join(out) + "\n"


def render_rules(fmt: str = "text") -> str:
    if fmt == "json":
        return json.dumps(
            [
                {
                    "id": r.id,
                    "title": r.title,
                    "severity": str(r.severity),
                    "side": r.side,
                    "description": r.description,
                    "remediation": r.remediation,
                }
                for r in RULES
            ],
            indent=2,
        ) + "\n"
    if fmt == "markdown":
        out = [
            "# Rules",
            "",
            "<!-- Generated by `diffguard rules --format markdown`. Do not edit by hand. -->",
            "",
            "Rules marked **removed** fire when a change *deletes* a safety control "
            "(and does not re-add the same line elsewhere in the diff).",
            "",
            "| ID | Severity | Trigger | Title |",
            "|---|---|---|---|",
        ]
        out += [
            f"| [{r.id}](#{r.id.lower()}) | {r.severity} | {r.side} | {r.title} |" for r in RULES
        ]
        for r in RULES:
            out += ["", f"## {r.id}", "", f"**{r.title}** ({r.severity}, {r.side} lines)", "",
                    r.description, "", f"**Fix:** {r.remediation}"]
            if r.bad:
                out += ["", "Flagged:", "", "```"]
                out += [f"{path}: {redact(line) if r.redact else line}" for path, line in r.bad]
                out += ["```"]
            if r.good:
                out += ["", "Not flagged:", "", "```"]
                out += [f"{path}: {redact(line) if r.redact else line}" for path, line in r.good]
                out += ["```"]
        return "\n".join(out) + "\n"
    width = max(len(r.title) for r in RULES)
    lines = [f"{r.id}  {str(r.severity):<8}  {r.side:<7}  {r.title:<{width}}" for r in RULES]
    return "\n".join(lines) + "\n"
