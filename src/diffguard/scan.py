"""Run every check over a diff and produce a :class:`Report`."""
from __future__ import annotations

import re
from collections.abc import Callable

from .config import Config
from .diff import parse_diff
from .domains import detect_domains
from .files import FileInfo, classify, match_glob, matches_any
from .models import DomainHit, FileDiff, FileSummary, Finding, Report, Severity
from .pyast import check_python
from .rules import RULES, Rule, redact
from .scoring import score

SourceProvider = Callable[[str], "str | None"]

_SUPPRESS_RE = re.compile(r"(?i)diffguard:\s*ignore(?:\[(?P<ids>[A-Z0-9,\s]+)\])?")
_MAX_LINE_LENGTH = 2000  # skip minified / generated lines


def _normalize(text: str) -> str:
    return " ".join(text.split())


def _suppressed(text: str, rule_id: str) -> bool:
    match = _SUPPRESS_RE.search(text)
    if not match:
        return False
    ids = match.group("ids")
    return ids is None or rule_id in {i.strip().upper() for i in ids.split(",")}


def _snippet(text: str) -> str:
    text = text.strip()
    return text if len(text) <= 200 else text[:197] + "..."


class _Checker:
    def __init__(self, cfg: Config, source: SourceProvider | None) -> None:
        self.cfg = cfg
        self.source = source

    def rules_for(self, info: FileInfo) -> list[Rule]:
        ignored: set[str] = set()
        for glob, ids in self.cfg.per_path_ignores.items():
            if match_glob(info.path, glob):
                ignored.update(ids)
        if "*" in ignored:
            return []
        return [
            rule
            for rule in RULES
            if rule.id not in self.cfg.disable and rule.id not in ignored and rule.applies_to(info)
        ]

    def finding(self, rule: Rule, path: str, line: int, text: str, kind: str) -> Finding:
        message = rule.description if kind == "added" else f"Removed: {rule.description}"
        return Finding(
            rule_id=rule.id,
            severity=self.cfg.severity.get(rule.id, rule.severity),
            title=rule.title,
            message=message,
            path=path,
            line=max(line, 1),
            snippet=_snippet(redact(text) if rule.redact else text),
            kind=kind,
        )

    def python_ast(self, fd: FileDiff, rules: list[Rule]) -> list[Finding] | None:
        """AST findings for a Python file, or None when the source is unavailable
        or does not match the diff (callers then fall back to regex matching)."""
        if self.source is None or not fd.added:
            return None
        text = self.source(fd.path)
        if text is None:
            return None
        lines = text.splitlines()
        for line in fd.added:
            if line.number > len(lines) or lines[line.number - 1].rstrip() != line.text.rstrip():
                return None
        results = check_python(text, {line.number for line in fd.added})
        if results is None:
            return None
        enabled = {rule.id: rule for rule in rules if rule.ast_checked}
        findings = []
        for rule_id, number in results:
            rule = enabled.get(rule_id)
            source_line = lines[number - 1]
            if rule and not _suppressed(source_line, rule_id):
                findings.append(self.finding(rule, fd.path, number, source_line, "added"))
        return findings

    def check(self, fd: FileDiff, info: FileInfo, added_elsewhere: set[str]) -> list[Finding]:
        rules = self.rules_for(info)
        if not rules:
            return []
        findings: list[Finding] = []

        ast_findings = None
        if info.language == "python" and info.kind == "code":
            ast_findings = self.python_ast(fd, rules)
        if ast_findings is not None:
            findings.extend(ast_findings)

        ast_ran = ast_findings is not None
        added_rules = [r for r in rules if r.side == "added" and not (ast_ran and r.ast_checked)]
        for line in fd.added:
            if len(line.text) > _MAX_LINE_LENGTH:
                continue
            for rule in added_rules:
                if rule.search(line.text, info) and not _suppressed(line.text, rule.id):
                    findings.append(self.finding(rule, fd.path, line.number, line.text, "added"))

        if fd.status != "deleted":
            removed_rules = [r for r in rules if r.side == "removed"]
            for line in fd.removed:
                if _normalize(line.text) in added_elsewhere or len(line.text) > _MAX_LINE_LENGTH:
                    continue  # moved, not deleted
                for rule in removed_rules:
                    if rule.search(line.text, info):
                        findings.append(
                            self.finding(rule, fd.path, line.anchor or 1, line.text, "removed")
                        )
        return findings


def scan(diff_text: str, cfg: Config | None = None, source: SourceProvider | None = None) -> Report:
    """Analyze *diff_text*. *source* returns the post-change contents of a path
    (enables AST checks for Python); without it, regex rules are used throughout."""
    cfg = cfg or Config()
    files = parse_diff(diff_text)
    added_everywhere = {_normalize(line.text) for fd in files for line in fd.added}
    checker = _Checker(cfg, source)

    findings: list[Finding] = []
    domains: dict[str, list[DomainHit]] = {}
    summaries: list[FileSummary] = []

    for fd in files:
        info = classify(fd.path, fd.binary, cfg.test_paths)
        excluded = matches_any(fd.path, cfg.exclude)
        summaries.append(
            FileSummary(
                path=fd.path,
                status=fd.status,
                language=info.language,
                kind=info.kind,
                added=len(fd.added),
                removed=len(fd.removed),
                excluded=excluded,
            )
        )
        if excluded or info.kind == "binary":
            continue
        findings.extend(checker.check(fd, info, added_everywhere))
        for hit in detect_domains(fd, info, cfg.domain_paths):
            domains.setdefault(hit.domain, []).append(hit)

    unique: dict[tuple[str, str, int], Finding] = {}
    for finding in findings:
        unique.setdefault((finding.rule_id, finding.path, finding.line), finding)
    findings = sorted(unique.values(), key=lambda f: (-f.severity, f.path, f.line, f.rule_id))

    code_lines = sum(
        s.added + s.removed for s in summaries if not s.excluded and s.kind in ("code", "config")
    )
    total, level, reasons = score(findings, domains, code_lines, cfg)

    reviewers: list[str] = []
    wanted = list(domains)
    if any(f.severity >= Severity.MEDIUM for f in findings):
        wanted.append("findings")
    for key in wanted:
        for person in cfg.reviewers.get(key, []):
            if person not in reviewers:
                reviewers.append(person)

    return Report(
        score=total,
        level=level,
        reasons=reasons,
        findings=findings,
        domains=domains,
        files=summaries,
        suggested_reviewers=reviewers,
    )
