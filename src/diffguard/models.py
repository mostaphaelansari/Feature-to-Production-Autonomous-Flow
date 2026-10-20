"""Core data types shared across DiffGuard."""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import IntEnum
from typing import Any


class _Named(IntEnum):
    @classmethod
    def parse(cls, value: str):
        try:
            return cls[value.strip().upper()]
        except KeyError:
            names = ", ".join(m.name.lower() for m in cls)
            raise ValueError(
                f"invalid {cls.__name__} {value!r} (expected one of: {names})"
            ) from None

    def __str__(self) -> str:
        return self.name.lower()


class Severity(_Named):
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4


class RiskLevel(_Named):
    LOW = 1
    MEDIUM = 2
    HIGH = 3


@dataclass(frozen=True)
class Line:
    """A changed line. ``number`` is in the new file for added lines and in the
    old file for removed lines; ``anchor`` is the new-file position of a removal."""

    number: int
    text: str
    anchor: int | None = None


@dataclass
class FileDiff:
    path: str
    old_path: str | None = None
    status: str = "modified"  # added | modified | deleted | renamed
    binary: bool = False
    added: list[Line] = field(default_factory=list)
    removed: list[Line] = field(default_factory=list)


@dataclass
class Finding:
    rule_id: str
    severity: Severity
    title: str
    message: str
    path: str
    line: int
    snippet: str
    kind: str  # "added" (introduced by the change) | "removed" (control deleted)

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "severity": str(self.severity),
            "title": self.title,
            "message": self.message,
            "path": self.path,
            "line": self.line,
            "snippet": self.snippet,
            "kind": self.kind,
        }


@dataclass
class DomainHit:
    domain: str
    path: str
    line: int | None
    evidence: str

    def to_dict(self) -> dict[str, Any]:
        return {"path": self.path, "line": self.line, "evidence": self.evidence}


@dataclass
class ScoreReason:
    code: str
    points: int
    detail: str

    def to_dict(self) -> dict[str, Any]:
        return {"code": self.code, "points": self.points, "detail": self.detail}


@dataclass
class FileSummary:
    path: str
    status: str
    language: str
    kind: str  # code | test | doc | markup | config | binary
    added: int
    removed: int
    excluded: bool

    def to_dict(self) -> dict[str, Any]:
        return {
            "path": self.path,
            "status": self.status,
            "language": self.language,
            "kind": self.kind,
            "added": self.added,
            "removed": self.removed,
            "excluded": self.excluded,
        }


@dataclass
class Report:
    score: int
    level: RiskLevel
    reasons: list[ScoreReason]
    findings: list[Finding]
    domains: dict[str, list[DomainHit]]
    files: list[FileSummary]
    suggested_reviewers: list[str]

    @property
    def stats(self) -> dict[str, int]:
        counted = [f for f in self.files if not f.excluded]
        return {
            "files": len(self.files),
            "added": sum(f.added for f in counted),
            "removed": sum(f.removed for f in counted),
            "code_lines_changed": sum(
                f.added + f.removed for f in counted if f.kind in ("code", "config")
            ),
        }

    def to_dict(self) -> dict[str, Any]:
        from . import __version__

        return {
            "schema_version": "1",
            "tool": {"name": "diffguard", "version": __version__},
            "risk": {
                "score": self.score,
                "level": str(self.level),
                "reasons": [r.to_dict() for r in self.reasons],
            },
            "findings": [f.to_dict() for f in self.findings],
            "domains": {
                name: [h.to_dict() for h in hits] for name, hits in self.domains.items()
            },
            "files": [f.to_dict() for f in self.files],
            "stats": self.stats,
            "suggested_reviewers": self.suggested_reviewers,
        }
