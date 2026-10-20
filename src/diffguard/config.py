"""Load ``[tool.diffguard]`` from pyproject.toml or a standalone .diffguard.toml."""
from __future__ import annotations

import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .domains import CUSTOM_DOMAIN_WEIGHT, DEFAULT_WEIGHTS
from .models import RiskLevel, Severity
from .rules import RULES_BY_ID

if sys.version_info >= (3, 11):
    import tomllib
else:  # pragma: no cover
    import tomli as tomllib

DEFAULT_EXCLUDE = [
    "**/node_modules/**",
    "**/vendor/**",
    "**/dist/**",
    "**/*.min.js",
    "**/*.min.css",
    "**/*.map",
    "**/package-lock.json",
    "**/yarn.lock",
    "**/pnpm-lock.yaml",
    "**/poetry.lock",
    "**/Pipfile.lock",
    "**/uv.lock",
    "**/Cargo.lock",
    "**/go.sum",
    "**/composer.lock",
    "**/Gemfile.lock",
]

_TOP_LEVEL_KEYS = {
    "fail-on",
    "thresholds",
    "size",
    "exclude",
    "extend-exclude",
    "test-paths",
    "disable",
    "severity",
    "per-path-ignores",
    "domains",
    "reviewers",
}


class ConfigError(ValueError):
    pass


@dataclass
class Config:
    fail_on: RiskLevel | None = RiskLevel.HIGH  # None = never fail
    medium_threshold: int = 25
    high_threshold: int = 60
    size_medium: int = 300
    size_large: int = 800
    exclude: list[str] = field(default_factory=lambda: list(DEFAULT_EXCLUDE))
    test_paths: list[str] = field(default_factory=list)
    disable: set[str] = field(default_factory=set)
    severity: dict[str, Severity] = field(default_factory=dict)
    per_path_ignores: dict[str, list[str]] = field(default_factory=dict)
    domain_weights: dict[str, int] = field(default_factory=lambda: dict(DEFAULT_WEIGHTS))
    domain_paths: dict[str, list[str]] = field(default_factory=dict)
    reviewers: dict[str, list[str]] = field(default_factory=dict)
    source: str | None = None


def parse_fail_on(value: str) -> RiskLevel | None:
    if value.strip().lower() == "never":
        return None
    return RiskLevel.parse(value)


def _norm(table: dict[str, Any]) -> dict[str, Any]:
    return {key.replace("_", "-"): value for key, value in table.items()}


def _str_list(value: Any, name: str) -> list[str]:
    if not isinstance(value, list) or not all(isinstance(v, str) for v in value):
        raise ConfigError(f"'{name}' must be a list of strings")
    return list(value)


def _check_rule_ids(ids: list[str], name: str, allow_star: bool = False) -> None:
    unknown = [i for i in ids if i not in RULES_BY_ID and not (allow_star and i == "*")]
    if unknown:
        raise ConfigError(f"unknown rule id(s) in '{name}': {', '.join(unknown)}")


def config_from_dict(data: dict[str, Any], source: str | None = None) -> Config:
    data = _norm(data)
    unknown = set(data) - _TOP_LEVEL_KEYS
    if unknown:
        raise ConfigError(f"unknown option(s): {', '.join(sorted(unknown))}")

    cfg = Config(source=source)
    try:
        if "fail-on" in data:
            cfg.fail_on = parse_fail_on(str(data["fail-on"]))

        thresholds = _norm(data.get("thresholds", {}))
        cfg.medium_threshold = int(thresholds.get("medium", cfg.medium_threshold))
        cfg.high_threshold = int(thresholds.get("high", cfg.high_threshold))
        if not 0 < cfg.medium_threshold < cfg.high_threshold <= 100:
            raise ConfigError("thresholds must satisfy 0 < medium < high <= 100")

        size = _norm(data.get("size", {}))
        cfg.size_medium = int(size.get("medium", cfg.size_medium))
        cfg.size_large = int(size.get("large", cfg.size_large))

        if "exclude" in data:
            cfg.exclude = _str_list(data["exclude"], "exclude")
        cfg.exclude += _str_list(data.get("extend-exclude", []), "extend-exclude")
        cfg.test_paths = _str_list(data.get("test-paths", []), "test-paths")

        disable = _str_list(data.get("disable", []), "disable")
        _check_rule_ids(disable, "disable")
        cfg.disable = set(disable)

        severity = data.get("severity", {})
        _check_rule_ids(list(severity), "severity")
        cfg.severity = {rule_id: Severity.parse(str(v)) for rule_id, v in severity.items()}

        for glob, ids in data.get("per-path-ignores", {}).items():
            ids = _str_list(ids, f"per-path-ignores.{glob}")
            _check_rule_ids(ids, f"per-path-ignores.{glob}", allow_star=True)
            cfg.per_path_ignores[glob] = ids

        for name, table in data.get("domains", {}).items():
            table = _norm(table)
            extra = ", ".join(sorted(set(table) - {"paths", "weight"}))
            if extra:
                raise ConfigError(f"unknown option(s) in domains.{name}: {extra}")
            if "weight" in table:
                cfg.domain_weights[name] = int(table["weight"])
            if "paths" in table:
                cfg.domain_paths[name] = _str_list(table["paths"], f"domains.{name}.paths")
                cfg.domain_weights.setdefault(name, CUSTOM_DOMAIN_WEIGHT)

        for name, people in data.get("reviewers", {}).items():
            cfg.reviewers[name] = _str_list(people, f"reviewers.{name}")
    except (TypeError, ValueError) as exc:
        if isinstance(exc, ConfigError):
            raise
        raise ConfigError(str(exc)) from exc
    return cfg


def load_config(path: Path | None = None, root: Path | None = None) -> Config:
    """Load an explicit config file, or discover one in *root*.

    Discovery order: ``.diffguard.toml``, then ``[tool.diffguard]`` in ``pyproject.toml``.
    """
    candidates = [path] if path else [
        (root or Path.cwd()) / ".diffguard.toml",
        (root or Path.cwd()) / "pyproject.toml",
    ]
    for candidate in candidates:
        if candidate is None or not candidate.is_file():
            if path is not None:
                raise ConfigError(f"config file not found: {path}")
            continue
        try:
            data = tomllib.loads(candidate.read_text(encoding="utf-8"))
        except tomllib.TOMLDecodeError as exc:
            raise ConfigError(f"{candidate}: {exc}") from exc
        table = data.get("tool", {}).get("diffguard")
        if table is None and candidate.name != "pyproject.toml":
            table = data
        if table is None:
            continue
        try:
            return config_from_dict(table, source=str(candidate))
        except ConfigError as exc:
            raise ConfigError(f"{candidate}: {exc}") from exc
    return Config()
