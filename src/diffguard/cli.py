"""Command-line interface: ``diffguard scan | gate | rules``."""
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from . import __version__, git
from .config import ConfigError, load_config, parse_fail_on
from .models import RiskLevel
from .report import FORMATS, render, render_rules
from .scan import SourceProvider, scan

EXIT_OK = 0
EXIT_RISK = 1
EXIT_ERROR = 2

_FAIL_ON_CHOICES = ("low", "medium", "high", "never")


def _working_tree_source(root: Path) -> SourceProvider:
    def read(path: str) -> str | None:
        try:
            return (root / path).read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            return None

    return read


def _git_source(root: Path, rev: str) -> SourceProvider:
    return lambda path: git.show_file(root, rev, path)


def _use_color(args: argparse.Namespace) -> bool:
    if args.no_color or os.environ.get("NO_COLOR") or not sys.stdout.isatty():
        return False
    return os.name != "nt" or "WT_SESSION" in os.environ or "TERM" in os.environ


def _parse_outputs(specs: list[str]) -> list[tuple[str, Path]]:
    outputs = []
    for spec in specs:
        fmt, sep, path = spec.partition("=")
        if not sep or not path or fmt not in FORMATS:
            choices = ", ".join(FORMATS)
            raise ValueError(
                f"invalid --output {spec!r}; expected FORMAT=PATH with FORMAT in {choices}"
            )
        outputs.append((fmt, Path(path)))
    return outputs


def cmd_scan(args: argparse.Namespace) -> int:
    outputs = _parse_outputs(args.output)
    start = Path(args.repo).resolve()

    if args.diff:
        try:
            root = git.repo_root(start)
        except git.GitError:
            root = start
        if args.diff == "-":
            text = sys.stdin.read()
        else:
            text = Path(args.diff).read_text(encoding="utf-8", errors="replace")
        source = _working_tree_source(root)
    else:
        root = git.repo_root(start)
        text = git.diff_text(root, base=args.base, head=args.head, staged=args.staged)
        if args.staged:
            source = _git_source(root, "")  # the index
        elif args.base:
            source = _git_source(root, args.head or "HEAD")
        else:
            source = _working_tree_source(root)

    cfg = load_config(Path(args.config) if args.config else None, root=root)
    if args.fail_on:
        cfg.fail_on = parse_fail_on(args.fail_on)

    report = scan(text, cfg, source)

    sys.stdout.write(render(report, args.format, color=_use_color(args)))
    for fmt, path in outputs:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(render(report, fmt), encoding="utf-8")

    if cfg.fail_on is not None and report.level >= cfg.fail_on:
        return EXIT_RISK
    return EXIT_OK


def cmd_gate(args: argparse.Namespace) -> int:
    data = json.loads(Path(args.report).read_text(encoding="utf-8"))
    try:
        level = RiskLevel.parse(data["risk"]["level"])
        score = data["risk"]["score"]
    except (KeyError, TypeError) as exc:
        raise ValueError(f"{args.report} is not a DiffGuard JSON report") from exc
    fail_on = parse_fail_on(args.fail_on)
    failed = fail_on is not None and level >= fail_on
    verdict = "FAIL" if failed else "PASS"
    threshold = "never" if fail_on is None else str(fail_on)
    print(f"DiffGuard gate: {verdict} - {str(level).upper()} risk (score {score}/100), "
          f"fail-on={threshold}")
    return EXIT_RISK if failed else EXIT_OK


def cmd_rules(args: argparse.Namespace) -> int:
    sys.stdout.write(render_rules(args.format))
    return EXIT_OK


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="diffguard",
        description="Risk triage and security checks for code changes.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = parser.add_subparsers(dest="command")

    p_scan = sub.add_parser(
        "scan",
        help="scan a diff",
        description=(
            "Scan a change. Default: uncommitted changes against HEAD. "
            "Exit codes: 0 = below --fail-on, 1 = at or above --fail-on, 2 = error."
        ),
    )
    source = p_scan.add_mutually_exclusive_group()
    source.add_argument("--diff", metavar="PATH", help="read a unified diff ('-' for stdin)")
    source.add_argument("--staged", action="store_true", help="scan staged changes (pre-commit)")
    source.add_argument("--base", metavar="REF", help="scan commits since REF (e.g. origin/main)")
    p_scan.add_argument("--head", metavar="REF", help="head commit with --base (default HEAD)")
    p_scan.add_argument("--repo", default=".", metavar="DIR", help="repository (default .)")
    p_scan.add_argument("--config", metavar="PATH", help="config file (default: auto-discover)")
    p_scan.add_argument("--format", choices=FORMATS, default="text", help="stdout format")
    p_scan.add_argument(
        "-o",
        "--output",
        action="append",
        default=[],
        metavar="FORMAT=PATH",
        help="also write a report file; repeatable (e.g. -o sarif=diffguard.sarif)",
    )
    p_scan.add_argument("--fail-on", choices=_FAIL_ON_CHOICES, help="override config fail-on")
    p_scan.add_argument("--no-color", action="store_true", help="disable colored output")
    p_scan.set_defaults(func=cmd_scan)

    p_gate = sub.add_parser("gate", help="apply --fail-on to a saved JSON report")
    p_gate.add_argument("report", help="path to a report written with -o json=PATH")
    p_gate.add_argument("--fail-on", choices=_FAIL_ON_CHOICES, default="high")
    p_gate.set_defaults(func=cmd_gate)

    p_rules = sub.add_parser("rules", help="list built-in rules")
    p_rules.add_argument("--format", choices=("text", "markdown", "json"), default="text")
    p_rules.set_defaults(func=cmd_rules)
    return parser


def main(argv: list[str] | None = None) -> int:
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8", errors="replace")
    parser = build_parser()
    args = parser.parse_args(argv)
    if not getattr(args, "func", None):
        parser.print_help()
        return EXIT_ERROR
    if getattr(args, "head", None) and not getattr(args, "base", None):
        parser.error("--head requires --base")
    try:
        return args.func(args)
    except (ConfigError, git.GitError, OSError, ValueError) as exc:
        print(f"diffguard: error: {exc}", file=sys.stderr)
        return EXIT_ERROR
