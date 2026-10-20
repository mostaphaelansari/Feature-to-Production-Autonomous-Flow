"""Thin wrappers around the git CLI."""
from __future__ import annotations

import subprocess
from pathlib import Path


class GitError(RuntimeError):
    pass


def run_git(args: list[str], cwd: Path) -> str:
    try:
        proc = subprocess.run(
            ["git", "-c", "core.quotepath=false", *args],
            cwd=cwd,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            check=False,
        )
    except FileNotFoundError as exc:
        raise GitError("git executable not found on PATH") from exc
    if proc.returncode != 0:
        raise GitError(proc.stderr.strip() or f"git {' '.join(args)} failed")
    return proc.stdout


def diff_text(cwd: Path, base: str | None = None, head: str | None = None,
              staged: bool = False) -> str:
    """Return the diff to scan.

    * ``staged``: the index against HEAD (pre-commit).
    * ``base``: changes on ``head`` (default HEAD) since it diverged from ``base``.
    * neither: uncommitted changes (staged and unstaged) against HEAD.
    """
    args = ["diff", "--no-color", "--no-ext-diff", "--unified=0", "-M"]
    if staged:
        args.append("--cached")
    elif base:
        args.append(f"{base}...{head or 'HEAD'}")
    else:
        args.append("HEAD")
    try:
        return run_git(args, cwd)
    except GitError as exc:
        message = str(exc)
        if base and ("no merge base" in message or "unknown revision" in message
                     or "bad revision" in message):
            message += (
                "\nhint: the base commit is missing locally. In CI, fetch full history "
                "(e.g. actions/checkout with fetch-depth: 0)."
            )
        raise GitError(message) from exc


def show_file(cwd: Path, rev: str, path: str) -> str | None:
    """Contents of *path* at *rev* (``""`` rev means the index), or None."""
    try:
        return run_git(["show", f"{rev}:{path}"], cwd)
    except GitError:
        return None


def repo_root(cwd: Path) -> Path:
    return Path(run_git(["rev-parse", "--show-toplevel"], cwd).strip())
