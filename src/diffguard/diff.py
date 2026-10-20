"""Unified diff parser that keeps line numbers for every change."""
from __future__ import annotations

import re

from .models import FileDiff, Line

_HUNK_RE = re.compile(r"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@")
_GIT_HEADER_RE = re.compile(r'^diff --git ("?a/.*?"?) ("?b/.*"?)$')


def _unquote(path: str) -> str:
    """Undo git's C-style quoting of paths with special characters."""
    path = path.strip()
    if len(path) >= 2 and path[0] == '"' and path[-1] == '"':
        inner = path[1:-1]
        try:
            path = inner.encode("latin-1").decode("unicode_escape").encode("latin-1").decode(
                "utf-8"
            )
        except (UnicodeDecodeError, UnicodeEncodeError):
            path = inner
    return path


def _strip_prefix(path: str) -> str:
    path = _unquote(path)
    if path.startswith(("a/", "b/")):
        return path[2:]
    return path


def parse_diff(text: str) -> list[FileDiff]:
    """Parse a unified diff (``git diff`` output or plain ``diff -u``)."""
    files: list[FileDiff] = []
    current: FileDiff | None = None
    old_no = new_no = 0
    old_left = new_left = 0

    for raw in text.splitlines():
        if old_left > 0 or new_left > 0:
            if raw.startswith("\\"):  # "\ No newline at end of file"
                continue
            tag, content = (raw[0], raw[1:]) if raw else (" ", "")
            if tag == "+" and new_left > 0:
                current.added.append(Line(new_no, content))
                new_no += 1
                new_left -= 1
                continue
            if tag == "-" and old_left > 0:
                current.removed.append(Line(old_no, content, anchor=new_no))
                old_no += 1
                old_left -= 1
                continue
            if tag == " ":
                old_no += 1
                new_no += 1
                old_left = max(old_left - 1, 0)
                new_left = max(new_left - 1, 0)
                continue
            old_left = new_left = 0  # malformed hunk: fall through to header parsing

        if raw.startswith("diff --git "):
            match = _GIT_HEADER_RE.match(raw)
            path = _strip_prefix(match.group(2)) if match else "unknown"
            current = FileDiff(path=path)
            files.append(current)
            continue

        if current is None:
            if not raw.startswith("--- "):
                continue
            current = FileDiff(path="unknown")
            files.append(current)

        hunk = _HUNK_RE.match(raw)
        if hunk:
            old_no, new_no = int(hunk.group(1)), int(hunk.group(3))
            old_left = int(hunk.group(2)) if hunk.group(2) is not None else 1
            new_left = int(hunk.group(4)) if hunk.group(4) is not None else 1
            continue

        if raw.startswith("--- "):
            # A second "--- " outside a hunk starts a new file in plain diffs.
            if current.added or current.removed:
                current = FileDiff(path="unknown")
                files.append(current)
            target = raw[4:].split("\t")[0]
            if target != "/dev/null":
                current.old_path = _strip_prefix(target)
                if current.path == "unknown":
                    current.path = current.old_path
            else:
                current.status = "added"
        elif raw.startswith("+++ "):
            target = raw[4:].split("\t")[0]
            if target == "/dev/null":
                current.status = "deleted"
            else:
                current.path = _strip_prefix(target)
        elif raw.startswith("new file mode"):
            current.status = "added"
        elif raw.startswith("deleted file mode"):
            current.status = "deleted"
        elif raw.startswith("rename from "):
            current.old_path = _unquote(raw[len("rename from "):])
            current.status = "renamed"
        elif raw.startswith("rename to "):
            current.path = _unquote(raw[len("rename to "):])
            current.status = "renamed"
        elif raw.startswith(("Binary files ", "GIT binary patch")):
            current.binary = True

    return files
