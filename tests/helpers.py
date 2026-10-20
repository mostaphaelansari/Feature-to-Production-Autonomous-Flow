from __future__ import annotations


def make_diff(
    path: str,
    added: list[str] | tuple[str, ...] = (),
    removed: list[str] | tuple[str, ...] = (),
    start: int = 1,
    status: str = "modified",
) -> str:
    """Build a single-hunk git diff for *path*."""
    header = f"diff --git a/{path} b/{path}\n"
    if status == "added":
        header += "new file mode 100644\n--- /dev/null\n"
    else:
        header += f"--- a/{path}\n"
    header += "+++ /dev/null\n" if status == "deleted" else f"+++ b/{path}\n"
    body = "".join(f"-{line}\n" for line in removed) + "".join(f"+{line}\n" for line in added)
    old_start = 0 if status == "added" else start
    new_start = 0 if status == "deleted" else start
    return f"{header}@@ -{old_start},{len(removed)} +{new_start},{len(added)} @@\n{body}"


def rule_ids(report) -> set[str]:
    return {f.rule_id for f in report.findings}
