"""AST checks run when the post-change Python source is available."""
from __future__ import annotations

from helpers import make_diff, rule_ids

from diffguard import scan
from diffguard.pyast import check_python


def _scan_source(source: str, changed: list[int]):
    lines = source.splitlines()
    added = [lines[n - 1] for n in changed]
    diff = make_diff("app/db.py", added=added, start=changed[0])
    return scan(diff, source=lambda path: source)


def test_multiline_sql_injection_is_caught():
    source = 'def get(cur, uid):\n    cur.execute(\n        f"SELECT * FROM users WHERE id={uid}"\n    )\n'
    report = _scan_source(source, [3])
    assert "DG201" in rule_ids(report)
    assert report.findings[0].line == 3


def test_parameterized_query_is_clean():
    source = 'def get(cur, uid):\n    cur.execute("SELECT * FROM users WHERE id = %s", (uid,))\n'
    assert "DG201" not in rule_ids(_scan_source(source, [2]))


def test_eval_inside_string_literal_is_ignored():
    source = 'HELP = "never call eval(x) on input"\n'
    assert "DG202" not in rule_ids(_scan_source(source, [1]))


def test_shell_true_with_literal_command_is_ignored_by_ast():
    source = "import subprocess\nsubprocess.run('ls -l', shell=True)\n"
    assert "DG203" not in rule_ids(_scan_source(source, [2]))


def test_shell_true_with_dynamic_command_is_caught():
    source = "import subprocess\nsubprocess.run(f'ls {d}', shell=True)\n"
    assert "DG203" in rule_ids(_scan_source(source, [2]))


def test_mismatched_source_falls_back_to_regex():
    diff = make_diff("app/db.py", added=["return eval(expr)"])
    report = scan(diff, source=lambda path: "something else entirely\n")
    assert "DG202" in rule_ids(report)


def test_syntax_error_returns_none():
    assert check_python("def broken(:\n", {1}) is None
