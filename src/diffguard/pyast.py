"""AST-based checks for Python files.

When the post-change source of a Python file is available, these checks replace
the regex matchers of rules marked ``ast_checked``. Working on the syntax tree
handles multi-line calls and ignores look-alikes in strings and comments.
"""
from __future__ import annotations

import ast
import re

_SQL_METHODS = {"execute", "executemany", "executescript", "exec_driver_sql", "mogrify", "raw"}
_SQL_FUNCTIONS = {"text"}
_SQL_KEYWORDS = re.compile(
    r"(?i)\b(select|insert|update|delete|drop|create|alter|truncate|merge|where|from|values|union)\b"
)
_SUBPROCESS_FUNCS = {"run", "call", "Popen", "check_output", "check_call"}
_SHELL_STRING_FUNCS = {("os", "system"), ("os", "popen"), ("subprocess", "getoutput"),
                       ("subprocess", "getstatusoutput")}


def _is_literal(node: ast.AST) -> bool:
    return isinstance(node, ast.Constant) and isinstance(node.value, (str, bytes))


def _literal_text(node: ast.AST) -> str:
    return " ".join(
        n.value for n in ast.walk(node) if isinstance(n, ast.Constant) and isinstance(n.value, str)
    )


def _is_dynamic_string(node: ast.AST) -> bool:
    """True for strings assembled from literals plus runtime values."""
    if isinstance(node, ast.JoinedStr):
        return any(isinstance(v, ast.FormattedValue) for v in node.values)
    if isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Mod, ast.Add)):
        parts = list(ast.walk(node))
        has_literal = any(_is_literal(p) or isinstance(p, ast.JoinedStr) for p in parts)
        value_nodes = (ast.Name, ast.Attribute, ast.Subscript, ast.Call)
        has_value = any(isinstance(p, value_nodes) for p in parts)
        return has_literal and has_value
    if (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "format"
        and _is_literal(node.func.value)
    ):
        return bool(node.args or node.keywords)
    return False


def _call_target(node: ast.Call) -> tuple[str | None, str]:
    func = node.func
    if isinstance(func, ast.Name):
        return None, func.id
    if isinstance(func, ast.Attribute):
        base = func.value.id if isinstance(func.value, ast.Name) else None
        return base, func.attr
    return None, ""


def _classify(node: ast.Call) -> str | None:
    base, name = _call_target(node)
    first = node.args[0] if node.args else None

    if base is None and name in ("eval", "exec") and first is not None and not _is_literal(first):
        return "DG202"

    is_sql_call = (isinstance(node.func, ast.Attribute) and name in _SQL_METHODS) or (
        name in _SQL_FUNCTIONS
    )
    if first is not None and is_sql_call:
        if _is_dynamic_string(first) and _SQL_KEYWORDS.search(_literal_text(first)):
            return "DG201"

    if base == "subprocess" and name in _SUBPROCESS_FUNCS:
        shell = any(
            kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True
            for kw in node.keywords
        )
        if shell and first is not None and not _is_literal(first):
            return "DG203"

    if (base, name) in _SHELL_STRING_FUNCS and first is not None and not _is_literal(first):
        return "DG203"

    return None


def check_python(source: str, added_lines: set[int]) -> list[tuple[str, int]] | None:
    """Return ``(rule_id, line)`` pairs for calls touching an added line,
    or ``None`` if the source does not parse (callers fall back to regexes)."""
    try:
        tree = ast.parse(source)
    except (SyntaxError, ValueError):
        return None

    results: list[tuple[str, int]] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        end = getattr(node, "end_lineno", None) or node.lineno
        line = next((n for n in range(node.lineno, end + 1) if n in added_lines), None)
        if line is None:
            continue
        rule_id = _classify(node)
        if rule_id:
            results.append((rule_id, line))
    return results
