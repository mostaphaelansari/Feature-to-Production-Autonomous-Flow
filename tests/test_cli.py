"""Drive the real CLI against temporary git repositories."""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

GIT = ["git", "-c", "user.name=t", "-c", "user.email=t@example.com", "-c", "commit.gpgsign=false"]


def git(repo: Path, *args: str) -> str:
    return subprocess.run(
        [*GIT, *args], cwd=repo, check=True, capture_output=True, text=True
    ).stdout


def diffguard(repo: Path, *args: str, stdin: str | None = None) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, "-m", "diffguard", *args],
        cwd=repo,
        input=stdin,
        capture_output=True,
        text=True,
        encoding="utf-8",
    )


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    git(tmp_path, "init", "-q", "-b", "main")
    (tmp_path / "app.py").write_text("def handler(request):\n    return 'ok'\n", encoding="utf-8")
    git(tmp_path, "add", ".")
    git(tmp_path, "commit", "-q", "-m", "init")
    return tmp_path


def write(repo: Path, name: str, text: str) -> None:
    path = repo / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def test_clean_working_tree_passes(repo):
    proc = diffguard(repo, "scan")
    assert proc.returncode == 0, proc.stderr
    assert "LOW risk" in proc.stdout


def test_uncommitted_change_blocks_and_writes_reports(repo):
    write(repo, "app.py", "def handler(request):\n    return eval(request.args['q'])\n")
    proc = diffguard(
        repo, "scan", "-o", "json=out/r.json", "-o", "sarif=out/r.sarif",
        "-o", "markdown=out/r.md", "--no-color",
    )
    assert proc.returncode == 1, proc.stderr
    assert "DG202" in proc.stdout and "app.py:2" in proc.stdout
    report = json.loads((repo / "out/r.json").read_text(encoding="utf-8"))
    assert report["risk"]["level"] == "high"
    sarif = json.loads((repo / "out/r.sarif").read_text(encoding="utf-8"))
    assert sarif["runs"][0]["results"][0]["ruleId"] == "DG202"
    assert "<!-- diffguard-report -->" in (repo / "out/r.md").read_text(encoding="utf-8")


def test_fail_on_override_and_never(repo):
    write(repo, "app.py", "import requests\nrequests.get(u, verify=False)\n")
    assert diffguard(repo, "scan").returncode == 0  # medium < default high
    assert diffguard(repo, "scan", "--fail-on", "medium").returncode == 1
    write(repo, "app.py", "eval(x)\n")
    assert diffguard(repo, "scan", "--fail-on", "never").returncode == 0


def test_staged_only_sees_the_index(repo):
    write(repo, "app.py", "eval(x)\n")
    assert diffguard(repo, "scan", "--staged").returncode == 0
    git(repo, "add", "app.py")
    assert diffguard(repo, "scan", "--staged").returncode == 1


def test_base_mode_scans_branch_commits_with_ast(repo):
    git(repo, "checkout", "-q", "-b", "feature")
    write(repo, "db.py", 'def get(cur, uid):\n    cur.execute(\n        f"SELECT * FROM t WHERE id={uid}"\n    )\n')
    git(repo, "add", ".")
    git(repo, "commit", "-q", "-m", "feature")
    proc = diffguard(repo, "scan", "--base", "main", "--format", "json")
    assert proc.returncode == 1, proc.stderr
    findings = json.loads(proc.stdout)["findings"]
    # New file: reported where the multi-line call starts.
    assert [(f["rule_id"], f["line"]) for f in findings] == [("DG201", 2)]


def test_diff_from_stdin_and_github_format(repo):
    diff = (
        "diff --git a/x.js b/x.js\n--- a/x.js\n+++ b/x.js\n@@ -1 +1 @@\n-a\n"
        "+el.innerHTML = msg\n"
    )
    proc = diffguard(repo, "scan", "--diff", "-", "--format", "github", stdin=diff)
    assert proc.returncode == 0
    assert proc.stdout.startswith("::warning file=x.js,line=1,title=DG205")


def test_config_is_respected(repo):
    write(repo, "pyproject.toml", '[tool.diffguard]\ndisable = ["DG202"]\n')
    write(repo, "app.py", "eval(x)\n")
    assert diffguard(repo, "scan").returncode == 0


def test_bad_config_and_non_repo_exit_2(repo, tmp_path_factory):
    write(repo, ".diffguard.toml", 'disable = ["DG000"]\n')
    proc = diffguard(repo, "scan")
    assert proc.returncode == 2 and "unknown rule id" in proc.stderr
    outside = tmp_path_factory.mktemp("not-a-repo")
    proc = diffguard(outside, "scan")
    assert proc.returncode == 2 and "diffguard: error" in proc.stderr


def test_missing_base_gives_hint(repo):
    proc = diffguard(repo, "scan", "--base", "origin/does-not-exist")
    assert proc.returncode == 2
    assert "fetch-depth" in proc.stderr


def test_gate_and_rules_commands(repo):
    write(repo, "app.py", "eval(x)\n")
    diffguard(repo, "scan", "--fail-on", "never", "-o", "json=r.json")
    assert diffguard(repo, "gate", "r.json").returncode == 1
    assert diffguard(repo, "gate", "r.json", "--fail-on", "never").returncode == 0
    rules = diffguard(repo, "rules")
    assert rules.returncode == 0 and "DG101" in rules.stdout
    assert diffguard(repo, "--version").stdout.startswith("diffguard ")


def test_invalid_output_spec(repo):
    proc = diffguard(repo, "scan", "-o", "pdf=x.pdf")
    assert proc.returncode == 2 and "FORMAT=PATH" in proc.stderr
