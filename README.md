# DiffGuard

[![CI](https://github.com/mostaphaelansari/Feature-to-Production-Autonomous-Flow/actions/workflows/ci.yml/badge.svg)](https://github.com/mostaphaelansari/Feature-to-Production-Autonomous-Flow/actions/workflows/ci.yml)
![Python](https://img.shields.io/badge/python-3.10%20%E2%80%93%203.13-blue)
![License](https://img.shields.io/badge/license-MIT-green)

**Security checks and risk triage for pull requests.** DiffGuard reads only what a
change *adds and removes*, so it needs no baseline for existing code and flags
only what the pull request introduced. A typical PR scans in well under a second
(a 30,000-line diff takes about 2.5 s).

- **Dangerous additions:** leaked keys, SQL built from strings, `eval` on input,
  shell injection, TLS verification turned off, unsafe deserialization, XSS sinks,
  CSRF or auth switched off, and more. See the [26 rules](docs/rules.md).
- **Deleted safety controls**, which most scanners don't look for: a removed
  `@login_required`, a deleted permission check, CSRF middleware or password
  hashing taken out.
- **Sensitive areas**: changes to auth, payments, migrations, infrastructure or
  dependencies get routed to the right reviewers.

Every point of the 0–100 score has a reason you can read.

```console
$ diffguard scan --base main
DiffGuard: HIGH risk (score 100/100) - 1 file, +2/-2 lines

Score breakdown:
  +70  DG201                  SQL built from string formatting (critical, 1 occurrence)
  +45  DG601                  Authentication or authorization check removed (high, 1 occurrence)
  +25  DOMAIN_AUTH            Touches auth (1 file)

Findings (2):
  CRITICAL DG201  app/views.py:6  SQL built from string formatting
           + rows = cursor.execute(f"SELECT * FROM orders WHERE status = '{status}'")
  HIGH     DG601  app/views.py:3  Authentication or authorization check removed
           - @login_required

Sensitive areas: auth
```

## Quick start

### GitHub Actions

```yaml
# .github/workflows/diffguard.yml
name: DiffGuard
on: pull_request

permissions:
  contents: read
  pull-requests: write   # for the PR comment

jobs:
  diffguard:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0
      - uses: mostaphaelansari/Feature-to-Production-Autonomous-Flow@v0.2.0
        with:
          fail-on: high          # low | medium | high | never
```

You get inline annotations on the diff, a PR comment that updates on each push,
a job summary, and a failing check on high risk. To block merging, make the
check required in branch protection.

| Input | Default | |
|---|---|---|
| `fail-on` | `high` | Fail at this level or above (`low`, `medium`, `high`, `never`). |
| `base` | PR base commit | Ref to compare against. |
| `config` | auto | Config file path. |
| `comment` | `true` | Post/update a PR comment. |
| `annotations` | `true` | Inline annotations on the diff. |
| `sarif-file` | | Also write SARIF, for `github/codeql-action/upload-sarif`. |

Outputs: `risk-level`, `risk-score`, `report-json`.

### Command line

```bash
pip install diffguard-scan          # Python 3.10+; no dependencies on 3.11+

diffguard scan                      # uncommitted changes vs HEAD
diffguard scan --staged             # what you're about to commit
diffguard scan --base origin/main   # everything on this branch
git diff main | diffguard scan --diff -
```

Until the first PyPI release:
`pip install "git+https://github.com/mostaphaelansari/Feature-to-Production-Autonomous-Flow"`.

### pre-commit

```yaml
# .pre-commit-config.yaml
repos:
  - repo: https://github.com/mostaphaelansari/Feature-to-Production-Autonomous-Flow
    rev: v0.2.0
    hooks:
      - id: diffguard
```

### GitLab CI

See [docs/gitlab.md](docs/gitlab.md).

## How the score works

| Source | Points |
|---|---|
| Each rule that fires (counted once per rule) | critical 70 · high 45 · medium 20 · low 5 |
| Sensitive area touched | auth, payment, database 25 · security 20 · infrastructure 15 · dependencies, concurrency 10 · configuration 5 |
| Change size (code lines) | ≥300: 10 · ≥800: 25 |

The score is capped at 100. **Low** is under 25, **medium** is 25 or more or
any medium/high finding, and **high** (the level that blocks by default) is any
critical finding, or a score of 60+ that includes at least one medium-or-worse
finding. Sensitive areas and size on their own top out at medium: they route
review but never block. Documentation and test files never count toward
sensitive areas, and test files skip most rules, so editing a README or a test
fixture stays low.

Sensitive areas come from **file paths** (`src/billing/`, `migrations/`,
`Dockerfile`, `requirements.txt`…) and **specific identifiers** in changed code
(`login`, `bcrypt`, `stripe`, `CREATE TABLE`, `threading.Lock`…). Identifiers are
matched as whole words after splitting `snake_case` and `camelCase`, so
`author` doesn't count as auth and `rapid` doesn't count as api.

## Configuration

Put this in `pyproject.toml` under `[tool.diffguard]`, or in a `.diffguard.toml`
without the prefix. Unknown keys and rule IDs are errors, not silently ignored.

```toml
[tool.diffguard]
fail-on = "high"
thresholds = { medium = 25, high = 60 }
extend-exclude = ["generated/**", "**/*.pb.go"]
test-paths = ["qa/**"]              # treated like tests
disable = ["DG303"]                 # turn rules off
severity = { DG305 = "high" }       # re-rank rules

[tool.diffguard.per-path-ignores]
"scripts/**" = ["DG203"]
"examples/**" = ["*"]

[tool.diffguard.domains.pricing]    # your own sensitive area
paths = ["src/pricing/**"]
weight = 30

[tool.diffguard.domains.configuration]
weight = 0                          # don't score config changes

[tool.diffguard.reviewers]          # shown as "suggested reviewers"
auth = ["@acme/identity"]
payment = ["@acme/payments"]
findings = ["@acme/appsec"]         # any medium+ finding
```

**Suppress one line** with a comment on that line: `# diffguard: ignore[DG203]`,
or `# diffguard: ignore` for all rules.

## Output formats

`--format text|json|markdown|sarif|github` sets what goes to stdout, and
`-o FORMAT=PATH` (repeatable) writes extra files. The JSON format has a
[schema](schema/report-v1.schema.json). `diffguard gate report.json --fail-on high`
applies a threshold to a saved report later.

Exit codes: `0` below the threshold, `1` at or above it, `2` for errors (bad
config, missing git history, etc.).

## Tamper resistance

A gate that runs from the pull request's own workflow file can be edited by the
pull request. For CI that has to hold against its own authors:

- **GitHub:** run DiffGuard through an organization
  [ruleset with required workflows](https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-rulesets/available-rules-for-rulesets#require-workflows-to-pass-before-merging),
  so the workflow comes from a repository the author can't change, and pin the
  action to a commit SHA.
- **GitLab:** use a pipeline execution policy or a compliance pipeline (see
  [docs/gitlab.md](docs/gitlab.md#tamper-resistance)).

Changes to CI files themselves (`.github/workflows/`, `.gitlab-ci.yml`) count as
the `infrastructure` area, so they're always visible in the report.

## Limitations

- **This is pattern matching, not program analysis.** It doesn't follow data
  across functions or files, so a query built in one function and run in another
  is missed. Python files get syntax-tree checks for SQL, `eval` and shell calls;
  other languages use line-level patterns.
- **The removed-control rules are heuristics.** Moving a check into middleware
  in another file is flagged unless the same line is re-added somewhere in the
  diff, and a reviewer has to confirm.
- **The accuracy numbers come only from this project's own test corpus**
  ([tests/test_corpus.py](tests/test_corpus.py)): 35 realistic changes, all
  classified as expected. That corpus was written alongside the rules, so treat
  it as a regression suite, not a benchmark. Please open an issue with any
  false positive or miss.
- It complements a full SAST tool (CodeQL, Semgrep) and a secret scanner on the
  whole repository. It doesn't replace them.

## Development

```bash
pip install -e ".[dev]"
pytest
ruff check .
diffguard rules --format markdown > docs/rules.md   # after changing rules
```

Each rule in [src/diffguard/rules.py](src/diffguard/rules.py) includes examples
it must flag and examples it must not. The test suite enforces both, and the
rules page is generated from them. To report a misclassification, add a case to
[tests/test_corpus.py](tests/test_corpus.py).

## History

The project started as a hackathon prototype for autonomous merge-request
review ([presentation](presentation.html), [slides](docs/gallery/)). Version 0.2
replaced the keyword-scoring prototype with the rule engine described here; see
the [changelog](CHANGELOG.md).

## License

[MIT](LICENSE)
