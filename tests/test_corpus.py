"""End-to-end expectations on realistic changes.

Each case is a small but realistic diff with the risk level a reviewer would
expect. Add a case here whenever DiffGuard gets something wrong.
"""
from __future__ import annotations

import pytest
from helpers import make_diff, rule_ids

from diffguard import scan

AWS_KEY = "AKIA" + "Z7QW3RT5YU8IOP2L"

# (name, expected level, expected rule ids subset, diff)
CASES = [
    # ── should pass quietly ───────────────────────────────────────────
    ("readme typo", "low", set(),
     make_diff("README.md", ["Written by the original author. See the auth guide."],
               ["Written by the author."])),
    ("plain refactor", "low", set(),
     make_diff("src/utils.py", [f"total_{i} = compute_{i}(items)" for i in range(40)],
               [f"t{i} = compute_{i}(items)" for i in range(40)])),
    ("tests with fake secrets and eval", "low", set(),
     make_diff("tests/test_api.py", ['PASSWORD = "hunter2hunter2"', "assert eval('1+1') == 2",
                                     "requests.get(url, verify=False)"])),
    ("huge lockfile bump", "low", set(),
     make_diff("package-lock.json", [f'"dep{i}": "1.0.{i}",' for i in range(5000)])),
    ("css tweak", "low", set(), make_diff("web/styles.css", ["color: #333;"], ["color: #222;"])),
    ("sqlalchemy session", "low", set(),
     make_diff("src/repo.py", ["with Session() as session:", "    session.add(item)"])),
    ("lexer tokens", "low", set(),
     make_diff("src/lexer.py", ["tokens = tokenize(text)", "for tok in tokens: emit(tok)"])),
    ("react route", "low", set(),
     make_diff("web/App.tsx", ["<Route path='/about' element={<About/>} />"])),
    ("parameterized query", "low", set(),
     make_diff("src/db.py", ['cur.execute("SELECT * FROM t WHERE id = %s", (uid,))'])),
    ("file lock", "low", set(), make_diff("src/cache.py", ["with FileLock(path):", "    write(path)"])),
    ("presentation html", "low", set(),
     make_diff("presentation.html", ["<p>Auth, payments and async work.</p>"])),
    ("dockerfile base bump", "low", set(),
     make_diff("Dockerfile", ["FROM python:3.12-slim"], ["FROM python:3.11-slim"])),
    ("dependency bump", "low", set(),
     make_diff("requirements.txt", ["requests==2.32.3"], ["requests==2.31.0"])),
    # ── should be routed to a reviewer ────────────────────────────────
    ("logging change in auth module", "medium", set(),
     make_diff("src/auth/views.py", ["logger.info('login page rendered')"])),
    ("django migration", "medium", set(),
     make_diff("app/migrations/0003_add_field.py",
               ["migrations.AddField(model_name='order', name='note', field=models.TextField())"],
               status="added")),
    ("hardcoded api key", "medium", {"DG103"},
     make_diff("src/client.py", ['API_KEY = "sk-live-9f8e7d6c5b"'])),
    ("tls verification off", "medium", {"DG301"},
     make_diff("src/http.py", ["r = requests.get(url, verify=False)"])),
    ("pickle from request", "medium", {"DG204"},
     make_diff("src/api.py", ["obj = pickle.loads(request.data)"])),
    ("xss sink", "medium", {"DG205"}, make_diff("web/app.js", ["el.innerHTML = comment.body"])),
    ("debug on in prod settings", "medium", {"DG501"},
     make_diff("config/settings.py", ["DEBUG = True"], ["DEBUG = False"])),
    ("cors any origin", "medium", {"DG502"},
     make_diff("src/main.py", ['app.add_middleware(CORSMiddleware, allow_origins=["*"])'])),
    ("go shell injection", "medium", {"DG203"},
     make_diff("cmd/run.go", ['cmd := exec.Command("sh", "-c", userInput)'])),
    ("big feature without keywords", "medium", set(),
     make_diff("src/reports/export.py", [f"row_{i} = build_row({i})" for i in range(900)])),
    # ── should block ─────────────────────────────────────────────────
    ("aws key in config", "high", {"DG102"},
     make_diff("config/prod.yml", [f"aws_access_key_id: {AWS_KEY}"])),
    ("sql injection", "high", {"DG201"},
     make_diff("src/q.py", ['cur.execute(f"SELECT * FROM t WHERE id={uid}")'])),
    ("js sql template", "high", {"DG201"},
     make_diff("api/users.js", ["db.query(`SELECT * FROM users WHERE id = ${req.params.id}`)"])),
    ("eval user input", "high", {"DG202"},
     make_diff("src/calc.py", ["return eval(request.args['expr'])"])),
    ("login_required removed", "high", {"DG601"},
     make_diff("src/views.py", ["def account(request):"],
               ["@login_required", "def account(request):"])),
    ("auth check removed", "high", {"DG601"},
     make_diff("src/views.py", ["pass"], ["if not current_user.is_authenticated:", "    abort(401)"])),
    ("csrf exempt added", "high", {"DG402"},
     make_diff("src/views.py", ["@csrf_exempt", "def webhook(request):"])),
    ("csrf middleware removed", "high", {"DG602"},
     make_diff("src/app.js", ["app.use(express.json())"], ["app.use(csrfProtection)"])),
    ("password hashing removed", "high", {"DG603"},
     make_diff("src/users.py", ["user.pw = raw"], ["user.pw = bcrypt.hash(raw)"])),
    ("allow any on api", "high", {"DG401"},
     make_diff("src/api/views.py", ["    permission_classes = [AllowAny]"],
               ["    permission_classes = [IsAuthenticated]"])),
    ("tls off in payment client", "high", {"DG301"},
     make_diff("src/payments/gateway.py", ["resp = requests.post(url, json=p, verify=False)"])),
    ("original fixture: weakened auth", "high", {"DG601", "DG604", "DG403"},
     make_diff("src/auth.py", ["if not token:", "    return False", "if is_internal(user):",
                               "grant_admin(user)"],
               ["if not validate(token):", "    return False",
                'if not has_permission(user, "admin"):'])),
]


@pytest.mark.parametrize(("name", "level", "rules", "diff"), CASES, ids=[c[0] for c in CASES])
def test_corpus(name, level, rules, diff):
    report = scan(diff)
    found = rule_ids(report)
    detail = f"{name}: score={report.score} reasons={[r.code for r in report.reasons]}"
    assert str(report.level) == level, detail
    assert rules <= found, detail
