"""Built-in rules.

Each rule inspects either the lines a change *adds* (new risk introduced) or the
lines it *removes* (a safety control deleted). Every rule carries ``bad`` and
``good`` examples: the test-suite asserts that each ``bad`` example triggers the
rule and each ``good`` example does not, and ``docs/rules.md`` is generated
from the same data.
"""
from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass, field

from .files import FileInfo, is_comment
from .models import Severity

PY = frozenset({"python"})
JS = frozenset({"javascript", "typescript"})
JVM = frozenset({"java", "kotlin", "scala"})
GO = frozenset({"go"})
PHP = frozenset({"php"})
RUBY = frozenset({"ruby"})
CS = frozenset({"csharp"})
HTML = frozenset({"html"})

CODE = frozenset({"code", "config"})
CODE_MARKUP = frozenset({"code", "markup"})
ALL_TEXT = frozenset({"code", "config", "test", "doc", "markup"})

_PLACEHOLDER_RE = re.compile(
    r"(?i)(change.?me|example|dummy|placeholder|redacted|your[_\-]|xxxx|\*{3}|<[^>]+>|"
    r"\$\{|\{\{|\{[\w.]*\}|%\(|%s|sample|fake|\btest|todo|replace|^password$|^secret$|^\.+$)"
)
_ENV_NAME_RE = re.compile(r"^[A-Z][A-Z0-9_]+$")

_SQL_KEYWORDS = re.compile(
    r"(?i)\b(select|insert|update|delete|drop|create|alter|truncate|merge|where|from|values|union)\b"
)
_SECRETISH = re.compile(
    r"(?i)token|secret|passw|nonce|salt|otp|api_?key|session|csrf|reset|invite|verif|auth"
)
_PASSWORDISH = re.compile(r"(?i)passw|pwd|secret|credential")
_NON_PROD_PATH = re.compile(
    r"(?i)(^|[/._-])(dev|development|local|test|testing|example|sample|demo)([/._-]|$)"
)


_SECRET_RUN_RE = re.compile(r"([A-Za-z0-9_\-+/=!&$#@.]{4})[A-Za-z0-9_\-+/=!&$#@.]{4,}")


def redact(text: str) -> str:
    """Keep the first four characters of every long token, mask the rest."""
    return _SECRET_RUN_RE.sub(r"\1****", text)


def _real_secret(match: re.Match[str]) -> bool:
    value = match.groupdict().get("value") or match.group(0)
    return not _PLACEHOLDER_RE.search(value) and len(set(value)) >= 5


def _real_assigned_secret(match: re.Match[str]) -> bool:
    """Like _real_secret, but also skips values that name an env variable."""
    return _real_secret(match) and not _ENV_NAME_RE.match(match.group("value"))


@dataclass(frozen=True)
class Matcher:
    pattern: re.Pattern[str]
    languages: frozenset[str] | None = None
    exclude: re.Pattern[str] | None = None
    requires: re.Pattern[str] | None = None
    check: Callable[[re.Match[str]], bool] | None = None

    def search(self, text: str, language: str) -> re.Match[str] | None:
        if self.languages is not None and language not in self.languages:
            return None
        match = self.pattern.search(text)
        if match is None:
            return None
        if self.exclude is not None and self.exclude.search(text):
            return None
        if self.requires is not None and not self.requires.search(text):
            return None
        if self.check is not None and not self.check(match):
            return None
        return match


def _m(
    pattern: str,
    languages: frozenset[str] | None = None,
    flags: int = 0,
    exclude: str | None = None,
    requires: re.Pattern[str] | str | None = None,
    check: Callable[[re.Match[str]], bool] | None = None,
) -> Matcher:
    return Matcher(
        pattern=re.compile(pattern, flags),
        languages=languages,
        exclude=re.compile(exclude, flags) if exclude else None,
        requires=re.compile(requires) if isinstance(requires, str) else requires,
        check=check,
    )


@dataclass(frozen=True)
class Rule:
    id: str
    title: str
    severity: Severity
    side: str  # "added" | "removed"
    description: str
    remediation: str
    matchers: tuple[Matcher, ...]
    kinds: frozenset[str] = CODE
    skip_comments: bool = True
    path_exclude: re.Pattern[str] | None = None
    ast_checked: bool = False  # Python files with parseable source use pyast instead
    redact: bool = False  # mask matched values in reports (secrets)
    bad: tuple[tuple[str, str], ...] = field(default=())
    good: tuple[tuple[str, str], ...] = field(default=())

    def applies_to(self, info: FileInfo) -> bool:
        if info.kind not in self.kinds:
            return False
        return not (self.path_exclude and self.path_exclude.search(info.path))

    def search(self, text: str, info: FileInfo) -> re.Match[str] | None:
        if self.skip_comments and is_comment(text, info.language):
            return None
        for matcher in self.matchers:
            match = matcher.search(text, info.language)
            if match:
                return match
        return None


RULES: tuple[Rule, ...] = (
    # ── Secrets ───────────────────────────────────────────────────────────
    Rule(
        id="DG101",
        title="Private key committed",
        severity=Severity.CRITICAL,
        side="added",
        description="A PEM private key block was added to the repository.",
        remediation="Remove the key, rotate it, and load it from a secret manager.",
        matchers=(
            _m(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY(?: BLOCK)?-----"),
        ),
        kinds=ALL_TEXT,
        redact=True,
        skip_comments=False,
        bad=(("deploy/key.pem", "-----BEGIN " + "RSA PRIVATE KEY-----"),),
        good=(("deploy/key.pub", "-----BEGIN PUBLIC KEY-----"),),
    ),
    Rule(
        id="DG102",
        title="Cloud or SaaS API key",
        severity=Severity.CRITICAL,
        side="added",
        description=(
            "A credential in a well-known provider format was added: AWS access key, "
            "GitHub token, Stripe live key, Slack token or Google API key."
        ),
        remediation="Revoke the credential now, then read it from the environment.",
        matchers=(
            _m(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b", check=_real_secret),
            _m(r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36}\b|\bgithub_pat_[A-Za-z0-9_]{60,}"),
            _m(r"\b(?:sk|rk)_live_[0-9A-Za-z]{16,}\b"),
            _m(r"\bxox[abposr]-[0-9A-Za-z-]{10,}"),
            _m(r"\bAIza[0-9A-Za-z_\-]{35}\b"),
        ),
        kinds=ALL_TEXT,
        redact=True,
        skip_comments=False,
        bad=(
            ("src/aws.py", 'KEY = "AKIA' + 'Z7QW3RT5YU8IOP2L"'),
            ("ci/env.sh", "export GH_TOKEN=ghp_" + "a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8"),
            ("pay.js", "const stripe = Stripe('sk_live_" + "51HxYzAbCdEfGhIjKlMnOp')"),
        ),
        good=(
            ("docs/aws.md", "aws_access_key_id = AKIA" + "IOSFODNN7EXAMPLE"),
            ("pay.js", "const stripe = Stripe(process.env.STRIPE_KEY)"),
        ),
    ),
    Rule(
        id="DG103",
        title="Hardcoded credential",
        severity=Severity.HIGH,
        side="added",
        description="A password, secret, API key or token is assigned a literal value.",
        remediation="Read the value from the environment or a secret manager.",
        matchers=(
            _m(
                r"(?i)(?P<key>[\w.\-]*(?:password|passwd|pwd|secret|api[_\-]?key|apikey"
                r"|access[_\-]?key|access[_\-]?token|auth[_\-]?token|bearer[_\-]?token"
                r"|client[_\-]?secret|private[_\-]?key|signing[_\-]?key)[\w.\-]*)[\"']?\s*"
                r"(?:=|:|=>|:=)\s*[bru]?[\"'](?P<value>[^\"'\s]{8,})[\"']",
                check=_real_assigned_secret,
            ),
        ),
        kinds=frozenset({"code", "config", "markup"}),
        redact=True,
        bad=(
            ("src/client.py", 'API_KEY = "sk-live-9f8e7d6c"'),
            ("config/prod.yml", 'db_password: "Tr0ub4dor&3x"'),
            ("src/mail.js", "const smtpPassword = 'hunter2hunter2!'"),
        ),
        good=(
            ("src/client.py", 'API_KEY = os.environ["API_KEY"]'),
            ("config/prod.yml", 'db_password: "${DB_PASSWORD}"'),
            ("src/forms.py", 'password_label = "Password"'),
            ("src/client.py", 'API_KEY = "YOUR_API_KEY_HERE"'),
        ),
    ),
    Rule(
        id="DG104",
        title="Credentials embedded in URL",
        severity=Severity.HIGH,
        side="added",
        description="A connection string or URL contains a username and password.",
        remediation="Pass credentials separately, read from the environment.",
        matchers=(
            _m(
                r"\b[a-z][a-z0-9+.\-]*://(?P<user>[^/\s:@'\"]+):(?P<value>[^/\s:@'\"]{3,})@",
                check=_real_secret,
            ),
        ),
        kinds=frozenset({"code", "config", "markup"}),
        redact=True,
        bad=(("src/db.py", 'URL = "postgres://admin:S3cr3tPw!@db.internal:5432/app"'),),
        good=(
            ("src/db.py", 'URL = "postgres://user:password@localhost/app"'),
            ("src/db.py", 'URL = f"postgres://{user}:{pw}@{host}/app"'),
        ),
    ),
    # ── Injection & code execution ───────────────────────────────────────
    Rule(
        id="DG201",
        title="SQL built from string formatting",
        severity=Severity.CRITICAL,
        side="added",
        description=(
            "A SQL statement is built with f-strings, %, +, .format() or template "
            "literals and passed to a query API. This is the classic SQL injection shape."
        ),
        remediation="Use parameterized queries (placeholders plus a separate params argument).",
        matchers=(
            _m(
                r"(?<![\w$])(?:execute|executemany|executescript|exec_driver_sql|mogrify|raw"
                r"|rawQuery|query|queryRaw|\$queryRawUnsafe|\$executeRawUnsafe|text|createQuery"
                r"|createNativeQuery|prepareStatement|executeQuery|executeUpdate|Exec|Query"
                r"|QueryRow|QueryContext|ExecContext)\s*\(\s*(?:[bru]?f[\"']|[bru]?(?P<q>[\"'])"
                r"(?:(?!(?P=q)).)*(?P=q)\s*(?:%|\+|\.format\b)|`[^`]*\$\{|fmt\.Sprintf\()",
                requires=_SQL_KEYWORDS,
            ),
            _m(
                r"(?:->query|->exec|mysqli_query|mysql_query|pg_query)\s*\((?:[^,]*,)?\s*\"[^\"]*\$\w+",
                PHP,
                requires=_SQL_KEYWORDS,
            ),
        ),
        ast_checked=True,
        bad=(
            ("app/db.py", 'cur.execute(f"SELECT * FROM users WHERE id={uid}")'),
            ("app/db.py", 'cursor.execute("DELETE FROM t WHERE id=%s" % uid)'),
            ("api/users.js", "db.query(`SELECT * FROM users WHERE id = ${req.params.id}`)"),
            ("repo/u.go", 'rows, _ := db.Query(fmt.Sprintf("SELECT * FROM u WHERE id=%s", id))'),
            ("Dao.java", "stmt.executeQuery(\"SELECT * FROM u WHERE name='\" + name + \"'\")"),
        ),
        good=(
            ("app/db.py", 'cur.execute("SELECT * FROM users WHERE id = %s", (uid,))'),
            ("api/users.js", "db.query('SELECT * FROM users WHERE id = $1', [id])"),
            ("app/log.py", 'logger.info(f"select a value from {x}")'),
        ),
    ),
    Rule(
        id="DG202",
        title="Dynamic code execution",
        severity=Severity.CRITICAL,
        side="added",
        description="eval/exec/new Function is called on a non-literal value.",
        remediation="Parse the input (json, ast.literal_eval) instead of executing it.",
        matchers=(
            _m(r"(?<![\w.])(?:eval|exec)\s*\((?!\s*[bru]?[\"'][^\"']*[\"']\s*\))", PY),
            _m(r"(?<![\w.$])eval\s*\((?!\s*[\"'`][^\"'`$]*[\"'`]\s*\))|\bnew\s+Function\s*\(", JS),
            _m(r"\b(?:eval|assert|create_function)\s*\(\s*\$", PHP),
            _m(r"(?<![\w.])(?:eval|instance_eval|class_eval)\s*[\( ]", RUBY),
        ),
        ast_checked=True,
        bad=(
            ("calc.py", "return eval(request.args['expr'])"),
            ("run.py", "exec(code)"),
            ("a.js", "const fn = new Function('a', body)"),
            ("a.js", "eval(userInput)"),
        ),
        good=(
            ("calc.py", "result = ast.literal_eval(text)"),
            ("a.js", "const m = re.exec(str)"),
            ("train.py", "model.eval()"),
            ("boot.py", "exec('import os')"),
        ),
    ),
    Rule(
        id="DG203",
        title="Shell command built from input",
        severity=Severity.HIGH,
        side="added",
        description="A shell command is run with shell=True or built by string concatenation.",
        remediation="Pass an argument list and avoid the shell (shell=False, execFile, exec.Command args).",
        matchers=(
            _m(r"\bsubprocess\.\w+\(.*\bshell\s*=\s*True", PY),
            _m(r"\bos\.(?:system|popen)\s*\((?!\s*[bru]?[\"'][^\"']*[\"']\s*\))", PY),
            _m(r"\bsubprocess\.getoutput\s*\((?!\s*[\"'][^\"']*[\"']\s*\))", PY),
            _m(
                r"\bchild_process\.(?:exec|execSync)\s*\(|(?<![\w.$])(?:exec|execSync)\s*\(\s*"
                r"(?:`[^`]*\$\{|[\"'][^\"']*[\"']\s*\+)",
                JS,
            ),
            _m(r"\b(?:shell_exec|system|passthru|popen|proc_open|exec)\s*\(\s*[\"']?[^\"')]*\$", PHP),
            _m(
                r"exec\.Command(?:Context)?\((?:ctx,\s*)?\"(?:sh|bash|/bin/sh|/bin/bash|cmd)\"\s*,"
                r"\s*\"(?:-c|/c)\"",
                GO,
            ),
            _m(r"Runtime\.getRuntime\(\)\.exec\((?:\s*[^\"\s)][^)]*\+|\s*\"[^\"]*\"\s*\+)", JVM),
        ),
        ast_checked=True,
        bad=(
            ("deploy.py", "subprocess.run(f'tar xf {name}', shell=True)"),
            ("deploy.py", "os.system('rm -rf ' + path)"),
            ("a.js", "exec(`git clone ${url}`)"),
            ("a.go", 'cmd := exec.Command("sh", "-c", userCmd)'),
        ),
        good=(
            ("deploy.py", "subprocess.run(['tar', 'xf', name], check=True)"),
            ("deploy.py", "os.system('clear')"),
            ("a.go", 'cmd := exec.Command("git", "clone", url)'),
        ),
    ),
    Rule(
        id="DG204",
        title="Unsafe deserialization",
        severity=Severity.HIGH,
        side="added",
        description=(
            "Data is deserialized with a format that can execute code "
            "(pickle, yaml.load, ObjectInputStream, unserialize)."
        ),
        remediation="Use a data-only format (JSON) or a safe loader (yaml.safe_load).",
        matchers=(
            _m(r"\b(?:c?[Pp]ickle|dill|marshal|jsonpickle)\.(?:loads?|decode|Unpickler)\s*\(", PY),
            _m(r"\byaml\.(?:load|load_all)\s*\(", PY, exclude=r"Loader\s*=\s*(?:yaml\.)?C?SafeLoader"),
            _m(r"\byaml\.(?:unsafe_load|full_load|unsafe_load_all)\s*\(", PY),
            _m(r"\bnew\s+ObjectInputStream\s*\(|\bnew\s+XMLDecoder\s*\(|\benableDefaultTyping\s*\(", JVM),
            _m(r"\bunserialize\s*\(\s*\$", PHP),
            _m(r"\bMarshal\.load\b|\bYAML\.(?:load|unsafe_load)\s*\(", RUBY),
            _m(r"\bBinaryFormatter\s*\(|\bTypeNameHandling\.(?:All|Auto|Objects)\b", CS),
            _m(r"\bnode-serialize\b|\bserialize\.unserialize\s*\(", JS),
        ),
        bad=(
            ("loader.py", "data = pickle.loads(request.body)"),
            ("conf.py", "cfg = yaml.load(stream)"),
            ("Svc.java", "ObjectInputStream in = new ObjectInputStream(sock.getInputStream());"),
        ),
        good=(
            ("conf.py", "cfg = yaml.safe_load(stream)"),
            ("conf.py", "cfg = yaml.load(stream, Loader=yaml.SafeLoader)"),
            ("loader.py", "data = json.loads(body)"),
        ),
    ),
    Rule(
        id="DG205",
        title="Unescaped HTML output (XSS sink)",
        severity=Severity.MEDIUM,
        side="added",
        description="Content is written to the page without escaping.",
        remediation="Render text (textContent, auto-escaped templates) or sanitize with a vetted library.",
        matchers=(
            _m(
                r"\bdangerouslySetInnerHTML\b|\.(?:innerHTML|outerHTML)\s*\+?=(?!=)"
                r"|\bdocument\.write(?:ln)?\s*\(|\binsertAdjacentHTML\s*\(|\bv-html\s*="
            ),
            _m(r"\|\s*safe\b|\{%-?\s*autoescape\s+(?:off|false)|\{\{\{[^}]+\}\}\}|<%-", HTML),
            _m(r"\bmark_safe\s*\(|\bMarkup\s*\((?!\s*[\"'][^\"']*[\"']\s*\))", PY),
            _m(r"\.html_safe\b|\braw\s*\(\s*@?\w+", RUBY),
        ),
        kinds=CODE_MARKUP,
        bad=(
            ("ui/App.tsx", "<div dangerouslySetInnerHTML={{__html: comment}} />"),
            ("ui/app.js", "el.innerHTML = msg"),
            ("templates/p.html", "{{ comment|safe }}"),
            ("views.py", "return mark_safe(user_bio)"),
        ),
        good=(
            ("ui/app.js", "el.textContent = msg"),
            ("ui/app.js", "if (el.innerHTML === '') {"),
            ("templates/p.html", "{{ comment }}"),
        ),
    ),
    # ── Transport & cryptography ─────────────────────────────────────────
    Rule(
        id="DG301",
        title="TLS certificate verification disabled",
        severity=Severity.HIGH,
        side="added",
        description="Certificate or hostname verification is turned off, enabling man-in-the-middle attacks.",
        remediation="Keep verification on; point to a custom CA bundle if you need one.",
        matchers=(
            _m(r"\bverify\s*=\s*False\b", PY),
            _m(r"\brejectUnauthorized\s*:\s*false\b|NODE_TLS_REJECT_UNAUTHORIZED\W{0,6}0\b"),
            _m(r"\bInsecureSkipVerify\s*:\s*true\b"),
            _m(
                r"\bssl\._create_unverified_context\b|\bcheck_hostname\s*=\s*False\b"
                r"|\b(?:verify_mode|cert_reqs)\s*=\s*(?:ssl\.)?CERT_NONE\b"
            ),
            _m(
                r"\bcurl\b.*\s(?:-k|--insecure)\b|\bwget\b.*--no-check-certificate"
                r"|\bstrict-ssl\s*[=:]\s*false|\bsslverify\s*=\s*false|\bhttp\.sslVerify\s+false",
                flags=re.IGNORECASE,
            ),
            _m(
                r"\bTrustAll\w*|\bNoopHostnameVerifier\b|\bALLOW_ALL_HOSTNAME_VERIFIER\b"
                r"|ServerCertificateValidationCallback\s*=[^;]*=>\s*true|\bInsecureRequestWarning\b"
            ),
        ),
        bad=(
            ("http.py", "r = requests.get(url, verify=False)"),
            ("client.ts", "const agent = new https.Agent({ rejectUnauthorized: false })"),
            ("tls.go", "cfg := &tls.Config{InsecureSkipVerify: true}"),
            ("Dockerfile", "RUN curl -k https://example.com/install.sh | sh"),
        ),
        good=(
            ("http.py", "r = requests.get(url, verify=True)"),
            ("http.py", "r = requests.get(url, verify=ca_bundle)"),
            ("Dockerfile", "RUN curl -fsSL https://example.com/x.sh -o x.sh"),
        ),
    ),
    Rule(
        id="DG302",
        title="Weak hash for passwords",
        severity=Severity.HIGH,
        side="added",
        description="MD5 or SHA-1 is applied to a password or secret.",
        remediation="Hash passwords with bcrypt, scrypt or argon2.",
        matchers=(
            _m(r"\bhashlib\.(?:md5|sha1|sha256)\s*\(|\bhashlib\.new\(\s*[\"'](?:md5|sha1)[\"']", PY,
               requires=_PASSWORDISH),
            _m(r"\bcreateHash\(\s*[\"'](?:md5|sha1|sha256)[\"']", JS, requires=_PASSWORDISH),
            _m(r"MessageDigest\.getInstance\(\s*\"(?:MD5|SHA-?1|SHA-256)\"", JVM, requires=_PASSWORDISH),
            _m(r"\b(?:md5|sha1)\s*\(", PHP, requires=_PASSWORDISH),
        ),
        bad=(("users.py", "user.pw_hash = hashlib.md5(password.encode()).hexdigest()"),),
        good=(("cache.py", "key = hashlib.md5(url.encode()).hexdigest()"),),
    ),
    Rule(
        id="DG303",
        title="Weak hash algorithm",
        severity=Severity.LOW,
        side="added",
        description="MD5 or SHA-1 is used. Fine for checksums, broken for anything security-related.",
        remediation="Use SHA-256 or better; pass usedforsecurity=False for non-security checksums.",
        matchers=(
            _m(
                r"\bhashlib\.(?:md5|sha1)\s*\((?![^)]*usedforsecurity\s*=\s*False)"
                r"|\bhashlib\.new\(\s*[\"'](?:md5|sha1)[\"']",
                PY,
                exclude=_PASSWORDISH.pattern,
            ),
            _m(r"\bcreateHash\(\s*[\"'](?:md5|sha1)[\"']", JS, exclude=_PASSWORDISH.pattern),
            _m(r"MessageDigest\.getInstance\(\s*\"(?:MD5|SHA-?1)\"", JVM, exclude=_PASSWORDISH.pattern),
            _m(r"\b(?:md5|sha1)\.(?:New|Sum)\(", GO),
            _m(r"Digest::(?:MD5|SHA1)\b", RUBY),
        ),
        bad=(("a.js", "crypto.createHash('sha1').update(body)"),),
        good=(
            ("a.py", "digest = hashlib.sha256(data).hexdigest()"),
            ("a.py", "etag = hashlib.md5(body, usedforsecurity=False).hexdigest()"),
        ),
    ),
    Rule(
        id="DG304",
        title="Weak cipher or mode",
        severity=Severity.MEDIUM,
        side="added",
        description="A broken cipher (DES, 3DES, RC4, Blowfish) or ECB mode is used.",
        remediation="Use AES-GCM or ChaCha20-Poly1305 from a high-level library.",
        matchers=(
            _m(
                r"\b(?:DES|DES3|TripleDES|ARC4|ARC2|Blowfish)\.new\(|\bAES\.MODE_ECB\b|\bmodes\.ECB\("
                r"|algorithms\.(?:TripleDES|ARC4|Blowfish)\(",
                PY,
            ),
            _m(r"createCipher(?:iv)?\(\s*[\"'](?:des|rc4|rc2|bf|aes-\d+-ecb)", JS, flags=re.IGNORECASE),
            _m(r"Cipher\.getInstance\(\s*\"(?:(?:DES|DESede|RC4|RC2|Blowfish)[\"/]|AES\"|AES/ECB)", JVM),
        ),
        bad=(
            ("c.py", "cipher = AES.new(key, AES.MODE_ECB)"),
            ("c.js", "crypto.createCipheriv('des-ede3-cbc', key, iv)"),
            ("C.java", 'Cipher c = Cipher.getInstance("AES/ECB/PKCS5Padding");'),
        ),
        good=(
            ("c.py", "cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)"),
            ("C.java", 'Cipher c = Cipher.getInstance("AES/GCM/NoPadding");'),
        ),
    ),
    Rule(
        id="DG305",
        title="Insecure randomness for a secret",
        severity=Severity.MEDIUM,
        side="added",
        description="A non-cryptographic random generator produces a token, password or nonce.",
        remediation="Use secrets (Python), crypto.randomBytes / crypto.randomUUID (Node) or SecureRandom.",
        matchers=(
            _m(
                r"\brandom\.(?:random|randint|randrange|choice|choices|getrandbits|sample)\s*\(",
                PY,
                requires=_SECRETISH,
            ),
            _m(r"\bMath\.random\s*\(\s*\)", JS, requires=_SECRETISH),
            _m(r"\bnew\s+Random\s*\(", JVM, requires=_SECRETISH),
            _m(r"\brand\.(?:Int|Intn|Int63|Read)\(", GO, requires=_SECRETISH),
        ),
        bad=(
            ("t.py", "token = ''.join(random.choice(chars) for _ in range(32))"),
            ("t.js", "const resetToken = Math.random().toString(36).slice(2)"),
        ),
        good=(
            ("t.py", "token = secrets.token_urlsafe(32)"),
            ("t.py", "delay = random.uniform(0.1, 0.5)"),
        ),
    ),
    Rule(
        id="DG306",
        title="JWT verification disabled",
        severity=Severity.HIGH,
        side="added",
        description="A JWT is accepted without checking its signature, algorithm or expiry.",
        remediation="Verify with an explicit algorithm allow-list and keep expiry checks on.",
        matchers=(
            _m(
                r"[\"']verify_signature[\"']\s*:\s*False|\bjwt\.decode\([^)]*\bverify\s*=\s*False"
                r"|algorithms\s*[=:]\s*\[\s*[\"']none[\"']|\bignoreExpiration\s*:\s*true"
                r"|[\"']verify_exp[\"']\s*:\s*False",
                flags=re.IGNORECASE,
            ),
        ),
        bad=(
            ("auth.py", 'claims = jwt.decode(token, options={"verify_signature": False})'),
            ("auth.js", "jwt.verify(token, key, { algorithms: ['none'] })"),
        ),
        good=(("auth.py", 'claims = jwt.decode(token, key, algorithms=["HS256"])'),),
    ),
    # ── Access control ──────────────────────────────────────────────────
    Rule(
        id="DG401",
        title="Authentication bypass added",
        severity=Severity.HIGH,
        side="added",
        description="An endpoint or the whole app is opened to unauthenticated users.",
        remediation="Scope public access to specific routes and keep authentication on by default.",
        matchers=(
            _m(
                r"\bpermission_classes\s*=\s*[\[(]\s*(?:permissions\.)?AllowAny\b"
                r"|\bauthentication_classes\s*=\s*[\[(]\s*[\])]",
                PY,
            ),
            _m(r"\banyRequest\(\)\s*\.permitAll\(\)|@AllowAnonymous\b|\[AllowAnonymous\]"),
            _m(r"\bskip_before_action\s+:(?:authenticate\w*|require_login|authorize\w*)", RUBY),
            _m(
                r"(?i)\b(?:skip|bypass|disable)_?(?:auth|authentication|authorization|login"
                r"|permission)s?\b[\"']?\s*[=:]\s*[\"']?(?:true|1|yes)\b"
                r"|\bAUTH(?:ENTICATION)?_DISABLED\s*[=:]\s*[\"']?(?:true|1|yes)\b"
                r"|\bAUTH(?:ENTICATION)?_ENABLED\s*[=:]\s*[\"']?(?:false|0|no)\b"
            ),
        ),
        bad=(
            ("views.py", "permission_classes = [AllowAny]"),
            ("Sec.java", "http.authorizeRequests().anyRequest().permitAll();"),
            ("settings.py", "SKIP_AUTH = True"),
            (".env", "AUTH_DISABLED=true"),
        ),
        good=(
            ("views.py", "permission_classes = [IsAuthenticated]"),
            ("Sec.java", '.requestMatchers("/health").permitAll()'),
            (".env", "AUTH_ENABLED=true"),
        ),
    ),
    Rule(
        id="DG402",
        title="CSRF protection disabled",
        severity=Severity.HIGH,
        side="added",
        description="Cross-site request forgery protection is turned off for a view or the app.",
        remediation="Keep CSRF on; for token-authenticated APIs, scope the exemption narrowly.",
        matchers=(
            _m(
                r"@csrf_exempt\b|\bcsrf_exempt\s*\(|\b(?:WTF_)?CSRF_ENABLED[\"']?\]?\s*=\s*False\b"
                r"|\bcsrf\s*:\s*false\b|\.csrf\(\)\s*\.disable\(\)|\.csrf\(\s*\w+\s*->\s*\w+\.disable\(\)\s*\)"
                r"|csrf\(AbstractHttpConfigurer::disable\)|\bskip_forgery_protection\b"
                r"|\bskip_before_action\s+:verify_authenticity_token|\[IgnoreAntiforgeryToken\]"
            ),
        ),
        bad=(
            ("views.py", "@csrf_exempt"),
            ("Sec.java", "http.csrf().disable();"),
            ("app.py", "app.config['WTF_CSRF_ENABLED'] = False"),
        ),
        good=(("views.py", "@csrf_protect"),),
    ),
    Rule(
        id="DG403",
        title="Privilege grant added",
        severity=Severity.MEDIUM,
        side="added",
        description="Code grants admin/superuser rights or assigns a privileged role.",
        remediation="Confirm the grant is intended, authorized and audited.",
        matchers=(
            _m(
                r"\bis_(?:superuser|staff|admin)\s*=\s*True\b"
                r"|\b(?:grant|make|promote|set)_?(?:to_)?(?:admin|superuser|root)\w*\s*\("
                r"|\brole\s*[=:]\s*[\"'](?:admin|superuser|root|owner)[\"']|\bisAdmin\s*[=:]\s*true\b",
                flags=re.IGNORECASE,
            ),
        ),
        bad=(
            ("users.py", "grant_admin(user)"),
            ("users.py", "user.is_superuser = True"),
            ("seed.js", "await User.create({ email, role: 'admin' })"),
        ),
        good=(
            ("users.py", "user.is_superuser = False"),
            ("users.py", "if user.role == 'admin':"),
        ),
    ),
    # ── Configuration ───────────────────────────────────────────────────
    Rule(
        id="DG501",
        title="Debug mode enabled",
        severity=Severity.MEDIUM,
        side="added",
        description="Debug mode is switched on in a non-development file; it leaks stack traces and secrets.",
        remediation="Drive debug from the environment and default it to off.",
        matchers=(
            _m(r"^\s*DEBUG\s*=\s*True\b", PY),
            _m(r"\.run\([^)]*\bdebug\s*=\s*True|\bapp\.debug\s*=\s*True", PY),
            _m(
                r"(?i)^\s*(?:FLASK_DEBUG|APP_DEBUG|DJANGO_DEBUG|DEBUG)\s*[=:]\s*[\"']?(?:1|true|on|yes)[\"']?\s*$",
                frozenset({"dotenv", "yaml", "ini", "toml"}),
            ),
        ),
        path_exclude=_NON_PROD_PATH,
        bad=(
            ("settings.py", "DEBUG = True"),
            ("app.py", "app.run(host='0.0.0.0', debug=True)"),
            (".env.production", "APP_DEBUG=true"),
        ),
        good=(
            ("settings.py", "DEBUG = env.bool('DEBUG', default=False)"),
            ("settings/dev.py", "DEBUG = True"),
        ),
    ),
    Rule(
        id="DG502",
        title="CORS allows any origin",
        severity=Severity.MEDIUM,
        side="added",
        description="Cross-origin requests are allowed from any origin.",
        remediation="List the origins that need access.",
        matchers=(
            _m(
                r"Access-Control-Allow-Origin[\"']?\s*[:,=]\s*[\"']\*[\"']"
                r"|\bCORS_(?:ORIGIN_)?ALLOW_ALL(?:_ORIGINS)?\s*=\s*True\b"
                r"|\ballow_origins\s*=\s*\[\s*[\"']\*[\"']|\borigins?\s*:\s*[\"']\*[\"']"
                r"|\bAllowAnyOrigin\(\)|allowedOrigins\(\s*\"\*\"|@CrossOrigin\(\s*(?:origins\s*=\s*)?\"\*\""
            ),
        ),
        bad=(
            ("main.py", 'app.add_middleware(CORSMiddleware, allow_origins=["*"])'),
            ("server.js", "app.use(cors({ origin: '*' }))"),
            ("settings.py", "CORS_ALLOW_ALL_ORIGINS = True"),
        ),
        good=(("main.py", 'app.add_middleware(CORSMiddleware, allow_origins=["https://app.example.com"])'),),
    ),
    Rule(
        id="DG503",
        title="World-writable permissions",
        severity=Severity.MEDIUM,
        side="added",
        description="Files are made writable by every user.",
        remediation="Grant the narrowest permissions needed (e.g. 755 / 644).",
        matchers=(
            _m(
                r"\bchmod\s+(?:-R\s+)?(?:0?777|0?666|a\+w|o\+w|ugo\+w)\b|\bchmod\(\s*[^,]+,\s*0o?777\b"
                r"|\bumask\(\s*0o?0+\s*\)"
            ),
        ),
        bad=(
            ("Dockerfile", "RUN chmod -R 777 /app"),
            ("setup.py", "os.chmod(path, 0o777)"),
        ),
        good=(("Dockerfile", "RUN chmod 755 /app/entrypoint.sh"),),
    ),
    # ── Removed safety controls ─────────────────────────────────────────
    Rule(
        id="DG601",
        title="Authentication or authorization check removed",
        severity=Severity.HIGH,
        side="removed",
        description=(
            "A line enforcing login, permissions or roles was deleted and not re-added "
            "elsewhere in the change."
        ),
        remediation="Confirm the endpoint is still protected (decorator, middleware or explicit check).",
        matchers=(
            _m(
                r"@(?:login_required|permission_required|user_passes_test|requires_auth|auth_required"
                r"|jwt_required|authenticated|roles_required|roles_accepted|PreAuthorize|Secured"
                r"|RolesAllowed|UseGuards)\b|\[Authorize\b"
                r"|\b(?:is_authenticated|isAuthenticated|is_authorized|isAuthorized|has_perms?"
                r"|has_permission|hasPermission|hasRole|has_role|check_permissions?|check_access"
                r"|ensureAuthenticated|require_(?:auth|login|permission|role)\w*|requireAuth\w*"
                r"|authorize!?)\b"
                r"|\bbefore_action\s+:(?:authenticate\w*|require_login|authorize\w*)"
                r"|\b(?:verify_jwt\w*|jwt\.verify|verifyToken|verify_token)\b"
                r"|\babort\(\s*40[13]\b|\braise\s+(?:PermissionDenied|Unauthorized|Forbidden"
                r"|AuthenticationFailed|NotAuthenticated|NotAuthorized|AccessDenied)\w*"
                r"|\bHTTPException\(\s*(?:status_code\s*=\s*)?(?:40[13]|status\.HTTP_40[13])"
                r"|\bHttpResponseForbidden\b|\.status\(\s*40[13]\s*\)"
                r"|\bthrow\s+new\s+(?:Unauthorized|Forbidden|AccessDenied)\w*"
                r"|\bDepends\(\s*(?:get_current_(?:active_)?user|require_\w+|verify_\w+)"
                r"|\b(?:permission|authentication)_classes\s*="
            ),
        ),
        bad=(
            ("views.py", "if not current_user.is_authenticated:"),
            ("views.py", "    abort(401)"),
            ("views.py", "@login_required"),
            ("api.py", "def read(user = Depends(get_current_user)):"),
            ("Ctl.java", "@PreAuthorize(\"hasRole('ADMIN')\")"),
        ),
        good=(("views.py", "logger.info('rendering page')"),),
    ),
    Rule(
        id="DG602",
        title="CSRF protection removed",
        severity=Severity.HIGH,
        side="removed",
        description="CSRF middleware, tokens or checks were deleted.",
        remediation="Restore CSRF protection or document why the endpoint does not need it.",
        matchers=(
            _m(
                r"\bcsrf\w*|\bCsrfViewMiddleware\b|\bprotect_from_forgery\b"
                r"|\bverify_authenticity_token\b|\bantiforgery\w*|\bcsurf\b",
                flags=re.IGNORECASE,
                exclude=(
                    r"csrf_exempt|csrf\(\)\s*\.disable|csrf\s*:\s*false|CSRF_ENABLED\W*=\s*False"
                    r"|skip_forgery|IgnoreAntiforgery|AbstractHttpConfigurer::disable"
                ),
            ),
        ),
        bad=(
            ("app.js", "app.use(csrfProtection)"),
            ("settings.py", "    'django.middleware.csrf.CsrfViewMiddleware',"),
        ),
        good=(("views.py", "@csrf_exempt"),),
    ),
    Rule(
        id="DG603",
        title="Password hashing removed",
        severity=Severity.HIGH,
        side="removed",
        description="A password hashing or verification call was deleted.",
        remediation="Make sure passwords are still hashed with a slow KDF before storage.",
        matchers=(
            _m(
                r"\b(?:bcrypt|argon2|scrypt|pbkdf2\w*|hashpw|make_password|check_password|set_password"
                r"|password_hash|password_verify|generate_password_hash|check_password_hash|passlib"
                r"|PasswordHasher|BCryptPasswordEncoder|Argon2PasswordEncoder)\b",
                flags=re.IGNORECASE,
            ),
        ),
        bad=(
            ("users.py", "user.pw = bcrypt.hash(raw)"),
            ("users.py", "user.set_password(raw)"),
        ),
        good=(("users.py", "user.name = name"),),
    ),
    Rule(
        id="DG604",
        title="Input validation removed",
        severity=Severity.MEDIUM,
        side="removed",
        description="A validation, sanitization or escaping step was deleted.",
        remediation="Confirm the input is still validated before use.",
        matchers=(
            _m(
                r"\b(?:validate\w*|sanitiz\w*|escape\w*|is_valid|full_clean|clean_\w+|validator\w*"
                r"|bleach\.\w+|htmlspecialchars|strip_tags)\b"
                r"|@(?:Valid|Validated|validator|field_validator|model_validator)\b|\bJoi\.\w+"
                r"|\bz\.(?:object|string|number)\b",
                flags=re.IGNORECASE,
            ),
        ),
        bad=(
            ("forms.py", "if not validate(token):"),
            ("api.py", "data = sanitize(payload)"),
        ),
        good=(("api.py", "data = payload"),),
    ),
    Rule(
        id="DG605",
        title="Security hardening removed",
        severity=Severity.MEDIUM,
        side="removed",
        description="Rate limiting, security headers or secure cookie settings were deleted.",
        remediation="Confirm the protection is provided elsewhere (proxy, middleware, framework default).",
        matchers=(
            _m(
                r"\bhelmet\s*\(|\b(?:rate_?limit\w*|limiter\.\w+|throttl\w*|SecurityMiddleware"
                r"|Content-Security-Policy|X-Frame-Options|Strict-Transport-Security"
                r"|X-Content-Type-Options|SESSION_COOKIE_SECURE|CSRF_COOKIE_SECURE|SECURE_SSL_REDIRECT"
                r"|SECURE_HSTS_\w+|httponly|samesite)\b|\bsecure\s*[=:]\s*true\b",
                flags=re.IGNORECASE,
            ),
        ),
        bad=(
            ("app.js", "app.use(helmet())"),
            ("settings.py", "SESSION_COOKIE_SECURE = True"),
            ("api.py", "@limiter.limit('5/minute')"),
        ),
        good=(("app.js", "app.use(express.json())"),),
    ),
)

RULES_BY_ID = {rule.id: rule for rule in RULES}
