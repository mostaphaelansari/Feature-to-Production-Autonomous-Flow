"""Detect which sensitive areas of a codebase a change touches.

Domains route a change to the right reviewers; they are not vulnerabilities.
Detection is driven by file paths first, then by specific identifiers in changed
code. Tests and documentation never contribute.
"""
from __future__ import annotations

import re

from .files import FileInfo, is_comment, matches_any
from .models import DomainHit, FileDiff

DEFAULT_WEIGHTS = {
    "auth": 25,
    "payment": 25,
    "database": 25,
    "security": 20,
    "infrastructure": 15,
    "dependencies": 10,
    "concurrency": 10,
    "configuration": 5,
}
CUSTOM_DOMAIN_WEIGHT = 15
MAX_EVIDENCE_PER_FILE = 3

_PATH_TOKENS = {
    "auth": re.compile(
        r"auth|authn|authz|authentication|authorization|login|logout|signin|signup|oauth2?"
        r"|sso|saml|openid|oidc|jwt|permissions?|rbac|acl|iam|passwords?|credentials?"
    ),
    "payment": re.compile(
        r"payments?|billing|invoices?|invoicing|checkout|stripe|paypal|braintree|refunds?"
        r"|payouts?|subscriptions?|wallets?|ledger"
    ),
    "database": re.compile(r"migrations?|alembic|migrate"),
    "security": re.compile(r"security|crypto|cryptography|secrets?|csrf|encryption"),
}

_PATH_PATTERNS = {
    "database": re.compile(r"\.sql$"),
    "infrastructure": re.compile(
        r"(^|/)(docker|container)file[^/]*$|(^|/)docker-compose[^/]*\.ya?ml$|\.tf$|\.tfvars$"
        r"|(^|/)\.github/workflows/|(^|/)\.gitlab-ci\.ya?ml$|(^|/)jenkinsfile$"
        r"|(^|/)(helm|charts|k8s|kubernetes|terraform|ansible|deploy|infra)/"
    ),
    "dependencies": re.compile(
        r"(^|/)((requirements|constraints)[\w.-]*\.txt|pyproject\.toml|setup\.py|setup\.cfg|pipfile"
        r"|package\.json|go\.mod|cargo\.toml|gemfile|pom\.xml|build\.gradle(\.kts)?|composer\.json"
        r"|[\w.-]+\.csproj)$"
    ),
    "configuration": re.compile(
        r"(^|/)(settings|config|configuration)(/|\.py$|\.[jt]s$)|(^|/)\.env(\.|$)"
        r"|(^|/)application[\w-]*\.(ya?ml|properties)$"
    ),
}

_CODE_TOKENS = {
    "auth": re.compile(
        r"auth|login|logout|signin|signout|authenticat\w*|authoriz\w*|authn|authz|oauth\w*|jwt"
        r"|passwords?|passwd|credentials?|permissions?|rbac|acl|bcrypt|argon2|scrypt|pbkdf2"
        r"|hashpw|mfa|totp|saml|sso"
    ),
    "payment": re.compile(
        r"payments?|billing|invoices?|refunds?|checkout|stripe|paypal|braintree|payouts?|chargebacks?"
    ),
    "security": re.compile(r"encrypt\w*|decrypt\w*|cipher\w*|hmac|csrf|xss|sanitiz\w*|crypto\w*"),
}

_CODE_PATTERNS = {
    "database": re.compile(
        r"(?i)\b(?:create|alter|drop|truncate)\s+(?:table|index|column|schema|database)\b"
        r"|\bop\.(?:add|drop|alter)_column\b|\bop\.(?:create|drop)_(?:table|index)\b"
        r"|\bmigrations\.(?:AddField|RemoveField|AlterField|RenameField|DeleteModel|CreateModel"
        r"|RunSQL|RunPython)\b|\bSchema::(?:create|table|drop)|\b(?:addColumn|removeColumn"
        r"|createTable|dropTable)\b"
    ),
    "concurrency": re.compile(
        r"\b(?:threading\.\w+|multiprocessing\.\w+|Mutex|RWMutex|RLock|Semaphore|BoundedSemaphore"
        r"|synchronized|AtomicInteger|AtomicLong|ConcurrentHashMap|ReentrantLock"
        r"|asyncio\.(?:Lock|Semaphore|gather|create_task)|sync\.(?:Mutex|RWMutex|WaitGroup))\b"
        r"|\bgo\s+func\b|(?<![\w.])Lock\(\)"
    ),
}


def tokenize(text: str) -> set[str]:
    """Split identifiers on case changes and non-alphanumerics, lowercased:
    ``getAuthToken`` -> {get, auth, token}; ``grant_admin`` -> {grant, admin}."""
    text = re.sub(r"([a-z0-9])([A-Z])", r"\1 \2", text)
    text = re.sub(r"([A-Z]+)([A-Z][a-z])", r"\1 \2", text)
    return {t for t in re.split(r"[^A-Za-z0-9]+", text.lower()) if t}


def detect_domains(
    fd: FileDiff, info: FileInfo, custom_paths: dict[str, list[str]] | None = None
) -> list[DomainHit]:
    if info.kind in ("doc", "test", "binary"):
        return []

    hits: dict[str, list[DomainHit]] = {}

    def add(domain: str, line: int | None, evidence: str) -> None:
        bucket = hits.setdefault(domain, [])
        if len(bucket) < MAX_EVIDENCE_PER_FILE:
            bucket.append(DomainHit(domain, fd.path, line, evidence))

    path = fd.path.lower()
    path_tokens = tokenize(fd.path)
    for domain, pattern in _PATH_TOKENS.items():
        token = next((t for t in sorted(path_tokens) if pattern.fullmatch(t)), None)
        if token:
            add(domain, None, f"path contains '{token}'")
    for domain, pattern in _PATH_PATTERNS.items():
        if pattern.search(path):
            add(domain, None, "path")
    for domain, globs in (custom_paths or {}).items():
        if matches_any(fd.path, globs):
            add(domain, None, "path matches configured glob")

    if info.kind in ("code", "config"):
        for line in [*fd.added, *fd.removed]:
            if is_comment(line.text, info.language):
                continue
            tokens = tokenize(line.text)
            for domain, pattern in _CODE_TOKENS.items():
                if domain in hits and len(hits[domain]) >= MAX_EVIDENCE_PER_FILE:
                    continue
                token = next((t for t in sorted(tokens) if pattern.fullmatch(t)), None)
                if token:
                    add(domain, line.number, f"identifier '{token}'")
            for domain, pattern in _CODE_PATTERNS.items():
                match = pattern.search(line.text)
                if match:
                    add(domain, line.number, f"'{match.group(0).strip()}'")

    return [hit for bucket in hits.values() for hit in bucket]
