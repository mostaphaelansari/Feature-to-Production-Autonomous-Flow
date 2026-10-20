"""Classify changed files by language and role (code, test, doc, ...)."""
from __future__ import annotations

import fnmatch
import re
from dataclasses import dataclass
from pathlib import PurePosixPath

LANGUAGE_BY_SUFFIX = {
    ".py": "python",
    ".pyi": "python",
    ".js": "javascript",
    ".mjs": "javascript",
    ".cjs": "javascript",
    ".jsx": "javascript",
    ".ts": "typescript",
    ".tsx": "typescript",
    ".vue": "javascript",
    ".svelte": "javascript",
    ".java": "java",
    ".kt": "kotlin",
    ".kts": "kotlin",
    ".scala": "scala",
    ".go": "go",
    ".rb": "ruby",
    ".erb": "ruby",
    ".php": "php",
    ".cs": "csharp",
    ".rs": "rust",
    ".swift": "swift",
    ".c": "c",
    ".h": "c",
    ".cc": "cpp",
    ".cpp": "cpp",
    ".hpp": "cpp",
    ".sql": "sql",
    ".sh": "shell",
    ".bash": "shell",
    ".zsh": "shell",
    ".ps1": "powershell",
    ".tf": "terraform",
    ".hcl": "terraform",
    ".yaml": "yaml",
    ".yml": "yaml",
    ".json": "json",
    ".toml": "toml",
    ".ini": "ini",
    ".cfg": "ini",
    ".conf": "ini",
    ".properties": "ini",
    ".env": "dotenv",
    ".xml": "xml",
    ".html": "html",
    ".htm": "html",
    ".jinja": "html",
    ".jinja2": "html",
    ".j2": "html",
    ".hbs": "html",
    ".ejs": "html",
    ".css": "css",
    ".scss": "css",
    ".md": "markdown",
    ".markdown": "markdown",
    ".rst": "text",
    ".txt": "text",
    ".adoc": "text",
}

FILENAME_LANGUAGES = {
    "dockerfile": "docker",
    "containerfile": "docker",
    "makefile": "make",
    "jenkinsfile": "groovy",
    "gemfile": "ruby",
    "rakefile": "ruby",
}

DOC_LANGUAGES = {"markdown", "text"}
MARKUP_LANGUAGES = {"html", "css", "xml"}
CONFIG_LANGUAGES = {"yaml", "json", "toml", "ini", "dotenv"}
DOC_NAMES = {
    "license",
    "licence",
    "copying",
    "changelog",
    "changes",
    "history",
    "authors",
    "contributors",
    "contributing",
    "notice",
    "codeowners",
}
BINARY_SUFFIXES = {
    ".png", ".jpg", ".jpeg", ".gif", ".webp", ".ico", ".pdf", ".zip", ".gz", ".tgz",
    ".jar", ".woff", ".woff2", ".ttf", ".eot", ".mp4", ".mp3", ".so", ".dll", ".exe",
}

_REQUIREMENTS_RE = re.compile(r"^(requirements|constraints)[\w.-]*\.txt$")
_TEST_DIRS = {"test", "tests", "__tests__", "spec", "specs", "testing", "e2e", "__mocks__"}
_TEST_NAME_RE = re.compile(
    r"^(test_.*\.py|.*_test\.py|conftest\.py|.*_test\.go|.*\.(test|spec)\.[jt]sx?"
    r"|.*(Test|Tests|IT)\.(java|kt|cs)|.*_spec\.rb|.*Test\.php)$"
)

COMMENT_PREFIXES = {
    "python": ("#",),
    "ruby": ("#",),
    "shell": ("#",),
    "powershell": ("#",),
    "yaml": ("#",),
    "toml": ("#",),
    "ini": ("#", ";"),
    "dotenv": ("#",),
    "docker": ("#",),
    "make": ("#",),
    "terraform": ("#", "//", "/*", "*"),
    "sql": ("--", "/*", "*"),
    "html": ("<!--",),
    "xml": ("<!--",),
    "css": ("/*", "*"),
}
_C_STYLE = ("//", "/*", "*")


@dataclass(frozen=True)
class FileInfo:
    path: str
    language: str
    kind: str  # code | test | doc | markup | config | binary

    @property
    def is_code_like(self) -> bool:
        """Files whose contents are scanned for code-level risk."""
        return self.kind in ("code", "config")


def detect_language(path: str) -> str:
    p = PurePosixPath(path.lower())
    if p.name in FILENAME_LANGUAGES:
        return FILENAME_LANGUAGES[p.name]
    if p.name.startswith(".env"):
        return "dotenv"
    if p.name.startswith("dockerfile"):
        return "docker"
    return LANGUAGE_BY_SUFFIX.get(p.suffix, "unknown")


def match_glob(path: str, pattern: str) -> bool:
    """fnmatch with ``**`` support: ``dir/**`` matches everything below ``dir``,
    and a leading ``**/`` also matches at the repository root."""
    if fnmatch.fnmatchcase(path, pattern):
        return True
    if pattern.endswith("/**"):
        prefix = pattern[:-3]
        if path.startswith(prefix + "/") or fnmatch.fnmatchcase(path, prefix + "/*"):
            return True
    if pattern.startswith("**/"):
        return match_glob(path, pattern[3:])
    return False


def matches_any(path: str, patterns: list[str]) -> bool:
    return any(match_glob(path, p) for p in patterns)


def is_test_path(path: str) -> bool:
    p = PurePosixPath(path)
    if any(part.lower() in _TEST_DIRS for part in p.parts[:-1]):
        return True
    return bool(_TEST_NAME_RE.match(p.name))


def classify(path: str, binary: bool = False, test_globs: list[str] | None = None) -> FileInfo:
    language = detect_language(path)
    lowered = path.lower()
    pure = PurePosixPath(lowered)
    is_doc_name = pure.stem in DOC_NAMES and pure.suffix in ("", ".md", ".txt", ".rst")

    if binary or pure.suffix in BINARY_SUFFIXES:
        kind = "binary"
    elif _REQUIREMENTS_RE.match(pure.name):
        kind = "config"
    elif (
        language in DOC_LANGUAGES
        or is_doc_name
        or lowered.startswith("docs/")
        or "/docs/" in lowered
    ):
        kind = "doc"
    elif is_test_path(path) or (test_globs and matches_any(path, test_globs)):
        kind = "test"
    elif language in MARKUP_LANGUAGES:
        kind = "markup"
    elif language in CONFIG_LANGUAGES:
        kind = "config"
    else:
        kind = "code"
    return FileInfo(path=path, language=language, kind=kind)


def is_comment(text: str, language: str) -> bool:
    stripped = text.lstrip()
    if not stripped:
        return False
    prefixes = COMMENT_PREFIXES.get(language, _C_STYLE)
    return stripped.startswith(prefixes)
