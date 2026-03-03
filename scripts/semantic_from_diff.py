from __future__ import annotations

import argparse
import json
import os
import re
from pathlib import Path


RISK_AREA_MAP = {
    "auth": "authentication",
    "permission": "authorization",
    "payment": "payment",
    "billing": "payment",
    "migrat": "database",
    "schema": "database",
    "thread": "concurrency",
    "async": "concurrency",
    "infra": "infrastructure",
    "k8s": "infrastructure",
    "api": "api",
    "config": "configuration",
    "security": "security",
}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Generate semantic analysis JSON from a unified diff."
    )
    parser.add_argument("--diff", required=True, type=Path, help="Path to unified diff.")
    parser.add_argument(
        "--output", required=True, type=Path, help="Path to semantic JSON output."
    )
    parser.add_argument(
        "--mr-id",
        default=os.getenv("CI_MERGE_REQUEST_IID", "local-mr"),
        help="Merge request ID.",
    )
    parser.add_argument(
        "--repo",
        default=os.getenv("CI_PROJECT_PATH", "local/repo"),
        help="Repository identifier.",
    )
    parser.add_argument(
        "--branch",
        default=os.getenv("CI_COMMIT_REF_NAME", "local-branch"),
        help="Branch name.",
    )
    parser.add_argument(
        "--sha",
        default=os.getenv("CI_COMMIT_SHA", "local-sha"),
        help="Commit SHA.",
    )
    return parser.parse_args()


def detect_language(path: str) -> str:
    suffix = Path(path).suffix.lower()
    mapping = {
        ".py": "python",
        ".js": "javascript",
        ".ts": "typescript",
        ".tsx": "typescript",
        ".java": "java",
        ".go": "go",
        ".rb": "ruby",
        ".cs": "csharp",
        ".php": "php",
        ".rs": "rust",
        ".sql": "sql",
        ".yaml": "yaml",
        ".yml": "yaml",
        ".json": "json",
        ".toml": "toml",
        ".md": "markdown",
    }
    return mapping.get(suffix, "unknown")


def infer_change_types(
    file_path: str, added_lines: list[str], removed_lines: list[str]
) -> list[str]:
    change_types: set[str] = set()
    added_text = "\n".join(added_lines).lower()
    removed_text = "\n".join(removed_lines).lower()

    if re.search(r"\b(def|function|func|class)\b", added_text):
        change_types.add("new_function")
    if added_lines or removed_lines:
        change_types.add("modified_logic")

    if re.search(r"\bif\b|\bguard\b|\bassert\b", removed_text):
        change_types.add("deleted_guard")
        change_types.add("removed_conditional")
    if re.search(r"\b(auth|login|token|permission|role)\b", added_text + removed_text):
        change_types.add("auth_related_edit")
    if re.search(r"\b(admin|sudo|root|superuser)\b", added_text):
        change_types.add("privilege_escalation_pattern")
    if re.search(r"\b(route|endpoint|public|private)\b", added_text + removed_text):
        change_types.add("api_signature_change")
    if re.search(r"\b(create table|alter table|drop table|migration)\b", added_text + removed_text):
        change_types.add("db_schema_change")
    if any(
        file_path.endswith(s)
        for s in (".yml", ".yaml", ".json", ".toml", ".ini", ".env", ".cfg")
    ):
        change_types.add("config_change")
    if re.search(r"\bfor\b|\bwhile\b|\breturn\b|\bbreak\b", added_text + removed_text):
        change_types.add("control_flow_change")

    return sorted(change_types)


def infer_risk_areas(paths: list[str], all_text: str) -> list[str]:
    areas: set[str] = set()
    blob = " ".join(paths).lower() + " " + all_text.lower()
    for key, area in RISK_AREA_MAP.items():
        if key in blob:
            areas.add(area)
    if "validation" in blob or "sanitize" in blob:
        areas.add("data_integrity")
    return sorted(areas)


def infer_categories(
    risk_areas: list[str],
    total_delta: int,
    change_types_all: set[str],
) -> list[str]:
    categories: set[str] = set()

    is_security = "security" in risk_areas or "authentication" in risk_areas
    has_auth_edit = "auth_related_edit" in change_types_all
    has_priv_esc = "privilege_escalation_pattern" in change_types_all

    # Hotfix: small targeted fix touching security/auth surfaces
    if total_delta <= 5 and (is_security or has_auth_edit):
        categories.add("hotfix")
    elif total_delta < 20:
        categories.add("refactor")
    else:
        categories.add("feature")

    if is_security or has_auth_edit or has_priv_esc:
        categories.add("security_sensitive")
    if "infrastructure" in risk_areas:
        categories.add("infra_change")
    return sorted(categories)


def main() -> None:
    args = parse_args()
    raw_diff = args.diff.read_text(encoding="utf-8", errors="replace")
    lines = raw_diff.splitlines()

    files: list[dict] = []
    current_file: dict | None = None
    added_lines: list[str] = []
    removed_lines: list[str] = []
    all_removed_lines: list[str] = []

    total_added = 0
    total_removed = 0
    combined_text_parts: list[str] = []
    path_list: list[str] = []
    all_change_types: set[str] = set()

    def flush_current_file() -> None:
        nonlocal current_file, added_lines, removed_lines
        if not current_file:
            return
        change_types = infer_change_types(current_file["path"], added_lines, removed_lines)
        current_file["change_types"] = change_types
        all_change_types.update(change_types)
        current_file["sensitive"] = (
            "auth_related_edit" in change_types
            or "privilege_escalation_pattern" in change_types
            or "db_schema_change" in change_types
        )
        files.append(current_file)
        added_lines = []
        removed_lines = []
        current_file = None

    for line in lines:
        if line.startswith("diff --git "):
            flush_current_file()
            parts = line.split(" ")
            new_path = parts[3][2:] if len(parts) >= 4 and parts[3].startswith("b/") else "unknown"
            current_file = {
                "path": new_path,
                "status": "modified",
                "language": detect_language(new_path),
                "lines_added": 0,
                "lines_removed": 0,
                "change_types": [],
                "sensitive": False,
            }
            path_list.append(new_path)
            continue

        if current_file is None:
            continue

        if line.startswith("new file mode"):
            current_file["status"] = "added"
            continue
        if line.startswith("deleted file mode"):
            current_file["status"] = "deleted"
            continue
        if line.startswith("rename from ") or line.startswith("rename to "):
            current_file["status"] = "renamed"
            continue

        if line.startswith("--- ") or line.startswith("+++ ") or line.startswith("@@"):
            continue

        if line.startswith("+"):
            content = line[1:]
            current_file["lines_added"] += 1
            total_added += 1
            added_lines.append(content)
            combined_text_parts.append(content)
        elif line.startswith("-"):
            content = line[1:]
            current_file["lines_removed"] += 1
            total_removed += 1
            removed_lines.append(content)
            all_removed_lines.append(content)
            combined_text_parts.append(content)

    flush_current_file()

    combined_text = "\n".join(combined_text_parts)
    removed_text = "\n".join(all_removed_lines)
    risk_areas = infer_risk_areas(path_list, combined_text)
    categories = infer_categories(risk_areas, total_added + total_removed, all_change_types)

    # validation_removed: only true when validation/sanitize code is in REMOVED lines
    validation_removed = bool(
        re.search(r"(validate|validation|sanitize|sanitization)", removed_text.lower())
    )

    payload = {
        "mr": {
            "id": str(args.mr_id),
            "repository": args.repo,
            "branch": args.branch,
            "commit_sha": args.sha,
        },
        "summary": f"Parsed {len(files)} files from diff.",
        "files_changed": files if files else [
            {
                "path": "unknown",
                "status": "modified",
                "language": "unknown",
                "lines_added": 0,
                "lines_removed": 0,
                "change_types": ["modified_logic"],
                "sensitive": False,
            }
        ],
        "risk_areas": risk_areas,
        "change_categories": categories,
        "signals": {
            "auth_touched": "authentication" in risk_areas or "authorization" in risk_areas,
            "payment_touched": "payment" in risk_areas,
            "db_migration_detected": any(
                "db_schema_change" in f["change_types"] for f in files
            ),
            "concurrency_logic_changed": "concurrency" in risk_areas,
            "validation_removed": validation_removed,
            "total_added": total_added,
            "total_removed": total_removed,
        },
        "behavioral_impact": {
            "level": "high"
            if (total_added + total_removed) > 300
            else "medium"
            if (total_added + total_removed) > 80
            else "low",
            "notes": [
                f"Total delta lines: {total_added + total_removed}",
                f"Detected risk areas: {', '.join(risk_areas) if risk_areas else 'none'}",
            ],
        },
    }

    args.output.write_text(
        json.dumps(payload, indent=2, ensure_ascii=True) + "\n", encoding="utf-8"
    )


if __name__ == "__main__":
    main()

