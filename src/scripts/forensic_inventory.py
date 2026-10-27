#!/usr/bin/env python3
"""Forensic Inventory and Target Classification Engine for Devia-CyberSecurity (Capa 3).

Safely inventories a quiescent local target (repository, skill, plugin, or directory)
without executing any target files, macros, or scripts.
Accurately accounts for Windows reparse points/junctions and POSIX symlinks.
Outputs deterministically to inventory.jsonl and summary.json.
"""

from __future__ import annotations

import argparse
from collections import Counter
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import stat
import sys
from typing import Any, Dict, List, Optional, Set, Tuple


CRITICAL_SECURITY_FILENAMES = {
    "package.json", "package-lock.json", "pnpm-lock.yaml", "yarn.lock",
    "pyproject.toml", "requirements.txt", "pipfile", "poetry.lock",
    "cargo.toml", "cargo.lock", "go.mod", "go.sum", "pom.xml", "build.gradle",
    "skill.md", "plugin.json", "agents.md", "claude.json", "mcp.json",
    ".env", ".env.local", ".env.production", ".env.example",
    "docker-compose.yml", "docker-compose.yaml", "dockerfile",
    "tsconfig.json", "security.json", "audit.json"
}

CODE_EXTENSIONS = {
    ".py", ".ts", ".js", ".mjs", ".cjs", ".rs", ".go", ".c", ".cpp",
    ".h", ".hpp", ".cs", ".java", ".kt", ".swift", ".rb", ".php",
    ".sh", ".ps1", ".bat", ".cmd", ".sol", ".v"
}

CONFIG_EXTENSIONS = {
    ".json", ".yaml", ".yml", ".toml", ".ini", ".xml", ".env", ".conf"
}

BINARY_EXTENSIONS = {
    ".exe", ".dll", ".so", ".dylib", ".bin", ".elf", ".asar", ".zip",
    ".tar", ".gz", ".7z", ".apk", ".ipa", ".wasm", ".pyc"
}


def get_utc_timestamp() -> str:
    return datetime.now(timezone.utc).isoformat()


def is_link_or_reparse(meta: os.stat_result) -> bool:
    if stat.S_ISLNK(meta.st_mode):
        return True
    attrs = getattr(meta, "st_file_attributes", 0)
    reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    return bool(attrs & reparse_flag)


def compute_file_sha256(path: Path, max_bytes: int = 10 * 1024 * 1024) -> Optional[str]:
    try:
        hasher = hashlib.sha256()
        with path.open("rb") as f:
            read_bytes = 0
            while chunk := f.read(64 * 1024):
                hasher.update(chunk)
                read_bytes += len(chunk)
                if read_bytes > max_bytes:
                    break
        return hasher.hexdigest()
    except Exception:
        return None


def categorize_file(rel_path: str, ext: str, filename: str) -> str:
    fn_lower = filename.lower()
    if fn_lower in CRITICAL_SECURITY_FILENAMES or fn_lower.startswith(".env"):
        return "CRITICAL_MANIFEST_OR_CONFIG"
    if "skill.md" in fn_lower or "plugin.json" in fn_lower:
        return "AGENTIC_SPECIFICATION"
    if ext in CODE_EXTENSIONS:
        return "SOURCE_CODE"
    if ext in CONFIG_EXTENSIONS:
        return "CONFIGURATION"
    if ext in BINARY_EXTENSIONS:
        return "BINARY_OR_PACKAGE"
    if ext in {".md", ".rst", ".txt", ".adoc"}:
        return "DOCUMENTATION"
    return "ASSET_OR_OTHER"


def detect_archetype(counts: Counter[str], filenames: Set[str]) -> str:
    if "skill.md" in filenames or "plugin.json" in filenames:
        return "AGENTIC_SKILL_OR_PLUGIN"
    if "package.json" in filenames and ("app.asar" in filenames or any("electron" in f for f in filenames)):
        return "PACKAGED_DESKTOP_ELECTRON"
    if "package.json" in filenames:
        return "TYPESCRIPT_JAVASCRIPT_ECOSYSTEM"
    if "pyproject.toml" in filenames or "requirements.txt" in filenames:
        return "PYTHON_ECOSYSTEM"
    if "cargo.toml" in filenames:
        return "RUST_ECOSYSTEM"
    if "go.mod" in filenames:
        return "GO_ECOSYSTEM"
    if counts.get("SOURCE_CODE", 0) > 0:
        return "POLYGLOT_SOURCE_REPOSITORY"
    if counts.get("BINARY_OR_PACKAGE", 0) > 0:
        return "BINARY_PACKAGE_OR_CONTAINER"
    return "GENERIC_FILESYSTEM_TREE"


def run_forensic_inventory(
    root_path: Path | str,
    output_dir: Path | str,
    max_entries: int = 150_000,
    exclude_dirs: Optional[Set[str]] = None,
    hash_critical: bool = True
) -> Tuple[Dict[str, Any], int]:
    root = Path(root_path).expanduser().resolve(strict=True)
    if not root.is_dir():
        raise ValueError(f"Root path must be an existing directory: {root}")

    out = Path(output_dir).expanduser().resolve()
    if out == root or root in out.parents:
        raise ValueError("Output directory must be outside the target tree")

    out.mkdir(parents=True, exist_ok=True)
    inventory_file = out / "inventory.jsonl"
    summary_file = out / "summary.json"

    effective_exclusions = {
        PurePosixPath(d).as_posix().lower()
        for d in (exclude_dirs or {".git", ".svn", ".hg", "node_modules", "__pycache__", ".venv", "venv"})
    }

    started_at = get_utc_timestamp()
    category_counts: Counter[str] = Counter()
    extension_counts: Counter[str] = Counter()
    discovered_filenames: Set[str] = set()

    total_files = 0
    total_directories = 0
    total_links_skipped = 0
    total_bytes = 0
    errors: List[Dict[str, str]] = []

    pending_dirs: List[Path] = [root]

    with inventory_file.open("w", encoding="utf-8", newline="\n") as stream:
        while pending_dirs:
            current_dir = pending_dirs.pop()
            total_directories += 1

            try:
                with os.scandir(current_dir) as iterator:
                    for entry in iterator:
                        if (total_files + total_directories) > max_entries:
                            errors.append({
                                "type": "RESOURCE_LIMIT_EXCEEDED",
                                "message": f"Exceeded maximum entries guard of {max_entries}"
                            })
                            pending_dirs.clear()
                            break

                        try:
                            entry_stat = entry.stat(follow_symlinks=False)
                        except OSError as e:
                            errors.append({"path": entry.path, "error": str(e)})
                            continue

                        rel_path = PurePosixPath(Path(entry.path).relative_to(root)).as_posix()
                        name_lower = entry.name.lower()

                        if is_link_or_reparse(entry_stat):
                            total_links_skipped += 1
                            record = {
                                "path": rel_path,
                                "kind": "symlink_or_reparse_point",
                                "status": "skipped_boundary",
                                "size_bytes": entry_stat.st_size
                            }
                            stream.write(json.dumps(record, ensure_ascii=False) + "\n")
                            continue

                        if entry.is_dir(follow_symlinks=False):
                            if name_lower in effective_exclusions or rel_path.lower() in effective_exclusions:
                                continue
                            pending_dirs.append(Path(entry.path))
                        elif entry.is_file(follow_symlinks=False):
                            total_files += 1
                            file_size = entry_stat.st_size
                            total_bytes += file_size
                            ext = Path(entry.name).suffix.lower()
                            extension_counts[ext or "[no_ext]"] += 1
                            discovered_filenames.add(name_lower)

                            category = categorize_file(rel_path, ext, entry.name)
                            category_counts[category] += 1

                            digest = None
                            if hash_critical and category in ("CRITICAL_MANIFEST_OR_CONFIG", "AGENTIC_SPECIFICATION"):
                                digest = compute_file_sha256(Path(entry.path))

                            record = {
                                "path": rel_path,
                                "kind": "file",
                                "extension": ext,
                                "size_bytes": file_size,
                                "category": category,
                                "is_security_critical": category in ("CRITICAL_MANIFEST_OR_CONFIG", "AGENTIC_SPECIFICATION"),
                                "sha256": digest
                            }
                            stream.write(json.dumps(record, ensure_ascii=False) + "\n")

            except OSError as dir_err:
                errors.append({"dir": str(current_dir), "error": str(dir_err)})

    archetype = detect_archetype(category_counts, discovered_filenames)
    finished_at = get_utc_timestamp()

    summary = {
        "target": {
            "root_path": str(root),
            "output_path": str(out),
            "archetype": archetype
        },
        "timestamps": {
            "started_at": started_at,
            "finished_at": finished_at
        },
        "metrics": {
            "total_files": total_files,
            "total_directories": total_directories,
            "total_links_or_reparse_skipped": total_links_skipped,
            "total_bytes": total_bytes,
            "total_errors": len(errors)
        },
        "category_distribution": dict(category_counts),
        "top_extensions": dict(extension_counts.most_common(15)),
        "errors": errors
    }

    with summary_file.open("w", encoding="utf-8") as f:
        json.dump(summary, f, indent=2, ensure_ascii=False)

    exit_code = 1 if errors else 0
    return summary, exit_code


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Forensic repository inventory and classification engine for Devia-CyberSecurity"
    )
    parser.add_argument("target", help="Path to the directory, repository or plugin to inventory")
    parser.add_argument("--output", "-o", required=True, help="Path to store inventory.jsonl and summary.json")
    parser.add_argument("--max-entries", type=int, default=150_000, help="Maximum entries before safety guard trips")
    parser.add_argument("--exclude", action="append", default=[], help="Directories to exclude from traversal")
    parser.add_argument("--no-hash", action="store_true", help="Disable SHA-256 computation of critical files")

    args = parser.parse_args()

    try:
        summary, code = run_forensic_inventory(
            root_path=args.target,
            output_dir=args.output,
            max_entries=args.max_entries,
            exclude_dirs=set(args.exclude) if args.exclude else None,
            hash_critical=not args.no_hash
        )
        print(f"Inventory completed. Archetype: {summary['target']['archetype']}. Files: {summary['metrics']['total_files']}. Code: {code}")
        sys.exit(code)
    except Exception as e:
        print(f"FATAL: {e}", file=sys.stderr)
        sys.exit(2)


if __name__ == "__main__":
    main()
