#!/usr/bin/env python3
"""Deterministic Target Snapshot and Finding Fingerprint Engine for Devia-CyberSecurity.

Implements clean-room deterministic calculations for workspace snapshots
(directory_snapshot, git_worktree) and stable finding primary fingerprints
independent of volatile source line numbers.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import sys
from typing import Any, Dict, List, Optional, Set, Tuple


DEFAULT_EXCLUSIONS: Set[str] = {
    ".git", ".svn", ".hg", "node_modules", "__pycache__", ".venv", "venv", "dist", "build"
}


def compute_file_sha256(path: Path) -> str:
    """Compute SHA-256 digest of a single file in chunks."""
    hasher = hashlib.sha256()
    with path.open("rb") as f:
        while chunk := f.read(64 * 1024):
            hasher.update(chunk)
    return hasher.hexdigest()


def compute_directory_snapshot(
    root_path: Path | str,
    exclude_dirs: Optional[Set[str]] = None
) -> Tuple[str, List[Dict[str, str]]]:
    """Calculate deterministic directory snapshot digest.

    Returns:
        (snapshot_digest, sorted_inventory)
        snapshot_digest format: "devia-snapshot/v1:sha256:<64-hex>"
    """
    root = Path(root_path).expanduser().resolve(strict=True)
    if not root.is_dir():
        raise ValueError(f"Root path must be an existing directory: {root}")

    exclusions = {d.lower() for d in (exclude_dirs or DEFAULT_EXCLUSIONS)}
    file_records: List[Tuple[str, str]] = []

    for dirpath, dirnames, filenames in os.walk(root, topdown=True, followlinks=False):
        # Prune excluded directories in-place
        dirnames[:] = [d for d in dirnames if d.lower() not in exclusions]

        for fname in filenames:
            fpath = Path(dirpath) / fname
            if fpath.is_symlink():
                continue
            try:
                rel_path = PurePosixPath(fpath.relative_to(root)).as_posix()
                f_hash = compute_file_sha256(fpath)
                file_records.append((rel_path, f_hash))
            except (OSError, PermissionError):
                continue

    # Sort deterministically by relative path
    file_records.sort(key=lambda x: x[0])

    # Hash the sorted lines
    manifest_hasher = hashlib.sha256()
    inventory_output: List[Dict[str, str]] = []
    for rel_path, digest in file_records:
        line = f"{rel_path}:{digest}\n"
        manifest_hasher.update(line.encode("utf-8"))
        inventory_output.append({"path": rel_path, "sha256": digest})

    master_digest = f"devia-snapshot/v1:sha256:{manifest_hasher.hexdigest()}"
    return master_digest, inventory_output


def derive_primary_fingerprint(
    target_id: str,
    rule_id: str,
    anchor: str,
    instance: Optional[str] = None
) -> str:
    """Derive stable primary finding fingerprint.

    Format: "devia/v1:sha256:<64-hex>"
    Decoupled from line numbers to survive refactorings and code shifts.
    """
    clean_target = target_id.strip()
    clean_rule = rule_id.strip().lower()
    clean_anchor = anchor.strip().lower()
    clean_inst = (instance or "").strip().lower()

    payload = f"{clean_target}:{clean_rule}:{clean_anchor}:{clean_inst}"
    digest = hashlib.sha256(payload.encode("utf-8")).hexdigest()
    return f"devia/v1:sha256:{digest}"


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Compute deterministic target snapshots or stable finding fingerprints."
    )
    subparsers = parser.add_subparsers(dest="subcommand", required=True)

    # Subcommand: snapshot
    snap_parser = subparsers.add_parser("snapshot", help="Compute deterministic directory snapshot")
    snap_parser.add_argument("path", help="Directory path to snapshot")
    snap_parser.add_argument("--json", action="store_true", help="Output full JSON manifest")

    # Subcommand: fingerprint
    fp_parser = subparsers.add_parser("fingerprint", help="Derive stable finding primary fingerprint")
    fp_parser.add_argument("--target-id", required=True, help="Stable target identifier")
    fp_parser.add_argument("--rule-id", required=True, help="Rule ID (category.control)")
    fp_parser.add_argument("--anchor", required=True, help="Semantic root-control anchor")
    fp_parser.add_argument("--instance", default=None, help="Optional instance differentiator")
    fp_parser.add_argument("--json", action="store_true", help="Output as JSON")

    args = parser.parse_args()

    if args.subcommand == "snapshot":
        digest, inventory = compute_directory_snapshot(args.path)
        if args.json:
            result = {
                "snapshotDigest": digest,
                "totalFiles": len(inventory),
                "inventory": inventory
            }
            print(json.dumps(result, indent=2))
        else:
            print(digest)

    elif args.subcommand == "fingerprint":
        fp = derive_primary_fingerprint(args.target_id, args.rule_id, args.anchor, args.instance)
        if args.json:
            print(json.dumps({"fingerprint": fp, "algorithm": "devia/v1"}))
        else:
            print(fp)


if __name__ == "__main__":
    main()
