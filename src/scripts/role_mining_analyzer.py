#!/usr/bin/env python3
"""Role Mining and Entitlement Optimization Analyzer for Devia-CyberSecurity.

Analyzes user-permission assignments to discover optimal RBAC roles,
eradicates role explosion and privilege creep, and enforces least privilege
using bottom-up consolidation and top-down Jaccard similarity clustering.
Outputs deterministically conforming to src/schemas/role-mining.schema.ts.
"""

from __future__ import annotations

import argparse
from collections import defaultdict
import csv
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import sys
from typing import Any, Dict, List, Optional, Set, Tuple
import uuid


def compute_jaccard_similarity(set_a: Set[str], set_b: Set[str]) -> float:
    """Calculate the Jaccard similarity coefficient between two sets."""
    if not set_a and not set_b:
        return 1.0
    union_len = len(set_a | set_b)
    if union_len == 0:
        return 0.0
    return len(set_a & set_b) / union_len


def load_assignments(
    file_path: Path | str,
    format_type: str = "auto"
) -> List[Dict[str, str]]:
    """Load user entitlement assignments from CSV or JSON file."""
    path = Path(file_path).expanduser().resolve()
    if not path.is_file():
        raise FileNotFoundError(f"Assignment file not found: {path}")

    fmt = format_type.lower()
    if fmt == "auto":
        fmt = "json" if path.suffix.lower() == ".json" else "csv"

    assignments: List[Dict[str, str]] = []
    if fmt == "json":
        with path.open("r", encoding="utf-8") as f:
            data = json.load(f)
            if isinstance(data, list):
                for item in data:
                    user = str(item.get("user") or item.get("username", "")).strip()
                    sys_name = str(item.get("system") or item.get("application", "default")).strip()
                    ent = str(item.get("entitlement") or item.get("permission", "")).strip()
                    if user and ent:
                        assignments.append({"user": user, "system": sys_name, "entitlement": ent})
    else:
        with path.open("r", encoding="utf-8", newline="") as f:
            reader = csv.DictReader(f)
            for row in reader:
                user = (row.get("user") or row.get("username") or "").strip()
                sys_name = (row.get("system") or row.get("application") or "default").strip()
                ent = (row.get("entitlement") or row.get("permission") or "").strip()
                if user and ent:
                    assignments.append({"user": user, "system": sys_name, "entitlement": ent})

    return assignments


def build_user_permission_matrix(assignments: List[Dict[str, str]]) -> Dict[str, Set[str]]:
    """Build a mapping of user -> set of canonical permissions ('system:entitlement')."""
    matrix: Dict[str, Set[str]] = defaultdict(set)
    for a in assignments:
        key = f"{a['system']}:{a['entitlement']}"
        matrix[a["user"]].add(key)
    return dict(matrix)


def mine_roles_bottom_up(
    user_matrix: Dict[str, Set[str]],
    min_users: int = 2
) -> Tuple[List[Dict[str, Any]], Set[str]]:
    """Mine candidate roles by grouping users with identical permission sets."""
    pattern_to_users: Dict[Tuple[str, ...], List[str]] = defaultdict(list)
    for user, perms in user_matrix.items():
        sorted_perms = tuple(sorted(perms))
        pattern_to_users[sorted_perms].append(user)

    mined_roles: List[Dict[str, Any]] = []
    covered_users: Set[str] = set()
    role_seq = 1

    for perm_tuple, users in pattern_to_users.items():
        if len(users) >= min_users and len(perm_tuple) > 0:
            role_id = f"ROLE-{role_seq:03d}"
            role_seq += 1
            mined_roles.append({
                "roleId": role_id,
                "name": f"Consolidated Exact Role {role_seq - 1}",
                "permissions": list(perm_tuple),
                "assignedUsers": sorted(users),
                "userCount": len(users),
                "algorithm": "BOTTOM_UP_EXACT"
            })
            covered_users.update(users)

    mined_roles.sort(key=lambda r: r["userCount"], reverse=True)
    return mined_roles, covered_users


def mine_roles_top_down_jaccard(
    user_matrix: Dict[str, Set[str]],
    similarity_threshold: float = 0.75,
    min_users: int = 2,
    existing_roles_count: int = 0
) -> List[Dict[str, Any]]:
    """Cluster users by Jaccard similarity and extract common permission intersections."""
    users = sorted(user_matrix.keys())
    role_seq = existing_roles_count + 1
    mined_roles: List[Dict[str, Any]] = []
    used_users: Set[str] = set()

    for i in range(len(users)):
        u1 = users[i]
        if u1 in used_users:
            continue
        perms1 = user_matrix[u1]
        cluster = [u1]
        sim_scores: List[float] = [1.0]

        for j in range(i + 1, len(users)):
            u2 = users[j]
            if u2 in used_users:
                continue
            perms2 = user_matrix[u2]
            sim = compute_jaccard_similarity(perms1, perms2)
            if sim >= similarity_threshold:
                cluster.append(u2)
                sim_scores.append(sim)

        if len(cluster) >= min_users:
            # Common core permissions
            common_perms = set.intersection(*(user_matrix[u] for u in cluster))
            if common_perms:
                role_id = f"ROLE-{role_seq:03d}"
                role_seq += 1
                avg_sim = round(sum(sim_scores) / len(sim_scores), 3)
                mined_roles.append({
                    "roleId": role_id,
                    "name": f"Clustered Jaccard Role {role_seq - 1}",
                    "permissions": sorted(common_perms),
                    "assignedUsers": sorted(cluster),
                    "userCount": len(cluster),
                    "algorithm": "TOP_DOWN_JACCARD",
                    "jaccardSimilarity": avg_sim
                })
                used_users.update(cluster)

    return mined_roles


def analyze_role_mining(
    assignments: List[Dict[str, str]],
    target_system: str = "Enterprise Identity Core",
    min_users: int = 2,
    similarity_threshold: float = 0.75
) -> Dict[str, Any]:
    """Execute complete role mining pipeline and compute optimization metrics."""
    user_matrix = build_user_permission_matrix(assignments)
    total_users = len(user_matrix)

    all_permissions: Set[str] = set()
    for perms in user_matrix.values():
        all_permissions.update(perms)
    total_unique_permissions = len(all_permissions)
    total_original_assignments = len(assignments)

    # 1. Exact bottom-up mining
    bottom_up_roles, covered_exact = mine_roles_bottom_up(user_matrix, min_users=min_users)

    # 2. Remaining users top-down Jaccard clustering
    residual_users = {u: perms for u, perms in user_matrix.items() if u not in covered_exact}
    top_down_roles = mine_roles_top_down_jaccard(
        residual_users,
        similarity_threshold=similarity_threshold,
        min_users=min_users,
        existing_roles_count=len(bottom_up_roles)
    )

    all_mined_roles = bottom_up_roles + top_down_roles

    # Identify residual unassigned permissions
    covered_in_roles: Set[str] = set()
    for r in all_mined_roles:
        covered_in_roles.update(r["assignedUsers"])

    residual_direct: List[Dict[str, Any]] = []
    for u, perms in user_matrix.items():
        if u not in covered_in_roles:
            residual_direct.append({
                "user": u,
                "permissions": sorted(perms)
            })

    # Metrics computation
    distinct_patterns = len(set(tuple(sorted(p)) for p in user_matrix.values()))
    role_explosion_ratio = round(distinct_patterns / max(1, total_users), 3)

    # Simulated new assignments: (roles * users) + direct residuals
    roles_assigned_count = sum(len(r["assignedUsers"]) for r in all_mined_roles)
    residual_assigned_count = sum(len(item["permissions"]) for item in residual_direct)
    new_assignments_total = roles_assigned_count + residual_assigned_count

    if total_original_assignments > 0:
        reduction_pct = max(0.0, round(((total_original_assignments - new_assignments_total) / total_original_assignments) * 100.0, 1))
    else:
        reduction_pct = 0.0

    metrics = {
        "totalUsers": total_users,
        "totalUniquePermissions": total_unique_permissions,
        "totalOriginalAssignments": total_original_assignments,
        "minedRolesCount": len(all_mined_roles),
        "roleExplosionRatio": role_explosion_ratio,
        "assignmentReductionPercent": reduction_pct
    }

    return {
        "analysisId": str(uuid.uuid4()),
        "analyzedAt": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "targetSystem": target_system,
        "minUsersThreshold": min_users,
        "similarityThreshold": similarity_threshold,
        "minedRoles": all_mined_roles,
        "residualDirectPermissions": residual_direct,
        "metrics": metrics
    }


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Role Mining and RBAC Entitlement Optimizer for Devia-CyberSecurity"
    )
    parser.add_argument("input", help="Path to CSV or JSON file containing user-entitlement assignments")
    parser.add_argument("--format", choices=["auto", "csv", "json"], default="auto", help="File format")
    parser.add_argument("--system", default="Enterprise Identity Core", help="Target system name")
    parser.add_argument("--min-users", type=int, default=2, help="Minimum users required to justify a role")
    parser.add_argument("--threshold", type=float, default=0.75, help="Jaccard similarity threshold for clustering")
    parser.add_argument("--output", "-o", help="Optional output JSON file path")
    parser.add_argument("--json", action="store_true", help="Output result as JSON to stdout")

    args = parser.parse_args()

    try:
        assignments = load_assignments(args.input, format_type=args.format)
        analysis = analyze_role_mining(
            assignments=assignments,
            target_system=args.system,
            min_users=args.min_users,
            similarity_threshold=args.threshold
        )

        if args.output:
            out_p = Path(args.output).expanduser().resolve()
            out_p.parent.mkdir(parents=True, exist_ok=True)
            with out_p.open("w", encoding="utf-8") as f:
                json.dump(analysis, f, indent=2, ensure_ascii=False)

        if args.json or not args.output:
            print(json.dumps(analysis, indent=2, ensure_ascii=False))
        else:
            print(f"Role mining completed: {analysis['metrics']['minedRolesCount']} roles mined. Assignment reduction: {analysis['metrics']['assignmentReductionPercent']}%.")

    except Exception as e:
        print(f"FATAL: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
