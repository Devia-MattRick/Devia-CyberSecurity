#!/usr/bin/env python3
"""Unit tests for role_mining_analyzer.py."""

import json
from pathlib import Path
import tempfile
import unittest

from src.scripts.role_mining_analyzer import (
    analyze_role_mining,
    build_user_permission_matrix,
    compute_jaccard_similarity,
    load_assignments,
    mine_roles_bottom_up,
    mine_roles_top_down_jaccard,
)


class TestRoleMiningAnalyzer(unittest.TestCase):
    def test_jaccard_similarity(self):
        set_a = {"aws:s3:read", "aws:ec2:describe"}
        set_b = {"aws:s3:read", "aws:ec2:describe"}
        self.assertEqual(compute_jaccard_similarity(set_a, set_b), 1.0)

        set_c = {"aws:s3:read", "aws:iam:list"}
        # Intersection = 1, Union = 3 -> 1/3 = 0.3333...
        sim = compute_jaccard_similarity(set_a, set_c)
        self.assertAlmostEqual(sim, 1.0 / 3.0, places=4)

        self.assertEqual(compute_jaccard_similarity(set(), set()), 1.0)
        self.assertEqual(compute_jaccard_similarity(set(), {"p1"}), 0.0)

    def test_load_assignments_csv(self):
        csv_content = """user,system,entitlement
alice,aws,S3Read
alice,aws,EC2List
bob,aws,S3Read
bob,aws,EC2List
charlie,azure,Reader
"""
        with tempfile.NamedTemporaryFile("w", delete=False, suffix=".csv", encoding="utf-8") as f:
            f.write(csv_content)
            temp_path = f.name

        try:
            assignments = load_assignments(temp_path)
            self.assertEqual(len(assignments), 5)
            self.assertEqual(assignments[0]["user"], "alice")
            self.assertEqual(assignments[0]["entitlement"], "S3Read")
        finally:
            Path(temp_path).unlink(missing_ok=True)

    def test_mine_roles_bottom_up(self):
        user_matrix = {
            "alice": {"aws:S3Read", "aws:EC2List"},
            "bob": {"aws:S3Read", "aws:EC2List"},
            "carol": {"aws:S3Read", "aws:EC2List"},
            "dave": {"aws:Admin"}
        }
        roles, covered = mine_roles_bottom_up(user_matrix, min_users=2)
        self.assertEqual(len(roles), 1)
        self.assertEqual(roles[0]["roleId"], "ROLE-001")
        self.assertEqual(roles[0]["userCount"], 3)
        self.assertEqual(covered, {"alice", "bob", "carol"})

    def test_mine_roles_top_down_jaccard(self):
        user_matrix = {
            "dev1": {"git:commit", "git:push", "ci:trigger"},
            "dev2": {"git:commit", "git:push", "ci:trigger", "docker:build"},
            "dev3": {"git:commit", "git:push", "npm:publish"}
        }
        # dev1 and dev2 have 3 common perms out of 4 union -> Jaccard 0.75
        roles = mine_roles_top_down_jaccard(user_matrix, similarity_threshold=0.7, min_users=2)
        self.assertGreaterEqual(len(roles), 1)
        self.assertIn("git:commit", roles[0]["permissions"])
        self.assertIn("git:push", roles[0]["permissions"])

    def test_full_analysis_pipeline(self):
        assignments = [
            {"user": "u1", "system": "crm", "entitlement": "view_leads"},
            {"user": "u1", "system": "crm", "entitlement": "edit_leads"},
            {"user": "u2", "system": "crm", "entitlement": "view_leads"},
            {"user": "u2", "system": "crm", "entitlement": "edit_leads"},
            {"user": "u3", "system": "erp", "entitlement": "finance_admin"}
        ]
        result = analyze_role_mining(assignments, min_users=2)
        self.assertEqual(result["metrics"]["totalUsers"], 3)
        self.assertEqual(result["metrics"]["totalOriginalAssignments"], 5)
        self.assertEqual(len(result["minedRoles"]), 1)
        self.assertEqual(result["minedRoles"][0]["userCount"], 2)
        self.assertEqual(len(result["residualDirectPermissions"]), 1)
        self.assertEqual(result["residualDirectPermissions"][0]["user"], "u3")


if __name__ == "__main__":
    unittest.main()
