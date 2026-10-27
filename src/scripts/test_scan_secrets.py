#!/usr/bin/env python3
"""Unit tests for src/scripts/scan_secrets.py."""

import json
from pathlib import Path
import re
import tempfile
import unittest

from src.scripts.scan_secrets import (
    SECRET_PATTERNS,
    check_gitignore,
    is_allowlisted,
    is_test_path,
    scan_file,
    shannon_entropy,
)


class TestScanSecrets(unittest.TestCase):

    def setUp(self):
        self.compiled = [
            (name, re.compile(pat), sev, desc, cwe)
            for (name, pat, sev, desc, cwe) in SECRET_PATTERNS
        ]

    def test_shannon_entropy(self):
        self.assertEqual(shannon_entropy(""), 0.0)
        self.assertAlmostEqual(shannon_entropy("AAAAAA"), 0.0)
        # Highly random hex string should have higher entropy
        ent = shannon_entropy("4a8b1c9e3f7d2a0b8c6e")
        self.assertGreater(ent, 3.0)

    def test_allowlist_filtering(self):
        self.assertTrue(is_allowlisted("stripe_key = 'sk_test_123456789'"))
        self.assertTrue(is_allowlisted("api_key = 'your_api_key_here'"))
        self.assertTrue(is_allowlisted("password = 'changeme'"))
        self.assertFalse(is_allowlisted("aws_access_key = 'AKIA1234567890ABCDEF'"))

    def test_is_test_path(self):
        self.assertTrue(is_test_path("tests/unit/test_auth.py"))
        self.assertTrue(is_test_path("src/fixtures/mock_data.json"))
        self.assertTrue(is_test_path("demo/sample_run.py"))
        self.assertFalse(is_test_path("src/core/auth_service.py"))

    def test_zero_severity_degradation_in_test_files(self):
        """Strict verification of PROACTIVE.md 3.12: Credential severity is NOT degraded in test paths."""
        with tempfile.TemporaryDirectory() as tmpdir:
            test_file = Path(tmpdir) / "tests" / "test_config.py"
            test_file.parent.mkdir(parents=True, exist_ok=True)
            test_file.write_text("AWS_KEY = 'AKIA1234567890ABCDEF'\n", encoding="utf-8")

            findings = scan_file(test_file, self.compiled, target_root=tmpdir)
            self.assertEqual(len(findings), 1)
            finding = findings[0]
            # Must remain CRITICAL despite residing in tests/
            self.assertEqual(finding["severity"], "critical")
            self.assertTrue(finding["inTestPath"])
            self.assertEqual(finding["type"], "AWS Access Key ID")

    def test_database_and_cloud_patterns(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            cfg = Path(tmpdir) / "database.py"
            cfg.write_text(
                "DB_URL = 'postgresql://admin:super_secret_pw@db.prod.internal:5432/corp'\n"
                "STRIPE = 'sk_live_123456789012345678901234'\n",
                encoding="utf-8"
            )
            findings = scan_file(cfg, self.compiled, target_root=tmpdir)
            types = {f["type"] for f in findings}
            self.assertIn("PostgreSQL Connection String", types)
            self.assertIn("Stripe Live Secret Key", types)

    def test_gitignore_detection(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            env_file = root / ".env"
            env_file.write_text("API_KEY=secret_12345\n", encoding="utf-8")

            # Case 1: Missing .gitignore entirely
            findings = check_gitignore(root)
            self.assertEqual(len(findings), 1)
            self.assertEqual(findings[0]["type"], "Missing .gitignore Configuration")

            # Case 2: .gitignore exists but does not ignore .env
            gi = root / ".gitignore"
            gi.write_text("node_modules/\ndist/\n", encoding="utf-8")
            findings2 = check_gitignore(root)
            self.assertEqual(len(findings2), 1)
            self.assertEqual(findings2[0]["type"], ".env Excluded from .gitignore")

            # Case 3: .gitignore properly ignores .env
            gi.write_text("node_modules/\n.env\n", encoding="utf-8")
            findings3 = check_gitignore(root)
            self.assertEqual(len(findings3), 0)


if __name__ == "__main__":
    unittest.main()
