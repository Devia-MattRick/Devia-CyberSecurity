#!/usr/bin/env python3
"""Unit tests for hard_exclusions.py."""

import unittest
from pathlib import Path
from src.scripts.hard_exclusions import HardExclusionEngine, ExclusionResult


class TestHardExclusionEngine(unittest.TestCase):

    def test_dos_resource_exhaustion_excluded(self):
        finding = {
            "title": "Potential Denial of Service",
            "description": "Unbounded loop could exhaust memory and cpu resources",
            "file": "service.py"
        }
        res = HardExclusionEngine.evaluate_finding(finding)
        self.assertTrue(res.is_excluded)
        self.assertEqual(res.rule_category, "DOS_RESOURCE_EXHAUSTION")

    def test_dos_with_rce_exploit_override_preserved(self):
        finding = {
            "title": "Stack overflow leading to RCE",
            "description": "Infinite recursion can be leveraged for remote code execution",
            "file": "engine.c",
            "exploit_scenario": "Attacker triggers buffer manipulation to execute arbitrary code"
        }
        res = HardExclusionEngine.evaluate_finding(finding)
        self.assertFalse(res.is_excluded)
        self.assertTrue(res.exploit_override)

    def test_rate_limiting_excluded(self):
        finding = {
            "title": "Missing rate limit on login",
            "description": "Lack of rate limiting allows unlimited requests",
            "file": "auth.py"
        }
        res = HardExclusionEngine.evaluate_finding(finding)
        self.assertTrue(res.is_excluded)
        self.assertEqual(res.rule_category, "RATE_LIMITING")

    def test_resource_leak_excluded(self):
        finding = {
            "title": "Unclosed database connection",
            "description": "Connection leak potential if cleanup function is omitted",
            "file": "db.py"
        }
        res = HardExclusionEngine.evaluate_finding(finding)
        self.assertTrue(res.is_excluded)
        self.assertEqual(res.rule_category, "RESOURCE_MANAGEMENT")

    def test_isolated_open_redirect_excluded(self):
        finding = {
            "title": "Unvalidated redirect vulnerability",
            "description": "User controlled parameter in redirect URL",
            "file": "views.py"
        }
        res = HardExclusionEngine.evaluate_finding(finding)
        self.assertTrue(res.is_excluded)
        self.assertEqual(res.rule_category, "OPEN_REDIRECT")

    def test_open_redirect_with_oauth_preserved(self):
        finding = {
            "title": "Open redirect in OAuth callback",
            "description": "Malicious redirect parameter allows Account Takeover (ATO)",
            "file": "oauth.py"
        }
        res = HardExclusionEngine.evaluate_finding(finding)
        self.assertFalse(res.is_excluded)
        self.assertTrue(res.exploit_override)

    def test_memory_safety_in_typescript_excluded(self):
        finding = {
            "title": "Buffer overflow detected",
            "description": "Array bounds access out of bounds without check",
            "file": "parser.ts"
        }
        res = HardExclusionEngine.evaluate_finding(finding)
        self.assertTrue(res.is_excluded)
        self.assertEqual(res.rule_category, "MEMORY_SAFETY_IN_SAFE_LANGUAGE")

    def test_memory_safety_in_c_cpp_preserved(self):
        finding = {
            "title": "Buffer overflow in packet processing",
            "description": "Out of bounds write in buffer manipulation",
            "file": "packet.cpp"
        }
        res = HardExclusionEngine.evaluate_finding(finding)
        self.assertFalse(res.is_excluded)

    def test_markdown_documentation_excluded(self):
        finding = {
            "title": "Insecure configuration example",
            "description": "Hardcoded secret shown in documentation",
            "file": "docs/architecture.md"
        }
        res = HardExclusionEngine.evaluate_finding(finding)
        self.assertTrue(res.is_excluded)
        self.assertEqual(res.rule_category, "DOCUMENTATION_FILE")

    def test_sqli_and_command_injection_preserved(self):
        sqli = {
            "title": "SQL Injection in Search Endpoint",
            "description": "User input concatenated directly into SQL statement",
            "file": "models/user.py",
            "category": "sql_injection"
        }
        res = HardExclusionEngine.evaluate_finding(sqli)
        self.assertFalse(res.is_excluded)

        cmdi = {
            "title": "Command Injection in File Converter",
            "description": "System call executes shell command with unsanitized parameters",
            "file": "utils/converter.py",
            "category": "command_injection"
        }
        res_cmdi = HardExclusionEngine.evaluate_finding(cmdi)
        self.assertFalse(res_cmdi.is_excluded)

    def test_batch_filter_findings(self):
        batch = [
            {"title": "Missing rate limit", "description": "Add rate limit", "file": "api.py"},
            {"title": "SQL Injection", "description": "Raw query with user input", "file": "api.py"},
            {"title": "Resource leak", "description": "Unclosed file handle", "file": "io.py"},
            {"title": "RCE in Deserialization", "description": "Pickle loads on untrusted data", "file": "tasks.py"}
        ]
        kept, excluded, summary = HardExclusionEngine.filter_findings(batch)
        self.assertEqual(summary.total_findings, 4)
        self.assertEqual(summary.kept_findings, 2)
        self.assertEqual(summary.excluded_findings, 2)
        self.assertEqual(len(kept), 2)
        self.assertEqual(len(excluded), 2)


if __name__ == "__main__":
    unittest.main()
