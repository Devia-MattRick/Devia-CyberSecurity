#!/usr/bin/env python3
"""Unit tests for target_scope_guard.py (Capa 3)."""

from __future__ import annotations

import json
import os
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parent))

try:
    from src.scripts.target_scope_guard import (
        ScopeConfig,
        ScopeDecision,
        ScopeError,
        evaluate_scope,
        load_scope_file,
        normalize_target_string,
        parse_scope_dict,
    )
except ImportError:
    from target_scope_guard import (
        ScopeConfig,
        ScopeDecision,
        ScopeError,
        evaluate_scope,
        load_scope_file,
        normalize_target_string,
        parse_scope_dict,
    )



class TestTargetScopeGuard(unittest.TestCase):

    def setUp(self):
        self.sample_scope_data = {
            "enabled": True,
            "allow": [
                {"cidr": "10.0.0.0/24"},
                {"cidr": "192.168.1.0/24"},
                {"host": "internal-corp.local"},
                {"host": "api.test.lan"}
            ],
            "deny": [
                {"cidr": "10.0.0.1/32"},
                {"host": "sensitive.internal-corp.local"}
            ],
            "ports": [80, 443, 8080]
        }
        self.config = parse_scope_dict(self.sample_scope_data)

    def test_parse_valid_scope(self):
        self.assertTrue(self.config.enabled)
        self.assertEqual(len(self.config.allow_cidrs), 2)
        self.assertEqual(len(self.config.deny_cidrs), 1)
        self.assertIn("internal-corp.local", self.config.allow_hosts)
        self.assertIn(80, self.config.ports)

    def test_parse_invalid_scope(self):
        with self.assertRaises(ScopeError):
            parse_scope_dict({"allow": [{"cidr": "999.999.999.999/99"}]})
        with self.assertRaises(ScopeError):
            parse_scope_dict({"ports": "not-a-list"})
        with self.assertRaises(ScopeError):
            parse_scope_dict({"ports": [99999]})

    def test_kill_switch_or_disabled(self):
        disabled_cfg = parse_scope_dict({"enabled": False, "allow": [{"cidr": "10.0.0.0/24"}]})
        decision = evaluate_scope(disabled_cfg, ["1.1.1.1"], "curl 1.1.1.1")
        self.assertTrue(decision.allowed)
        self.assertFalse(decision.enforced)

        os.environ["SCOPE_ENFORCE"] = "0"
        try:
            decision = evaluate_scope(self.config, ["8.8.8.8"], "nmap 8.8.8.8")
            self.assertTrue(decision.allowed)
            self.assertFalse(decision.enforced)
        finally:
            del os.environ["SCOPE_ENFORCE"]

    def test_fail_closed_on_missing_declared_targets(self):
        decision = evaluate_scope(self.config, [], "nmap 10.0.0.5")
        self.assertFalse(decision.allowed)
        self.assertTrue(decision.enforced)
        self.assertEqual(decision.violations[0]["rule"], "MISSING_DECLARED_TARGETS")

    def test_allowed_targets_in_cidr(self):
        decision = evaluate_scope(self.config, ["10.0.0.15"], "nmap 10.0.0.15")
        self.assertTrue(decision.allowed)
        self.assertEqual(len(decision.violations), 0)

    def test_denied_cidr_has_priority(self):
        # 10.0.0.1 is in 10.0.0.0/24 (allow) but explicitly denied in 10.0.0.1/32 (deny)
        decision = evaluate_scope(self.config, ["10.0.0.1"], "nmap 10.0.0.1")
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.violations[0]["rule"], "DENIED_CIDR")

    def test_literal_host_allow_and_deny(self):
        decision_allowed = evaluate_scope(self.config, ["internal-corp.local"], "curl http://internal-corp.local")
        self.assertTrue(decision_allowed.allowed)

        # Denied host
        decision_denied = evaluate_scope(self.config, ["sensitive.internal-corp.local"])
        self.assertFalse(decision_denied.allowed)
        self.assertEqual(decision_denied.violations[0]["rule"], "DENIED_HOST")

        # Non-matching host suffix (no wildcards unless configured)
        decision_suffix = evaluate_scope(self.config, ["evilinternal-corp.local"])
        self.assertFalse(decision_suffix.allowed)
        self.assertEqual(decision_suffix.violations[0]["rule"], "NOT_IN_ALLOW_LIST")

    def test_port_restriction(self):
        # Port 8080 allowed
        decision_8080 = evaluate_scope(self.config, ["http://10.0.0.5:8080"])
        self.assertTrue(decision_8080.allowed)

        # Port 22 blocked
        decision_22 = evaluate_scope(self.config, ["10.0.0.5:22"])
        self.assertFalse(decision_22.allowed)
        self.assertEqual(decision_22.violations[0]["rule"], "PORT_NOT_ALLOWED")

    def test_belt_and_suspenders_command_inspection(self):
        # Target declared is valid, but command injects undeclared IP
        decision = evaluate_scope(self.config, ["10.0.0.5"], "nmap -sV 10.0.0.5 8.8.8.8")
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.violations[0]["rule"], "COMMAND_CONTAINS_UNDECLARED_FOREIGN_IP")

        # Command has denied IP
        decision_deny_cmd = evaluate_scope(self.config, ["10.0.0.5"], "curl 10.0.0.1")
        self.assertFalse(decision_deny_cmd.allowed)
        self.assertEqual(decision_deny_cmd.violations[0]["rule"], "COMMAND_ARG_IN_DENY_CIDR")

    def test_normalize_target_string(self):
        t1 = normalize_target_string("https://api.test.lan:443/v1/auth")
        self.assertEqual(t1.host, "api.test.lan")
        self.assertEqual(t1.port, 443)

        t2 = normalize_target_string("192.168.1.50:8080")
        self.assertEqual(str(t2.ip), "192.168.1.50")
        self.assertEqual(t2.port, 8080)

    def test_load_scope_file(self):
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
            json.dump(self.sample_scope_data, f)
            temp_path = f.name

        try:
            loaded_cfg = load_scope_file(temp_path)
            self.assertIsNotNone(loaded_cfg)
            self.assertTrue(loaded_cfg.enabled)
        finally:
            os.unlink(temp_path)


if __name__ == "__main__":
    unittest.main()
