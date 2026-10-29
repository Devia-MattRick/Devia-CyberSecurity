#!/usr/bin/env python3
"""Unit tests for deception_canary_auditor.py."""

import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))

from deception_canary_auditor import (
    compute_bounded_entropy,
    generate_spa_packet,
    validate_spa_packet,
    audit_deception_assets,
    audit_ztna_device_posture
)


class TestDeceptionCanaryAuditor(unittest.TestCase):

    def test_bounded_entropy_plain_vs_high(self):
        # Plain text has low entropy (< 4.5)
        with tempfile.NamedTemporaryFile("wb", delete=False) as f:
            f.write(b"AAAAABBBBBCCCCCDDDDDEEEEE" * 100)
            plain_path = f.name

        try:
            entropy_plain, bytes_read, sha = compute_bounded_entropy(plain_path, max_bytes=1024)
            self.assertLess(entropy_plain, 4.0)
            self.assertGreater(bytes_read, 0)
            self.assertEqual(len(sha), 64)
        finally:
            os.unlink(plain_path)

        # Pseudorandom / encrypted data has high entropy (> 7.5)
        with tempfile.NamedTemporaryFile("wb", delete=False) as f:
            f.write(os.urandom(4096))
            random_path = f.name

        try:
            entropy_rand, bytes_read, sha = compute_bounded_entropy(random_path, max_bytes=1024)
            self.assertGreater(entropy_rand, 7.5)
            self.assertEqual(bytes_read, 1024)
        finally:
            os.unlink(random_path)

    def test_spa_generation_and_validation(self):
        key = "shared-secret-key-123456"
        pkt = generate_spa_packet("192.168.1.50", "ssh", key, nonce="nonce-alpha-123")
        
        custom_cache = {}
        # First verification should pass
        res1 = validate_spa_packet(pkt, key, max_age_seconds=60, nonce_cache=custom_cache)
        self.assertTrue(res1["valid"])
        self.assertTrue(res1["hmacVerified"])
        self.assertFalse(res1["replayDetected"])
        self.assertEqual(res1["sourceIp"], "192.168.1.50")
        self.assertEqual(res1["serviceRequested"], "ssh")

        # Second verification with same nonce must be detected as replay (VULN-ARCH-026)
        res2 = validate_spa_packet(pkt, key, max_age_seconds=60, nonce_cache=custom_cache)
        self.assertFalse(res2["valid"])
        self.assertTrue(res2["replayDetected"])
        self.assertIn("Replay attack detected", res2["errors"][0])

    def test_spa_tampered_hmac(self):
        key = "correct-key"
        wrong_key = "attacker-tampered-key"
        pkt = generate_spa_packet("10.0.0.1", "admin-port", key)
        
        res = validate_spa_packet(pkt, wrong_key, max_age_seconds=60)
        self.assertFalse(res["valid"])
        self.assertFalse(res["hmacVerified"])
        self.assertIn("HMAC-SHA256 signature verification failed", res["errors"][0])

    def test_audit_deception_assets_deny_all(self):
        assets = [
            {
                "id": "DEC-001",
                "name": "canary-iam-user",
                "type": "DECOY_PRINCIPAL",
                "denyAllPolicyEnforced": True,
                "detectionWiring": {
                    "telemetrySource": "CloudTrail",
                    "alertRule": "CanaryAccessKeyAlert",
                    "notificationSink": "sns:soc"
                },
                "internalTagPresent": True
            },
            {
                "id": "DEC-002",
                "name": "vulnerable-honeytoken",
                "type": "DECOY_PRINCIPAL",
                "denyAllPolicyEnforced": False,  # Missing deny-all (VULN-CONF-018)
                "detectionWiring": {
                    "telemetrySource": "CloudTrail",
                    "alertRule": "Alert",
                    "notificationSink": "sns:soc"
                },
                "internalTagPresent": True
            }
        ]

        result = audit_deception_assets(assets)
        self.assertEqual(result["totalAssets"], 2)
        self.assertEqual(result["compliantCount"], 1)
        self.assertEqual(result["nonCompliantCount"], 1)
        self.assertEqual(result["postureScore"], 50.0)
        self.assertIn("VULN-CONF-018", result["issues"][0]["issues"][0])

    def test_audit_ztna_device_key_expiry(self):
        devices = [
            {"hostname": "dev-laptop-01", "keyExpiryDisabled": False, "online": True},
            {"hostname": "stolen-laptop-02", "keyExpiryDisabled": True, "online": True}  # VULN-ARCH-027
        ]

        result = audit_ztna_device_posture(devices)
        self.assertEqual(result["totalDevices"], 2)
        self.assertEqual(result["violationsCount"], 1)
        self.assertFalse(result["compliant"])
        self.assertIn("VULN-ARCH-027", result["violations"][0]["issue"])


if __name__ == "__main__":
    unittest.main()
