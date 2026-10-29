#!/usr/bin/env python3
"""Unit tests for endpoint_hardening_auditor.py."""

import unittest
from endpoint_hardening_auditor import (
    CANONICAL_ASR_RULES,
    evaluate_endpoint_posture,
    generate_sample_profile,
    normalize_mode,
)


class TestEndpointHardeningAuditor(unittest.TestCase):

    def test_canonical_asr_rules_count(self):
        """Confirm there are exactly 16 canonical ASR rules mapped."""
        self.assertEqual(len(CANONICAL_ASR_RULES), 16)
        # LSASS protection GUID check
        self.assertIn("9E6C4E1F-7D60-472F-BA1A-A39EF669E4B2", CANONICAL_ASR_RULES)

    def test_normalize_mode(self):
        self.assertEqual(normalize_mode(1), "BLOCK")
        self.assertEqual(normalize_mode("enabled"), "BLOCK")
        self.assertEqual(normalize_mode(2), "AUDIT")
        self.assertEqual(normalize_mode("audit"), "AUDIT")
        self.assertEqual(normalize_mode(0), "DISABLED")
        self.assertEqual(normalize_mode("disabled"), "DISABLED")

    def test_evaluate_compliant_endpoint(self):
        profile = {
            "hostId": "SECURE-BOX-01",
            "osPlatform": "WINDOWS_11",
            "defenderPreferences": {
                "realTimeProtection": True,
                "behaviorMonitoring": True,
                "ioavProtection": True,
                "networkProtection": "BLOCK",
                "controlledFolderAccess": "BLOCK",
                "cloudBlockLevel": "HIGH",
                "puaProtection": "ENABLED",
                "tamperProtection": True,
            },
            "asrRules": {guid: "BLOCK" for guid in CANONICAL_ASR_RULES.keys()},
        }

        report = evaluate_endpoint_posture(profile)
        self.assertEqual(report["hostId"], "SECURE-BOX-01")
        self.assertEqual(report["complianceScore"], 100.0)
        self.assertEqual(report["verdict"], "PASS")
        self.assertEqual(len(report["criticalGaps"]), 0)
        self.assertEqual(len(report["remediationGuidance"]), 0)

    def test_evaluate_non_compliant_endpoint(self):
        profile = {
            "hostId": "VULNERABLE-BOX-02",
            "osPlatform": "WINDOWS_10",
            "defenderPreferences": {
                "realTimeProtection": False,  # Critical gap
                "behaviorMonitoring": False,
                "networkProtection": "DISABLED",
                "tamperProtection": False,
            },
            "asrRules": {},  # All ASR rules disabled
        }

        report = evaluate_endpoint_posture(profile)
        self.assertEqual(report["hostId"], "VULNERABLE-BOX-02")
        self.assertEqual(report["verdict"], "FAIL")
        self.assertLess(report["complianceScore"], 50.0)
        # Must detect critical real-time protection gap and critical ASR rules
        self.assertTrue(any("Real-time protection is DISABLED" in gap for gap in report["criticalGaps"]))
        self.assertTrue(any("lsass.exe" in gap for gap in report["criticalGaps"]))
        self.assertGreater(len(report["remediationGuidance"]), 10)


if __name__ == "__main__":
    unittest.main()
