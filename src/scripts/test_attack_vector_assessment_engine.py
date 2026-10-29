#!/usr/bin/env python3
"""Unit tests for attack_vector_assessment_engine.py."""

from __future__ import annotations

import os
import sys
import unittest

sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))
from attack_vector_assessment_engine import CANONICAL_VECTORS, evaluate_vectors


class TestAttackVectorAssessmentEngine(unittest.TestCase):

    def test_canonical_vectors_integrity(self):
        self.assertGreaterEqual(len(CANONICAL_VECTORS), 10)
        for vec in CANONICAL_VECTORS:
            self.assertTrue(vec["vectorId"].startswith("VEC-"))
            self.assertIn("title", vec)
            self.assertIn("dimension", vec)
            self.assertTrue(vec["cwe"].startswith("CWE-"))
            self.assertGreater(len(vec["prerequisites"]), 0)
            self.assertGreater(len(vec["remediationControls"]), 0)
            self.assertIn("verificationOracle", vec)

            metrics = vec["metrics"]
            self.assertIn(metrics["attackVector"], ["NETWORK", "ADJACENT", "LOCAL", "PHYSICAL"])
            self.assertIn(metrics["attackComplexity"], ["LOW", "HIGH"])
            self.assertIn(metrics["privilegesRequired"], ["NONE", "LOW", "HIGH"])
            self.assertIn(metrics["userInteraction"], ["NONE", "REQUIRED"])
            self.assertIsInstance(metrics["scopeChanged"], bool)
            self.assertGreaterEqual(metrics["exploitabilityScore"], 0.0)
            self.assertLessEqual(metrics["exploitabilityScore"], 10.0)

    def test_evaluate_vectors_default_state(self):
        report = evaluate_vectors("Test-Target", "scope.test", "INTERNAL_AUDIT")
        self.assertIn("assessmentId", report)
        self.assertIn("timestamp", report)
        self.assertEqual(report["target"]["name"], "Test-Target")
        self.assertEqual(report["target"]["environment"], "INTERNAL_AUDIT")

        summary = report["summary"]
        self.assertEqual(summary["totalVectorsEvaluated"], len(CANONICAL_VECTORS))
        self.assertEqual(summary["prerequisitesMetCount"], len(CANONICAL_VECTORS))
        self.assertEqual(summary["prerequisitesBlockedCount"], 0)
        self.assertEqual(summary["postureGrade"], "CRITICAL_EXPOSURE")

    def test_evaluate_vectors_with_mitigated_vectors(self):
        blocked = ["VEC-ADCS-ESC1", "VEC-HTTP-SMUGGLING", "VEC-PROTOTYPE-POLLUTION"]
        report = evaluate_vectors("Test-Target", "scope.test", "INTERNAL_AUDIT", blocked_vector_ids=blocked)
        summary = report["summary"]
        self.assertEqual(summary["prerequisitesBlockedCount"], 3)
        self.assertEqual(summary["prerequisitesMetCount"], len(CANONICAL_VECTORS) - 3)

        evaluated_map = {item["vectorId"]: item["status"] for item in report["evaluatedVectors"]}
        self.assertEqual(evaluated_map["VEC-ADCS-ESC1"], "PREREQUISITES_BLOCKED")
        self.assertEqual(evaluated_map["VEC-HTTP-SMUGGLING"], "PREREQUISITES_BLOCKED")
        self.assertEqual(evaluated_map["VEC-PROTOTYPE-POLLUTION"], "PREREQUISITES_BLOCKED")
        self.assertEqual(evaluated_map["VEC-SSTI"], "PREREQUISITES_MET")

    def test_evaluate_vectors_hardened_state(self):
        all_ids = [v["vectorId"] for v in CANONICAL_VECTORS]
        report = evaluate_vectors("Test-Target", "scope.test", "INTERNAL_AUDIT", blocked_vector_ids=all_ids)
        summary = report["summary"]
        self.assertEqual(summary["prerequisitesBlockedCount"], len(CANONICAL_VECTORS))
        self.assertEqual(summary["prerequisitesMetCount"], 0)
        self.assertEqual(summary["postureGrade"], "HARDENED")


if __name__ == "__main__":
    unittest.main()
