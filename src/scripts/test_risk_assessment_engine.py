#!/usr/bin/env python3
"""Unit tests for risk_assessment_engine.py."""

import unittest
from pathlib import Path
import tempfile
import json
import os

from src.scripts.risk_assessment_engine import (
    compute_risk_level,
    evaluate_threat_events,
    build_risk_assessment_report,
    render_markdown_summary,
    NIST_800_30_MATRIX
)


class TestRiskAssessmentEngine(unittest.TestCase):
    def test_compute_risk_level_boundaries(self):
        # Very High: Likelihood 5, Impact 5
        level, score = compute_risk_level(5, 5)
        self.assertEqual(level, "VERY_HIGH")
        self.assertEqual(score, 100.0)

        # High: Likelihood 4, Impact 4
        level, score = compute_risk_level(4, 4)
        self.assertEqual(level, "HIGH")
        self.assertEqual(score, 64.0)

        # Moderate: Likelihood 3, Impact 3
        level, score = compute_risk_level(3, 3)
        self.assertEqual(level, "MODERATE")
        self.assertEqual(score, 36.0)

        # Low: Likelihood 2, Impact 2
        level, score = compute_risk_level(2, 2)
        self.assertEqual(level, "LOW")
        self.assertEqual(score, 16.0)

        # Very Low: Likelihood 1, Impact 1
        level, score = compute_risk_level(1, 1)
        self.assertEqual(level, "VERY_LOW")
        self.assertEqual(score, 4.0)

    def test_clamping_out_of_range(self):
        # Likelihood > 5 and Impact < 1
        level, score = compute_risk_level(10, 0)
        self.assertEqual(level, "LOW") # L=5, I=1 -> LOW
        self.assertEqual(score, 20.0)

    def test_evaluate_threat_events_ranking(self):
        events = [
            {"id": "EVT-001", "title": "Low Threat", "likelihoodLevel": 1, "impactLevel": 2},
            {"id": "EVT-002", "title": "Critical DCSync", "likelihoodLevel": 5, "impactLevel": 5},
            {"id": "EVT-003", "title": "Medium Issue", "likelihoodLevel": 3, "impactLevel": 3}
        ]
        processed, metrics = evaluate_threat_events(events)
        
        self.assertEqual(len(processed), 3)
        # First event must be EVT-002 due to highest score
        self.assertEqual(processed[0]["id"], "EVT-002")
        self.assertEqual(processed[0]["riskLevel"], "VERY_HIGH")
        self.assertEqual(processed[1]["id"], "EVT-003")
        self.assertEqual(processed[2]["id"], "EVT-001")

        self.assertEqual(metrics["totalEvents"], 3)
        self.assertEqual(metrics["veryHighCount"], 1)
        self.assertEqual(metrics["moderateCount"], 1)
        self.assertEqual(metrics["veryLowCount"], 1)

    def test_build_risk_assessment_report(self):
        events = [
            {
                "id": "RISK-101",
                "title": "Unauthenticated RCE",
                "threatSource": "ADVERSARIAL",
                "vulnerabilityOrPredisposingCondition": "Insecure deserialization",
                "likelihoodLevel": 4,
                "impactLevel": 5,
                "cwe": ["CWE-502"],
                "mitreTechniques": ["T1203"]
            }
        ]
        report = build_risk_assessment_report(
            name="Test Assessment",
            scope="API Gateway",
            tier=3,
            conducted_by="Auditor",
            raw_events=events
        )

        self.assertIn("assessmentId", report)
        self.assertEqual(report["name"], "Test Assessment")
        self.assertEqual(len(report["threatEvents"]), 1)
        self.assertEqual(report["topRisks"], ["RISK-101"])
        self.assertEqual(report["metrics"]["veryHighCount"], 1)

    def test_render_markdown_summary(self):
        events = [{"id": "EVT-001", "title": "Sample", "likelihoodLevel": 3, "impactLevel": 4}]
        report = build_risk_assessment_report(
            name="Sample Audit",
            scope="Scope",
            tier=2,
            conducted_by="Tester",
            raw_events=events
        )
        md = render_markdown_summary(report)
        self.assertIn("# Resumen de Evaluación de Riesgos — Sample Audit", md)
        self.assertIn("| `EVT-001` | Sample |", md)


if __name__ == "__main__":
    unittest.main()
