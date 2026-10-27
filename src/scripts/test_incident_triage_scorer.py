#!/usr/bin/env python3
"""Unit tests for incident_triage_scorer.py."""

import unittest
from incident_triage_scorer import (
    calculate_incident_score,
    score_to_severity,
    severity_to_sla_hours,
    evaluate_incident
)


class TestIncidentTriageScorer(unittest.TestCase):
    def test_critical_ransomware_evaluation(self):
        eval_res = evaluate_incident(
            incident_id="INC-TEST-001",
            title="Enterprise Ransomware Attack",
            incident_type="ransomware",
            asset_criticality="critical",
            data_sensitivity="pii_phi",
            threat_status="active",
            scope="enterprise",
            affected_assets=["dc01.corp", "db01.corp"]
        )

        self.assertEqual(eval_res["incidentId"], "INC-TEST-001")
        self.assertEqual(eval_res["severity"], "CRITICAL")
        self.assertEqual(eval_res["score"], 10.0)
        self.assertEqual(eval_res["slaResponseHours"], 0.25)
        self.assertEqual(eval_res["assignedPlaybook"], "ransomware-ir-playbook-v3")
        self.assertTrue(eval_res["escalationRequired"])
        self.assertGreater(len(eval_res["containmentRecommendations"]), 2)

    def test_low_recon_evaluation(self):
        eval_res = evaluate_incident(
            incident_id="INC-TEST-002",
            title="Single Port Scan from External Source",
            incident_type="web_attack",
            asset_criticality="low",
            data_sensitivity="public",
            threat_status="recon",
            scope="single_user",
            affected_assets=["dmz-proxy-01"]
        )

        self.assertEqual(eval_res["severity"], "INFORMATIONAL")
        self.assertEqual(eval_res["score"], 0.0)
        self.assertEqual(eval_res["slaResponseHours"], 72.0)
        self.assertFalse(eval_res["escalationRequired"])

    def test_medium_phishing_evaluation(self):
        score = calculate_incident_score(
            asset_criticality="medium",
            data_sensitivity="confidential",
            threat_status="attempted",
            scope="single_user"
        )
        self.assertGreater(score, 1.0)
        self.assertLess(score, 6.0)

    def test_severity_levels_consistency(self):
        self.assertEqual(score_to_severity(9.0), "CRITICAL")
        self.assertEqual(score_to_severity(7.0), "HIGH")
        self.assertEqual(score_to_severity(5.0), "MEDIUM")
        self.assertEqual(score_to_severity(3.0), "LOW")
        self.assertEqual(score_to_severity(1.0), "INFORMATIONAL")


if __name__ == "__main__":
    unittest.main()
