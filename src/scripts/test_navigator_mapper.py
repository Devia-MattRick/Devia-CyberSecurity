#!/usr/bin/env python3
"""Unit tests for navigator_mapper.py."""

import json
from pathlib import Path
import tempfile
import unittest

from navigator_mapper import (
    load_navigator_layer,
    validate_navigator_layer,
    map_technique_to_dimension,
    analyze_layer_coverage,
    CANONICAL_DIMENSIONS
)


class TestNavigatorMapper(unittest.TestCase):

    def setUp(self) -> None:
        self.sample_layer = {
            "name": "Test Layer",
            "versions": {
                "attack": "14",
                "navigator": "4.9.1",
                "layer": "4.5"
            },
            "domain": "enterprise-attack",
            "techniques": [
                {"techniqueID": "T1059", "score": 80, "enabled": True},
                {"techniqueID": "T1059.001", "score": 90, "enabled": True},
                {"techniqueID": "T1195", "score": 50, "enabled": True},
                {"techniqueID": "T1552.001", "score": 60, "enabled": True},
                {"techniqueID": "T1078", "score": 70, "enabled": True},
                {"techniqueID": "T1021", "score": 40, "enabled": True},
                {"techniqueID": "T1547.001", "score": 30, "enabled": True},
                {"techniqueID": "T1041", "score": 20, "enabled": True}
            ]
        }

    def test_validate_navigator_layer_valid(self) -> None:
        result = validate_navigator_layer(self.sample_layer)
        self.assertTrue(result["valid"])
        self.assertEqual(result["validTechniques"], 8)
        self.assertEqual(len(result["issues"]), 0)

    def test_validate_navigator_layer_invalid_technique(self) -> None:
        corrupted = {
            "name": "Corrupted Layer",
            "versions": {"attack": "14", "navigator": "4.9.1", "layer": "4.5"},
            "techniques": [{"techniqueID": "NOT_A_TECHNIQUE"}]
        }
        result = validate_navigator_layer(corrupted)
        self.assertFalse(result["valid"])
        self.assertEqual(result["validTechniques"], 0)
        self.assertTrue(any("ID inválido" in issue for issue in result["issues"]))

    def test_map_technique_to_dimension(self) -> None:
        self.assertEqual(map_technique_to_dimension("T1059.001"), "SOURCE_CODE_SAST")
        self.assertEqual(map_technique_to_dimension("T1195"), "SUPPLY_CHAIN_SCA")
        self.assertEqual(map_technique_to_dimension("T1552.001"), "SECRETS_CRYPTOGRAPHY")
        self.assertEqual(map_technique_to_dimension("T1078"), "IDENTITY_ACCESS_SESSION")
        self.assertEqual(map_technique_to_dimension("T1021"), "ARCHITECTURE_BOUNDARIES_ZERO_TRUST")
        self.assertEqual(map_technique_to_dimension("T1547.001"), "CONFIGURATION_HARDENING")
        self.assertEqual(map_technique_to_dimension("T1041"), "RESILIENCE_LOGGING_TELEMETRY")
        self.assertEqual(map_technique_to_dimension("T9999"), "THREAT_MODELING_ATTACK_SURFACE")

    def test_analyze_layer_coverage(self) -> None:
        analysis = analyze_layer_coverage(self.sample_layer)
        self.assertEqual(analysis["layerName"], "Test Layer")
        self.assertEqual(analysis["metrics"]["totalEntries"], 8)
        self.assertEqual(analysis["metrics"]["parentTechniquesCount"], 7)
        self.assertEqual(analysis["metrics"]["subTechniquesCount"], 3)


        # Verify all 8 canonical dimensions are present
        for dim in CANONICAL_DIMENSIONS:
            self.assertIn(dim, analysis["dimensionProjection"])

        # Check SAST has 2 entries (T1059, T1059.001)
        self.assertEqual(analysis["dimensionProjection"]["SOURCE_CODE_SAST"]["count"], 2)

    def test_real_external_layer_parsing(self) -> None:
        external_layer = Path("external-reps/mappings/attack-navigator-layer.json")
        if external_layer.exists():
            data = load_navigator_layer(external_layer)
            result = validate_navigator_layer(data)
            self.assertTrue(result["valid"])
            self.assertEqual(result["totalTechniques"], 218)

            analysis = analyze_layer_coverage(data)
            self.assertEqual(analysis["metrics"]["totalEntries"], 218)
            self.assertGreater(analysis["metrics"]["averageScore"], 0)


if __name__ == "__main__":
    unittest.main()
