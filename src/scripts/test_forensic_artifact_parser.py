#!/usr/bin/env python3
"""Unit tests for forensic_artifact_parser.py."""

import struct
import unittest
from pathlib import Path
import sys

# Ensure script can be imported
sys.path.insert(0, str(Path(__file__).parent))
from forensic_artifact_parser import (
    parse_lnk_header,
    analyze_sddl_rights,
    detect_network_c2_beacon_indicators,
    generate_forensic_report
)


class TestForensicArtifactParser(unittest.TestCase):

    def test_parse_lnk_header_valid(self):
        # Construct minimal 76-byte valid LNK header
        # HeaderSize: 0x4c (4 bytes)
        # LinkCLSID: 16 bytes
        # LinkFlags: 0x01 (HasTargetIDList) (4 bytes)
        # FileAttributes: 0x20 (Archive) (4 bytes)
        # CreationTime: 8 bytes
        # AccessTime: 8 bytes
        # WriteTime: 8 bytes
        # FileSize: 1024 (4 bytes)
        # Reserved: 16 bytes
        header = bytearray(76)
        struct.pack_into("<I", header, 0, 0x4c)
        struct.pack_into("<I", header, 20, 0x01)
        struct.pack_into("<I", header, 24, 0x20)
        struct.pack_into("<I", header, 52, 1024)

        result = parse_lnk_header(bytes(header))
        self.assertEqual(result["header_size"], 0x4c)
        self.assertTrue(result["has_target_id_list"])
        self.assertFalse(result["has_link_info"])
        self.assertEqual(result["target_file_size"], 1024)

    def test_parse_lnk_header_invalid_size(self):
        with self.assertRaises(ValueError):
            parse_lnk_header(b"short_data")

    def test_analyze_sddl_rights_generic_all(self):
        # GenericAll mask = 0x10000000
        rights = analyze_sddl_rights(0x10000000)
        right_names = [r["right"] for r in rights]
        self.assertIn("GENERIC_ALL", right_names)

    def test_analyze_sddl_rights_write_dacl_and_owner(self):
        # WriteDACL (0x00040000) + WriteOwner (0x00080000) = 0x000c0000
        rights = analyze_sddl_rights(0x000c0000)
        right_names = [r["right"] for r in rights]
        self.assertIn("WRITE_DACL", right_names)
        self.assertIn("WRITE_OWNER", right_names)

    def test_detect_network_c2_beacon_indicators(self):
        # 5 regular requests to same IP with exactly 10s intervals (zero jitter)
        flows = [
            {"dst_ip": "198.51.100.42", "timestamp_epoch": 1000.0},
            {"dst_ip": "198.51.100.42", "timestamp_epoch": 1010.0},
            {"dst_ip": "198.51.100.42", "timestamp_epoch": 1020.0},
            {"dst_ip": "198.51.100.42", "timestamp_epoch": 1030.0},
            {"dst_ip": "198.51.100.42", "timestamp_epoch": 1040.0},
        ]
        beacons = detect_network_c2_beacon_indicators(flows)
        self.assertEqual(len(beacons), 1)
        self.assertEqual(beacons[0]["dst_ip"], "198.51.100.42")
        self.assertEqual(beacons[0]["mean_interval_sec"], 10.0)
        self.assertLessEqual(beacons[0]["jitter_coef"], 0.05)

    def test_generate_forensic_report_contract(self):
        raw = [
            {
                "id": "ART-001",
                "source": "WINDOWS_PREFETCH",
                "category": "EXECUTION_HISTORY",
                "entityName": "SVCHOST.EXE",
                "observedTimestamp": "2026-10-28T14:00:00Z",
                "isAnomaly": False
            }
        ]
        rep = generate_forensic_report("TEST_HOST", raw)
        self.assertIn("reportId", rep)
        self.assertEqual(rep["targetHostOrImage"], "TEST_HOST")
        self.assertEqual(rep["metrics"]["totalArtifacts"], 1)
        self.assertEqual(rep["metrics"]["anomaliesCount"], 0)


if __name__ == "__main__":
    unittest.main()
