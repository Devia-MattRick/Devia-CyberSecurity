#!/usr/bin/env python3
"""Unit tests for c2_beaconing_detector.py in Devia-CyberSecurity."""

import json
import math
from pathlib import Path
import tempfile
import unittest

from src.scripts.c2_beaconing_detector import (
    compute_shannon_entropy,
    is_benign_domain,
    parse_timestamp,
    normalize_record,
    analyze_beaconing_patterns,
    load_connection_logs
)


class TestC2BeaconingDetector(unittest.TestCase):

    def test_compute_shannon_entropy(self):
        # Empty string
        self.assertEqual(compute_shannon_entropy(""), 0.0)
        # Low entropy (uniform single character)
        self.assertEqual(compute_shannon_entropy("aaaaaaa"), 0.0)
        # Random DGA-like string has high entropy
        dga = "xkj49v1n20m98zq"
        self.assertGreater(compute_shannon_entropy(dga), 3.5)

    def test_is_benign_domain(self):
        self.assertTrue(is_benign_domain("microsoft.com"))
        self.assertTrue(is_benign_domain("update.microsoft.com"))
        self.assertTrue(is_benign_domain("sub.google.com."))
        self.assertFalse(is_benign_domain("evil-c2-server.xyz"))
        self.assertFalse(is_benign_domain("attacker.com"))

    def test_parse_timestamp(self):
        # Epoch seconds
        self.assertEqual(parse_timestamp(1600000000), 1600000000.0)
        self.assertEqual(parse_timestamp("1600000000.5"), 1600000000.5)
        # ISO format
        self.assertIsNotNone(parse_timestamp("2026-10-28T14:00:00Z"))
        self.assertIsNotNone(parse_timestamp("2026-10-28 14:00:00"))
        # Invalid
        self.assertIsNone(parse_timestamp("invalid-date-string"))

    def test_normalize_record(self):
        # Standard json format
        raw = {
            "timestamp": "2026-10-28T12:00:00Z",
            "src_ip": "192.168.1.50",
            "dst_ip": "104.244.42.1",
            "dst_port": "4444",
            "bytes_sent": "128"
        }
        norm = normalize_record(raw)
        self.assertIsNotNone(norm)
        self.assertEqual(norm["src"], "192.168.1.50")
        self.assertEqual(norm["dst"], "104.244.42.1")
        self.assertEqual(norm["port"], "4444")
        self.assertEqual(norm["bytes_sent"], 128)

        # Zeek format
        zeek_raw = {
            "ts": "1700000000.00",
            "id.orig_h": "10.0.0.5",
            "id.resp_h": "198.51.100.25",
            "id.resp_p": "8080",
            "orig_bytes": "256"
        }
        zeek_norm = normalize_record(zeek_raw)
        self.assertIsNotNone(zeek_norm)
        self.assertEqual(zeek_norm["src"], "10.0.0.5")
        self.assertEqual(zeek_norm["dst"], "198.51.100.25")
        self.assertEqual(zeek_norm["port"], "8080")
        self.assertEqual(zeek_norm["bytes_sent"], 256)

    def test_analyze_beaconing_patterns_detection(self):
        # Generate synthetic beacon: exactly every 60 seconds with 1 second jitter
        base_time = 1700000000.0
        conns = []
        for i in range(25):
            ts = base_time + (i * 60.0) + (0.5 if i % 2 == 0 else -0.5)
            conns.append({
                "timestamp": ts,
                "src": "192.168.1.100",
                "dst": "c2-domain-evil-98z7q.xyz",
                "port": "8443",
                "bytes_sent": 200 + (i % 3)
            })

        findings = analyze_beaconing_patterns(conns, min_connections=10, max_cv=0.25)
        self.assertEqual(len(findings), 1)
        f = findings[0]
        self.assertEqual(f["src"], "192.168.1.100")
        self.assertEqual(f["dst"], "c2-domain-evil-98z7q.xyz")
        self.assertLess(f["coefficient_of_variation"], 0.05)
        self.assertGreaterEqual(f["risk_score"], 60)
        self.assertEqual(f["total_connections"], 25)

    def test_analyze_beaconing_patterns_rejects_random(self):
        # Generate completely irregular traffic
        base_time = 1700000000.0
        conns = []
        import random
        rng = random.Random(42)
        curr = base_time
        for _ in range(25):
            curr += rng.uniform(5.0, 3600.0)
            conns.append({
                "timestamp": curr,
                "src": "192.168.1.100",
                "dst": "normal-site-random.org",
                "port": "443",
                "bytes_sent": rng.randint(100, 50000)
            })

        findings = analyze_beaconing_patterns(conns, min_connections=10, max_cv=0.25)
        # Should be filtered out due to high CV
        self.assertEqual(len(findings), 0)


if __name__ == "__main__":
    unittest.main()
