#!/usr/bin/env python3
"""Unit tests for pqc_inventory_scanner.py."""

import json
from pathlib import Path
import tempfile
import unittest

from pqc_inventory_scanner import scan_target, scan_text_for_crypto

class TestPqcInventoryScanner(unittest.TestCase):
    def test_scan_text_detects_classical_rsa_and_ecc(self):
        sample_code = """
        const crypto = require('crypto');
        const rsaKey = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
        const ecdh = crypto.createECDH('secp256k1');
        """
        findings = scan_text_for_crypto(sample_code, "test.js")
        algorithms = [f["algorithm"] for f in findings]
        self.assertIn("RSA", algorithms)
        self.assertIn("ECDH/ECC", algorithms)
        
        rsa_finding = next(f for f in findings if f["algorithm"] == "RSA")
        self.assertEqual(rsa_finding["quantumStatus"], "VULNERABLE_CLASSICAL")
        self.assertEqual(rsa_finding["migrationPriority"], "CRITICAL_LONG_TERM_CONFIDENTIALITY")

    def test_scan_text_detects_pqc_hybrid_and_standardized(self):
        sample_code = """
        import { mlkem768 } from '@noble/post-quantum';
        const cipherGroup = 'X25519MLKEM768';
        const signatureAlgorithm = 'ML-DSA-65';
        """
        findings = scan_text_for_crypto(sample_code, "pqc_client.ts")
        algorithms = [f["algorithm"] for f in findings]
        self.assertIn("X25519MLKEM768", algorithms)
        self.assertIn("ML-DSA (Dilithium)", algorithms)

        hybrid_finding = next(f for f in findings if f["algorithm"] == "X25519MLKEM768")
        self.assertEqual(hybrid_finding["quantumStatus"], "TRANSITIONAL_HYBRID")

    def test_scan_target_directory(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            file1 = Path(tmpdir) / "auth.js"
            file1.write_text("const token = signJWT(payload, privateKey, { algorithm: 'RS256' });", encoding="utf-8")

            file2 = Path(tmpdir) / "tls.ts"
            file2.write_text("const group = 'X25519MLKEM768';", encoding="utf-8")

            report = scan_target(Path(tmpdir))
            metrics = report["metrics"]
            self.assertEqual(metrics["vulnerableClassicalCount"], 1)
            self.assertEqual(metrics["transitionalHybridCount"], 1)
            self.assertEqual(metrics["totalPrimitives"], 2)

if __name__ == "__main__":
    unittest.main()
