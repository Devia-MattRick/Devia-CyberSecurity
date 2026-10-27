#!/usr/bin/env python3
"""Deterministic Post-Quantum Cryptography (PQC) Inventory Scanner for Devia-CyberSecurity.

Audits quiescent codebases, manifests, and configs to discover cryptographic primitives,
classifies them into classical vs quantum-safe/hybrid status (FIPS 203/204/205, RFC 10024),
and outputs structured JSON conforming to CryptographicInventoryReportSchema.
"""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import sys
from typing import Any, Dict, List, Optional
import uuid

# Canonical PQC rules and patterns
PQC_RULES = [
    {
        "id": "RULE-CRYPTO-RSA",
        "algorithm": "RSA",
        "category": "ASYMMETRIC_KEY_EXCHANGE",
        "usage": "KEY_EXCHANGE",
        "quantumStatus": "VULNERABLE_CLASSICAL",
        "migrationPriority": "CRITICAL_LONG_TERM_CONFIDENTIALITY",
        "standard": "PKCS#1 / NIST SP 800-56B",
        "pattern": re.compile(r"\b(RSA\.generate|RS256|RS384|RS512|RSA_PKCS1|createPrivateKey\(.*rsa|RSAKey)\b", re.IGNORECASE)
    },
    {
        "id": "RULE-CRYPTO-ECDH",
        "algorithm": "ECDH/ECC",
        "category": "ASYMMETRIC_KEY_EXCHANGE",
        "usage": "KEY_EXCHANGE",
        "quantumStatus": "VULNERABLE_CLASSICAL",
        "migrationPriority": "CRITICAL_LONG_TERM_CONFIDENTIALITY",
        "standard": "SEC 1 / NIST SP 800-56A",
        "pattern": re.compile(r"\b(ECDH|secp256k1|secp384r1|prime256v1|X25519(?![a-zA-Z0-9_-]*mlkem))\b", re.IGNORECASE)
    },
    {
        "id": "RULE-CRYPTO-ECDSA",
        "algorithm": "ECDSA/EdDSA",
        "category": "ASYMMETRIC_SIGNATURE",
        "usage": "DIGITAL_SIGNATURE",
        "quantumStatus": "VULNERABLE_CLASSICAL",
        "migrationPriority": "HIGH_LONG_TERM_TRUST",
        "standard": "FIPS 186-4",
        "pattern": re.compile(r"\b(ES256|ES384|ES512|EdDSA|Ed25519|ECDSA)\b", re.IGNORECASE)
    },
    {
        "id": "RULE-CRYPTO-DH",
        "algorithm": "Diffie-Hellman",
        "category": "ASYMMETRIC_KEY_EXCHANGE",
        "usage": "KEY_EXCHANGE",
        "quantumStatus": "VULNERABLE_CLASSICAL",
        "migrationPriority": "CRITICAL_LONG_TERM_CONFIDENTIALITY",
        "standard": "RFC 3526 / RFC 7919",
        "pattern": re.compile(r"\b(Diffie-Hellman|createDiffieHellman|DHE-RSA|DH-GEX)\b", re.IGNORECASE)
    },
    {
        "id": "RULE-CRYPTO-MLKEM",
        "algorithm": "ML-KEM (Kyber)",
        "category": "HYBRID_CLASSICAL_PQC",
        "usage": "KEY_EXCHANGE",
        "quantumStatus": "QUANTUM_SAFE_STANDARDIZED",
        "migrationPriority": "LOW_SHORT_LIVED",
        "standard": "NIST FIPS 203",
        "pattern": re.compile(r"\b(ML-KEM-512|ML-KEM-768|ML-KEM-1024|KYBER768|KYBER1024)\b", re.IGNORECASE)
    },
    {
        "id": "RULE-CRYPTO-HYBRID-TLS",
        "algorithm": "X25519MLKEM768",
        "category": "HYBRID_CLASSICAL_PQC",
        "usage": "TRANSPORT_TLS",
        "quantumStatus": "TRANSITIONAL_HYBRID",
        "migrationPriority": "LOW_SHORT_LIVED",
        "standard": "RFC 10024 / NIST FIPS 203",
        "pattern": re.compile(r"\b(X25519MLKEM768|X25519Kyber768Draft00|SecP256r1MLKEM768)\b", re.IGNORECASE)
    },
    {
        "id": "RULE-CRYPTO-MLDSA",
        "algorithm": "ML-DSA (Dilithium)",
        "category": "ASYMMETRIC_SIGNATURE",
        "usage": "DIGITAL_SIGNATURE",
        "quantumStatus": "QUANTUM_SAFE_STANDARDIZED",
        "migrationPriority": "LOW_SHORT_LIVED",
        "standard": "NIST FIPS 204",
        "pattern": re.compile(r"\b(ML-DSA-44|ML-DSA-65|ML-DSA-87|Dilithium2|Dilithium3|Dilithium5)\b", re.IGNORECASE)
    },
    {
        "id": "RULE-CRYPTO-AES256",
        "algorithm": "AES-256",
        "category": "SYMMETRIC_CIPHER",
        "usage": "DATA_AT_REST",
        "quantumStatus": "ADEQUATE_SYMMETRIC",
        "migrationPriority": "LOW_SHORT_LIVED",
        "standard": "NIST FIPS 197",
        "pattern": re.compile(r"\b(AES-256-GCM|AES-256-CBC|AES-256-CTR|aes_256_gcm)\b", re.IGNORECASE)
    }
]

EXCLUDE_DIRS = {
    ".git", "node_modules", ".venv", "venv", "__pycache__", "dist", "build", ".next", ".astro"
}

ALLOWED_EXTENSIONS = {
    ".py", ".ts", ".js", ".mjs", ".cjs", ".go", ".rs", ".java", ".json", ".yaml", ".yml", ".md"
}

def scan_text_for_crypto(text: str, filename: str) -> List[Dict[str, Any]]:
    findings = []
    lines = text.splitlines()
    for line_idx, line in enumerate(lines, start=1):
        for rule in PQC_RULES:
            match = rule["pattern"].search(line)
            if match:
                findings.append({
                    "ruleId": rule["id"],
                    "algorithm": rule["algorithm"],
                    "category": rule["category"],
                    "usage": rule["usage"],
                    "quantumStatus": rule["quantumStatus"],
                    "migrationPriority": rule["migrationPriority"],
                    "standard": rule["standard"],
                    "sourceLocation": f"{filename}:{line_idx}",
                    "snippet": line.strip()[:140]
                })
    return findings

def scan_target(target_path: Path) -> Dict[str, Any]:
    target = target_path.resolve()
    scanned_files = []
    all_findings = []
    
    if target.is_file():
        files = [target]
    else:
        files = []
        for root, dirs, filenames in os.walk(target):
            dirs[:] = [d for d in dirs if d not in EXCLUDE_DIRS]
            for f in filenames:
                p = Path(root) / f
                if p.suffix.lower() in ALLOWED_EXTENSIONS:
                    files.append(p)

    entry_id = 1
    inventory_entries: List[Dict[str, Any]] = []

    for fpath in files:
        rel_str = str(fpath.relative_to(target)) if target.is_dir() else fpath.name
        try:
            content = fpath.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            continue
        
        matches = scan_text_for_crypto(content, rel_str)
        if matches:
            scanned_files.append(rel_str)
            for m in matches:
                inventory_entries.append({
                    "id": f"CRYPTO-{entry_id:03d}",
                    "purpose": f"Uso detectado de {m['algorithm']} en {m['sourceLocation']}",
                    "usage": m["usage"],
                    "category": m["category"],
                    "algorithm": m["algorithm"],
                    "quantumStatus": m["quantumStatus"],
                    "migrationPriority": m["migrationPriority"],
                    "standard": m["standard"],
                    "sourceLocations": [m["sourceLocation"]],
                    "dependencies": []
                })
                entry_id += 1

    vulnerable_count = sum(1 for e in inventory_entries if e["quantumStatus"] == "VULNERABLE_CLASSICAL")
    hybrid_count = sum(1 for e in inventory_entries if e["quantumStatus"] == "TRANSITIONAL_HYBRID")
    quantum_safe_count = sum(1 for e in inventory_entries if e["quantumStatus"] == "QUANTUM_SAFE_STANDARDIZED")
    adequate_count = sum(1 for e in inventory_entries if e["quantumStatus"] == "ADEQUATE_SYMMETRIC")

    report = {
        "reportId": str(uuid.uuid4()),
        "scannedAt": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "target": str(target),
        "metrics": {
            "totalPrimitives": len(inventory_entries),
            "vulnerableClassicalCount": vulnerable_count,
            "transitionalHybridCount": hybrid_count,
            "quantumSafeCount": quantum_safe_count,
            "adequateSymmetricCount": adequate_count
        },
        "entries": inventory_entries
    }
    return report

def main():
    parser = argparse.ArgumentParser(description="Deterministic PQC Inventory Scanner")
    parser.add_argument("target", help="Path to target directory or file")
    parser.add_argument("--json", action="store_true", help="Output full JSON report")
    args = parser.parse_args()

    target_path = Path(args.target)
    if not target_path.exists():
        print(f"Error: Target path {target_path} does not exist.", file=sys.stderr)
        sys.exit(1)

    report = scan_target(target_path)

    if args.json:
        print(json.dumps(report, indent=2, ensure_ascii=False))
    else:
        m = report["metrics"]
        print(f"\n[+] PQC Inventory Scan Summary for: {report['target']}")
        print(f"    Total Primitives Detected:   {m['totalPrimitives']}")
        print(f"    - Classical Vulnerable (RSA/ECC): {m['vulnerableClassicalCount']}")
        print(f"    - Transitional Hybrid:            {m['transitionalHybridCount']}")
        print(f"    - Standardized PQC (FIPS 203/4):  {m['quantumSafeCount']}")
        print(f"    - Adequate Symmetric (AES-256):   {m['adequateSymmetricCount']}")
        if m["vulnerableClassicalCount"] > 0:
            print("\n[!] Alerta: Se detectaron primitivas vulnerables al algoritmo de Shor.")
            print("    Consulte .agent/skills/secrets-cryptography/references/post-quantum-cryptography-migration.md para remediación.")

if __name__ == "__main__":
    main()
