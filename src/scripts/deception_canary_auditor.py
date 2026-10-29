#!/usr/bin/env python3
"""Deterministic Deception and Canary Posture Auditor for Devia-CyberSecurity.

Capabilities:
1. Bounded-buffer Shannon entropy calculation (max 64KB chunks, O(1) memory) to detect
   ransomware encryption without risk of OOM denial of service (VULN-RESI-011).
2. Single Packet Authorization (SPA) packet generation and validation with sliding-window
   nonce persistence to prevent replay attacks (VULN-ARCH-026).
3. Cloud deception decoy validation ensuring mandatory explicit deny-all policies on
   canary credentials and principals (VULN-CONF-018).
4. Zero Trust mesh device auditing verifying that keyExpiryDisabled is not set (VULN-ARCH-027).

Conforms strictly to DeceptionPostureSchema and provides CLI with --json output.
"""

from __future__ import annotations

import argparse
from collections import Counter
from datetime import datetime, timezone
import hashlib
import hmac
import json
import math
import os
from pathlib import Path
import struct
import sys
import time
from typing import Any, Dict, List, Optional, Set, Tuple


# In-memory sliding-window cache for SPA nonces: maps nonce -> expiration timestamp
SPA_NONCE_CACHE: Dict[str, float] = {}


def compute_bounded_entropy(filepath: Path | str, max_bytes: int = 65536) -> Tuple[float, int, str]:
    """Compute Shannon entropy over a bounded chunk of bytes to prevent memory exhaustion (OOM DoS).
    
    Returns:
        (entropy, bytes_read, sha256_hexdigest)
    """
    path = Path(filepath)
    if not path.is_file():
        return 0.0, 0, ""

    hasher = hashlib.sha256()
    byte_counts: Counter[int] = Counter()
    total_read = 0

    try:
        with path.open("rb") as f:
            while chunk := f.read(8192):
                hasher.update(chunk)
                to_count = chunk[:max(0, max_bytes - total_read)]
                if to_count:
                    byte_counts.update(to_count)
                    total_read += len(to_count)
                if total_read >= max_bytes:
                    # Continue hashing rest of file for integrity without counting in RAM
                    while rest := f.read(65536):
                        hasher.update(rest)
                    break
    except (OSError, PermissionError):
        return 0.0, 0, ""

    if total_read == 0:
        return 0.0, 0, hasher.hexdigest()

    entropy = -sum(
        (count / total_read) * math.log2(count / total_read)
        for count in byte_counts.values()
        if count > 0
    )
    return round(entropy, 4), total_read, hasher.hexdigest()


def generate_spa_packet(
    source_ip: str,
    service: str,
    shared_key: str,
    nonce: Optional[str] = None,
    timestamp: Optional[float] = None
) -> bytes:
    """Generate Single Packet Authorization (SPA) binary packet."""
    ts = timestamp if timestamp is not None else time.time()
    n = nonce or hashlib.sha256(f"{time.time()}:{source_ip}:{service}".encode()).hexdigest()[:16]

    payload_dict = {
        "version": 2,
        "source_ip": source_ip,
        "service": service,
        "timestamp": ts,
        "nonce": n
    }
    payload_bytes = json.dumps(payload_dict, separators=(",", ":"), sort_keys=True).encode("utf-8")
    mac = hmac.new(shared_key.encode("utf-8"), payload_bytes, hashlib.sha256).digest()

    return struct.pack("!I", len(payload_bytes)) + payload_bytes + mac


def clean_expired_nonces(current_time: float) -> None:
    """Evict expired nonces from sliding window cache."""
    expired = [k for k, exp in SPA_NONCE_CACHE.items() if exp <= current_time]
    for k in expired:
        SPA_NONCE_CACHE.pop(k, None)


def validate_spa_packet(
    packet: bytes,
    shared_key: str,
    max_age_seconds: int = 60,
    current_time: Optional[float] = None,
    nonce_cache: Optional[Dict[str, float]] = None
) -> Dict[str, Any]:
    """Validate SPA packet with cryptographic HMAC and sliding-window anti-replay nonce cache."""
    now = current_time if current_time is not None else time.time()
    cache = nonce_cache if nonce_cache is not None else SPA_NONCE_CACHE
    clean_expired_nonces(now)

    result: Dict[str, Any] = {
        "valid": False,
        "sourceIp": "0.0.0.0",
        "serviceRequested": "unknown",
        "timestamp": 0.0,
        "nonce": "",
        "hmacVerified": False,
        "ageSeconds": 0.0,
        "replayDetected": False,
        "errors": []
    }

    if len(packet) < 4 + 32:
        result["errors"].append("Packet too short to contain header, payload and HMAC")
        return result

    try:
        payload_len = struct.unpack("!I", packet[:4])[0]
        if len(packet) < 4 + payload_len + 32:
            result["errors"].append(f"Payload length declaration ({payload_len}) exceeds packet buffer")
            return result

        payload_bytes = packet[4:4 + payload_len]
        received_mac = packet[4 + payload_len:4 + payload_len + 32]

        expected_mac = hmac.new(shared_key.encode("utf-8"), payload_bytes, hashlib.sha256).digest()
        if not hmac.compare_digest(received_mac, expected_mac):
            result["errors"].append("HMAC-SHA256 signature verification failed")
            return result

        result["hmacVerified"] = True

        data = json.loads(payload_bytes.decode("utf-8"))
        result["sourceIp"] = data.get("source_ip", "0.0.0.0")
        result["serviceRequested"] = data.get("service", "unknown")
        ts = float(data.get("timestamp", 0.0))
        result["timestamp"] = ts
        nonce = str(data.get("nonce", ""))
        result["nonce"] = nonce

        age = now - ts
        result["ageSeconds"] = round(age, 2)

        if age > max_age_seconds:
            result["errors"].append(f"Packet expired (age: {age:.1f}s, max: {max_age_seconds}s)")
            return result

        if age < -5.0:
            result["errors"].append(f"Packet timestamp is in the future (skew: {abs(age):.1f}s)")
            return result

        # Anti-replay nonce check (VULN-ARCH-026)
        if nonce in cache:
            result["replayDetected"] = True
            result["errors"].append(f"Replay attack detected: nonce '{nonce}' already received")
            return result

        # Register nonce with expiration TTL
        cache[nonce] = now + max_age_seconds
        result["valid"] = True
        return result

    except Exception as exc:
        result["errors"].append(f"Parsing error: {str(exc)}")
        return result


def audit_deception_assets(assets_data: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Audit deception assets enforcing deny-all policy on canary credentials and presence of wiring."""
    compliant_count = 0
    non_compliant_count = 0
    issues: List[Dict[str, Any]] = []

    CREDENTIAL_TYPES = {"DECOY_PRINCIPAL", "HONEYTOKEN", "DECOY_SECRET"}

    for a in assets_data:
        asset_id = a.get("id", "UNKNOWN")
        asset_type = a.get("type", "UNKNOWN")
        asset_name = a.get("name", "unnamed")
        deny_all = a.get("denyAllPolicyEnforced", False)
        wiring = a.get("detectionWiring", {})
        has_wiring = bool(wiring.get("telemetrySource") and wiring.get("alertRule") and wiring.get("notificationSink"))
        internal_tag = a.get("internalTagPresent", False)

        asset_issues = []
        if asset_type in CREDENTIAL_TYPES and not deny_all:
            asset_issues.append("Canary credential is missing explicit deny-all policy (VULN-CONF-018 liability)")

        if not has_wiring:
            asset_issues.append("Missing required detection wiring (telemetry source, alert rule, or sink)")

        if not internal_tag:
            asset_issues.append("Missing internal deception tag (risk of inadvertent operational deletion)")

        if asset_issues:
            non_compliant_count += 1
            issues.append({
                "assetId": asset_id,
                "assetName": asset_name,
                "type": asset_type,
                "issues": asset_issues
            })
        else:
            compliant_count += 1

    total = len(assets_data)
    score = round((compliant_count / total * 100.0) if total > 0 else 100.0, 2)

    return {
        "totalAssets": total,
        "compliantCount": compliant_count,
        "nonCompliantCount": non_compliant_count,
        "postureScore": score,
        "issues": issues
    }


def audit_ztna_device_posture(devices: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Audit Zero Trust mesh devices identifying keyExpiryDisabled flags (VULN-ARCH-027)."""
    violations = []
    for d in devices:
        hostname = d.get("hostname", "unknown")
        key_expiry_disabled = d.get("keyExpiryDisabled", False)
        online = d.get("online", False)

        if key_expiry_disabled:
            violations.append({
                "hostname": hostname,
                "issue": "keyExpiryDisabled is true: node bypasses continuous ZTNA re-authentication (VULN-ARCH-027)",
                "severity": "HIGH",
                "online": online
            })

    return {
        "totalDevices": len(devices),
        "violationsCount": len(violations),
        "compliant": len(violations) == 0,
        "violations": violations
    }


def main():
    parser = argparse.ArgumentParser(description="Deterministic Deception & Canary Posture Auditor")
    subparsers = parser.add_subparsers(dest="command")

    # Subcommand: entropy
    entropy_parser = subparsers.add_parser("entropy", help="Compute bounded Shannon entropy of a file")
    entropy_parser.add_argument("file", help="Path to file")
    entropy_parser.add_argument("--max-bytes", type=int, default=65536, help="Max buffer size for RAM bounds (default: 65536)")
    entropy_parser.add_argument("--json", action="store_true", help="Emit JSON output")

    # Subcommand: spa-test
    spa_parser = subparsers.add_parser("spa-test", help="Generate and test Single Packet Authorization payload")
    spa_parser.add_argument("--ip", default="192.168.1.100", help="Client source IP")
    spa_parser.add_argument("--service", default="ssh", help="Service name")
    spa_parser.add_argument("--key", default="secret-shared-key-for-testing", help="HMAC shared key")
    spa_parser.add_argument("--test-replay", action="store_true", help="Send the packet twice to test anti-replay cache")
    spa_parser.add_argument("--json", action="store_true", help="Emit JSON output")

    # Subcommand: audit-decoys
    decoy_parser = subparsers.add_parser("audit-decoys", help="Audit deception assets inventory JSON")
    decoy_parser.add_argument("inventory_file", help="JSON file with deception assets")
    decoy_parser.add_argument("--json", action="store_true", help="Emit JSON output")

    # Subcommand: audit-ztna
    ztna_parser = subparsers.add_parser("audit-ztna", help="Audit Zero Trust network mesh devices for key expiry")
    ztna_parser.add_argument("devices_file", help="JSON file with device inventory")
    ztna_parser.add_argument("--json", action="store_true", help="Emit JSON output")

    args = parser.parse_args()

    if args.command == "entropy":
        entropy, bytes_read, sha256 = compute_bounded_entropy(args.file, args.max_bytes)
        result = {
            "file": str(args.file),
            "entropy": entropy,
            "bytesAnalyzed": bytes_read,
            "sha256": sha256,
            "status": "ENCRYPTED" if entropy >= 7.5 else "NORMAL"
        }
        if args.json:
            print(json.dumps(result, indent=2))
        else:
            print(f"File: {args.file}")
            print(f"Entropy: {entropy} / 8.0 ({result['status']})")
            print(f"Bytes Analyzed: {bytes_read}")
            print(f"SHA-256: {sha256}")

    elif args.command == "spa-test":
        pkt = generate_spa_packet(args.ip, args.service, args.key)
        res1 = validate_spa_packet(pkt, args.key)
        output = {"firstVerification": res1}

        if args.test_replay:
            res2 = validate_spa_packet(pkt, args.key)
            output["replayVerification"] = res2

        if args.json:
            print(json.dumps(output, indent=2))
        else:
            print("First SPA Verification:", "PASSED" if res1["valid"] else "FAILED")
            if args.test_replay:
                print("Replay Verification (should fail):", "REPLAY DETECTED" if res2.get("replayDetected") else "UNEXPECTED PASS")

    elif args.command == "audit-decoys":
        with open(args.inventory_file, "r", encoding="utf-8") as f:
            data = json.load(f)
        assets = data if isinstance(data, list) else data.get("assets", [])
        res = audit_deception_assets(assets)
        if args.json:
            print(json.dumps(res, indent=2))
        else:
            print(f"Total Assets: {res['totalAssets']}, Compliant: {res['compliantCount']}, Score: {res['postureScore']}%")
            for iss in res["issues"]:
                print(f"  [{iss['type']}] {iss['assetName']}: {', '.join(iss['issues'])}")

    elif args.command == "audit-ztna":
        with open(args.devices_file, "r", encoding="utf-8") as f:
            data = json.load(f)
        devices = data if isinstance(data, list) else data.get("devices", [])
        res = audit_ztna_device_posture(devices)
        if args.json:
            print(json.dumps(res, indent=2))
        else:
            print(f"Total Devices: {res['totalDevices']}, Violations: {res['violationsCount']}")
            for v in res["violations"]:
                print(f"  [VIOLATION] {v['hostname']}: {v['issue']}")

    else:
        parser.print_help()


if __name__ == "__main__":
    main()
