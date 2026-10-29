#!/usr/bin/env python3
"""Endpoint Hardening Auditor - Evaluates Microsoft Defender and Attack Surface Reduction (ASR) posture.

Analyzes exported Windows Defender configurations, verifies the 16 canonical ASR rules,
detects critical security gaps (LSASS protection, script obfuscation, network protection),
computes compliance scores, and emits deterministic remediation guidance.

Usage:
    python src/scripts/endpoint_hardening_auditor.py --input <path_to_config.json> [--json]
    python src/scripts/endpoint_hardening_auditor.py --generate-sample
"""

import argparse
import json
import os
import sys
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Tuple

# Canonical ASR Rules Mapping (16 Microsoft GUIDs)
CANONICAL_ASR_RULES: Dict[str, Dict[str, str]] = {
    "BE9BA2D9-53EA-4CDC-84E5-9B1EEEE46550": {
        "name": "Block executable content from email client and webmail",
        "technique": "T1566.001",
        "severity": "HIGH",
    },
    "D4F940AB-401B-4EFC-AADC-AD5F3C50688A": {
        "name": "Block all Office applications from creating child processes",
        "technique": "T1059.001",
        "severity": "CRITICAL",
    },
    "3B576869-A4EC-4529-8536-B80A7769E899": {
        "name": "Block Office applications from creating executable content",
        "technique": "T1204.002",
        "severity": "HIGH",
    },
    "75668C1F-73B5-4CF0-BB93-3ECF5CB7CC84": {
        "name": "Block Office applications from injecting code into other processes",
        "technique": "T1055",
        "severity": "CRITICAL",
    },
    "D3E037E1-3EB8-44C8-A917-57927947596D": {
        "name": "Block JavaScript or VBScript from launching downloaded executable content",
        "technique": "T1059.005",
        "severity": "HIGH",
    },
    "5BEB7EFE-FD9A-4556-801D-275E5FFC04CC": {
        "name": "Block execution of potentially obfuscated scripts",
        "technique": "T1027",
        "severity": "HIGH",
    },
    "92E97FA1-2EDF-4476-BDD6-9DD0B4DDDC7B": {
        "name": "Block Win32 API calls from Office macros",
        "technique": "T1204.002",
        "severity": "HIGH",
    },
    "9E6C4E1F-7D60-472F-BA1A-A39EF669E4B2": {
        "name": "Block credential stealing from Windows local security authority subsystem (lsass.exe)",
        "technique": "T1003.001",
        "severity": "CRITICAL",
    },
    "D1E49AAC-8F56-4280-B9BA-993A6D77406C": {
        "name": "Block process creations originating from PSExec and WMI commands",
        "technique": "T1047",
        "severity": "HIGH",
    },
    "B2B3F03D-6A65-4F7B-A9C7-1C7EF74A9BA4": {
        "name": "Block untrusted and unsigned processes that run from USB",
        "technique": "T1091",
        "severity": "MEDIUM",
    },
    "26190899-770F-478B-AE56-4FF587E3C9E8": {
        "name": "Block abuse of exploited vulnerable signed drivers (BYOVD)",
        "technique": "T1068",
        "severity": "CRITICAL",
    },
    "E6DB77E5-3DF2-4CF1-B95A-636979351E5B": {
        "name": "Block persistence through WMI event subscription",
        "technique": "T1546.003",
        "severity": "HIGH",
    },
    "01443614-CD74-433A-B99E-2ECDC07BFC25": {
        "name": "Block executable files unless they meet prevalence/age criterion",
        "technique": "T1204.002",
        "severity": "MEDIUM",
    },
    "C1DB55AB-C21A-4637-BB3F-A12568109D35": {
        "name": "Use advanced protection against ransomware",
        "technique": "T1486",
        "severity": "HIGH",
    },
    "A8F58958-CBA8-4D6F-9A0E-6577B7642BF5": {
        "name": "Block Adobe Reader from creating child processes",
        "technique": "T1059",
        "severity": "HIGH",
    },
    "7674BA52-37EB-4A4F-A9A1-F0F9A1619A2C": {
        "name": "Block Adobe Reader from creating executable content",
        "technique": "T1204.002",
        "severity": "HIGH",
    },
}

MODE_INT_MAP = {
    0: "DISABLED",
    1: "BLOCK",
    2: "AUDIT",
    6: "WARN",
}


def normalize_mode(val: Any) -> str:
    if isinstance(val, int):
        return MODE_INT_MAP.get(val, "DISABLED")
    if isinstance(val, str):
        v = val.strip().upper()
        if v in ("ENABLED", "BLOCK", "1"):
            return "BLOCK"
        if v in ("AUDIT", "2"):
            return "AUDIT"
        if v in ("WARN", "6"):
            return "WARN"
        return "DISABLED"
    return "DISABLED"


def evaluate_endpoint_posture(data: Dict[str, Any]) -> Dict[str, Any]:
    """Evaluates an endpoint configuration against the Microsoft Defender and ASR baseline."""
    host_id = data.get("hostId") or data.get("ComputerName") or "HOST-UNKNOWN"
    os_platform = data.get("osPlatform", "WINDOWS_11")
    if os_platform not in ("WINDOWS_10", "WINDOWS_11", "WINDOWS_SERVER", "OTHER"):
        os_platform = "WINDOWS_11"

    prefs = data.get("defenderPreferences", {})
    if not prefs and "Preferences" in data:
        raw_p = data["Preferences"]
        prefs = {
            "realTimeProtection": bool(raw_p.get("RealTimeProtectionEnabled", False)),
            "behaviorMonitoring": bool(raw_p.get("BehaviorMonitoringEnabled", False)),
            "ioavProtection": bool(raw_p.get("IoavProtectionEnabled", False)),
            "networkProtection": "BLOCK" if raw_p.get("EnableNetworkProtection") == 1 else "DISABLED",
            "controlledFolderAccess": "BLOCK" if raw_p.get("EnableControlledFolderAccess") == 1 else "DISABLED",
            "cloudBlockLevel": "HIGH" if raw_p.get("CloudBlockLevel", 0) >= 2 else "DEFAULT",
            "puaProtection": "ENABLED" if raw_p.get("PUAProtection") == 1 else "DISABLED",
            "tamperProtection": bool(raw_p.get("TamperProtection", True)),
        }

    raw_asr = data.get("asrRules", {})
    if isinstance(raw_asr, list):
        # Already a list of dicts or list of GUIDs
        asr_lookup = {}
        for item in raw_asr:
            if isinstance(item, dict) and "guid" in item:
                g = item["guid"].upper()
                mode = normalize_mode(item.get("currentMode") or item.get("mode"))
                asr_lookup[g] = mode
    elif isinstance(raw_asr, dict):
        asr_lookup = {k.upper(): normalize_mode(v) for k, v in raw_asr.items()}
    else:
        asr_lookup = {}

    asr_statuses = []
    critical_gaps = []
    remediation_guidance = []
    compliant_rules_count = 0

    for guid, info in CANONICAL_ASR_RULES.items():
        current_mode = asr_lookup.get(guid, "DISABLED")
        expected_mode = "BLOCK"
        is_compliant = current_mode == expected_mode

        if is_compliant:
            compliant_rules_count += 1
        else:
            gap_msg = f"ASR Rule '{info['name']}' ({guid}) is {current_mode} (expected {expected_mode})."
            if info["severity"] == "CRITICAL" and current_mode == "DISABLED":
                critical_gaps.append(f"[CRITICAL] {gap_msg}")
            elif info["severity"] == "HIGH" and current_mode == "DISABLED":
                critical_gaps.append(f"[HIGH] {gap_msg}")

            cmd = (
                f"Add-MpPreference -AttackSurfaceReductionRules_Ids {guid} "
                f"-AttackSurfaceReductionRules_Actions Enabled"
            )
            remediation_guidance.append(cmd)

        asr_statuses.append({
            "guid": guid,
            "name": info["name"],
            "currentMode": current_mode,
            "expectedMode": expected_mode,
            "isCompliant": is_compliant,
            "mitreTechnique": info["technique"],
        })

    # Evaluate Defender preferences
    pref_score = 0
    total_pref_points = 5

    if prefs.get("realTimeProtection"):
        pref_score += 1
    else:
        critical_gaps.append("[CRITICAL] Real-time protection is DISABLED.")
        remediation_guidance.append("Set-MpPreference -DisableRealtimeMonitoring $false")

    if prefs.get("behaviorMonitoring"):
        pref_score += 1
    else:
        critical_gaps.append("[HIGH] Behavior monitoring is DISABLED.")
        remediation_guidance.append("Set-MpPreference -DisableBehaviorMonitoring $false")

    if prefs.get("networkProtection") == "BLOCK":
        pref_score += 1
    elif prefs.get("networkProtection") == "AUDIT":
        pref_score += 0.5
        critical_gaps.append("[MEDIUM] Network protection is set to AUDIT instead of BLOCK.")
        remediation_guidance.append("Set-MpPreference -EnableNetworkProtection Enabled")
    else:
        critical_gaps.append("[HIGH] Network protection is DISABLED.")
        remediation_guidance.append("Set-MpPreference -EnableNetworkProtection Enabled")

    if prefs.get("controlledFolderAccess") in ("BLOCK", "AUDIT"):
        pref_score += 1
    else:
        critical_gaps.append("[MEDIUM] Controlled Folder Access (Ransomware protection) is DISABLED.")
        remediation_guidance.append("Set-MpPreference -EnableControlledFolderAccess Enabled")

    if prefs.get("tamperProtection", False):
        pref_score += 1
    else:
        critical_gaps.append("[HIGH] Tamper Protection is DISABLED.")
        remediation_guidance.append("Enable Tamper Protection via Microsoft Intune or Windows Security.")

    # Calculate final score (60% ASR rules, 40% Defender preferences)
    asr_ratio = compliant_rules_count / len(CANONICAL_ASR_RULES)
    pref_ratio = pref_score / total_pref_points
    compliance_score = round((asr_ratio * 60) + (pref_ratio * 40), 1)

    has_critical = any(gap.startswith("[CRITICAL]") for gap in critical_gaps)
    if compliance_score >= 90 and not has_critical:
        verdict = "PASS"
    elif compliance_score >= 70 and not has_critical:
        verdict = "WARN"
    else:
        verdict = "FAIL"

    now_iso = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    report = {
        "reportId": str(uuid.uuid4()),
        "evaluatedAt": now_iso,
        "hostId": host_id,
        "osPlatform": os_platform,
        "defenderPreferences": {
            "realTimeProtection": bool(prefs.get("realTimeProtection", False)),
            "behaviorMonitoring": bool(prefs.get("behaviorMonitoring", False)),
            "ioavProtection": bool(prefs.get("ioavProtection", False)),
            "networkProtection": prefs.get("networkProtection", "DISABLED"),
            "controlledFolderAccess": prefs.get("controlledFolderAccess", "DISABLED"),
            "cloudBlockLevel": prefs.get("cloudBlockLevel", "DEFAULT"),
            "puaProtection": prefs.get("puaProtection", "DISABLED"),
            "tamperProtection": bool(prefs.get("tamperProtection", False)),
        },
        "asrRules": asr_statuses,
        "complianceScore": compliance_score,
        "criticalGaps": critical_gaps,
        "verdict": verdict,
        "remediationGuidance": remediation_guidance,
    }
    return report


def generate_sample_profile() -> Dict[str, Any]:
    return {
        "hostId": "WIN-ENTERPRISE-01",
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
        "asrRules": {
            "9E6C4E1F-7D60-472F-BA1A-A39EF669E4B2": "BLOCK",
            "D4F940AB-401B-4EFC-AADC-AD5F3C50688A": "BLOCK",
            "75668C1F-73B5-4CF0-BB93-3ECF5CB7CC84": "BLOCK",
            "26190899-770F-478B-AE56-4FF587E3C9E8": "BLOCK",
            "5BEB7EFE-FD9A-4556-801D-275E5FFC04CC": "BLOCK",
            "92E97FA1-2EDF-4476-BDD6-9DD0B4DDDC7B": "BLOCK",
            "D1E49AAC-8F56-4280-B9BA-993A6D77406C": "BLOCK",
            "C1DB55AB-C21A-4637-BB3F-A12568109D35": "BLOCK",
        },
    }


def main():
    parser = argparse.ArgumentParser(
        description="Endpoint Hardening Auditor for Microsoft Defender and ASR Rules"
    )
    parser.add_argument("--input", help="Path to exported Defender JSON configuration")
    parser.add_argument("--json", action="store_true", help="Emit output strictly formatted as JSON")
    parser.add_argument("--generate-sample", action="store_true", help="Print sample input configuration")
    args = parser.parse_args()

    if args.generate_sample:
        print(json.dumps(generate_sample_profile(), indent=2))
        sys.exit(0)

    if not args.input:
        parser.print_help()
        sys.exit(1)

    if not os.path.isfile(args.input):
        print(f"Error: Input file not found: {args.input}", file=sys.stderr)
        sys.exit(1)

    with open(args.input, "r", encoding="utf-8") as f:
        data = json.load(f)

    report = evaluate_endpoint_posture(data)

    if args.json:
        print(json.dumps(report, indent=2, ensure_ascii=False))
    else:
        print(f"\n========================================================")
        print(f"  ENDPOINT HARDENING AUDIT REPORT")
        print(f"  Host ID:          {report['hostId']} ({report['osPlatform']})")
        print(f"  Compliance Score: {report['complianceScore']} / 100")
        print(f"  Verdict:          {report['verdict']}")
        print(f"========================================================\n")
        print(f"Critical Gaps Detected: {len(report['criticalGaps'])}")
        for gap in report["criticalGaps"]:
            print(f"  * {gap}")
        print(f"\nRemediation Steps Required: {len(report['remediationGuidance'])}")
        for step in report["remediationGuidance"][:5]:
            print(f"  - {step}")
        if len(report["remediationGuidance"]) > 5:
            print(f"  ... and {len(report['remediationGuidance']) - 5} more steps.")


if __name__ == "__main__":
    main()
