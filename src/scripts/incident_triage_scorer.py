#!/usr/bin/env python3
"""Incident Triage Quantitative Scoring and Playbook Dispatch Engine.

Devia-CyberSecurity - Layer 3 Deterministic Python Utility.
Calculates multidimensional incident severity scores and assigns authoritative
IR playbooks and SLA response windows aligned with NIST SP 800-61 and SANS PICERL.
Outputs deterministically to standard JSON conforming to IncidentTriageEvaluationSchema.
"""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
import sys
from typing import Any, Dict, List, Optional


SEVERITY_WEIGHTS = {
    "asset_criticality": {"critical": 4, "high": 3, "medium": 2, "low": 1},
    "data_sensitivity": {"pii_phi": 4, "pci": 3, "confidential": 2, "public": 1},
    "threat_status": {"active": 4, "confirmed": 3, "attempted": 2, "recon": 1},
    "scope": {"enterprise": 4, "department": 3, "single_system": 2, "single_user": 1},
}

DIMENSION_WEIGHTS = {
    "asset_criticality": 0.30,
    "data_sensitivity": 0.25,
    "threat_status": 0.25,
    "scope": 0.20,
}

PLAYBOOK_ROUTING = {
    "malware": {
        "playbook": "malware-ir-playbook-v2",
        "team": "Tier 2 SOC + Malware Analysis Team",
        "category": "RS.MA-01",
        "recommendations": [
            "Isolate the host at network layer (EDR host containment)",
            "Capture memory dump for volatile code extraction",
            "Identify persistence mechanisms (scheduled tasks, run keys, services)",
            "Search enterprise SIEM for matching C2 hashes and domains"
        ]
    },
    "ransomware": {
        "playbook": "ransomware-ir-playbook-v3",
        "team": "Tier 3 Incident Response Team + Executive Crisis Team",
        "category": "RS.MA-01",
        "recommendations": [
            "Execute immediate network segmentation to isolate affected broadcast domains",
            "Halt storage sync and protect immutable offline volume shadow backups",
            "Preserve infected host memory dump for decryption key recovery feasibility",
            "Engage CISO, Legal and breach response counsel immediately"
        ]
    },
    "phishing": {
        "playbook": "phishing-ir-playbook-v2",
        "team": "Email Security Team + SOC Tier 2",
        "category": "RS.MA-02",
        "recommendations": [
            "Purge phishing email from all recipient inboxes across the tenant",
            "Revoke active sessions and force password reset for users who submitted credentials",
            "Block malicious sender domain, IP and payload URL at email gateway and web proxy",
            "Review authentication logs for subsequent anomalous logins"
        ]
    },
    "unauthorized_access": {
        "playbook": "unauthorized-access-playbook-v2",
        "team": "Identity Response Team + AD Operations",
        "category": "RS.AN-03",
        "recommendations": [
            "Immediately disable compromised user/service accounts",
            "Revoke Kerberos TGT and invalidate cloud session refresh tokens (PRT)",
            "Trace logon sessions (Event ID 4624 type 3/10) to determine blast radius",
            "Audit group memberships and newly created service principals"
        ]
    },
    "data_exfiltration": {
        "playbook": "data-exfiltration-playbook-v2",
        "team": "Data Protection Team + Legal & Compliance",
        "category": "RS.AN-03",
        "recommendations": [
            "Block destination egress IP/FQDN at firewall, proxy and DNS resolvers",
            "Identify exact volume and classification of data transferred (DLP/NetFlow logs)",
            "Initiate forensic timeline reconstruction from initial access to egress",
            "Notify data privacy officer (DPO) and regulatory compliance leads"
        ]
    },
    "ddos": {
        "playbook": "ddos-response-playbook-v1",
        "team": "Network Operations Center + DDoS Mitigation Provider",
        "category": "RC.RP-01",
        "recommendations": [
            "Enable cloud anti-DDoS scrubbing center and upstream BGP redirection",
            "Apply rate limiting and drop illegitimate flood vectors at CDN/WAF edge",
            "Monitor upstream transit link utilization and core router CPU",
            "Engage ISP for upstream null-routing of attacked VIP if saturation persists"
        ]
    },
    "insider_threat": {
        "playbook": "insider-threat-playbook-v2",
        "team": "Insider Risk Team + HR + Legal",
        "category": "RS.AN-03",
        "recommendations": [
            "Suspend account access without alerting the suspect user prematurely",
            "Preserve forensic disk images of workstation, cloud drives and email archive",
            "Cross-correlate physical access badge logs with abnormal file copy events",
            "Maintain strict chain of custody for all digital artifacts"
        ]
    },
    "account_compromise": {
        "playbook": "account-compromise-playbook-v2",
        "team": "Identity Response Team",
        "category": "RS.MA-02",
        "recommendations": [
            "Terminate all active OAuth grants and app consents for the user",
            "Revoke all registered MFA devices and issue temporary TAP credential",
            "Audit mailbox inbox rules and forwarding rules for hidden forwarding",
            "Review conditional access policy logs for impossible travel anomalies"
        ]
    },
    "web_attack": {
        "playbook": "web-application-incident-playbook-v2",
        "team": "Application Security Team + SOC Tier 2",
        "category": "RS.MA-01",
        "recommendations": [
            "Block attacking IP addresses and user agents at Web Application Firewall (WAF)",
            "Review web server access and error logs for successful exploit status codes (200/500)",
            "Verify database integrity if SQLi or deserialization was attempted",
            "Patch or apply virtual patch via WAF rule for the targeted endpoint"
        ]
    },
    "privilege_escalation": {
        "playbook": "privilege-escalation-playbook-v1",
        "team": "Identity Response Team + Endpoint Defense",
        "category": "RS.AN-03",
        "recommendations": [
            "Isolate the endpoint where elevated privileges were spawned",
            "Audit parent-child process tree (e.g. spoolsv.exe spawning cmd.exe)",
            "Inspect newly created local administrators or modified sudoers configurations",
            "Scan host for kernel exploits, vulnerable services or potato-style exploits"
        ]
    },
    "lateral_movement": {
        "playbook": "lateral-movement-playbook-v1",
        "team": "Network Defense Team + Incident Response",
        "category": "RS.AN-03",
        "recommendations": [
            "Block SMB (port 445) and WinRM (ports 5985/5986) between workstation subnets",
            "Purge compromised credential cache and reset KRBTGT password if Kerberoasting occurred",
            "Trace Event IDs 4648, 4672, and 7045 across all reachable systems",
            "Enforce local administrator password solution (LAPS) password rotation"
        ]
    },
    "supply_chain": {
        "playbook": "supply-chain-incident-playbook-v1",
        "team": "Third-Party Risk Team + Application Security",
        "category": "RS.MA-01",
        "recommendations": [
            "Pin or remove the compromised dependency version across all package manifests",
            "Quarantine and invalidate internal artifact repository caches (npm/PyPI/Docker)",
            "Verify SLSA provenance and cryptographic signatures against Rekor transparency log",
            "Audit all production systems running artifacts compiled with the affected version"
        ]
    }
}


def calculate_incident_score(
    asset_criticality: str,
    data_sensitivity: str,
    threat_status: str,
    scope: str
) -> float:
    """Calculate weighted normalized incident score from 0.0 to 10.0."""
    w_asset = SEVERITY_WEIGHTS["asset_criticality"].get(asset_criticality.lower(), 2)
    w_data = SEVERITY_WEIGHTS["data_sensitivity"].get(data_sensitivity.lower(), 2)
    w_threat = SEVERITY_WEIGHTS["threat_status"].get(threat_status.lower(), 2)
    w_scope = SEVERITY_WEIGHTS["scope"].get(scope.lower(), 2)

    raw_score = (
        w_asset * DIMENSION_WEIGHTS["asset_criticality"] +
        w_data * DIMENSION_WEIGHTS["data_sensitivity"] +
        w_threat * DIMENSION_WEIGHTS["threat_status"] +
        w_scope * DIMENSION_WEIGHTS["scope"]
    )
    # raw_score is in range [1.0, 4.0]
    normalized = ((raw_score - 1.0) / 3.0) * 10.0
    return round(max(0.0, min(10.0, normalized)), 2)


def score_to_severity(score: float) -> str:
    if score >= 8.0:
        return "CRITICAL"
    if score >= 6.0:
        return "HIGH"
    if score >= 4.0:
        return "MEDIUM"
    if score >= 2.0:
        return "LOW"
    return "INFORMATIONAL"


def severity_to_sla_hours(severity: str) -> float:
    mapping = {
        "CRITICAL": 0.25,
        "HIGH": 1.0,
        "MEDIUM": 4.0,
        "LOW": 24.0,
        "INFORMATIONAL": 72.0
    }
    return mapping.get(severity, 4.0)


def evaluate_incident(
    incident_id: str,
    title: str,
    incident_type: str,
    asset_criticality: str,
    data_sensitivity: str,
    threat_status: str,
    scope: str,
    affected_assets: Optional[List[str]] = None,
    indicators_of_compromise: Optional[List[str]] = None
) -> Dict[str, Any]:
    """Execute complete deterministic incident evaluation."""
    now_iso = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    score = calculate_incident_score(asset_criticality, data_sensitivity, threat_status, scope)
    severity = score_to_severity(score)
    sla_hours = severity_to_sla_hours(severity)

    routing = PLAYBOOK_ROUTING.get(
        incident_type.lower(),
        {
            "playbook": "general-security-incident-playbook-v1",
            "team": "SOC Tier 2 Incident Response",
            "category": "RS.MA-01",
            "recommendations": ["Conduct initial alert triage and verify indicators of compromise."]
        }
    )

    escalation_required = severity in ["CRITICAL", "HIGH"]

    return {
        "incidentId": incident_id,
        "evaluatedAt": now_iso,
        "severity": severity,
        "score": score,
        "assignedPlaybook": routing["playbook"],
        "assignedTeam": routing["team"],
        "slaResponseHours": sla_hours,
        "dimension": "RESILIENCE_LOGGING_TELEMETRY",
        "nistCsfCategory": routing["category"],
        "sansPicerlPhase": "IDENTIFICATION_AND_TRIAGE",
        "escalationRequired": escalation_required,
        "containmentRecommendations": routing["recommendations"]
    }


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Deterministic Incident Triage Scoring & Playbook Dispatcher (Devia-CyberSecurity)"
    )
    parser.add_argument("--incident-id", required=True, help="Unique incident identifier")
    parser.add_argument("--title", required=True, help="Descriptive title of the security event")
    parser.add_argument(
        "--incident-type",
        required=True,
        choices=list(PLAYBOOK_ROUTING.keys()),
        help="Classified incident type"
    )
    parser.add_argument(
        "--asset-criticality",
        required=True,
        choices=["critical", "high", "medium", "low"],
        help="Criticality of target asset"
    )
    parser.add_argument(
        "--data-sensitivity",
        required=True,
        choices=["pii_phi", "pci", "confidential", "public"],
        help="Data sensitivity level"
    )
    parser.add_argument(
        "--threat-status",
        required=True,
        choices=["active", "confirmed", "attempted", "recon"],
        help="Observed adversary status"
    )
    parser.add_argument(
        "--scope",
        required=True,
        choices=["enterprise", "department", "single_system", "single_user"],
        help="Blast radius scope"
    )
    parser.add_argument("--affected-assets", nargs="*", default=[], help="List of affected hostnames/IPs")
    parser.add_argument("--iocs", nargs="*", default=[], help="List of associated indicators of compromise")
    parser.add_argument("--json", action="store_true", help="Output machine-readable JSON only")

    args = parser.parse_args()

    evaluation = evaluate_incident(
        incident_id=args.incident_id,
        title=args.title,
        incident_type=args.incident_type,
        asset_criticality=args.asset_criticality,
        data_sensitivity=args.data_sensitivity,
        threat_status=args.threat_status,
        scope=args.scope,
        affected_assets=args.affected_assets,
        indicators_of_compromise=args.iocs
    )

    if args.json:
        print(json.dumps(evaluation, indent=2, ensure_ascii=False))
    else:
        print(f"=== INCIDENT TRIAGE EVALUATION: {evaluation['incidentId']} ===")
        print(f"Severity:           {evaluation['severity']} (Score: {evaluation['score']}/10.0)")
        print(f"Assigned Playbook:  {evaluation['assignedPlaybook']}")
        print(f"Assigned Team:      {evaluation['assignedTeam']}")
        print(f"SLA Window:         {evaluation['slaResponseHours']}h")
        print(f"NIST CSF Category:  {evaluation['nistCsfCategory']}")
        print(f"Escalation:         {'YES' if evaluation['escalationRequired'] else 'NO'}")
        print("Containment Recommendations:")
        for rec in evaluation["containmentRecommendations"]:
            print(f"  - {rec}")


if __name__ == "__main__":
    main()
