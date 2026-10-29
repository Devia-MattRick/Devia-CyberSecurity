#!/usr/bin/env python3
"""NIST SP 800-30 Rev 1 Risk Assessment Engine for Devia-CyberSecurity.

Deterministic scoring engine for threat events, predisposing conditions, and risk levels
using the canonical 5x5 Likelihood x Impact matrix specified in NIST SP 800-30 Rev 1 Table I-2.
Strictly outputs contract-compliant JSON conforming to cyber-risk-assessment.schema.ts.
"""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import sys
from typing import Any, Dict, List, Optional, Tuple
import uuid

# Ensure UTF-8 output on Windows
if sys.platform == "win32":
    sys.stdout.reconfigure(encoding="utf-8")

# NIST SP 800-30 Rev 1 Table I-2 Canonical 5x5 Matrix:
# Likelihood (rows: 1 to 5) x Impact (cols: 1 to 5)
# Values: "VERY_LOW", "LOW", "MODERATE", "HIGH", "VERY_HIGH"
NIST_800_30_MATRIX: Dict[int, Dict[int, str]] = {
    5: {1: "LOW", 2: "MODERATE", 3: "HIGH", 4: "VERY_HIGH", 5: "VERY_HIGH"},
    4: {1: "LOW", 2: "MODERATE", 3: "HIGH", 4: "HIGH", 5: "VERY_HIGH"},
    3: {1: "VERY_LOW", 2: "LOW", 3: "MODERATE", 4: "HIGH", 5: "HIGH"},
    2: {1: "VERY_LOW", 2: "LOW", 3: "LOW", 4: "MODERATE", 5: "MODERATE"},
    1: {1: "VERY_LOW", 2: "VERY_LOW", 3: "LOW", 4: "LOW", 5: "LOW"},
}

QUALITATIVE_LABELS = {
    1: "VERY_LOW",
    2: "LOW",
    3: "MODERATE",
    4: "HIGH",
    5: "VERY_HIGH",
}

SEVERITY_ORDER = {
    "VERY_HIGH": 5,
    "HIGH": 4,
    "MODERATE": 3,
    "LOW": 2,
    "VERY_LOW": 1,
}


def get_utc_timestamp() -> str:
    """Return ISO 8601 UTC timestamp."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def compute_risk_level(likelihood: int, impact: int) -> Tuple[str, float]:
    """Compute NIST SP 800-30 5x5 risk level and normalized 0-100 score."""
    clamped_l = max(1, min(5, likelihood))
    clamped_i = max(1, min(5, impact))
    level = NIST_800_30_MATRIX.get(clamped_l, {}).get(clamped_i, "MODERATE")
    
    # Semi-quantitative scoring: (Likelihood * Impact) normalized to 0-100 scale
    # Max value = 5 * 5 = 25 -> 100.0
    raw_score = (clamped_l * clamped_i) / 25.0 * 100.0
    return level, round(raw_score, 1)


def evaluate_threat_events(
    events_data: List[Dict[str, Any]]
) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
    """Process, score, and rank threat events deterministically."""
    processed_events = []
    counts = {
        "VERY_HIGH": 0,
        "HIGH": 0,
        "MODERATE": 0,
        "LOW": 0,
        "VERY_LOW": 0,
    }
    total_score = 0.0

    for idx, raw in enumerate(events_data, 1):
        event_id = raw.get("id") or f"EVT-{idx:03d}"
        l_level = int(raw.get("likelihoodLevel", 3))
        i_level = int(raw.get("impactLevel", 3))
        
        risk_level, risk_score = compute_risk_level(l_level, i_level)
        counts[risk_level] = counts.get(risk_level, 0) + 1
        total_score += risk_score

        processed_event = {
            "id": event_id,
            "title": raw.get("title", f"Threat Event {idx}"),
            "description": raw.get("description", "No description provided"),
            "threatSource": raw.get("threatSource", "ADVERSARIAL"),
            "threatActorOrCapability": raw.get("threatActorOrCapability"),
            "vulnerabilityOrPredisposingCondition": raw.get(
                "vulnerabilityOrPredisposingCondition", "Unmitigated condition"
            ),
            "cwe": raw.get("cwe", []),
            "mitreTechniques": raw.get("mitreTechniques", []),
            "likelihoodLevel": l_level,
            "impactLevel": i_level,
            "qualitativeLikelihood": QUALITATIVE_LABELS.get(l_level, "MODERATE"),
            "qualitativeImpact": QUALITATIVE_LABELS.get(i_level, "MODERATE"),
            "riskLevel": risk_level,
            "riskScore": risk_score,
            "mitigationControls": raw.get("mitigationControls", []),
            "status": raw.get("status", "OPEN")
        }
        if processed_event["threatActorOrCapability"] is None:
            del processed_event["threatActorOrCapability"]
        processed_events.append(processed_event)

    # Sort deterministically: highest riskScore descending, then event ID
    processed_events.sort(key=lambda x: (-x["riskScore"], x["id"]))

    total_events = len(processed_events)
    avg_score = round(total_score / total_events, 1) if total_events > 0 else 0.0

    metrics = {
        "totalEvents": total_events,
        "veryHighCount": counts["VERY_HIGH"],
        "highCount": counts["HIGH"],
        "moderateCount": counts["MODERATE"],
        "lowCount": counts["LOW"],
        "veryLowCount": counts["VERY_LOW"],
        "averageRiskScore": avg_score
    }

    return processed_events, metrics


def build_risk_assessment_report(
    name: str,
    scope: str,
    tier: int,
    conducted_by: str,
    raw_events: List[Dict[str, Any]]
) -> Dict[str, Any]:
    """Generate contract-compliant RiskAssessmentReport dictionary."""
    processed_events, metrics = evaluate_threat_events(raw_events)
    top_risks = [e["id"] for e in processed_events if e["riskLevel"] in ["VERY_HIGH", "HIGH"]][:5]
    if not top_risks and processed_events:
        top_risks = [processed_events[0]["id"]]

    return {
        "assessmentId": str(uuid.uuid4()),
        "name": name,
        "scope": scope,
        "tier": tier,
        "conductedAt": get_utc_timestamp(),
        "conductedBy": conducted_by,
        "threatEvents": processed_events,
        "metrics": metrics,
        "topRisks": top_risks
    }


def render_markdown_summary(report: Dict[str, Any]) -> str:
    """Format assessment results into an executive Markdown table."""
    m = report["metrics"]
    md = f"""# Resumen de Evaluación de Riesgos — {report['name']}

- **ID de Evaluación:** `{report['assessmentId']}`
- **Alcance:** {report['scope']}
- **Nivel Organizacional:** Tier {report['tier']}
- **Fecha:** `{report['conductedAt']}`
- **Evaluador:** {report['conductedBy']}

## 📊 Métricas Consolidadas
| Métrica | Valor |
| :--- | :--- |
| **Total Eventos Evaluados** | {m['totalEvents']} |
| **Riesgo Muy Alto (VERY_HIGH)** | {m['veryHighCount']} |
| **Riesgo Alto (HIGH)** | {m['highCount']} |
| **Riesgo Moderado (MODERATE)** | {m['moderateCount']} |
| **Riesgo Bajo (LOW)** | {m['lowCount']} |
| **Riesgo Muy Bajo (VERY_LOW)** | {m['veryLowCount']} |
| **Puntuación Media de Riesgo** | {m['averageRiskScore']} / 100.0 |

## 🚨 Eventos de Mayor Criticidad Priorizados
| ID | Título | Fuente | Verosimilitud | Impacto | Nivel de Riesgo | Score | Estado |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
"""
    for e in report["threatEvents"]:
        md += f"| `{e['id']}` | {e['title']} | {e['threatSource']} | {e['qualitativeLikelihood']} ({e['likelihoodLevel']}) | {e['qualitativeImpact']} ({e['impactLevel']}) | **{e['riskLevel']}** | {e['riskScore']} | `{e['status']}` |\n"

    return md


def main() -> int:
    parser = argparse.ArgumentParser(
        description="NIST SP 800-30 Rev 1 Risk Assessment Scoring Engine"
    )
    parser.add_argument("-i", "--input", help="Path to input threat events JSON")
    parser.add_argument("-o", "--output", help="Path to output report JSON")
    parser.add_argument("-m", "--markdown", help="Path to output executive Markdown summary")
    parser.add_argument("--name", default="NIST SP 800-30 Security Assessment", help="Assessment Name")
    parser.add_argument("--scope", default="Enterprise Hybrid Infrastructure", help="Assessment Scope")
    parser.add_argument("--tier", type=int, default=3, choices=[1, 2, 3], help="NIST Tier (1-3)")
    parser.add_argument("--evaluator", default="Devia-CyberSecurity Lead Threat Modeler", help="Evaluator Name")
    parser.add_argument("--json", action="store_true", help="Print report JSON to stdout")

    args = parser.parse_args()

    raw_events = []
    if args.input and os.path.isfile(args.input):
        with open(args.input, "r", encoding="utf-8") as f:
            data = json.load(f)
            if isinstance(data, list):
                raw_events = data
            elif isinstance(data, dict):
                raw_events = data.get("threatEvents", data.get("events", []))
    else:
        # Default sample assessment events
        raw_events = [
            {
                "id": "RISK-001",
                "title": "Ataque DCSync para Exfiltración de Credenciales de Dominio",
                "description": "Atacante abusa de permisos DS-Replication-Get-Changes para replicar hashes NTDS.",
                "threatSource": "ADVERSARIAL",
                "vulnerabilityOrPredisposingCondition": "Delegación de derechos de replicación a usuarios no administradores de dominio",
                "cwe": ["CWE-269", "CWE-285"],
                "mitreTechniques": ["T1003.006"],
                "likelihoodLevel": 4,
                "impactLevel": 5,
                "mitigationControls": ["Revocar derechos de replicación", "Monitorear Event ID 4662"]
            },
            {
                "id": "RISK-002",
                "title": "Exposición de Metadatos Cloud por SSRF hacia IMDSv1",
                "description": "Falta de token IMDSv2 permite robo de credenciales temporales de instancia EC2.",
                "threatSource": "ADVERSARIAL",
                "vulnerabilityOrPredisposingCondition": "Instancia EC2 configurada con HttpTokens=optional",
                "cwe": ["CWE-918"],
                "mitreTechniques": ["T1552.005"],
                "likelihoodLevel": 3,
                "impactLevel": 4,
                "mitigationControls": ["Requerir IMDSv2 (HttpTokens=required)"]
            }
        ]

    report = build_risk_assessment_report(
        name=args.name,
        scope=args.scope,
        tier=args.tier,
        conducted_by=args.evaluator,
        raw_events=raw_events
    )

    if args.output:
        out_p = Path(args.output).resolve()
        out_p.parent.mkdir(parents=True, exist_ok=True)
        with open(out_p, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2, ensure_ascii=False)

    if args.markdown:
        md_p = Path(args.markdown).resolve()
        md_p.parent.mkdir(parents=True, exist_ok=True)
        md_content = render_markdown_summary(report)
        with open(md_p, "w", encoding="utf-8") as f:
            f.write(md_content)

    if args.json or (not args.output and not args.markdown):
        print(json.dumps(report, indent=2, ensure_ascii=False))

    return 0


if __name__ == "__main__":
    sys.exit(main())
