#!/usr/bin/env python3
"""Absorption Planner and Knowledge Adoption Engine for Devia-CyberSecurity (Capa 3).

Analyzes inventoried repositories, skills, plugins, or codebases,
maps extracted security methodologies and patterns against the 8 Canonical Dimensions,
and generates a structured Absorption Plan (absorption-plan.json) and Markdown dossier
strictly conforming to Devia-CyberSecurity's Tri-Tier Architecture and Zod contracts.
"""

from __future__ import annotations

import argparse
from collections import Counter
from datetime import datetime, timezone
import json
from pathlib import Path, PurePosixPath
import sys
from typing import Any, Dict, List, Optional
import uuid


CANONICAL_DIMENSIONS = [
    "THREAT_MODELING_ATTACK_SURFACE",
    "SOURCE_CODE_SAST",
    "SECRETS_CRYPTOGRAPHY",
    "IDENTITY_ACCESS_SESSION",
    "SUPPLY_CHAIN_SCA",
    "ARCHITECTURE_BOUNDARIES_ZERO_TRUST",
    "CONFIGURATION_HARDENING",
    "RESILIENCE_LOGGING_TELEMETRY"
]


def get_utc_timestamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def build_absorption_plan(
    target_path: Path | str,
    inventory_summary: Dict[str, Any],
    inventory_records: List[Dict[str, Any]],
    output_path: Optional[Path | str] = None
) -> Dict[str, Any]:
    target_root = Path(target_path).expanduser().resolve()
    target_name = target_root.name
    archetype = inventory_summary.get("target", {}).get("archetype", "GENERIC_REPOSITORY")
    total_files = inventory_summary.get("metrics", {}).get("total_files", len(inventory_records))

    extracted_knowledge: List[Dict[str, Any]] = []
    absorption_actions: List[Dict[str, Any]] = []
    knowledge_counter = 1
    action_counter = 1

    skill_records = [r for r in inventory_records if "skill.md" in r.get("path", "").lower()]
    if skill_records:
        know_id = f"KNOW-{knowledge_counter:03d}"
        knowledge_counter += 1
        extracted_knowledge.append({
            "id": know_id,
            "title": "Metodología y Heurística de Skills Agenticas",
            "description": f"Se identificaron {len(skill_records)} skills con instrucciones operativas, flujos de razonamiento y herramientas MCP.",
            "dimension": "THREAT_MODELING_ATTACK_SURFACE",
            "cwe": ["CWE-1059"],
            "owasp": ["A04:2021-Insecure Design"],
            "sourceLocations": [r["path"] for r in skill_records[:5]],
            "authority": "OBSERVED",
            "valueProposition": "Aporta flujos de trabajo autónomos especializados que pueden incorporarse como nuevas Skills o Referencias en Capa 1 de Devia-CyberSecurity."
        })

        act_id = f"ABS-{action_counter:03d}"
        action_counter += 1
        is_new = len(skill_records) > 2
        absorption_actions.append({
            "id": act_id,
            "knowledgeId": know_id,
            "title": "Adopción de Skills Especializadas o Guías de Referencia",
            "destination": "NEW_SKILL" if is_new else "SKILL_REFERENCE",
            "intent": "CREATE_NEW" if is_new else "ABSORB_EXPAND",
            "existingVulnerabilityId": "VULN-TM-001",
            "targetPathInRepo": f".agent/skills/{target_name.lower()}/" if is_new else ".agent/skills/security-reverse-engineering/references/",
            "architecturalRationale": "Capa 1: Orquestación agentica y heurística. Desacoplada del motor de contratos y utilidades de ejecución.",
            "priority": "HIGH",
            "implementationSteps": [
                "Extraer las directivas operativas y checklists del archivo SKILL.md",
                "Sanitizar referencias a herramientas externas no disponibles",
                "Adaptar al formato estándar de Devia-CyberSecurity y registrar en el mapa de skills",
                "Vincular con docs/VULNERABILITIES.md si aporta heurísticas para vectores catalogados"
            ]
        })

    crypto_records = [
        r for r in inventory_records
        if any(term in r.get("path", "").lower() for term in ["crypto", "cipher", "secret", "token", "hash", "key"])
    ]
    if crypto_records:
        know_id = f"KNOW-{knowledge_counter:03d}"
        knowledge_counter += 1
        extracted_knowledge.append({
            "id": know_id,
            "title": "Módulos de Criptografía y Gestión de Claves/Tokens",
            "description": f"Se detectaron {len(crypto_records)} archivos con implementaciones criptográficas o manejo de credenciales.",
            "dimension": "SECRETS_CRYPTOGRAPHY",
            "cwe": ["CWE-798", "CWE-327"],
            "owasp": ["A02:2021-Cryptographic Failures"],
            "sourceLocations": [r["path"] for r in crypto_records[:5]],
            "authority": "DERIVED",
            "valueProposition": "Permite extraer patrones de auditoría de claves y utilidades de cálculo de entropía de Shannon para detección de secretos."
        })

        act_id = f"ABS-{action_counter:03d}"
        action_counter += 1
        absorption_actions.append({
            "id": act_id,
            "knowledgeId": know_id,
            "title": "Algoritmo de Cálculo de Entropía y Scanner de Secretos",
            "destination": "PYTHON_SCRIPT",
            "intent": "ROBUSTIFY_HARDEN",
            "existingVulnerabilityId": "VULN-CRYP-001",
            "targetPathInRepo": "src/scripts/secrets_entropy_scanner.py",
            "architecturalRationale": "Capa 3: Utilidad determinista de análisis matemático de bajo nivel y alta velocidad en Python 3.11+ para robustecer VULN-CRYP-001.",
            "priority": "HIGH",
            "implementationSteps": [
                "Implementar cálculo de entropía de Shannon sobre cadenas candidatas",
                "Definir umbrales de detección deterministas con filtrado de falsos positivos",
                "Integrar soporte CLI con salida JSON estándar",
                "Actualizar docs/VULNERABILITIES.md si se agregan nuevos patrones de tokens o proveedores"
            ]
        })

    manifest_records = [r for r in inventory_records if r.get("is_security_critical", False) and r.get("extension") in [".json", ".yaml", ".yml", ".toml"]]
    if manifest_records:
        know_id = f"KNOW-{knowledge_counter:03d}"
        knowledge_counter += 1
        extracted_knowledge.append({
            "id": know_id,
            "title": "Arquitectura de Dependencias y Modelos de Paquetes",
            "description": f"Se auditaron manifiestos y lockfiles del ecosistema ({len(manifest_records)} detectados).",
            "dimension": "SUPPLY_CHAIN_SCA",
            "cwe": ["CWE-1395"],
            "owasp": ["A06:2021-Vulnerable and Outdated Components"],
            "sourceLocations": [r["path"] for r in manifest_records[:5]],
            "authority": "OBSERVED",
            "valueProposition": "Proporciona esquemas de validación de SBOM y parsers de lockfiles para análisis automatizado de dependencias."
        })

        act_id = f"ABS-{action_counter:03d}"
        action_counter += 1
        absorption_actions.append({
            "id": act_id,
            "knowledgeId": know_id,
            "title": "Contrato Zod para Inventario de Dependencias (SCA)",
            "destination": "ZOD_SCHEMA",
            "intent": "CREATE_NEW",
            "existingVulnerabilityId": "VULN-SCA-001",
            "targetPathInRepo": "src/schemas/supply-chain.schema.ts",
            "architecturalRationale": "Capa 2: Definición contract-first con Zod para validar la integridad de dependencias de proyectos auditados.",
            "priority": "MEDIUM",
            "implementationSteps": [
                "Modelar dependencias directas y transitivas con versiones semánticas estrictas",
                "Validar licencias permitidas y flags de riesgo (scripts postinstall)",
                "Exportar tipos TypeScript inferidos en src/types/index.ts"
            ]
        })

    source_code_records = [r for r in inventory_records if r.get("category") == "SOURCE_CODE"]
    if source_code_records:
        know_id = f"KNOW-{knowledge_counter:03d}"
        knowledge_counter += 1
        extracted_knowledge.append({
            "id": know_id,
            "title": "Flujos de Control, Taint Analysis e Inyecciones (SAST)",
            "description": f"El objetivo cuenta con {len(source_code_records)} archivos de código fuente que implementan lógica de negocio y despacho.",
            "dimension": "SOURCE_CODE_SAST",
            "cwe": ["CWE-89", "CWE-78", "CWE-22"],
            "owasp": ["A03:2021-Injection"],
            "sourceLocations": [r["path"] for r in source_code_records[:5]],
            "authority": "DERIVED",
            "valueProposition": "Permite sintetizar heurísticas de propagación de datos no confiables (Taint Trace) hacia sumideros (Sinks)."
        })

        act_id = f"ABS-{action_counter:03d}"
        action_counter += 1
        absorption_actions.append({
            "id": act_id,
            "knowledgeId": know_id,
            "title": "Extensión de Heurísticas de Auditoría SAST",
            "destination": "UPDATE_EXISTING",
            "intent": "UPDATE_ENHANCE",
            "existingVulnerabilityId": "VULN-SAST-001",
            "targetPathInRepo": ".agent/skills/security-reverse-engineering/references/security-dimensions-mapping.md",
            "architecturalRationale": "Reutilizar antes de añadir maquinaria: Enriquecer y robustecer la matriz de mapeo canónica con los sinks e inyecciones descubiertas.",
            "priority": "MEDIUM",
            "implementationSteps": [
                "Incorporar patrones de sinks de este framework al catálogo de referencias",
                "Verificar si se descubrieron variantes más robustas para VULN-SAST-001 o VULN-SAST-002",
                "Actualizar docs/VULNERABILITIES.md si se amplía el mecanismo de fallo",
                "Actualizar tests de verificación"
            ]
        })

    destinations_count: Dict[str, int] = {
        "NEW_SKILL": 0,
        "SKILL_REFERENCE": 0,
        "PYTHON_SCRIPT": 0,
        "ZOD_SCHEMA": 0,
        "MCP_TOOL_OR_ENGINE": 0,
        "UPDATE_EXISTING": 0
    }
    for act in absorption_actions:
        destinations_count[act["destination"]] = destinations_count.get(act["destination"], 0) + 1

    plan: Dict[str, Any] = {
        "planId": str(uuid.uuid4()),
        "createdAt": get_utc_timestamp(),
        "target": {
            "path": str(target_path),
            "canonicalPath": str(target_root),
            "name": target_name,
            "type": "SKILL" if archetype == "AGENTIC_SKILL_OR_PLUGIN" else "REPOSITORY",
            "archetypeDescription": archetype
        },
        "scopeSummary": {
            "totalEntriesScanned": total_files,
            "primaryLanguages": list(inventory_summary.get("top_extensions", {}).keys())[:5],
            "securityDimensionsEvaluated": CANONICAL_DIMENSIONS
        },
        "extractedKnowledge": extracted_knowledge,
        "absorptionActions": absorption_actions,
        "metrics": {
            "totalKnowledgeItems": len(extracted_knowledge),
            "destinationsBreakdown": dict(destinations_count)
        }
    }

    if output_path:
        out = Path(output_path).expanduser().resolve()
        out.parent.mkdir(parents=True, exist_ok=True)
        with out.open("w", encoding="utf-8") as f:
            json.dump(plan, f, indent=2, ensure_ascii=False)

        md_path = out.with_suffix(".md")
        render_markdown_plan(plan, md_path)

    return plan


def render_markdown_plan(plan: Dict[str, Any], destination: Path) -> None:
    lines = [
        f"# Plan de Absorción de Ingeniería Inversa Forense — {plan['target']['name']}",
        "",
        f"- **Plan ID:** `{plan['planId']}`",
        f"- **Fecha:** `{plan['createdAt']}`",
        f"- **Arquetipo:** `{plan['target']['archetypeDescription']}`",
        f"- **Total Archivos Evaluados:** `{plan['scopeSummary']['totalEntriesScanned']}`",
        "",
        "---",
        "",
        "## 💡 Conocimiento y Metodologías Extraídas",
        ""
    ]

    for k in plan["extractedKnowledge"]:
        lines.append(f"### [{k['id']}] {k['title']} ({k['authority']})")
        lines.append(f"- **Dimensión:** `{k['dimension']}`")
        if k.get("cwe"):
            lines.append(f"- **CWE:** {', '.join(k['cwe'])}")
        lines.append(f"- **Descripción:** {k['description']}")
        lines.append(f"- **Propuesta de Valor:** {k['valueProposition']}")
        lines.append("- **Ubicaciones Muestra:**")
        for loc in k.get("sourceLocations", []):
            lines.append(f"  - `{loc}`")
        lines.append("")

    lines.extend([
        "---",
        "",
        "## 🚀 Acciones de Absorción y Adopción en Devia-CyberSecurity",
        ""
    ])

    for a in plan["absorptionActions"]:
        intent_str = a.get("intent", "CREATE_NEW")
        vuln_str = f" | Ref: `{a['existingVulnerabilityId']}`" if a.get("existingVulnerabilityId") else ""
        lines.append(f"### [{a['id']}] {a['title']} -> `{a['destination']}` [{intent_str}{vuln_str}]")
        lines.append(f"- **Intención Evolutiva:** `{intent_str}`")
        if a.get("existingVulnerabilityId"):
            lines.append(f"- **Vulnerabilidad Catalogada en docs/VULNERABILITIES.md:** [`{a['existingVulnerabilityId']}`](file:///docs/VULNERABILITIES.md)")
        lines.append(f"- **Ruta Destino en Repo:** `{a['targetPathInRepo']}`")
        lines.append(f"- **Prioridad:** `{a['priority']}`")
        lines.append(f"- **Justificación Arquitectónica:** {a['architecturalRationale']}")
        lines.append("- **Pasos de Implementación:**")
        for step in a.get("implementationSteps", []):
            lines.append(f"  1. {step}")
        lines.append("")

    lines.extend([
        "---",
        "",
        "## 📊 Métricas de Absorción por Capa",
        "",
        "| Destino Canónico | Cantidad | Capa Devia-CyberSecurity |",
        "| :--- | :--- | :--- |"
    ])

    for dest, count in plan["metrics"]["destinationsBreakdown"].items():
        layer_desc = {
            "NEW_SKILL": "Capa 1: Orquestación Agentica",
            "SKILL_REFERENCE": "Capa 1: Referencias y Checklists",
            "PYTHON_SCRIPT": "Capa 3: Utilidades Políglotas Deterministas",
            "ZOD_SCHEMA": "Capa 2: Motor de Contratos Zod",
            "MCP_TOOL_OR_ENGINE": "Capa 2: Runners y Servidores MCP",
            "UPDATE_EXISTING": "Reutilización / Refactorización In-Place"
        }.get(dest, "General")
        lines.append(f"| `{dest}` | {count} | {layer_desc} |")

    lines.append("")
    with destination.open("w", encoding="utf-8") as f:
        f.write("\n".join(lines))


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Synthesize forensic inventory facts into an authoritative Absorption Plan"
    )
    parser.add_argument("target", help="Path to original analyzed target")
    parser.add_argument("--inventory", "-i", required=True, help="Path to inventory.jsonl")
    parser.add_argument("--summary", "-s", required=True, help="Path to summary.json")
    parser.add_argument("--output", "-o", required=True, help="Path to save absorption-plan.json")

    args = parser.parse_args()

    try:
        with open(args.summary, "r", encoding="utf-8") as sf:
            summary = json.load(sf)

        records = []
        with open(args.inventory, "r", encoding="utf-8") as inf:
            for line in inf:
                line = line.strip()
                if line:
                    records.append(json.loads(line))

        plan = build_absorption_plan(
            target_path=args.target,
            inventory_summary=summary,
            inventory_records=records,
            output_path=args.output
        )

        print(f"Absorption Plan created successfully: {plan['planId']}. Total actions: {len(plan['absorptionActions'])}")
    except Exception as e:
        print(f"FATAL: {e}", file=sys.stderr)
        sys.exit(2)


if __name__ == "__main__":
    main()
