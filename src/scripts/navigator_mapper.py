#!/usr/bin/env python3
"""MITRE ATT&CK Navigator Layer Parser and Cross-Framework Mapping Engine.

Validates ATT&CK Navigator JSON layers (v4.x format), extracts metrics,
and deterministically projects techniques onto Devia-CyberSecurity's 8 Canonical Dimensions.
Strictly adheres to Python 3.11+ stdlib, contract-first design, and CLI --json output.
"""

from __future__ import annotations

import argparse
from collections import Counter, defaultdict
import json
import os
from pathlib import Path
import re
import sys
from typing import Any, Dict, List, Optional, Set, Tuple

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

TECHNIQUE_PATTERN = re.compile(r"^T\d{4}(\.\d{3})?$")

# Mapeo canónico heurístico de familias de técnicas ATT&CK hacia las 8 Dimensiones de Devia-CyberSecurity
TACTIC_TO_DIMENSION_MAP: Dict[str, str] = {
    "reconnaissance": "THREAT_MODELING_ATTACK_SURFACE",
    "resource-development": "THREAT_MODELING_ATTACK_SURFACE",
    "initial-access": "THREAT_MODELING_ATTACK_SURFACE",
    "execution": "SOURCE_CODE_SAST",
    "persistence": "CONFIGURATION_HARDENING",
    "privilege-escalation": "IDENTITY_ACCESS_SESSION",
    "defense-evasion": "CONFIGURATION_HARDENING",
    "credential-access": "SECRETS_CRYPTOGRAPHY",
    "discovery": "THREAT_MODELING_ATTACK_SURFACE",
    "lateral-movement": "ARCHITECTURE_BOUNDARIES_ZERO_TRUST",
    "collection": "RESILIENCE_LOGGING_TELEMETRY",
    "command-and-control": "ARCHITECTURE_BOUNDARIES_ZERO_TRUST",
    "exfiltration": "RESILIENCE_LOGGING_TELEMETRY",
    "impact": "RESILIENCE_LOGGING_TELEMETRY"
}

# Sobrescrituras específicas de técnicas para máxima precisión dimensional
TECHNIQUE_SPECIFIC_DIMENSION_MAP: Dict[str, str] = {
    # Supply chain
    "T1195": "SUPPLY_CHAIN_SCA",
    "T1195.001": "SUPPLY_CHAIN_SCA",
    "T1195.002": "SUPPLY_CHAIN_SCA",
    "T1195.003": "SUPPLY_CHAIN_SCA",
    "T1525": "SUPPLY_CHAIN_SCA",
    # SAST e inyecciones
    "T1059": "SOURCE_CODE_SAST",
    "T1059.001": "SOURCE_CODE_SAST",
    "T1059.003": "SOURCE_CODE_SAST",
    "T1059.004": "SOURCE_CODE_SAST",
    "T1059.005": "SOURCE_CODE_SAST",
    "T1059.006": "SOURCE_CODE_SAST",
    "T1059.007": "SOURCE_CODE_SAST",
    "T1190": "SOURCE_CODE_SAST",
    "T1203": "SOURCE_CODE_SAST",
    "T1055": "SOURCE_CODE_SAST",
    # Secrets & Cryptography
    "T1552": "SECRETS_CRYPTOGRAPHY",
    "T1552.001": "SECRETS_CRYPTOGRAPHY",
    "T1552.002": "SECRETS_CRYPTOGRAPHY",
    "T1552.003": "SECRETS_CRYPTOGRAPHY",
    "T1552.004": "SECRETS_CRYPTOGRAPHY",
    "T1558": "SECRETS_CRYPTOGRAPHY",
    "T1558.003": "SECRETS_CRYPTOGRAPHY",
    "T1003": "SECRETS_CRYPTOGRAPHY",
    "T1003.001": "SECRETS_CRYPTOGRAPHY",
    "T1003.006": "SECRETS_CRYPTOGRAPHY",
    "T1573": "SECRETS_CRYPTOGRAPHY",
    "T1486": "SECRETS_CRYPTOGRAPHY",
    # Identity & Access
    "T1078": "IDENTITY_ACCESS_SESSION",
    "T1110": "IDENTITY_ACCESS_SESSION",
    "T1134": "IDENTITY_ACCESS_SESSION",
    "T1539": "IDENTITY_ACCESS_SESSION",
    "T1550": "IDENTITY_ACCESS_SESSION",
    "T1550.001": "IDENTITY_ACCESS_SESSION",
    "T1550.002": "IDENTITY_ACCESS_SESSION",
    "T1484": "IDENTITY_ACCESS_SESSION",
    # Architecture & Boundaries
    "T1021": "ARCHITECTURE_BOUNDARIES_ZERO_TRUST",
    "T1021.002": "ARCHITECTURE_BOUNDARIES_ZERO_TRUST",
    "T1071": "ARCHITECTURE_BOUNDARIES_ZERO_TRUST",
    "T1071.001": "ARCHITECTURE_BOUNDARIES_ZERO_TRUST",
    "T1090": "ARCHITECTURE_BOUNDARIES_ZERO_TRUST",
    "T1105": "ARCHITECTURE_BOUNDARIES_ZERO_TRUST",
    "T1611": "ARCHITECTURE_BOUNDARIES_ZERO_TRUST",
    # Configuration & Hardening
    "T1547": "CONFIGURATION_HARDENING",
    "T1547.001": "CONFIGURATION_HARDENING",
    "T1053": "CONFIGURATION_HARDENING",
    "T1053.005": "CONFIGURATION_HARDENING",
    "T1014": "CONFIGURATION_HARDENING",
    "T1070": "CONFIGURATION_HARDENING",
    "T1136": "CONFIGURATION_HARDENING",
    # Resilience & Telemetry
    "T1041": "RESILIENCE_LOGGING_TELEMETRY",
    "T1048": "RESILIENCE_LOGGING_TELEMETRY",
    "T1489": "RESILIENCE_LOGGING_TELEMETRY",
    "T1490": "RESILIENCE_LOGGING_TELEMETRY",
    "T1562": "RESILIENCE_LOGGING_TELEMETRY"
}


def load_navigator_layer(file_path: Path | str) -> Dict[str, Any]:
    """Carga y valida mínimamente un archivo JSON de capa de ATT&CK Navigator."""
    p = Path(file_path).resolve()
    if not p.is_file():
        raise FileNotFoundError(f"No se encontró el archivo de capa: {p}")
    with p.open("r", encoding="utf-8") as f:
        data = json.load(f)
    if not isinstance(data, dict):
        raise ValueError("El contenido del archivo no es un objeto JSON válido.")
    if "techniques" not in data or not isinstance(data["techniques"], list):
        raise ValueError("El archivo JSON no contiene un arreglo 'techniques' válido.")
    return data


def validate_navigator_layer(data: Dict[str, Any]) -> Dict[str, Any]:
    """Valida la conformidad del objeto de capa con el estándar Navigator v4.x."""
    issues: List[str] = []
    versions = data.get("versions", {})
    if not isinstance(versions, dict):
        issues.append("Falta el bloque 'versions' o no es un diccionario.")
    else:
        for key in ["attack", "navigator", "layer"]:
            if key not in versions:
                issues.append(f"Falta versión '{key}' en bloque versions.")

    techniques = data.get("techniques", [])
    valid_tech_count = 0
    invalid_techs = []

    for idx, t in enumerate(techniques):
        if not isinstance(t, dict):
            issues.append(f"Técnica en índice {idx} no es un diccionario.")
            continue
        tid = t.get("techniqueID")
        if not tid or not TECHNIQUE_PATTERN.match(tid):
            invalid_techs.append(str(tid))
        else:
            valid_tech_count += 1

    if invalid_techs:
        issues.append(f"Se encontraron {len(invalid_techs)} técnicas con ID inválido: {invalid_techs[:5]}")

    return {
        "valid": len(issues) == 0,
        "issues": issues,
        "name": data.get("name", "Unnamed Layer"),
        "totalTechniques": len(techniques),
        "validTechniques": valid_tech_count
    }


def map_technique_to_dimension(technique_id: str, tactic: Optional[str] = None) -> str:
    """Proyecta una técnica ATT&CK a una de las 8 Dimensiones Canónicas inmutables."""
    # 1. Búsqueda específica directa
    if technique_id in TECHNIQUE_SPECIFIC_DIMENSION_MAP:
        return TECHNIQUE_SPECIFIC_DIMENSION_MAP[technique_id]

    # 2. Búsqueda de técnica padre (si es sub-técnica T1xxx.xxx)
    if "." in technique_id:
        parent_id = technique_id.split(".")[0]
        if parent_id in TECHNIQUE_SPECIFIC_DIMENSION_MAP:
            return TECHNIQUE_SPECIFIC_DIMENSION_MAP[parent_id]

    # 3. Mapeo por táctica si está disponible
    if tactic and tactic.lower() in TACTIC_TO_DIMENSION_MAP:
        return TACTIC_TO_DIMENSION_MAP[tactic.lower()]

    # 4. Fallback determinista hacia THREAT_MODELING_ATTACK_SURFACE
    return "THREAT_MODELING_ATTACK_SURFACE"


def analyze_layer_coverage(data: Dict[str, Any]) -> Dict[str, Any]:
    """Calcula estadísticas exhaustivas y proyecciones dimensionales de la capa."""
    techniques = data.get("techniques", [])
    parent_techniques: Set[str] = set()
    sub_techniques: Set[str] = set()
    scores: List[float] = []

    dimension_counts: Counter[str] = Counter()
    dimension_techniques: Dict[str, List[str]] = defaultdict(list)

    for t in techniques:
        tid = t.get("techniqueID", "")
        if not tid:
            continue
        if "." in tid:
            sub_techniques.add(tid)
            parent_techniques.add(tid.split(".")[0])
        else:
            parent_techniques.add(tid)

        score = t.get("score")
        if isinstance(score, (int, float)):
            scores.append(float(score))

        tactic = t.get("tactic")
        dim = map_technique_to_dimension(tid, tactic)
        dimension_counts[dim] += 1
        dimension_techniques[dim].append(tid)

    total_unique = len(parent_techniques | sub_techniques)
    avg_score = round(sum(scores) / len(scores), 2) if scores else 0.0

    return {
        "layerName": data.get("name", "Unnamed Layer"),
        "domain": data.get("domain", "enterprise-attack"),
        "attackVersion": data.get("versions", {}).get("attack", "unknown"),
        "metrics": {
            "totalEntries": len(techniques),
            "parentTechniquesCount": len(parent_techniques),
            "subTechniquesCount": len(sub_techniques),
            "uniqueTechniquesCount": total_unique,
            "minScore": min(scores) if scores else 0,
            "maxScore": max(scores) if scores else 0,
            "averageScore": avg_score
        },
        "dimensionProjection": {
            dim: {
                "count": dimension_counts.get(dim, 0),
                "percentage": round((dimension_counts.get(dim, 0) / len(techniques) * 100), 2) if techniques else 0.0,
                "sampleTechniques": dimension_techniques.get(dim, [])[:8]
            }
            for dim in CANONICAL_DIMENSIONS
        }
    }


def main() -> None:
    parser = argparse.ArgumentParser(
        description="MITRE ATT&CK Navigator Layer Parser & Dimension Mapping Engine for Devia-CyberSecurity"
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    # Subcomando validate
    val_p = subparsers.add_parser("validate", help="Valida la estructura de una capa Navigator")
    val_p.add_argument("layer_file", help="Ruta al archivo JSON de capa")
    val_p.add_argument("--json", action="store_true", help="Salida en formato JSON estricto")

    # Subcomando summary
    sum_p = subparsers.add_parser("summary", help="Resumen estadístico y distribución de cobertura")
    sum_p.add_argument("layer_file", help="Ruta al archivo JSON de capa")
    sum_p.add_argument("--json", action="store_true", help="Salida en formato JSON estricto")

    # Subcomando project
    proj_p = subparsers.add_parser("project", help="Proyecta las técnicas hacia las 8 Dimensiones Canónicas")
    proj_p.add_argument("layer_file", help="Ruta al archivo JSON de capa")
    proj_p.add_argument("--json", action="store_true", help="Salida en formato JSON estricto")

    args = parser.parse_args()

    try:
        data = load_navigator_layer(args.layer_file)

        if args.command == "validate":
            result = validate_navigator_layer(data)
            if args.json:
                print(json.dumps(result, indent=2))
            else:
                status = "VÁLIDO" if result["valid"] else "INVÁLIDO"
                print(f"Estado: {status}")
                print(f"Capa: {result['name']}")
                print(f"Técnicas válidas: {result['validTechniques']} / {result['totalTechniques']}")
                if result["issues"]:
                    print("Incidencias:")
                    for issue in result["issues"]:
                        print(f" - {issue}")
            sys.exit(0 if result["valid"] else 1)

        elif args.command in ("summary", "project"):
            analysis = analyze_layer_coverage(data)
            if args.json:
                print(json.dumps(analysis, indent=2))
            else:
                print(f"=== Resumen de Capa: {analysis['layerName']} ===")
                print(f"Dominio: {analysis['domain']} | Versión ATT&CK: {analysis['attackVersion']}")
                m = analysis["metrics"]
                print(f"Técnicas totales: {m['totalEntries']} (Padres: {m['parentTechniquesCount']}, Sub-técnicas: {m['subTechniquesCount']})")
                print(f"Score Promedio: {m['averageScore']} (Min: {m['minScore']}, Max: {m['maxScore']})\n")
                print("--- Proyección sobre las 8 Dimensiones Canónicas ---")
                for dim, details in analysis["dimensionProjection"].items():
                    print(f"[{dim}]: {details['count']} técnicas ({details['percentage']}%)")
                    if details["sampleTechniques"]:
                        print(f"  Muestra: {', '.join(details['sampleTechniques'])}")
            sys.exit(0)

    except Exception as e:
        if getattr(args, "json", False):
            print(json.dumps({"error": str(e)}, indent=2))
        else:
            print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
