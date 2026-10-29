#!/usr/bin/env python3
"""stack_detector_mapper.py — Deterministic Stack Reconnaissance & Dimensional Mapper.

Capa 3 Utility for Devia-CyberSecurity.
Inspects an external target repository without executing any untrusted code, detects
languages, frameworks, manifest files, databases, auth patterns, and deployment configurations,
and maps them to:
  1. The Canonical Security Dimensions (1-8).
  2. The responsible specialized Skills (.agents/skills/).
  3. The specific technical references (references/*.md).
  4. The relevant deterministic Capa 3 scripts (src/scripts/*.py).
  5. Priority canonical vulnerability vectors (VULN-*).
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Any, Dict, List, Set


# Canonical Mappings
DIMENSION_MAPPINGS = {
    "THREAT_MODELING_ATTACK_SURFACE": {
        "skill": "threat-modeling-attack-surface",
        "scripts": [
            "target_snapshot.py",
            "risk_assessment_engine.py",
            "navigator_mapper.py",
            "incident_triage_scorer.py",
            "vulnerability_sla_analyzer.py",
        ],
    },
    "SOURCE_CODE_SAST": {
        "skill": "source-code-sast",
        "scripts": [
            "differential_exploit_verifier.py",
            "attack_vector_assessment_engine.py",
            "poc_safety_linter.py",
        ],
    },
    "SECRETS_CRYPTOGRAPHY": {
        "skill": "secrets-cryptography",
        "scripts": [
            "scan_secrets.py",
            "pqc_inventory_scanner.py",
        ],
    },
    "IDENTITY_ACCESS_SESSION": {
        "skill": "identity-access-session",
        "scripts": [
            "role_mining_analyzer.py",
        ],
    },
    "SUPPLY_CHAIN_SCA": {
        "skill": "supply-chain-sca",
        "scripts": [
            "check_lockfiles.py",
        ],
    },
    "ARCHITECTURE_BOUNDARIES_ZERO_TRUST": {
        "skill": "architecture-boundaries-zero-trust",
        "scripts": [
            "mcp_tool_poisoning_scanner.py",
            "c2_beaconing_detector.py",
            "deception_canary_auditor.py",
            "threat_detection_engine.py",
            "url_validator.py",
            "hard_exclusions.py",
        ],
    },
    "CONFIGURATION_HARDENING": {
        "skill": "configuration-hardening",
        "scripts": [
            "endpoint_hardening_auditor.py",
        ],
    },
    "RESILIENCE_LOGGING_TELEMETRY": {
        "skill": "resilience-logging-telemetry",
        "scripts": [
            "scan_covert_telemetry.py",
            "sarif_toolkit.py",
        ],
    },
}

EXCLUDED_DIRS = {
    ".git",
    "node_modules",
    "__pycache__",
    ".venv",
    "venv",
    "dist",
    "build",
    "target",
    ".idea",
    ".vscode",
    ".angular",
    ".next",
    ".nuxt",
}


def scan_target_stack(target_dir: str) -> Dict[str, Any]:
    """Inspects the target directory and identifies tech stack markers."""
    target_path = Path(target_dir).resolve()
    if not target_path.exists():
        raise FileNotFoundError(f"Target directory does not exist: {target_dir}")

    languages: Set[str] = set()
    manifests: List[str] = []
    frameworks: Set[str] = set()
    configs: Set[str] = set()
    auth_markers: Set[str] = set()
    database_markers: Set[str] = set()
    ai_llm_markers: Set[str] = set()
    desktop_mobile: Set[str] = set()

    total_files = 0

    for root, dirs, files in os.walk(target_path):
        # Prune excluded directories
        dirs[:] = [d for d in dirs if d not in EXCLUDED_DIRS and not d.startswith(".")]

        for file_name in files:
            total_files += 1
            rel_path = os.path.relpath(os.path.join(root, file_name), target_path)
            lower_name = file_name.lower()
            ext = os.path.splitext(lower_name)[1]

            # 1. Languages by extension
            if ext in {".ts", ".tsx"}:
                languages.add("TypeScript")
            elif ext in {".js", ".jsx", ".mjs", ".cjs"}:
                languages.add("JavaScript")
            elif ext in {".py", ".pyw"}:
                languages.add("Python")
            elif ext in {".go"}:
                languages.add("Go")
            elif ext in {".rs"}:
                languages.add("Rust")
            elif ext in {".java"}:
                languages.add("Java")
            elif ext in {".cs"}:
                languages.add("C#")
            elif ext in {".php"}:
                languages.add("PHP")
            elif ext in {".c", ".h", ".cpp", ".hpp", ".cc"}:
                languages.add("C/C++")
            elif ext in {".rb"}:
                languages.add("Ruby")
            elif ext in {".sol"}:
                languages.add("Solidity")

            # 2. Manifests & Dependencies
            if lower_name in {
                "package.json",
                "pnpm-lock.yaml",
                "package-lock.json",
                "yarn.lock",
                "bun.lockb",
            }:
                manifests.append(rel_path)
                languages.add("JavaScript/Node.js")
            elif lower_name in {
                "pyproject.toml",
                "requirements.txt",
                "setup.py",
                "poetry.lock",
                "pipfile",
            }:
                manifests.append(rel_path)
                languages.add("Python")
            elif lower_name in {"cargo.toml", "cargo.lock"}:
                manifests.append(rel_path)
                languages.add("Rust")
            elif lower_name in {"go.mod", "go.sum"}:
                manifests.append(rel_path)
                languages.add("Go")
            elif lower_name in {"pom.xml", "build.gradle"}:
                manifests.append(rel_path)
                languages.add("Java")
            elif lower_name in {"composer.json", "composer.lock"}:
                manifests.append(rel_path)
                languages.add("PHP")

            # 3. Configurations & Cloud Infrastructure
            if lower_name.startswith("dockerfile") or lower_name.endswith(".dockerfile"):
                configs.add("Docker")
            elif lower_name in {"docker-compose.yml", "docker-compose.yaml", "compose.yml"}:
                configs.add("Docker Compose")
            elif ext in {".tf", ".tfvars"}:
                configs.add("Terraform (IaC)")
            elif ".github/workflows" in rel_path.replace("\\", "/"):
                configs.add("GitHub Actions CI/CD")
            elif ".gitlab-ci.yml" in lower_name:
                configs.add("GitLab CI/CD")
            elif lower_name in {"k8s.yaml", "k8s.yml", "deployment.yaml"} or "k8s" in rel_path:
                configs.add("Kubernetes")
            elif lower_name.endswith((".conf", ".nginx")):
                configs.add("Nginx / WebServer")

            # 4. Check specific file content markers for small manifest/config files
            if lower_name in {"package.json", "pyproject.toml", "requirements.txt", "cargo.toml"} or (
                ext in {".json", ".toml", ".yml", ".yaml"} and os.path.getsize(os.path.join(root, file_name)) < 100000
            ):
                try:
                    with open(os.path.join(root, file_name), "r", encoding="utf-8", errors="ignore") as f:
                        content = f.read().lower()

                        # Frameworks
                        if "react" in content:
                            frameworks.add("React")
                        if "angular" in content:
                            frameworks.add("Angular")
                        if "vue" in content:
                            frameworks.add("Vue")
                        if "next" in content or "next.js" in content:
                            frameworks.add("Next.js")
                        if "express" in content:
                            frameworks.add("Express")
                        if "fastify" in content:
                            frameworks.add("Fastify")
                        if "nestjs" in content or "@nestjs" in content:
                            frameworks.add("NestJS")
                        if "django" in content:
                            frameworks.add("Django")
                        if "fastapi" in content:
                            frameworks.add("FastAPI")
                        if "flask" in content:
                            frameworks.add("Flask")
                        if "spring" in content:
                            frameworks.add("Spring Boot")

                        # Auth
                        if "jsonwebtoken" in content or "jwt" in content or "jose" in content:
                            auth_markers.add("JWT / Token Auth")
                        if "passport" in content:
                            auth_markers.add("Passport.js")
                        if "oauth" in content:
                            auth_markers.add("OAuth 2.0 / OIDC")
                        if "bcrypt" in content or "argon2" in content:
                            auth_markers.add("Password Hashing (Bcrypt/Argon2)")

                        # Databases
                        if "pg" in content or "postgres" in content:
                            database_markers.add("PostgreSQL")
                        if "mysql" in content:
                            database_markers.add("MySQL")
                        if "sqlite" in content:
                            database_markers.add("SQLite")
                        if "mongodb" in content or "mongoose" in content:
                            database_markers.add("MongoDB")
                        if "redis" in content or "ioredis" in content:
                            database_markers.add("Redis")

                        # AI / LLM
                        if "openai" in content or "anthropic" in content or "langchain" in content or "model context protocol" in content or "mcp" in content:
                            ai_llm_markers.add("LLM / Agentic Systems / MCP")

                        # Desktop / Mobile
                        if "electron" in content:
                            desktop_mobile.add("Electron Desktop App")
                        if "react-native" in content:
                            desktop_mobile.add("React Native Mobile App")
                except Exception:
                    pass

    return {
        "targetDirectory": str(target_path),
        "totalFilesDiscovered": total_files,
        "languages": sorted(list(languages)),
        "frameworks": sorted(list(frameworks)),
        "manifests": sorted(manifests),
        "infrastructure": sorted(list(configs)),
        "authPatterns": sorted(list(auth_markers)),
        "databases": sorted(list(database_markers)),
        "aiAndAgentic": sorted(list(ai_llm_markers)),
        "desktopAndMobile": sorted(list(desktop_mobile)),
    }


def compute_dimensional_mapping(recon_data: Dict[str, Any]) -> Dict[str, Any]:
    """Maps the detected stack elements to the 8 canonical dimensions, skills, references, and scripts."""
    active_dimensions: Set[str] = set()
    recommended_references: List[str] = []
    recommended_scripts: Set[str] = set()
    priority_vulnerabilities: List[str] = []

    # Universal Baselines: Every repo undergoes SAST, Secrets scanning, and Supply Chain audit
    active_dimensions.add("SOURCE_CODE_SAST")
    active_dimensions.add("SECRETS_CRYPTOGRAPHY")
    active_dimensions.add("THREAT_MODELING_ATTACK_SURFACE")
    recommended_scripts.add("scan_secrets.py")
    recommended_scripts.add("target_snapshot.py")
    recommended_scripts.add("risk_assessment_engine.py")

    # Supply Chain SCA if manifests exist
    if recon_data["manifests"]:
        active_dimensions.add("SUPPLY_CHAIN_SCA")
        recommended_scripts.add("check_lockfiles.py")
        recommended_references.append(
            ".agents/skills/supply-chain-sca/references/package-integrity-and-patch-risk-rubric.md"
        )
        priority_vulnerabilities.extend(["VULN-SCA-001", "VULN-SCA-006", "VULN-SCA-007"])

    # SAST additions
    recommended_scripts.add("differential_exploit_verifier.py")
    recommended_scripts.add("attack_vector_assessment_engine.py")
    recommended_scripts.add("poc_safety_linter.py")
    recommended_references.append(
        ".agents/skills/source-code-sast/references/code-evidence-and-root-cause-reasoning.md"
    )

    if "Angular" in recon_data["frameworks"]:
        recommended_references.append(
            ".agents/skills/source-code-sast/references/angular-spa-ssr-hydration-security.md"
        )
        priority_vulnerabilities.append("VULN-SAST-016")

    if any(l in recon_data["languages"] for l in ["JavaScript", "TypeScript", "JavaScript/Node.js"]):
        recommended_references.append(
            ".agents/skills/source-code-sast/references/prototype-pollution-and-property-injection.md"
        )
        priority_vulnerabilities.append("VULN-SAST-018")

    # Secrets & Cryptography
    recommended_references.append(
        ".agents/skills/secrets-cryptography/references/source-exposed-secrets-standard.md"
    )
    recommended_scripts.add("pqc_inventory_scanner.py")
    priority_vulnerabilities.append("VULN-CRYP-001")

    # Identity, Access & Session
    if recon_data["authPatterns"] or recon_data["databases"]:
        active_dimensions.add("IDENTITY_ACCESS_SESSION")
        recommended_scripts.add("role_mining_analyzer.py")
        recommended_references.append(
            ".agents/skills/identity-access-session/references/rls-deep-audit-guide.md"
        )
        recommended_references.append(
            ".agents/skills/identity-access-session/references/multitenant-and-sibling-guard-auditing.md"
        )
        priority_vulnerabilities.extend(["VULN-IAM-001", "VULN-IAM-002"])

    # Configuration & Hardening
    if recon_data["infrastructure"]:
        active_dimensions.add("CONFIGURATION_HARDENING")
        recommended_scripts.add("endpoint_hardening_auditor.py")
        if any("docker" in i.lower() for i in recon_data["infrastructure"]):
            recommended_references.append(
                ".agents/skills/configuration-hardening/references/docker-container-hardening.md"
            )
            priority_vulnerabilities.append("VULN-CONF-007")
        if any("github" in i.lower() or "gitlab" in i.lower() for i in recon_data["infrastructure"]):
            recommended_references.append(
                ".agents/skills/architecture-boundaries-zero-trust/references/ci-cd-agentic-security-boundaries.md"
            )

    # Architecture, Boundaries & Zero Trust
    active_dimensions.add("ARCHITECTURE_BOUNDARIES_ZERO_TRUST")
    recommended_scripts.add("url_validator.py")
    recommended_scripts.add("hard_exclusions.py")
    recommended_references.append(
        ".agents/skills/architecture-boundaries-zero-trust/references/sealed-scan-contracts-and-projections.md"
    )

    if recon_data["aiAndAgentic"]:
        recommended_scripts.add("mcp_tool_poisoning_scanner.py")
        recommended_scripts.add("prompt_injection_detector.py")
        recommended_references.append(
            ".agents/skills/architecture-boundaries-zero-trust/references/agentic-system-security-mcp.md"
        )
        recommended_references.append(
            ".agents/skills/architecture-boundaries-zero-trust/references/mcp-tool-poisoning-and-rug-pull-defense.md"
        )
        priority_vulnerabilities.extend(["VULN-ARCH-010", "VULN-ARCH-011"])

    if "Electron Desktop App" in recon_data["desktopAndMobile"]:
        recommended_references.append(
            ".agents/skills/architecture-boundaries-zero-trust/references/electron-ipc-hardening.md"
        )
        priority_vulnerabilities.append("VULN-ARCH-008")

    # Resilience, Logging & Telemetry
    active_dimensions.add("RESILIENCE_LOGGING_TELEMETRY")
    recommended_scripts.add("sarif_toolkit.py")
    recommended_scripts.add("scan_covert_telemetry.py")
    recommended_references.append(
        ".agents/skills/resilience-logging-telemetry/references/interrupted-scan-recovery.md"
    )

    ordered_dimensions = [
        dim for dim in [
            "THREAT_MODELING_ATTACK_SURFACE",
            "SOURCE_CODE_SAST",
            "SECRETS_CRYPTOGRAPHY",
            "IDENTITY_ACCESS_SESSION",
            "SUPPLY_CHAIN_SCA",
            "ARCHITECTURE_BOUNDARIES_ZERO_TRUST",
            "CONFIGURATION_HARDENING",
            "RESILIENCE_LOGGING_TELEMETRY",
        ] if dim in active_dimensions
    ]

    skills_involved = [
        DIMENSION_MAPPINGS[d]["skill"] for d in ordered_dimensions
    ]

    return {
        "activeDimensions": ordered_dimensions,
        "skillsInvolved": skills_involved,
        "recommendedScripts": sorted(list(recommended_scripts)),
        "recommendedReferences": sorted(list(set(recommended_references))),
        "priorityVulnerabilities": sorted(list(set(priority_vulnerabilities))),
    }


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Devia-CyberSecurity — Deterministic Stack Reconnaissance & Dimensional Mapper"
    )
    parser.add_argument("target", help="Path to the target repository or folder to inspect")
    parser.add_argument("--json", action="store_true", help="Output results strictly as a JSON object")
    parser.add_argument("-o", "--output", help="Optional path to write output JSON")

    args = parser.parse_args()

    try:
        recon = scan_target_stack(args.target)
        mapping = compute_dimensional_mapping(recon)
        result = {
            "status": "SUCCESS",
            "reconnaissance": recon,
            "mapping": mapping,
        }

        json_output = json.dumps(result, indent=2, ensure_ascii=False)

        if args.output:
            os.makedirs(os.path.dirname(os.path.abspath(args.output)), exist_ok=True)
            with open(args.output, "w", encoding="utf-8") as f:
                f.write(json_output)

        if args.json:
            print(json_output)
        else:
            print("=================================================================")
            print("  DEVIA-CYBERSECURITY — RECONOCIMIENTO Y MAPEO DIMENSIONAL")
            print("=================================================================")
            print(f"Target: {recon['targetDirectory']}")
            print(f"Total archivos escaneados: {recon['totalFilesDiscovered']}")
            print(f"Lenguajes detectados: {', '.join(recon['languages']) or 'Ninguno'}")
            print(f"Frameworks detectados: {', '.join(recon['frameworks']) or 'Ninguno'}")
            print(f"Manifiestos encontrados: {len(recon['manifests'])}")
            print(f"Infraestructura / CI: {', '.join(recon['infrastructure']) or 'Ninguna'}")
            print(f"Patrones de Autenticación: {', '.join(recon['authPatterns']) or 'Ninguno'}")
            print(f"Bases de Datos: {', '.join(recon['databases']) or 'Ninguna'}")
            print(f"Sistemas IA / Agénticos: {', '.join(recon['aiAndAgentic']) or 'Ninguno'}")
            print(f"Desktop / Mobile: {', '.join(recon['desktopAndMobile']) or 'Ninguno'}")
            print("-----------------------------------------------------------------")
            print("  DIMENSIONES Y SKILLS ACTIVADAS")
            print("-----------------------------------------------------------------")
            for dim in mapping["activeDimensions"]:
                skill = DIMENSION_MAPPINGS[dim]["skill"]
                print(f"  • [{dim}] -> Skill: {skill}")
            print("-----------------------------------------------------------------")
            print(f"Scripts Deterministas Sugeridos ({len(mapping['recommendedScripts'])}):")
            for s in mapping["recommendedScripts"]:
                print(f"  - src/scripts/{s}")
            print("-----------------------------------------------------------------")
            print(f"Referencias Clave Recomendadas ({len(mapping['recommendedReferences'])}):")
            for r in mapping["recommendedReferences"]:
                print(f"  - {r}")
            print("=================================================================")
    except Exception as e:
        error_result = {"status": "ERROR", "error": str(e)}
        if args.json:
            print(json.dumps(error_result, indent=2))
        else:
            print(f"[-] Error durante el escaneo: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()

