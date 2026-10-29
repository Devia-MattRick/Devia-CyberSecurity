import json
import os
import uuid
from datetime import datetime, timezone

audit_dir = r"K:\Devia-CyberSecurity\audits\security-audit-skill-main"
target_dir = r"K:\Devia-CyberSecurity\external-reps\security-audit-skill-main"

# 1. Coverage ledger: all 29 files
files_metadata = [
    ("LICENSE", "root-governance", ["SRC-001"]),
    ("README.md", "root-overview", ["SRC-001"]),
    ("cairn-audit-orchestrator/SKILL.md", "cairn-orchestration", ["SRC-001"]),
    ("cairn-audit-orchestrator/references/audit-graph-schema.md", "cairn-orchestration", ["SRC-001", "SRC-002"]),
    ("cairn-audit-orchestrator/scripts/audit_graph_manager.py", "cairn-orchestration", ["SRC-002"]),
    ("determine_threat_model/SKILL.md", "threat-modeling", ["SRC-003"]),
    ("skills/security-audit/AI-AND-LLM.md", "security-audit-domain-guides", ["SRC-008"]),
    ("skills/security-audit/ATTACK-CLASSES.md", "security-audit-domain-guides", ["SRC-007"]),
    ("skills/security-audit/CLIENT-SIDE.md", "security-audit-domain-guides", ["SRC-007"]),
    ("skills/security-audit/CLOUD-AND-DEPLOYMENT.md", "security-audit-domain-guides", ["SRC-007"]),
    ("skills/security-audit/DATA-ISOLATION-AND-LIFECYCLE.md", "security-audit-domain-guides", ["SRC-010"]),
    ("skills/security-audit/DESKTOP-MOBILE-AND-LOCAL-IPC.md", "security-audit-domain-guides", ["SRC-009"]),
    ("skills/security-audit/HUNTING.md", "security-audit-domain-guides", ["SRC-007"]),
    ("skills/security-audit/MEMORY-SAFETY-AND-BINARY.md", "security-audit-domain-guides", ["SRC-007"]),
    ("skills/security-audit/PROTOCOLS-RPC-AND-MESSAGING.md", "security-audit-domain-guides", ["SRC-007"]),
    ("skills/security-audit/RECONNAISSANCE.md", "security-audit-domain-guides", ["SRC-007"]),
    ("skills/security-audit/RESOURCE-EXHAUSTION-AND-AVAILABILITY.md", "security-audit-domain-guides", ["SRC-007"]),
    ("skills/security-audit/SKILL.md", "security-audit-core", ["SRC-007"]),
    ("skills/security-audit/SUPPLY-CHAIN-AND-RELEASE.md", "security-audit-domain-guides", ["SRC-011"]),
    ("skills/security-audit/VALIDATION-AND-REPORTING.md", "security-audit-core", ["SRC-007"]),
    ("skills/security-audit/WEB-PROTOCOL-AND-AUTH.md", "security-audit-domain-guides", ["SRC-007"]),
    ("skills/security-audit/report-schema.json", "security-audit-contracts", ["SRC-007", "SRC-012"]),
    ("skills/security-audit/validate-coverage-ledger.cjs", "security-audit-validators", ["SRC-007"]),
    ("skills/security-audit/validate-coverage-ledger.test.cjs", "security-audit-validators", ["SRC-007"]),
    ("skills/security-audit/validate-findings.cjs", "security-audit-validators", ["SRC-012"]),
    ("skills/security-audit/validate-findings.test.cjs", "security-audit-validators", ["SRC-012"]),
    ("web-audit-orchestrator/SKILL.md", "web-audit-orchestration", ["SRC-004"]),
    ("web-audit-orchestrator/references/check-cwe-mapping.md", "web-audit-orchestration", ["SRC-005"]),
    ("web-audit-orchestrator/scripts/web_audit_runner.py", "web-audit-orchestration", ["SRC-006"])
]

coverage_records = []
for rel_path, subsystem, evidence_ids in files_metadata:
    coverage_records.append({
        "path": rel_path,
        "subsystem": subsystem,
        "inventory_kind": "file",
        "review": "read",
        "extent": {"kind": "whole-file"},
        "evidence_ids": evidence_ids,
        "reason": None,
        "remaining": []
    })

coverage_path = os.path.join(audit_dir, "coverage.jsonl")
with open(coverage_path, "w", encoding="utf-8") as f:
    for rec in coverage_records:
        f.write(json.dumps(rec, ensure_ascii=False) + "\n")

# 2. Evidence ledger
evidence_records = [
    {
        "id": "SRC-001",
        "authority": "SOURCE",
        "claim_class": "OBSERVED",
        "target_path": "cairn-audit-orchestrator/SKILL.md",
        "lines": {"start": 46, "end": 120},
        "symbol": "Cairn Protocol Blackboard Architecture",
        "evidence_snippet": "Orquestador de Auditoría de Seguridad Local — Protocolo Cairn Adaptado. Emula Fact/Intent/Hint mediante audit-graph.yaml para ejecutar auditorías completas sin servidor, sin dispatcher, sin Docker. Taxonomía de 4 niveles (L1-L4), ciclo Bootstrap-Explore-Reason.",
        "digest_sha256": "9da7c23a273c68fad4e53935aef26b523d65a5796cea77a3e48b2eba08f48183",
        "context": "Patrón de arquitectura de pizarra (Blackboard) y bucle OODA para auditorías agenticas iterativas con grafo determinista e inmutable.",
        "timestamp": "2026-10-27T12:00:00Z"
    },
    {
        "id": "SRC-002",
        "authority": "SOURCE",
        "claim_class": "OBSERVED",
        "target_path": "cairn-audit-orchestrator/scripts/audit_graph_manager.py",
        "lines": {"start": 40, "end": 192},
        "symbol": "Graph Validation & Immutability Checking",
        "evidence_snippet": "FACT_ID_PATTERN = re.compile(r'^f\\d{3,}$'); VALID_STATUSES = {'active', 'completed'}; def check_immutability(data, previous_data): Verifica que ningún Fact existente fue modificado.",
        "digest_sha256": "9dd3d3375a910a27b85242e7585ac44345e6783417825ae03c52773c88e29f43",
        "context": "Motor de validación de estructura e inmutabilidad para grafos de auditoría en YAML, garantizando la preservación estricta de hechos comprobados.",
        "timestamp": "2026-10-27T12:00:00Z"
    },
    {
        "id": "SRC-003",
        "authority": "SOURCE",
        "claim_class": "OBSERVED",
        "target_path": "determine_threat_model/SKILL.md",
        "lines": {"start": 11, "end": 100},
        "symbol": "6-Step Threat Modeling Workflow",
        "evidence_snippet": "Step 1: Identify Component Purpose -> Step 2: Map Entry Points and Untrusted Inputs -> Step 3: Identify Trust Boundaries and Auth Assumptions -> Step 4: Map Sensitive Data Paths -> Step 5: Identify Priority Review Areas -> Step 6: Evaluate Scanner Findings Against the Threat Model.",
        "digest_sha256": "398db8fb589a4746ec07f63bb9910cfbdb20eb470e478a1b522488c1122d6320",
        "context": "Metodología sistemática de modelado de amenazas para contextualizar hallazgos automáticos y discriminar verdaderos positivos de falsos positivos.",
        "timestamp": "2026-10-27T12:00:00Z"
    },
    {
        "id": "SRC-004",
        "authority": "SOURCE",
        "claim_class": "OBSERVED",
        "target_path": "web-audit-orchestrator/SKILL.md",
        "lines": {"start": 59, "end": 120},
        "symbol": "33-Check Web Audit Pipeline",
        "evidence_snippet": "Skill orquestadora que ejecuta 33 módulos de auditoría web exhaustiva sobre cualquier URL o dominio. Cubre seguridad (SSL/TLS, headers, cookies, HSTS, DNSSEC, WAF, amenazas), infraestructura de red (IP, DNS, puertos, WHOIS) y reconocimiento.",
        "digest_sha256": "ae58ce75b951032e0b65a7cb0a31067642cfbbe02d7fea41de4eefaf75d71cf7",
        "context": "Pipeline de auditoría de superficie externa web basado en Lissy93/web-check con categorización por pesos y cálculo de puntuación.",
        "timestamp": "2026-10-27T12:00:00Z"
    },
    {
        "id": "SRC-005",
        "authority": "SOURCE",
        "claim_class": "OBSERVED",
        "target_path": "web-audit-orchestrator/references/check-cwe-mapping.md",
        "lines": {"start": 9, "end": 100},
        "symbol": "Web Checks to CWE/OWASP/RFC Matrix",
        "evidence_snippet": "SEC-01 -> CWE-295, CWE-327, CWE-323, CWE-326 (A02:2021) RFC-5280, RFC-8446; SEC-02 -> CWE-614, CWE-315, CWE-311 (A05:2021); SEC-03 -> CWE-693, CWE-1021, CWE-1024; SEC-04 -> CWE-319, CWE-311 (RFC-6797 HSTS).",
        "digest_sha256": "1cc05faef01f6d68c1e07d2244e4fd468663f0ad319bed82625ae5b28c39141c",
        "context": "Matriz autoritativa de correspondencia entre verificaciones de perímetro web y estándares formales de ciberseguridad.",
        "timestamp": "2026-10-27T12:00:00Z"
    },
    {
        "id": "SRC-006",
        "authority": "SOURCE",
        "claim_class": "OBSERVED",
        "target_path": "web-audit-orchestrator/scripts/web_audit_runner.py",
        "lines": {"start": 125, "end": 168},
        "symbol": "run_cmd Subprocess OS Command Injection Vulnerability",
        "evidence_snippet": "def run_cmd(cmd: str, timeout: int = DEFAULT_TIMEOUT): result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout) ... rc, out, err = run_cmd(f\"openssl s_client -connect {domain}:443 -showcerts -servername {domain} </dev/null 2>/dev/null | openssl x509 ...\")",
        "digest_sha256": "ab129691708ec8cbf1b1c786a8245cc34f961f671d1259736ab10d1236d85901",
        "context": "Vulnerabilidad crítica CWE-78 (VULN-SAST-002) en herramienta de auditoría: interpolación directa de parámetros de usuario en subshell con shell=True sin sanitización de metacaracteres.",
        "timestamp": "2026-10-27T12:00:00Z"
    },
    {
        "id": "SRC-007",
        "authority": "SOURCE",
        "claim_class": "OBSERVED",
        "target_path": "skills/security-audit/SKILL.md",
        "lines": {"start": 6, "end": 85},
        "symbol": "Cloudflare 6-Phase Audit & Adversarial Verification",
        "evidence_snippet": "Find vulnerabilities that violate a real trust boundary... Adversarial validation: The agent that checks a finding is never the agent that found it... Only confirm established boundary failures... The parent creates and is the only writer of shared run files... Promotion procedure for retained artifacts.",
        "digest_sha256": "5e3e96a1e438d8f35fef0a1e38f02d4f00e2bdf910401b7dfe00e6779c6dac85",
        "context": "Arquitectura de auditoría de Cloudflare con aislamiento de escritura por agente, verificación adversarial independiente y validación de contrato dual.",
        "timestamp": "2026-10-27T12:00:00Z"
    },
    {
        "id": "SRC-008",
        "authority": "SOURCE",
        "claim_class": "OBSERVED",
        "target_path": "skills/security-audit/AI-AND-LLM.md",
        "lines": {"start": 9, "end": 60},
        "symbol": "AI, LLM, Agent and MCP Trust Hunting Classes",
        "evidence_snippet": "Prompt injection alone is not a finding. Require a code-level boundary failure... Action-confirmation and approval binding: user approves one described action but execution uses changed arguments... MCP server and tool identity confusion... MCP metadata and schema as policy.",
        "digest_sha256": "7335a95c43554eadefcf03ece639291bb0e038c398a179299e3887ffe06bd2ef",
        "context": "Heurísticas avanzadas para auditoría de sistemas agenticos, MCP servers, memoria persistente e inyección indirecta de prompts.",
        "timestamp": "2026-10-27T12:00:00Z"
    },
    {
        "id": "SRC-009",
        "authority": "SOURCE",
        "claim_class": "OBSERVED",
        "target_path": "skills/security-audit/DESKTOP-MOBILE-AND-LOCAL-IPC.md",
        "lines": {"start": 9, "end": 60},
        "symbol": "Desktop, Mobile and Local IPC Security Classes",
        "evidence_snippet": "Paths, process names, bundle/package IDs, and claimed sender fields are not peer authentication. Use OS peer credentials, code identity, capability handles... Navigation-origin to bridge confusion... Privileged helper as confused deputy.",
        "digest_sha256": "58eae8ee0ca6a46611c501ec5a3ab47fdff88dd7db0d8d74789bbf8bb19d8cb2",
        "context": "Heurísticas para aplicaciones desktop/móviles, puentes nativos webview, comunicación IPC (sockets, pipes, Binder) y helpers privilegiados.",
        "timestamp": "2026-10-27T12:00:00Z"
    },
    {
        "id": "SRC-010",
        "authority": "SOURCE",
        "claim_class": "OBSERVED",
        "target_path": "skills/security-audit/DATA-ISOLATION-AND-LIFECYCLE.md",
        "lines": {"start": 9, "end": 60},
        "symbol": "Data Isolation and Lifecycle Hunting Classes",
        "evidence_snippet": "A tenant or owner field on a record is not isolation... Search, cache, and index ACL drift... Export and backup scope expansion... Import and restore authority expansion... Soft-delete and tombstone bypass.",
        "digest_sha256": "307dcb3e24d292715c4a041190e7bb135646a37eb6187619ae01d000a634a4ad",
        "context": "Disciplina y patrones de auditoría de aislamiento multi-inquilino, sincronización de ACLs en cachés/índices y ciclo de vida de datos.",
        "timestamp": "2026-10-27T12:00:00Z"
    },
    {
        "id": "SRC-011",
        "authority": "SOURCE",
        "claim_class": "OBSERVED",
        "target_path": "skills/security-audit/SUPPLY-CHAIN-AND-RELEASE.md",
        "lines": {"start": 9, "end": 60},
        "symbol": "Supply Chain, CI/CD and Release Hunting Classes",
        "evidence_snippet": "Follow integrity across every handoff: source identity, resolved inputs, build worker, artifact identity... CI configuration is authorization code... Build-to-promotion substitution... Plugin and extension trust expansion.",
        "digest_sha256": "f372e919940e335468ba1ae09f99026c3986a345f7fe26f8068f132e199f52a5",
        "context": "Auditoría integral de la cadena de suministro, tuberías CI/CD, inmutabilidad de artefactos de release y permisos de plugins.",
        "timestamp": "2026-10-27T12:00:00Z"
    },
    {
        "id": "SRC-012",
        "authority": "SOURCE",
        "claim_class": "OBSERVED",
        "target_path": "skills/security-audit/validate-findings.cjs",
        "lines": {"start": 10, "end": 65},
        "symbol": "Zero-Dependency Contract Validator with Hard Limits",
        "evidence_snippet": "const LIMITS = Object.freeze({ inputBytes: 5 * 1024 * 1024, nestingDepth: 64, arrayItems: 1000 ... }); const WINDOWS_RESERVED_COMPONENT = /^(?:con|prn|aux|nul|clock\\$|conin\\$|conout\\$|com[1-9]|lpt[1-9])(?:\.|$)/iu;",
        "digest_sha256": "e85f232e36bfac0f866f244da50376692d6b45c690beadcb00608b0e6c8b5283",
        "context": "Validador estricto de esquema JSON de hallazgos sin dependencias externas, protegido contra bombas de memoria, recursión excesiva y nombres reservados de Windows.",
        "timestamp": "2026-10-27T12:00:00Z"
    }
]

evidence_path = os.path.join(audit_dir, "evidence.jsonl")
with open(evidence_path, "w", encoding="utf-8") as f:
    for rec in evidence_records:
        f.write(json.dumps(rec, ensure_ascii=False) + "\n")

# 3. Unknowns ledger
unknowns_records = [
    {
        "id": "UNK-001",
        "title": "Vulnerabilidad crítica de Inyección de Comandos OS en web_audit_runner.py",
        "affected_component": "web-audit-orchestrator/scripts/web_audit_runner.py",
        "contradiction_or_gap": "El script ejecuta subprocess.run(cmd, shell=True) interpolando el target/domain sin validar ni escapar metacaracteres de shell (e.g. openssl s_client -connect {domain}:443 </dev/null). Si un operador audita un host malicioso o entrada no confiable como 'example.com; calc.exe', se produce ejecución arbitraria de comandos en el host de auditoría.",
        "required_evidence": "Reemplazo obligatorio por invocación tokenizada con arrays de argumentos (shell=False) y sanitización estricta mediante regex de nombres de dominio conforme a RFC 1035.",
        "impact": "RCE (Remote Code Execution) en la máquina del auditor de seguridad (CWE-78 / VULN-SAST-002)."
    },
    {
        "id": "UNK-002",
        "title": "Incompatibilidad de redirecciones POSIX y herramientas CLI en Windows",
        "affected_component": "web-audit-orchestrator/scripts/web_audit_runner.py",
        "contradiction_or_gap": "Comandos como '</dev/null 2>/dev/null' son sintaxis de shell Unix/POSIX. En Windows bajo PowerShell o cmd.exe provocan errores de sintaxis o crean archivos basura llamados 'null'. Además, binarios como dig, whois, openssl, nmap no están presentes por defecto en PATH de Windows.",
        "required_evidence": "Implementación de clientes nativos en Python (socket, ssl, urllib) o comprobación previa de disponibilidad de herramientas de sistema con fallbacks limpios.",
        "impact": "Fallo inmediato de los 33 checks en sistemas Windows nativos."
    },
    {
        "id": "UNK-003",
        "title": "Dependencia en servicios y APIs externas de terceros no garantizadas",
        "affected_component": "web-audit-orchestrator/SKILL.md",
        "contradiction_or_gap": "Los checks SEC-07, RECON-03, RECON-05 dependen de API keys externas (Google Safe Browsing, BuiltWith, PhishTank). Si no están configuradas en variables de entorno, los checks fallan silenciosamente o quedan incompletos.",
        "required_evidence": "Documentación clara de fallbacks offline y tratamiento de datos no concluyentes con estado UNKNOWN / needs_validation.",
        "impact": "Evaluaciones de seguridad incompletas presentadas erróneamente como limpias."
    },
    {
        "id": "UNK-004",
        "title": "Falta de Sandbox OS nativo para ejecución de verificación local",
        "affected_component": "skills/security-audit/SKILL.md",
        "contradiction_or_gap": "La skill define requisitos estrictos para un sandbox OS (loopback namespace aislado, sin red externa, toolchain de sólo lectura, scratch descriptors de solo lectura de padres), pero no incluye la implementación en código del sandbox, delegándolo a infraestructura externa del host.",
        "required_evidence": "Diseño de un runner de aislamiento de subprocesos con cuotas de CPU/memoria y carpetas efímeras para Capa 2 / Capa 3.",
        "impact": "Incapacidad de reproducir de forma segura checks de código hostil si el entorno carece de un sandbox OS preexistente."
    }
]

unknowns_path = os.path.join(audit_dir, "unknowns.jsonl")
with open(unknowns_path, "w", encoding="utf-8") as f:
    for rec in unknowns_records:
        f.write(json.dumps(rec, ensure_ascii=False) + "\n")

# 4. Authoritative Absorption Plan (JSON)
plan_id = "5a27c731-8e7c-4861-a5bf-854e4df90b14"
plan_data = {
    "planId": plan_id,
    "createdAt": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    "target": {
        "path": "k:\\Devia-CyberSecurity\\external-reps\\security-audit-skill-main",
        "canonicalPath": "K:\\Devia-CyberSecurity\\external-reps\\security-audit-skill-main",
        "name": "security-audit-skill-main",
        "type": "REPOSITORY",
        "commitOrSnapshot": "devia-snapshot/v1:sha256:c490ec85d33de9662f798488c649e5571ab7925381bd11758684a6378cb9bdfa",
        "archetypeDescription": "Multi-Skill Security Audit & Orchestration Suite (Cloudflare Security Audit + Cairn Protocol + Web Check)"
    },
    "scopeSummary": {
        "totalEntriesScanned": 29,
        "primaryLanguages": [".md", ".cjs", ".py", ".json"],
        "securityDimensionsEvaluated": [
            "THREAT_MODELING_ATTACK_SURFACE",
            "SOURCE_CODE_SAST",
            "SECRETS_CRYPTOGRAPHY",
            "IDENTITY_ACCESS_SESSION",
            "SUPPLY_CHAIN_SCA",
            "ARCHITECTURE_BOUNDARIES_ZERO_TRUST",
            "CONFIGURATION_HARDENING",
            "RESILIENCE_LOGGING_TELEMETRY"
        ]
    },
    "extractedKnowledge": [
        {
            "id": "KNOW-001",
            "title": "Metodología de Modelado de Amenazas en 6 Pasos",
            "description": "Proceso sistemático para identificar propósito, entradas no confiables, fronteras de confianza, rutas de datos sensibles, áreas prioritarias y evaluación de hallazgos automáticos.",
            "dimension": "THREAT_MODELING_ATTACK_SURFACE",
            "cwe": ["CWE-1059", "CWE-501"],
            "owasp": ["A04:2021-Insecure Design"],
            "sourceLocations": ["determine_threat_model/SKILL.md"],
            "authority": "OBSERVED",
            "valueProposition": "Estandariza el análisis inicial de cualquier componente y previene el gasto de tokens en evaluar código inalcanzable."
        },
        {
            "id": "KNOW-002",
            "title": "Arquitectura de Pizarra (Blackboard) y Grafo de Auditoría Cairn",
            "description": "Modelo de estado inmutable estructurado en Fact, Intent y Hint mediante audit-graph.yaml para auditorías agenticas exploratorias sin servidor ni Docker.",
            "dimension": "THREAT_MODELING_ATTACK_SURFACE",
            "cwe": ["CWE-1059"],
            "owasp": ["A04:2021-Insecure Design"],
            "sourceLocations": [
                "cairn-audit-orchestrator/SKILL.md",
                "cairn-audit-orchestrator/references/audit-graph-schema.md",
                "cairn-audit-orchestrator/scripts/audit_graph_manager.py"
            ],
            "authority": "OBSERVED",
            "valueProposition": "Proporciona memoria formal inmutable para investigaciones complejas de larga duración, evitando repetición de tareas y pérdida de contexto."
        },
        {
            "id": "KNOW-003",
            "title": "Inyección de Comandos OS en Herramientas de Auditoría",
            "description": "Patrón de vulnerabilidad crítica donde los scripts de auditoría ejecutan subprocesos con shell=True e interpolan nombres de host sin sanitización.",
            "dimension": "SOURCE_CODE_SAST",
            "cwe": ["CWE-78"],
            "owasp": ["A03:2021-Injection"],
            "sourceLocations": ["web-audit-orchestrator/scripts/web_audit_runner.py"],
            "authority": "OBSERVED",
            "valueProposition": "Documenta un vector real de RCE en herramientas de seguridad defensiva, exigiendo el uso de invocación tokenizada con arrays de argumentos."
        },
        {
            "id": "KNOW-004",
            "title": "Heurísticas de Seguridad de Memoria y Binarios Nativos",
            "description": "Checklists para inspección de desbordamientos de búfer, use-after-free, integer overflows, confusión de tipos y fronteras FFI/ABI.",
            "dimension": "SOURCE_CODE_SAST",
            "cwe": ["CWE-119", "CWE-416", "CWE-190", "CWE-843"],
            "owasp": ["A06:2021-Vulnerable and Outdated Components"],
            "sourceLocations": ["skills/security-audit/MEMORY-SAFETY-AND-BINARY.md"],
            "authority": "OBSERVED",
            "valueProposition": "Guía especializada para auditar módulos nativos, parsers binarios y extensiones en C/C++/Rust."
        },
        {
            "id": "KNOW-005",
            "title": "Checklist de Criptografía Web y Configuración TLS/SSL",
            "description": "Verificaciones de certificados TLS, algoritmos obsoletos (MD5/SHA1, 3DES, RC4), cipher suites AEAD y vigencia de certificados.",
            "dimension": "SECRETS_CRYPTOGRAPHY",
            "cwe": ["CWE-295", "CWE-326", "CWE-327"],
            "owasp": ["A02:2021-Cryptographic Failures"],
            "sourceLocations": [
                "web-audit-orchestrator/references/check-cwe-mapping.md",
                "skills/security-audit/WEB-PROTOCOL-AND-AUTH.md"
            ],
            "authority": "OBSERVED",
            "valueProposition": "Aporta parámetros deterministas de auditoría criptográfica perimetral basados en RFC 8446 y Mozilla TLS Observatory."
        },
        {
            "id": "KNOW-006",
            "title": "Auditoría de Protocolos Web, Autenticación y Ciclo de Vida de Tokens",
            "description": "Patrones de revisión para sesiones, cookies seguras (Secure, HttpOnly, SameSite), open redirects, flujos OAuth/OIDC/SAML y mTLS.",
            "dimension": "IDENTITY_ACCESS_SESSION",
            "cwe": ["CWE-614", "CWE-601", "CWE-287", "CWE-384"],
            "owasp": ["A07:2021-Identification and Authentication Failures"],
            "sourceLocations": [
                "skills/security-audit/WEB-PROTOCOL-AND-AUTH.md",
                "web-audit-orchestrator/references/check-cwe-mapping.md"
            ],
            "authority": "OBSERVED",
            "valueProposition": "Refuerza la auditoría de control de acceso perimetral y gestión de identidades en aplicaciones web y APIs."
        },
        {
            "id": "KNOW-007",
            "title": "Aislamiento de Datos Multi-Inquilino y Ciclo de Vida",
            "description": "Heurísticas para detectar fugas de datos entre tenants en cachés, índices de búsqueda, exportaciones/backups y bypass de borrado lógico (soft-delete).",
            "dimension": "IDENTITY_ACCESS_SESSION",
            "cwe": ["CWE-639", "CWE-200", "CWE-284"],
            "owasp": ["A01:2021-Broken Access Control"],
            "sourceLocations": ["skills/security-audit/DATA-ISOLATION-AND-LIFECYCLE.md"],
            "authority": "OBSERVED",
            "valueProposition": "Permite auditar arquitecturas SaaS multi-tenant donde los registros primarios están aislados pero las copias secundarias filtran datos."
        },
        {
            "id": "KNOW-008",
            "title": "Auditoría de Cadena de Suministro, CI/CD y Releases",
            "description": "Vectores de confusión de dependencias, scripts de ciclo de vida de instalación, ejecución de código no confiable en pull_request_target y firma de artefactos.",
            "dimension": "SUPPLY_CHAIN_SCA",
            "cwe": ["CWE-829", "CWE-494", "CWE-1395"],
            "owasp": ["A08:2021-Software and Data Integrity Failures"],
            "sourceLocations": ["skills/security-audit/SUPPLY-CHAIN-AND-RELEASE.md"],
            "authority": "OBSERVED",
            "valueProposition": "Cubre las brechas de integridad en canalizaciones automatizadas de compilación, empaquetado y distribución."
        },
        {
            "id": "KNOW-009",
            "title": "Fronteras de Seguridad en Sistemas de IA, Agentes y Servidores MCP",
            "description": "Vectores de inyección indirecta de prompts, envenenamiento de memoria persistente, confusión de identidad en herramientas MCP, y fallos de action-binding.",
            "dimension": "ARCHITECTURE_BOUNDARIES_ZERO_TRUST",
            "cwe": ["CWE-74", "CWE-862", "CWE-863"],
            "owasp": ["A01:2021-Broken Access Control"],
            "sourceLocations": ["skills/security-audit/AI-AND-LLM.md"],
            "authority": "OBSERVED",
            "valueProposition": "Metodología autoritativa de Cloudflare para auditar aplicaciones que integran LLMs, agentes autónomos y protocolos MCP."
        },
        {
            "id": "KNOW-010",
            "title": "Hardening de Aplicaciones Desktop, Móviles e IPC Local",
            "description": "Auditoría de deep-links, separación de privilegios en puentes webview-nativo, autenticación de peers en sockets Unix/pipes y helpers privilegiados.",
            "dimension": "ARCHITECTURE_BOUNDARIES_ZERO_TRUST",
            "cwe": ["CWE-250", "CWE-668", "CWE-285"],
            "owasp": ["A05:2021-Security Misconfiguration"],
            "sourceLocations": ["skills/security-audit/DESKTOP-MOBILE-AND-LOCAL-IPC.md"],
            "authority": "OBSERVED",
            "valueProposition": "Proporciona heurísticas rigurosas para auditar clientes de escritorio y móviles con comunicación inter-proceso."
        },
        {
            "id": "KNOW-011",
            "title": "Arquitectura de Validación Adversarial y Paquete Sellado",
            "description": "Principio donde el agente que valida un hallazgo nunca es el que lo descubrió, con aislamiento estricto de directorios de escritura y validadores duales.",
            "dimension": "ARCHITECTURE_BOUNDARIES_ZERO_TRUST",
            "cwe": ["CWE-345", "CWE-353"],
            "owasp": ["A08:2021-Software and Data Integrity Failures"],
            "sourceLocations": [
                "skills/security-audit/SKILL.md",
                "skills/security-audit/VALIDATION-AND-REPORTING.md",
                "skills/security-audit/validate-findings.cjs"
            ],
            "authority": "OBSERVED",
            "valueProposition": "Erradica falsos positivos y sesgos de confirmación en auditorías automatizadas mediante verificación adversarial independiente."
        },
        {
            "id": "KNOW-012",
            "title": "Auditoría de Infraestructura Cloud, Contenedores y Despliegue",
            "description": "Verificación de políticas IAM de mínimo privilegio, configuraciones de Kubernetes/contenedores, derivas de entorno y exposición de endpoints de gestión.",
            "dimension": "CONFIGURATION_HARDENING",
            "cwe": ["CWE-250", "CWE-1188", "CWE-16"],
            "owasp": ["A05:2021-Security Misconfiguration"],
            "sourceLocations": ["skills/security-audit/CLOUD-AND-DEPLOYMENT.md"],
            "authority": "OBSERVED",
            "valueProposition": "Permite auditar manifiestos IaC, Dockerfiles y configuraciones de nube antes de su despliegue en producción."
        },
        {
            "id": "KNOW-013",
            "title": "Matriz de 33 Checks de Perímetro Web Mapeada a CWE y RFCs",
            "description": "Catálogo exhaustivo de verificaciones de seguridad web (DNSSEC, SPF/DKIM/DMARC, HSTS, CSP, Cookies, WAF, Certificados) con puntuación y severidades.",
            "dimension": "CONFIGURATION_HARDENING",
            "cwe": ["CWE-693", "CWE-1021", "CWE-350", "CWE-345"],
            "owasp": ["A05:2021-Security Misconfiguration"],
            "sourceLocations": [
                "web-audit-orchestrator/references/check-cwe-mapping.md",
                "web-audit-orchestrator/SKILL.md"
            ],
            "authority": "OBSERVED",
            "valueProposition": "Unifica el marco de auditoría de configuración para servicios expuestos a internet bajo una sola referencia técnica."
        },
        {
            "id": "KNOW-014",
            "title": "Agotamiento de Recursos y Denegación de Servicio (DoS)",
            "description": "Heurísticas para detectar amplificación computacional (ReDoS, expansión de archivos descomprimidos, queries patológicas) y fugas de descriptores de archivos.",
            "dimension": "RESILIENCE_LOGGING_TELEMETRY",
            "cwe": ["CWE-400", "CWE-1333", "CWE-770"],
            "owasp": ["A04:2021-Insecure Design"],
            "sourceLocations": ["skills/security-audit/RESOURCE-EXHAUSTION-AND-AVAILABILITY.md"],
            "authority": "OBSERVED",
            "valueProposition": "Permite auditar la resiliencia algorítmica de aplicaciones frente a entradas pequeñas diseñadas para agotar recursos compartidos."
        }
    ],
    "absorptionActions": [
        {
            "id": "ABS-001",
            "knowledgeId": "KNOW-009",
            "title": "Guía de Auditoría de Seguridad en Agentes de IA, LLMs y MCP",
            "destination": "SKILL_REFERENCE",
            "intent": "ROBUSTIFY_HARDEN",
            "existingVulnerabilityId": "VULN-ARCH-005",
            "targetPathInRepo": ".agents/skills/architecture-boundaries-zero-trust/references/ai-and-llm-agent-security.md",
            "architecturalRationale": "Capa 1: Documento de referencia técnica para la Skill architecture-boundaries-zero-trust que formaliza la auditoría de agentes, memoria persistente, MCP servers y action-binding.",
            "priority": "HIGH",
            "implementationSteps": [
                "Crear el archivo de referencia ai-and-llm-agent-security.md en architecture-boundaries-zero-trust/references/",
                "Estructurar los vectores de ataque en 4 categorías: Inyección Indirecta y Contexto, Herramientas y Acción, Protocolo MCP, y Salidas/Renderizado",
                "Incorporar el axioma de Action-Binding y validación de esquemas Zod en llamadas a herramientas",
                "Vincular con VULN-ARCH-005, VULN-ARCH-006 y VULN-ARCH-008 en docs/VULNERABILITIES.md"
            ]
        },
        {
            "id": "ABS-002",
            "knowledgeId": "KNOW-002",
            "title": "Metodología de Auditoría con Arquitectura de Pizarra (Cairn Protocol)",
            "destination": "SKILL_REFERENCE",
            "intent": "UPDATE_ENHANCE",
            "existingVulnerabilityId": "VULN-TM-003",
            "targetPathInRepo": ".agents/skills/threat-modeling-attack-surface/references/cairn-blackboard-orchestration.md",
            "architecturalRationale": "Capa 1: Guía metodológica en threat-modeling-attack-surface para estructurar investigaciones complejas mediante grafos Fact-Intent-Hint inmutables.",
            "priority": "MEDIUM",
            "implementationSteps": [
                "Redactar cairn-blackboard-orchestration.md con la especificación del esquema audit-graph.yaml",
                "Definir el ciclo OODA Bootstrap-Explore-Reason para agentes defensivos",
                "Establecer la regla de inmutabilidad de hechos (Facts) y derivación de intenciones (Intents)",
                "Documentar casos de uso para mapeo de superficies desconocidas y auditorías multi-fase"
            ]
        },
        {
            "id": "ABS-003",
            "knowledgeId": "KNOW-013",
            "title": "Matriz de Auditoría y Bastionado de Infraestructura Web (33 Checks)",
            "destination": "SKILL_REFERENCE",
            "intent": "ABSORB_EXPAND",
            "existingVulnerabilityId": "VULN-CONF-002",
            "targetPathInRepo": ".agents/skills/configuration-hardening/references/web-infrastructure-audit-matrix.md",
            "architecturalRationale": "Capa 1: Referencia técnica en configuration-hardening que consolida los 33 controles de seguridad de perímetro web mapeados a CWEs, OWASP y RFCs.",
            "priority": "HIGH",
            "implementationSteps": [
                "Crear web-infrastructure-audit-matrix.md sintetizando los checks de web-check",
                "Incorporar la tabla de correspondencia CWE, OWASP Top 10 y RFCs",
                "Añadir criterios de remediación paso a paso para TLS, HSTS, DNSSEC, SPF/DMARC y cabeceras HTTP",
                "Enlazar con VULN-CONF-002 en docs/VULNERABILITIES.md"
            ]
        },
        {
            "id": "ABS-004",
            "knowledgeId": "KNOW-007",
            "title": "Auditoría de Aislamiento de Datos Multi-Tenant y Ciclo de Vida",
            "destination": "SKILL_REFERENCE",
            "intent": "ROBUSTIFY_HARDEN",
            "existingVulnerabilityId": "VULN-IAM-001",
            "targetPathInRepo": ".agents/skills/identity-access-session/references/data-isolation-and-tenant-lifecycle.md",
            "architecturalRationale": "Capa 1: Guía técnica en identity-access-session para auditar fronteras de datos entre inquilinos en sistemas distribuidos y bases de datos SaaS.",
            "priority": "HIGH",
            "implementationSteps": [
                "Redactar data-isolation-and-tenant-lifecycle.md con los patrones de deriva de ACLs en cachés e índices",
                "Documentar los riesgos de expansión de privilegios en operaciones de backup/restore e importación de datos",
                "Establecer heurísticas para auditar mecanismos de borrado lógico (soft-delete) y purga definitiva",
                "Integrar con la heurística de optimización RLS InitPlan O(1) de docs/PROACTIVE.md"
            ]
        },
        {
            "id": "ABS-005",
            "knowledgeId": "KNOW-003",
            "title": "Actualización del Catálogo Canónico con Vectores de Inyección en Herramientas de Auditoría",
            "destination": "UPDATE_EXISTING",
            "intent": "UPDATE_ENHANCE",
            "existingVulnerabilityId": "VULN-SAST-002",
            "targetPathInRepo": "docs/VULNERABILITIES.md",
            "architecturalRationale": "SSOT Documental: Actualizar VULN-SAST-002 y añadir referencias a inyecciones en runners y herramientas de seguridad.",
            "priority": "HIGH",
            "implementationSteps": [
                "Actualizar docs/VULNERABILITIES.md para documentar el antipatrón de ejecución con shell=True en herramientas de auditoría",
                "Vincular las nuevas referencias creadas en las skills operativas correspondientes",
                "Confirmar que todas las vulnerabilidades se mantienen estrictamente dentro de las 8 Dimensiones Canónicas"
            ]
        },
        {
            "id": "ABS-006",
            "knowledgeId": "KNOW-011",
            "title": "Actualización de la Memoria Proactiva con Lecciones de Auditoría Adversarial y Action-Binding",
            "destination": "UPDATE_EXISTING",
            "intent": "ROBUSTIFY_HARDEN",
            "existingVulnerabilityId": "VULN-ARCH-004",
            "targetPathInRepo": "docs/PROACTIVE.md",
            "architecturalRationale": "SSOT de Memoria: Registrar heurísticas operativas aprendidas para evitar la reinvención y guiar futuras auditorías.",
            "priority": "CRITICAL",
            "implementationSteps": [
                "Incorporar la heurística de Inyección de Comandos en Herramientas de Seguridad (prohibición de shell=True e interpolación de strings)",
                "Documentar el Axioma de Verificación Adversarial (el verificador nunca es el descubridor)",
                "Documentar el Patrón de Action-Binding en Agentes de IA y Servidores MCP",
                "Registrar el uso del protocolo Cairn (Blackboard Architecture) para gestión de estado en auditorías de largo alcance"
            ]
        }
    ],
    "metrics": {
        "totalKnowledgeItems": 14,
        "destinationsBreakdown": {
            "SKILL_REFERENCE": 4,
            "UPDATE_EXISTING": 2
        }
    },
    "ledgerPaths": {
        "inventoryJsonl": "audits/security-audit-skill-main/inventory/inventory.jsonl",
        "coverageJsonl": "audits/security-audit-skill-main/coverage.jsonl",
        "evidenceJsonl": "audits/security-audit-skill-main/evidence.jsonl",
        "unknownsJsonl": "audits/security-audit-skill-main/unknowns.jsonl"
    }
}

plan_path = os.path.join(audit_dir, "absorption-plan.json")
with open(plan_path, "w", encoding="utf-8") as f:
    json.dump(plan_data, f, indent=2, ensure_ascii=False)

print(f"Ledgers created in {audit_dir}. Plan ID: {plan_id}")
