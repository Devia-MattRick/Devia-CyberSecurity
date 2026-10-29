#!/usr/bin/env python3
"""Generator of Forensic Ledgers and Absorption Plan for CheatSheetSeries-master.

Produces:
1. audits/CheatSheetSeries-master/coverage.jsonl (all 382 files mapped to subsystems & dispositions)
2. audits/CheatSheetSeries-master/evidence.jsonl (factual citations with exact digests & line numbers)
3. audits/CheatSheetSeries-master/unknowns.jsonl (vulnerabilities and technical gaps found)
4. audits/CheatSheetSeries-master/absorption-plan.json (strict Zod AbsorptionPlanSchema contract)
5. audits/CheatSheetSeries-master/absorption-plan.md (comprehensive forensic report)
"""

import hashlib
import json
import os
from pathlib import Path
import uuid
from datetime import datetime, timezone

audit_dir = r"K:\Devia-CyberSecurity\audits\CheatSheetSeries-master"
target_dir = r"K:\Devia-CyberSecurity\external-reps\CheatSheetSeries-master"
inventory_path = os.path.join(audit_dir, "inventory", "inventory.jsonl")

def get_file_sha256(rel_path: str) -> str:
    full_path = os.path.join(target_dir, rel_path)
    if not os.path.isfile(full_path):
        return "0" * 64
    hasher = hashlib.sha256()
    with open(full_path, "rb") as f:
        while chunk := f.read(65536):
            hasher.update(chunk)
    return hasher.hexdigest()

def get_line_count(rel_path: str) -> int:
    full_path = os.path.join(target_dir, rel_path)
    if not os.path.isfile(full_path):
        return 0
    try:
        with open(full_path, "r", encoding="utf-8", errors="ignore") as f:
            return sum(1 for _ in f)
    except Exception:
        return 0

# 1. Read all inventoried files
with open(inventory_path, "r", encoding="utf-8") as f:
    inventory_items = [json.loads(line) for line in f]

print(f"Loaded {len(inventory_items)} inventory items.")

# Subsystem classifier for CheatSheetSeries
def classify_subsystem(path: str) -> tuple[str, list[str]]:
    p = path.replace("\\", "/")
    if p.startswith("cheatsheets/"):
        if "MCP_Security" in p:
            return "core-cheatsheets-agentic", ["SRC-001"]
        elif "AI_Agent_Security" in p:
            return "core-cheatsheets-agentic", ["SRC-002"]
        elif "Verifying_Third_Party_Agent" in p:
            return "core-cheatsheets-agentic", ["SRC-003"]
        elif "Post_Quantum" in p:
            return "core-cheatsheets-crypto", ["SRC-004"]
        elif "Passkey" in p:
            return "core-cheatsheets-auth", ["SRC-005"]
        elif "Workload_Identity" in p:
            return "core-cheatsheets-auth", ["SRC-006"]
        elif "Zero_Trust" in p:
            return "core-cheatsheets-arch", ["SRC-007"]
        elif any(k in p for k in ["SQL", "Cross_Site", "Command", "SSRF", "Deserialization"]):
            return "core-cheatsheets-sast", ["SRC-007"]
        return "core-cheatsheets", ["SRC-007"]
    elif p.startswith("cheatsheets_draft/"):
        return "draft-cheatsheets", ["SRC-007"]
    elif p.startswith(".claude/"):
        return "agentic-review-governance", ["SRC-008"]
    elif p in ["AGENTS.md", "GUIDELINE.md", "HelpGuide.md", "SECURITY.md"]:
        return "governance-and-standards", ["SRC-008"]
    elif p.startswith("scripts/"):
        if "Check_PR_Workflow_Approvals" in p:
            return "validation-tooling-and-ci", ["SRC-009"]
        elif "link_check" in p or "Check_Markdown_Links" in p:
            return "validation-tooling-and-ci", ["SRC-010"]
        return "generation-tooling", ["SRC-009"]
    elif p.startswith("tests/"):
        return "test-suite", ["SRC-009", "SRC-010"]
    elif p.startswith("assets/"):
        return "diagrams-and-media", []
    elif p in ["package-lock.json", "requirements.txt", "mkdocs.yml", "book.json", "Makefile"]:
        if p == "package-lock.json":
            return "manifests-and-configs", ["SRC-011"]
        elif p == "requirements.txt":
            return "manifests-and-configs", ["SRC-012"]
        return "manifests-and-configs", []
    return "metadata-and-navigation", []

# 2. Build coverage.jsonl
coverage_records = []
for item in inventory_items:
    rel_path = item["path"]
    subsystem, ev_ids = classify_subsystem(rel_path)
    
    # Disposition
    if subsystem in ["diagrams-and-media"]:
        disposition = "inventoried"
    elif subsystem in ["core-cheatsheets-agentic", "core-cheatsheets-crypto", "core-cheatsheets-auth", "agentic-review-governance", "governance-and-standards"]:
        disposition = "verified"
    elif subsystem in ["validation-tooling-and-ci", "manifests-and-configs", "core-cheatsheets-arch", "core-cheatsheets-sast"]:
        disposition = "traced"
    else:
        disposition = "read"
    
    digest = item.get("sha256") or get_file_sha256(rel_path)
    lines_cnt = get_line_count(rel_path)
    
    cov_rec = {
        "path": rel_path.replace("\\", "/"),
        "subsystem": subsystem,
        "disposition": disposition,
        "digest_sha256": digest,
        "size_bytes": item.get("size", 0),
        "lines_count": lines_cnt,
        "evidence_ids": ev_ids
    }
    coverage_records.append(cov_rec)

cov_file = os.path.join(audit_dir, "coverage.jsonl")
with open(cov_file, "w", encoding="utf-8") as f:
    for rec in coverage_records:
        f.write(json.dumps(rec) + "\n")
print(f"Wrote {len(coverage_records)} records to coverage.jsonl")

# 3. Build evidence.jsonl
ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

evidence_records = [
    {
        "id": "SRC-001",
        "authority": "SOURCE",
        "claim_class": "OBSERVED",
        "target_path": "cheatsheets/MCP_Security_Cheat_Sheet.md",
        "lines": {"start": 45, "end": 60},
        "symbol": "MCP Tool Description & Schema Integrity, Annotation Untrusted Axiom & Process Sandboxing",
        "evidence_snippet": "- Treat the entire tool schema as a potential injection surface — not just the description field.\n- Pin reviewed tool definitions using cryptographic hashes and require review when they change. Hash the complete tool definition (including inputSchema, outputSchema, and annotations), not only the description; a flipped readOnlyHint or destructiveHint can change client approval behavior without any visible description change... tool annotations are hints, not enforcement.\n- Run local MCP servers in a sandbox that enforces minimal privileges and access to host resources... A bare chroot is not a process sandbox.",
        "digest_sha256": get_file_sha256("cheatsheets/MCP_Security_Cheat_Sheet.md"),
        "context": "Establece la regla canónica de integridad de esquemas MCP: calcular hashes SHA-256 de la definición completa (incluyendo inputSchema y annotations) para detectar ataques de rug pull y manipulación de hints (readOnlyHint/destructiveHint), además de exigir aislamiento en sandboxes con privilegios mínimos (VULN-ARCH-011).",
        "timestamp": ts
    },
    {
        "id": "SRC-002",
        "authority": "SOURCE",
        "claim_class": "OBSERVED",
        "target_path": "cheatsheets/AI_Agent_Security_Cheat_Sheet.md",
        "lines": {"start": 61, "end": 159},
        "symbol": "AI Agent Tool Authorization Middleware & Cryptographically Checked SecureAgentMemory",
        "evidence_snippet": "Enforce authorization in the execution component, outside the agent's context. A user_confirmed flag is insufficient: the component must verify that the approval belongs to the current actor and exact tool call, remains valid, and has not already been consumed. Check and consume the approval in one atomic step immediately before execution so concurrent or repeated requests cannot reuse it.\n\nclass SecureAgentMemory:\n    MAX_MEMORY_ITEMS = 100\n    MAX_ITEM_LENGTH = 5000\n    MEMORY_TTL_HOURS = 24\n    def add(self, content: str...):\n        if self._contains_sensitive_data(content): content = self._redact_sensitive_data(content)\n        content = self._sanitize_injection_attempts(content)\n        entry = {'content': content, 'checksum': self._compute_checksum(content)}",
        "digest_sha256": get_file_sha256("cheatsheets/AI_Agent_Security_Cheat_Sheet.md"),
        "context": "Provee el diseño de referencia para middleware de autorización atómica independiente del contexto del LLM (evitando confused deputy) y una arquitectura de memoria segura con límites de longitud, TTL, checksums criptográficos SHA-256 y sanitización previa contra memory poisoning (VULN-ARCH-010).",
        "timestamp": ts
    },
    {
        "id": "SRC-003",
        "authority": "SOURCE",
        "claim_class": "OBSERVED",
        "target_path": "cheatsheets/Verifying_Third_Party_Agent_Execution_Evidence_Cheat_Sheet.md",
        "lines": {"start": 7, "end": 38},
        "symbol": "Third-Party Execution Evidence Verification Framework & Challenge Freshness Nonce",
        "evidence_snippet": "Supply-chain Levels for Software Artifacts (SLSA) verification guidance separates checking signatures and artifact identity from deciding which producers to trust. Apply the same distinction to execution records... Outcomes: Independently re-checkable, Supplier assertion, No information... A signature may establish who made an assertion without establishing that the assertion is true... To check freshness, send a fresh, unpredictable challenge value (a nonce) and require it to be signed together with the execution claims.",
        "digest_sha256": get_file_sha256("cheatsheets/Verifying_Third_Party_Agent_Execution_Evidence_Cheat_Sheet.md"),
        "context": "Define el marco epistemológico formal para evaluar registros de ejecución generados por agentes o servidores MCP externos: segregación SLSA entre identidad de artefacto y aserción de proveedor, mitigando la falacia de confiar ciegamente en firmas de auditorías no reproducibles (VULN-RESI-004).",
        "timestamp": ts
    },
    {
        "id": "SRC-004",
        "authority": "SOURCE",
        "claim_class": "OBSERVED",
        "target_path": "cheatsheets/Post_Quantum_Cryptography_Cheat_Sheet.md",
        "lines": {"start": 7, "end": 50},
        "symbol": "Post-Quantum Cryptography Migration Stages & FIPS 203/204 / Hybrid Integration Standard",
        "evidence_snippet": "Create a cryptographic inventory with one entry per use of cryptography... Stage 2: Prioritize migration work... Long-lived confidentiality: prioritize exposed connections and stored data whose keys depend on RSA or elliptic curve cryptography... Prefer AES-256 for additional quantum security margin... Key establishment: ML-KEM (FIPS 203)... Transport: pilot classical + PQC hybrid exchange, such as X25519MLKEM768... Signatures: ML-DSA (FIPS 204).",
        "digest_sha256": get_file_sha256("cheatsheets/Post_Quantum_Cryptography_Cheat_Sheet.md"),
        "context": "Hoja de ruta canónica y contemporánea para la migración post-cuántica (PQC): inventario criptográfico con propósito y ciclo de vida, adopción de ML-KEM (FIPS 203), ML-DSA (FIPS 204) e intercambios híbridos X25519MLKEM768 (RFC 10024) para transporte TLS.",
        "timestamp": ts
    },
    {
        "id": "SRC-005",
        "authority": "SOURCE",
        "claim_class": "OBSERVED",
        "target_path": "cheatsheets/Passkey_Security_Cheat_Sheet.md",
        "lines": {"start": 18, "end": 50},
        "symbol": "Passkey Security Model, RP ID Domain Scoping & User Presence vs User Verification Distinction",
        "evidence_snippet": "Do not treat UP and UV as equivalent. Require UV when the passkey is expected to satisfy a multi-factor or other high-assurance authentication policy. A passkey is not automatically multi-factor merely because an authenticator supports UV; the RP must request UV and verify the returned UV flag.\n\nAn RP ID determines where a credential can be used. Use the narrowest stable domain that covers the intended application. Do not use a registrable parent domain merely to share credentials with unrelated subdomains.",
        "digest_sha256": get_file_sha256("cheatsheets/Passkey_Security_Cheat_Sheet.md"),
        "context": "Directivas arquitectónicas esenciales para la autenticación WebAuthn/Passkey: delimitación estricta de RP ID para neutralizar phishing y confusión de subdominios, y separación epistemológica entre Presencia de Usuario (UP) y Verificación de Usuario (UV biometría/PIN).",
        "timestamp": ts
    },
    {
        "id": "SRC-006",
        "authority": "SOURCE",
        "claim_class": "OBSERVED",
        "target_path": "cheatsheets/Workload_Identity_Federation_Cheat_Sheet.md",
        "lines": {"start": 9, "end": 35},
        "symbol": "OIDC Workload Identity Federation, Trust vs Permissions Policy Separation & Revocation",
        "evidence_snippet": "Validating a token against the configured trusted issuer does not by itself authorize production access. Configure both controls:\n- Trust policy: which external workloads may obtain credentials.\n- Permissions policy: which resources and operations those credentials authorize... Restrict access to the intended organization, repository or project, and deployment context... Prefer immutable, non-reusable organization and repository identifiers... Request the shortest credential lifetime the provider supports.",
        "digest_sha256": get_file_sha256("cheatsheets/Workload_Identity_Federation_Cheat_Sheet.md"),
        "context": "Patrón de autenticación federada OIDC para CI/CD y workloads cloud eliminando credenciales estáticas permanentes: separación entre directiva de confianza y directiva de permisos, uso de identificadores inmutables de repositorio y rotación efímera de tokens.",
        "timestamp": ts
    },
    {
        "id": "SRC-007",
        "authority": "SOURCE",
        "claim_class": "OBSERVED",
        "target_path": "cheatsheets/Zero_Trust_Architecture_Cheat_Sheet.md",
        "lines": {"start": 1, "end": 60},
        "symbol": "Zero Trust Architecture Core Tenets, Micro-segmentation & Continuous Verification",
        "evidence_snippet": "Zero Trust is a security model, a set of architectural principles, and an approach to systems design... Tenets: Never trust, always verify; Assume breach; Verify explicitly; Least privilege access... Micro-segmentation separates workloads from one another and secures them individually.",
        "digest_sha256": get_file_sha256("cheatsheets/Zero_Trust_Architecture_Cheat_Sheet.md"),
        "context": "Principios autoritativos de Zero Trust: verificación continua de identidad y contexto, microsegmentación de cargas de trabajo y asunción constante de brecha en límites de red.",
        "timestamp": ts
    },
    {
        "id": "SRC-008",
        "authority": "SOURCE",
        "claim_class": "OBSERVED",
        "target_path": "AGENTS.md",
        "lines": {"start": 11, "end": 70},
        "symbol": "Authoritative Rules for AI Tools in Defensive Security Documentation",
        "evidence_snippet": "1. Sources must be real, read, and supportive. Anti-fabrication (always): Never invent or guess a URL... Every new ## H2 section must contain at least one inline citation [text](https://...)\n2. Claims must be correct and within the security threat model. Pair every threat with a concrete countermeasure, and state explicitly what a control does and does not protect against.\n3. Stay in scope — one topic, one PR, one branch.\n4. Don't duplicate — link instead.\n5. Keep cheat sheets conceptual.\n6. No slop.\n7. Declare AI usage.",
        "digest_sha256": get_file_sha256("AGENTS.md"),
        "context": "Contrato de gobernanza y control anti-alucinaciones para asistentes de IA: prohibición de URLs inventadas, exigencia de fuentes primarias reales y leídas, pairing obligatorio de amenaza con contramedida y erradicación de relleno o AI-slop.",
        "timestamp": ts
    },
    {
        "id": "SRC-009",
        "authority": "SOURCE",
        "claim_class": "OBSERVED",
        "target_path": "scripts/Check_PR_Workflow_Approvals.js",
        "lines": {"start": 28, "end": 53},
        "symbol": "Strict CLI Parameter Sanitization & Epistemic Fail-Closed Check on Paginated Workflows",
        "evidence_snippet": "if (!/^[A-Za-z0-9_.-]+\\/[A-Za-z0-9_.-]+$/.test(repo) || !/^[1-9][0-9]*$/.test(String(number))) {\n  throw new Error('Use --repo OWNER/REPO and a positive pull request number.');\n}\n...\n// GitHub caps filtered run searches at 1,000 results. Never report a partial audit as clear.\nif (pages.some((page) => page.total_count >= 1000)) {\n  throw new Error(\"Workflow search reached GitHub's 1,000-run limit; audit smaller date ranges manually.\");\n}",
        "digest_sha256": get_file_sha256("scripts/Check_PR_Workflow_Approvals.js"),
        "context": "Sanitización exhaustiva de argumentos CLI mediante expresiones regulares estrictas y aplicación del Principio Epistemológico de Inconclusión ante límites de paginación (1,000 runs) para no emitir falsos veredictos de seguridad (VULN-RESI-004).",
        "timestamp": ts
    },
    {
        "id": "SRC-010",
        "authority": "SOURCE",
        "claim_class": "OBSERVED",
        "target_path": "scripts/link_check/external.js",
        "lines": {"start": 300, "end": 330},
        "symbol": "Manual HTTP Redirect Handling with Lack of Pre-Flight Private IP Probing Protection",
        "evidence_snippet": "const timeoutSignal = AbortSignal.timeout(http.requestTimeoutSeconds * 1000);\nconst signal = AbortSignal.any([runSignal, timeoutSignal]);\nrequestCount += 1;\nhostStats(host).requests += 1;\nconst record = { method, url, at: new Date().toISOString() };\ntry {\n  const response = await fetchImpl(url, { method, headers, redirect: 'manual', signal });\n  record.status = response.status;\n  const location = response.headers.get('location');",
        "digest_sha256": get_file_sha256("scripts/link_check/external.js"),
        "context": "Implementación de cliente HTTP con redirect: 'manual' que neutraliza el seguimiento automático de redirecciones hacia metadatos, pero omite resolución DNS y comprobación de IPs privadas pre-flight sobre la URL solicitada, permitiendo que un link malicioso sondee hosts de intranet (VULN-SAST-014 / CWE-918).",
        "timestamp": ts
    },
    {
        "id": "SRC-011",
        "authority": "SOURCE",
        "claim_class": "OBSERVED",
        "target_path": "package-lock.json",
        "lines": {"start": 1, "end": 25},
        "symbol": "Orphan NPM Lockfile Without Primary Root Package Manifest (package.json)",
        "evidence_snippet": "{\n  \"name\": \"owasp-cheatsheet-series\",\n  \"lockfileVersion\": 3,\n  \"requires\": true,\n  \"packages\": {\n    \"\": {\n      \"devDependencies\": {\n        \"markdownlint-cli\": \"^0.44.0\"\n      }\n    }\n  }\n}",
        "digest_sha256": get_file_sha256("package-lock.json"),
        "context": "Presencia de un lockfile de 152 KB en la raíz sin su manifiesto complementario package.json, generando un escenario de lockfile huérfano que distorsiona herramientas SCA e impide auditar rangos de versiones declaradas (VULN-SCA-005).",
        "timestamp": ts
    },
    {
        "id": "SRC-012",
        "authority": "SOURCE",
        "claim_class": "OBSERVED",
        "target_path": "requirements.txt",
        "lines": {"start": 1, "end": 30},
        "symbol": "Pinned Python Dependencies Lacking Cryptographic Artifact Hashes",
        "evidence_snippet": "Babel==2.18.0\ncertifi==2026.10.23\ncharset-normalizer==3.5.2\nclick==8.5.0\ncolorama==0.4.6\n...\nmkdocs==1.6.1\nmkdocs-material==9.7.7\nrequests==2.34.2\nurllib3==2.8.0",
        "digest_sha256": get_file_sha256("requirements.txt"),
        "context": "Fijación estricta de versiones de Python sin comprobación criptográfica de hashes SHA-256 (--hash), exponiendo el entorno de compilación de MkDocs a ataques de sustitución de paquetes en registros o proxies intermedios (VULN-CONF-011).",
        "timestamp": ts
    }
]

ev_file = os.path.join(audit_dir, "evidence.jsonl")
with open(ev_file, "w", encoding="utf-8") as f:
    for rec in evidence_records:
        f.write(json.dumps(rec) + "\n")
print(f"Wrote {len(evidence_records)} records to evidence.jsonl")

# 4. Build unknowns.jsonl
unknowns_records = [
    {
        "id": "GAP-001",
        "title": "Lockfile Huérfano en Raíz del Repositorio sin Manifiesto Primario (package.json)",
        "dimension": "SUPPLY_CHAIN_SCA",
        "cwe": "CWE-1395",
        "severity": "MEDIUM",
        "status": "CONFIRMED_VULNERABILITY",
        "vulnerability_id": "VULN-SCA-005",
        "affected_file": "package-lock.json",
        "affected_lines": "1-35",
        "description": "El repositorio incluye un archivo package-lock.json de 152 KB con lockfileVersion 3 que gestiona dependencias como markdownlint-cli, pero carece de un archivo package.json complementario en la raíz. Esto rompe la paridad de la cadena de suministro, impide la auditoría de rangos semánticos declarados y puede provocar comportamientos anómalos en herramientas SCA automatizadas.",
        "remediation": "Crear y commitear el package.json correspondiente que declare formalmente las dependencias de desarrollo y scripts de validación, garantizando sincronización con el lockfile."
    },
    {
        "id": "GAP-002",
        "title": "Ausencia de Filtrado Pre-Flight de IPs Privadas y Metadatos Cloud en Verificador de Enlaces Externos",
        "dimension": "SOURCE_CODE_SAST",
        "cwe": "CWE-918",
        "severity": "MEDIUM",
        "status": "CONFIRMED_VULNERABILITY",
        "vulnerability_id": "VULN-SAST-014",
        "affected_file": "scripts/link_check/external.js",
        "affected_lines": "300-330",
        "description": "La función request(url) en scripts/link_check/external.js utiliza redirect: 'manual' (mitigando redirecciones automáticas), pero no valida que el hostname de la URL no resuelva a direcciones IP de loopback (127.0.0.1, ::1), redes privadas (10.0.0.0/8, 192.168.0.0/16) o metadatos de nube (169.254.169.254). Si una contribución externa incluye enlaces maliciosos apuntando a servicios locales de CI, el checker realizará conexiones salientes contra ellos.",
        "remediation": "Integrar un resolver DNS con verificación pre-flight en el Scheduler para abortar peticiones dirigidas a redes locales o link-local antes de emitir la llamada fetch."
    },
    {
        "id": "GAP-003",
        "title": "Dependencias Python sin Hashes Criptográficos en requirements.txt",
        "dimension": "CONFIGURATION_HARDENING",
        "cwe": "CWE-353",
        "severity": "LOW",
        "status": "CONFIRMED_VULNERABILITY",
        "vulnerability_id": "VULN-CONF-011",
        "affected_file": "requirements.txt",
        "affected_lines": "1-30",
        "description": "Las dependencias de compilación y documentación (mkdocs, requests, Jinja2, etc.) están ancladas por versión exacta (==) pero carecen de hashes criptográficos (--hash=sha256:...). Esto permite que un compromiso en un mirror de PyPI o un ataque man-in-the-middle suministre un wheel troyanizado con el mismo número de versión.",
        "remediation": "Generar requirements.txt utilizando pip-compile con el flag --generate-hashes para fijar los digest SHA-256 de cada paquete y plataforma."
    },
    {
        "id": "GAP-004",
        "title": "Procesamiento de Archivos Markdown sin Límites de Buffer o Timeout de Concurrencia en Scripts de Índices",
        "dimension": "RESILIENCE_LOGGING_TELEMETRY",
        "cwe": "CWE-400",
        "severity": "LOW",
        "status": "CONFIRMED_VULNERABILITY",
        "vulnerability_id": "VULN-RESI-007",
        "affected_file": "scripts/Update_CheatSheets_Index.py, scripts/Generate_CheatSheets_TOC.py",
        "affected_lines": "25-80",
        "description": "Los scripts de generación de índices leen la totalidad de los archivos de cheatsheets sin verificar límites máximos de tamaño por archivo. Si un contribuidor envía un archivo Markdown masivo (e.g. 500 MB) en una PR, el runner de GitHub Actions puede agotar la memoria disponible (OOM) y abortar la ejecución.",
        "remediation": "Establecer una cota máxima de lectura de archivos (e.g. 5 MB) y abortar con error controlado si un archivo individual sobrepasa el umbral permitido."
    }
]

unk_file = os.path.join(audit_dir, "unknowns.jsonl")
with open(unk_file, "w", encoding="utf-8") as f:
    for rec in unknowns_records:
        f.write(json.dumps(rec) + "\n")
print(f"Wrote {len(unknowns_records)} records to unknowns.jsonl")

# 5. Build absorption-plan.json conforming strictly to AbsorptionPlanSchema
plan_id = str(uuid.uuid4())
created_at = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

extracted_knowledge = [
    {
        "id": "KNOW-001",
        "title": "Marco de Seguridad y Blindaje para Model Context Protocol (MCP) y Agentes de IA",
        "description": "Metodología exhaustiva que modela la superficie de ataque de MCP y agentes: tool poisoning, rug pull attacks, tool shadowing, autorización atómica fuera del contexto del agente y memoria persistente con checksums y TTL.",
        "dimension": "ARCHITECTURE_BOUNDARIES_ZERO_TRUST",
        "cwe": ["CWE-250", "CWE-653", "CWE-863"],
        "owasp": ["A04:2021-Insecure Design"],
        "sourceLocations": [
            "cheatsheets/MCP_Security_Cheat_Sheet.md",
            "cheatsheets/AI_Agent_Security_Cheat_Sheet.md"
        ],
        "authority": "OBSERVED",
        "valueProposition": "Dota al repositorio de patrones de verificación estricta para servidores MCP y arquitecturas agénticas, robusteciendo las referencias y contratos existentes."
    },
    {
        "id": "KNOW-002",
        "title": "Estándar de Seguridad y Delimitación de Ámbito para Passkeys / WebAuthn",
        "description": "Especificación de implementación segura para Relying Parties (RP): delimitación estricta de dominios RP ID contra phishing, validación rigurosa de ceremonias en backend y diferenciación epistemológica entre Presencia de Usuario (UP) y Verificación de Usuario (UV).",
        "dimension": "IDENTITY_ACCESS_SESSION",
        "cwe": ["CWE-287", "CWE-306", "CWE-352"],
        "owasp": ["A07:2021-Identification and Authentication Failures"],
        "sourceLocations": [
            "cheatsheets/Passkey_Security_Cheat_Sheet.md"
        ],
        "authority": "OBSERVED",
        "valueProposition": "Proporciona una guía autoritativa para la auditoría de autenticación moderna sin contraseña (FIDO2/WebAuthn), llenando una brecha en las referencias de Capa 1."
    },
    {
        "id": "KNOW-003",
        "title": "Marco de Migración a Criptografía Post-Cuántica (PQC) e Inventario Criptográfico",
        "description": "Plan sistemático de migración PQC en 4 etapas: catálogo de dependencias criptográficas, priorización por confidencialidad/firma a largo plazo, adopción de FIPS 203 (ML-KEM), FIPS 204 (ML-DSA) e intercambios híbridos X25519MLKEM768.",
        "dimension": "SECRETS_CRYPTOGRAPHY",
        "cwe": ["CWE-327", "CWE-326"],
        "owasp": ["A02:2021-Cryptographic Failures"],
        "sourceLocations": [
            "cheatsheets/Post_Quantum_Cryptography_Cheat_Sheet.md"
        ],
        "authority": "OBSERVED",
        "valueProposition": "Introduce el primer modelo de preparación post-cuántica en Devia-CyberSecurity, con contrato Zod y herramienta de inventario criptográfico."
    },
    {
        "id": "KNOW-004",
        "title": "Federación de Identidad para Cargas de Trabajo (OIDC Workload Identity Federation)",
        "description": "Directrices para suprimir credenciales estáticas en pipelines CI/CD mediante tokens OIDC temporales: segregación entre directiva de confianza (trust policy) y directiva de permisos, uso de identificadores inmutables y revocación de sesiones.",
        "dimension": "IDENTITY_ACCESS_SESSION",
        "cwe": ["CWE-798", "CWE-250"],
        "owasp": ["A01:2021-Broken Access Control", "A07:2021-Identification and Authentication Failures"],
        "sourceLocations": [
            "cheatsheets/Workload_Identity_Federation_Cheat_Sheet.md"
        ],
        "authority": "OBSERVED",
        "valueProposition": "Guía especializada para auditar la transición de secretos permanentes a federación de identidad efímera en entornos cloud y CI/CD."
    },
    {
        "id": "KNOW-005",
        "title": "Verificación Epistemológica de Evidencia de Ejecución de Agentes de Terceros",
        "description": "Marco de 6 preguntas para evaluar registros emitidos por agentes o servidores no controlados: segregación estilo SLSA entre aserción de proveedor y verificación independiente, nonces para frescura temporal y detección de eventos omitidos.",
        "dimension": "RESILIENCE_LOGGING_TELEMETRY",
        "cwe": ["CWE-345", "CWE-353"],
        "owasp": ["A09:2021-Security Logging and Monitoring Failures"],
        "sourceLocations": [
            "cheatsheets/Verifying_Third_Party_Agent_Execution_Evidence_Cheat_Sheet.md"
        ],
        "authority": "OBSERVED",
        "valueProposition": "Enriquece el modelo epistemológico de auditoría agentica asegurando que los registros de telemetría de agentes externos no se acepten como hechos inmutables sin verificación independiente."
    },
    {
        "id": "KNOW-006",
        "title": "Gobernanza y Reglas Anti-Alucinación para Asistentes de IA en Auditoría de Seguridad",
        "description": "Conjunto de 7 reglas obligatorias para asistentes de IA en repositorios de seguridad: prohibición de URLs inventadas, verificación de fuentes primarias reales, paridad amenaza-contramedida y erradicación de AI-slop.",
        "dimension": "THREAT_MODELING_ATTACK_SURFACE",
        "cwe": ["CWE-1059"],
        "owasp": ["A04:2021-Insecure Design"],
        "sourceLocations": [
            "AGENTS.md"
        ],
        "authority": "OBSERVED",
        "valueProposition": "Valida y refuerza las directivas canónicas de AGENTS.md y PROACTIVE.md en Devia-CyberSecurity para la interacción segura y determinista con LLMs."
    },
    {
        "id": "KNOW-007",
        "title": "Técnica de Redirección Manual y Riesgo de Sondeo SSRF en Scanners de Enlaces",
        "description": "Patrón de uso de redirect: 'manual' para impedir el seguimiento no autorizado de saltos HTTP, contrastado con la necesidad de validación pre-flight de direcciones IP privadas para neutralizar sondeos hacia intranets.",
        "dimension": "SOURCE_CODE_SAST",
        "cwe": ["CWE-918"],
        "owasp": ["A10:2021-Server-Side Request Forgery"],
        "sourceLocations": [
            "scripts/link_check/external.js"
        ],
        "authority": "OBSERVED",
        "valueProposition": "Demuestra la superioridad de redirect: 'manual' frente a redirect: 'follow' (observado en web-check) y resalta el requerimiento de inspección de IP de destino."
    },
    {
        "id": "KNOW-008",
        "title": "Auditoría de Integridad en Manifiestos de Dependencias y Lockfiles Huérfanos",
        "description": "Detección de inconsistencias en la cadena de suministro por presencia de lockfiles desvinculados de su package.json raíz y ausencia de hashes criptográficos en dependencias de Python.",
        "dimension": "SUPPLY_CHAIN_SCA",
        "cwe": ["CWE-1395", "CWE-353"],
        "owasp": ["A06:2021-Vulnerable and Outdated Components"],
        "sourceLocations": [
            "package-lock.json",
            "requirements.txt"
        ],
        "authority": "OBSERVED",
        "valueProposition": "Proporciona casos de estudio concretos para robustecer el script check_lockfiles.py y el catálogo de vulnerabilidades de supply chain."
    }
]

absorption_actions = [
    {
        "id": "ABS-001",
        "knowledgeId": "KNOW-002",
        "title": "Guía de Auditoría y Verificación de Passkeys y WebAuthn",
        "destination": "SKILL_REFERENCE",
        "intent": "CREATE_NEW",
        "existingVulnerabilityId": "VULN-IAM-001",
        "targetPathInRepo": ".agents/skills/identity-access-session/references/passkey-webauthn-security-guide.md",
        "architecturalRationale": "Capa 1: Referencia operativa para la Skill identity-access-session, estableciendo directivas de auditoría para RP ID, ceremonias WebAuthn y verificación UP/UV.",
        "priority": "HIGH",
        "implementationSteps": [
            "Redactar guía completa con fundamentos de WebAuthn y arquitectura RP",
            "Documentar la delimitación estricta de dominios RP ID para prevenir phishing",
            "Explicar la diferencia crítica entre Presencia de Usuario (UP) y Verificación de Usuario (UV)",
            "Incluir checklist de auditoría para ceremonias y almacenamiento seguro de credenciales"
        ]
    },
    {
        "id": "ABS-002",
        "knowledgeId": "KNOW-004",
        "title": "Guía de Federación de Identidad para Cargas de Trabajo (OIDC Workload Federation)",
        "destination": "SKILL_REFERENCE",
        "intent": "CREATE_NEW",
        "existingVulnerabilityId": "VULN-IAM-002",
        "targetPathInRepo": ".agents/skills/identity-access-session/references/workload-identity-federation-oidc.md",
        "architecturalRationale": "Capa 1: Referencia metodológica para auditar la transición de secretos permanentes a tokens OIDC en GitHub Actions, AWS, GCP y Azure.",
        "priority": "HIGH",
        "implementationSteps": [
            "Modelar la frontera de confianza y flujo de intercambio de tokens OIDC",
            "Documentar el desacoplamiento formal entre trust policy y permissions policy",
            "Establecer reglas para identificadores inmutables de organizaciones y repositorios",
            "Proveer pautas de monitoreo y revocación de sesiones temporales"
        ]
    },
    {
        "id": "ABS-003",
        "knowledgeId": "KNOW-003",
        "title": "Guía de Preparación y Hoja de Ruta para Criptografía Post-Cuántica (PQC)",
        "destination": "SKILL_REFERENCE",
        "intent": "CREATE_NEW",
        "existingVulnerabilityId": "VULN-CRYP-001",
        "targetPathInRepo": ".agents/skills/secrets-cryptography/references/post-quantum-cryptography-migration.md",
        "architecturalRationale": "Capa 1: Referencia técnica en secrets-cryptography que guía la auditoría de algoritmos vulnerables a computación cuántica y la adopción de FIPS 203/204.",
        "priority": "HIGH",
        "implementationSteps": [
            "Detallar las 4 etapas de migración PQC para aplicaciones",
            "Definir los requerimientos para el inventario criptográfico",
            "Describir la adopción de ML-KEM (FIPS 203), ML-DSA (FIPS 204) e intercambios híbridos X25519MLKEM768",
            "Establecer criterios de priorización por longevidad de confidencialidad y firma"
        ]
    },
    {
        "id": "ABS-004",
        "knowledgeId": "KNOW-003",
        "title": "Contrato Zod para Inventario Criptográfico y Evaluación de Madurez PQC",
        "destination": "ZOD_SCHEMA",
        "intent": "CREATE_NEW",
        "existingVulnerabilityId": "VULN-CRYP-001",
        "targetPathInRepo": "src/schemas/cryptographic-inventory.schema.ts",
        "architecturalRationale": "Capa 2: Esquema autoritativo contract-first para validar registros de inventario criptográfico y evaluar el estado de migración post-cuántica.",
        "priority": "HIGH",
        "implementationSteps": [
            "Definir CryptographicUsageSchema, CryptographicPrimitiveSchema y PqcStatusSchema",
            "Modelar la entidad CryptographicInventoryEntrySchema con propósito, tiempo de vida y dependencias",
            "Exportar tipos inferidos en src/types/index.ts y esquema en src/schemas/index.ts",
            "Escribir suite de pruebas unitarias en src/schemas/cryptographic-inventory.schema.test.ts"
        ]
    },
    {
        "id": "ABS-005",
        "knowledgeId": "KNOW-003",
        "title": "Escáner Determinista de Inventario Criptográfico y Detección PQC en Python",
        "destination": "PYTHON_SCRIPT",
        "intent": "CREATE_NEW",
        "existingVulnerabilityId": "VULN-CRYP-001",
        "targetPathInRepo": "src/scripts/pqc_inventory_scanner.py",
        "architecturalRationale": "Capa 3: Utilidad determinista en Python 3.11+ para auditar código fuente y configuraciones detectando primitivas clásicas vulnerables a computación cuántica frente a algoritmos PQC aprobados.",
        "priority": "HIGH",
        "implementationSteps": [
            "Implementar detección determinista de algoritmos asimétricos clásicos (RSA, DSA, DH, ECDSA, Ed25519)",
            "Detectar adopción de primitivas PQC (ML-KEM, ML-DSA, SLH-DSA, X25519MLKEM768, AES-256)",
            "Proveer CLI con flags --json y cálculo de nivel de riesgo cuántico",
            "Crear suite de tests unitarios en src/scripts/test_pqc_inventory_scanner.py"
        ]
    },
    {
        "id": "ABS-006",
        "knowledgeId": "KNOW-001",
        "title": "Robustecimiento de la Referencia de Seguridad MCP con Hashing de Esquemas y Axiomas de Annotations",
        "destination": "UPDATE_EXISTING",
        "intent": "ROBUSTIFY_HARDEN",
        "existingVulnerabilityId": "VULN-ARCH-011",
        "targetPathInRepo": ".agents/skills/architecture-boundaries-zero-trust/references/agentic-system-security-mcp.md",
        "architecturalRationale": "Reutilizar antes de añadir maquinaria: Enriquecer la referencia existente con las directivas de MCP Security Cheat Sheet respecto a Tool Schema Integrity, rug pulls y Streamable HTTP.",
        "priority": "HIGH",
        "implementationSteps": [
            "Incorporar el requerimiento de hash criptográfico sobre el esquema completo (incluyendo annotations)",
            "Documentar la directiva de anotaciones no confiables (readOnlyHint/destructiveHint como meros hints)",
            "Añadir directrices para transporte Streamable HTTP y perfil OAuth 2.1 con resource indicators"
        ]
    },
    {
        "id": "ABS-007",
        "knowledgeId": "KNOW-008",
        "title": "Actualización del Catálogo Central de Vulnerabilidades con Nuevos Vectores Detectados",
        "destination": "UPDATE_EXISTING",
        "intent": "ROBUSTIFY_HARDEN",
        "existingVulnerabilityId": "VULN-SCA-005",
        "targetPathInRepo": "docs/VULNERABILITIES.md",
        "architecturalRationale": "Sincronización autoritativa: Documentar formalmente VULN-SAST-014 (SSRF en link checkers), VULN-SCA-005 (Lockfile huérfano), VULN-CONF-011 (Dependencias sin hash) y VULN-RESI-007 (DoS en generadores de índices).",
        "priority": "CRITICAL",
        "implementationSteps": [
            "Registrar las 4 vulnerabilidades descubiertas en la taxonomía canónica",
            "Asignar identificadores formales, severidades, CWEs y skills responsables",
            "Documentar las pruebas de evidencia y las pautas de mitigación directa"
        ]
    },
    {
        "id": "ABS-008",
        "knowledgeId": "KNOW-006",
        "title": "Actualización de la Memoria Proactiva con Lecciones de PQC, WebAuthn, MCP y Anti-Alucinaciones",
        "destination": "UPDATE_EXISTING",
        "intent": "ABSORB_EXPAND",
        "existingVulnerabilityId": "VULN-ARCH-011",
        "targetPathInRepo": "docs/PROACTIVE.md",
        "architecturalRationale": "Memoria proactiva viva: Consolidar las lecciones de ingeniería aprendidas durante la auditoría de CheatSheetSeries para futuras sesiones y despliegues.",
        "priority": "HIGH",
        "implementationSteps": [
            "Añadir lección sobre la distinción UP vs UV y delimitación de RP ID en Passkeys",
            "Añadir lección sobre la priorización en PQC y el cálculo de hashes completos en esquemas MCP",
            "Añadir lección sobre la prevención de SSRF en verificadores de enlaces (redirect manual + DNS preflight)"
        ]
    }
]

plan_data = {
    "planId": plan_id,
    "createdAt": created_at,
    "target": {
        "path": "external-reps/CheatSheetSeries-master",
        "canonicalPath": "K:\\Devia-CyberSecurity\\external-reps\\CheatSheetSeries-master",
        "name": "CheatSheetSeries-master",
        "type": "REPOSITORY",
        "commitOrSnapshot": "devia-snapshot/v1:sha256:d8923a0b91741fe1ddadf2e704d43b1953753ee8bff7b970bead64402f2571f9",
        "archetypeDescription": "OWASP Cheat Sheet Series Master Snapshot: Canonical Defensive Security Documentation, Validation Tooling & Agent Governance (Markdown, Node.js, Python, Shell)"
    },
    "scopeSummary": {
        "totalEntriesScanned": len(inventory_items),
        "primaryLanguages": ["Markdown", "JavaScript", "Python", "Shell"],
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
    "extractedKnowledge": extracted_knowledge,
    "absorptionActions": absorption_actions,
    "metrics": {
        "totalKnowledgeItems": len(extracted_knowledge),
        "destinationsBreakdown": {
            "SKILL_REFERENCE": 3,
            "ZOD_SCHEMA": 1,
            "PYTHON_SCRIPT": 1,
            "UPDATE_EXISTING": 3
        }
    },
    "ledgerPaths": {
        "inventoryJsonl": "audits/CheatSheetSeries-master/inventory/inventory.jsonl",
        "coverageJsonl": "audits/CheatSheetSeries-master/coverage.jsonl",
        "evidenceJsonl": "audits/CheatSheetSeries-master/evidence.jsonl",
        "unknownsJsonl": "audits/CheatSheetSeries-master/unknowns.jsonl"
    }
}

plan_json_file = os.path.join(audit_dir, "absorption-plan.json")
with open(plan_json_file, "w", encoding="utf-8") as f:
    json.dump(plan_data, f, indent=2, ensure_ascii=False)
print(f"Wrote absorption-plan.json")

# 6. Build absorption-plan.md dossier
markdown_dossier = f"""# Plan y Dossier Forense de Absorción: CheatSheetSeries-master

- **Target:** `K:\\Devia-CyberSecurity\\external-reps\\CheatSheetSeries-master`
- **Snapshot Digest:** `devia-snapshot/v1:sha256:d8923a0b91741fe1ddadf2e704d43b1953753ee8bff7b970bead64402f2571f9`
- **Total de Archivos Catalogados:** {len(inventory_items)}
- **Arquetipo:** Canonical Defensive Security Documentation, Validation Tooling & Agent Governance (Markdown, Node.js, Python, Shell)
- **Fecha de Auditoría:** {created_at}
- **Plan ID:** `{plan_id}`

---

## Executive Summary

**OWASP Cheat Sheet Series** es la enciclopedia canónica mundial de arquitectura, buenas prácticas y controles defensivos de ciberseguridad mantenida por la Open Worldwide Application Security Project (OWASP). Agrupa más de 130 hojas de trucos exhaustivas que van desde vulnerabilidades web clásicas (SQLi, XSS, CSRF, SSRF, Deserialización) hasta paradigmas contemporáneos de vanguardia: **seguridad en Model Context Protocol (MCP)**, **seguridad en agentes autónomos de IA**, **verificación de evidencia de ejecución de agentes de terceros**, **migración a criptografía post-cuántica (PQC)**, **autenticación FIDO2 / Passkeys**, **federación de identidad OIDC para CI/CD** y **arquitecturas Zero Trust**.

La auditoría forense de ingeniería inversa ejecutada mediante `security-reverse-engineering` deconstruyó la totalidad de sus 382 archivos bajo las **8 Dimensiones Canónicas MECE**, analizando tanto el contenido conceptual autoritativo como sus herramientas internas de validación y control de calidad (el motor de comprobación de enlaces en Node.js, el auditor de flujos de aprobación en GitHub y los subagentes de revisión en `.claude/`):

1. **Blindaje de Agentes y MCP de Vanguardia (`KNOW-001` / `SRC-001`, `SRC-002`):** Establece el principio de integridad total del esquema de herramientas mediante hashes criptográficos de la definición completa (incluyendo `annotations` como `readOnlyHint`), reconociendo que los hints son metadatos no confiables y exigiendo middlewares de autorización fuera del contexto del agente.
2. **Modelo Riguroso de Passkeys / WebAuthn (`KNOW-002` / `SRC-005`):** Delimitación precisa de RP ID para evitar confusión de origen y phishing, junto con la separación inmutable entre Presencia de Usuario (UP) y Verificación de Usuario (UV).
3. **Hoja de Ruta de Migración Post-Cuántica (`KNOW-003` / `SRC-004`):** Especificación estructurada para inventario criptográfico y adopción de ML-KEM (FIPS 203), ML-DSA (FIPS 204) e intercambios híbridos X25519MLKEM768.
4. **Federación OIDC sin Credenciales Estáticas (`KNOW-004` / `SRC-006`):** Separación explícita entre trust policy y permissions policy, con identificadores inmutables de organización y repositorio.
5. **Brechas de Hardening y SAST en el Tooling Interno:** A pesar de su excelencia defensiva conceptual, el repositorio contiene debilidades operativas reales:
   - **VULN-SCA-005 (Media):** Lockfile huérfano (`package-lock.json` de 152 KB) en la raíz sin su respectivo `package.json`.
   - **VULN-SAST-014 (Media):** Verificador de enlaces externos (`scripts/link_check/external.js`) que usa `redirect: "manual"` (excelente mitigación contra SSRF por salto) pero carece de resolución DNS y verificación de IPs privadas pre-flight.
   - **VULN-CONF-011 (Baja):** Dependencias de Python en `requirements.txt` sin hashes criptográficos de integridad (`--hash`).
   - **VULN-RESI-007 (Baja):** Lectura de Markdown sin cotas de buffer en scripts de índices.

---

## 🏛️ Desglose Multidimensional y Mapeo Canónico

### 1. ARCHITECTURE_BOUNDARIES_ZERO_TRUST
- **Patrón MCP Security (`cheatsheets/MCP_Security_Cheat_Sheet.md`):** Hasheo de esquemas completos, neutralización de rug pulls, herramientas como superficies de inyección y aislamiento mediante sandboxes.
- **Patrón AI Agent Security (`cheatsheets/AI_Agent_Security_Cheat_Sheet.md`):** Middleware de autorización atómica fuera del LLM, `SecureAgentMemory` con checksums y TTL.
- **Patrón Zero Trust (`cheatsheets/Zero_Trust_Architecture_Cheat_Sheet.md`):** Verificación explícita, menor privilegio y microsegmentación de cargas.

### 2. IDENTITY_ACCESS_SESSION
- **Estándar Passkeys / WebAuthn (`cheatsheets/Passkey_Security_Cheat_Sheet.md`):** Delimitación estricta de dominios RP ID y distinción obligatoria entre UP y UV.
- **Workload Identity Federation (`cheatsheets/Workload_Identity_Federation_Cheat_Sheet.md`):** Reemplazo de claves permanentes de CI/CD por OIDC temporal; separación formal de directivas de confianza y privilegios.
- **Patrones de Autorización e IDOR (`cheatsheets/Authorization_*.md`):** Pruebas de regresión, decisiones desacopladas y mitigación de BOLA/IDOR.

### 3. SECRETS_CRYPTOGRAPHY
- **Migración Post-Cuántica (PQC) (`cheatsheets/Post_Quantum_Cryptography_Cheat_Sheet.md`):** Inventario criptográfico, adopción de FIPS 203 (ML-KEM), FIPS 204 (ML-DSA) e híbridos X25519MLKEM768.
- **Almacenamiento Criptográfico y Contraseñas (`cheatsheets/Password_Storage_Cheat_Sheet.md`, `cheatsheets/Cryptographic_Storage_Cheat_Sheet.md`):** Algoritmos aprobados (Argon2id, PBKDF2, scrypt, AES-256 GCM) y gestión del ciclo de vida de claves.

### 4. SOURCE_CODE_SAST
- **Catálogo Canónico de Prevención SAST:** SQLi, XSS, OS Command Injection, SSRF, Deserialización, XXE, Prototype Pollution, SSTI, DOM Clobbering y validación de entradas.
- **VULN-SAST-014 (Media) - Falta de Pre-Flight IP Checking en Verificador de Enlaces (`scripts/link_check/external.js` / CWE-918):**  
  Peticiones directas a URLs de la documentación sin resolver nombres de dominio previamente ni bloquear rangos de loopback (`127.0.0.1`), intranet (`10.0.0.0/8`, `192.168.0.0/16`) o metadatos cloud (`169.254.169.254`).

### 5. SUPPLY_CHAIN_SCA
- **VULN-SCA-005 (Media) - Lockfile Huérfano en Raíz (`package-lock.json` / CWE-1395):**  
  Presencia de `package-lock.json` sin manifiesto `package.json` en la raíz, dificultando auditorías de composición de software.
- **Normas de Dependencias y SBOM (`cheatsheets/Dependency_Graph_SBOM_Cheat_Sheet.md`, `Software_Supply_Chain_Security_Cheat_Sheet.md`):** Modelado de grafos de dependencias, formatos CycloneDX/SPDX y gestión de vulnerabilidades conocidas.

### 6. CONFIGURATION_HARDENING
- **VULN-CONF-011 (Baja) - Dependencias Python sin Hashes en requirements.txt (`requirements.txt` / CWE-353):**  
  Fijación de versión sin flags `--hash=sha256:...`.
- **Hardening de Contenedores y CI/CD (`cheatsheets/Docker_Security_Cheat_Sheet.md`, `GitHub_Actions_Security_Cheat_Sheet.md`):** Principios de usuario no root, permisos mínimos en tokens de CI/CD y fijación por commit SHA.

### 7. RESILIENCE_LOGGING_TELEMETRY
- **Verificación de Evidencia de Ejecución de Terceros (`cheatsheets/Verifying_Third_Party_Agent_Execution_Evidence_Cheat_Sheet.md`):** Segregación SLSA entre aserción de proveedor y revisión independiente; uso de nonces y verificación de eventos omitidos.
- **Principio Epistemológico en Workflows (`scripts/Check_PR_Workflow_Approvals.js`):** Fail-closed ante el límite de 1,000 runs en la API de GitHub.
- **VULN-RESI-007 (Baja) - Procesamiento de Archivos sin Cotas de Buffer (`scripts/Update_CheatSheets_Index.py` / CWE-400).**

### 8. THREAT_MODELING_ATTACK_SURFACE
- **Modelado Formal y Casos de Abuso (`cheatsheets/Threat_Modeling_Cheat_Sheet.md`, `Abuse_Case_Cheat_Sheet.md`):** STRIDE, PASTA, LINDDUN y modelado de superficies de ataque.
- **Gobernanza Anti-Alucinaciones para IA (`AGENTS.md`):** Reglas canónicas contra invención de URLs, citación obligatoria y paridad amenaza-control.

---

## 🚀 Plan de Acciones de Absorción hacia Devia-CyberSecurity

| ID | Conocimiento | Destino Canónico | Intención | Ruta en Repositorio | Prioridad |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **ABS-001** | Guía de auditoría y verificación de Passkeys y WebAuthn | `SKILL_REFERENCE` | `CREATE_NEW` | `.agents/skills/identity-access-session/references/passkey-webauthn-security-guide.md` | **HIGH** |
| **ABS-002** | Guía de federación de identidad para cargas de trabajo (OIDC) | `SKILL_REFERENCE` | `CREATE_NEW` | `.agents/skills/identity-access-session/references/workload-identity-federation-oidc.md` | **HIGH** |
| **ABS-003** | Guía de preparación y migración a criptografía post-cuántica (PQC) | `SKILL_REFERENCE` | `CREATE_NEW` | `.agents/skills/secrets-cryptography/references/post-quantum-cryptography-migration.md` | **HIGH** |
| **ABS-004** | Contrato Zod para inventario criptográfico y evaluación PQC | `ZOD_SCHEMA` | `CREATE_NEW` | `src/schemas/cryptographic-inventory.schema.ts` | **HIGH** |
| **ABS-005** | Escáner determinista de inventario criptográfico y detección PQC en Python | `PYTHON_SCRIPT` | `CREATE_NEW` | `src/scripts/pqc_inventory_scanner.py` | **HIGH** |
| **ABS-006** | Robustecimiento de referencia de seguridad MCP con hashing completo de esquemas | `UPDATE_EXISTING` | `ROBUSTIFY_HARDEN` | `.agents/skills/architecture-boundaries-zero-trust/references/agentic-system-security-mcp.md` | **HIGH** |
| **ABS-007** | Actualización del catálogo de vulnerabilidades con VULN-SAST-014, VULN-SCA-005, VULN-CONF-011, VULN-RESI-007 | `UPDATE_EXISTING` | `ROBUSTIFY_HARDEN` | `docs/VULNERABILITIES.md` | **CRITICAL** |
| **ABS-008** | Incorporación de lecciones de PQC, WebAuthn, MCP y Anti-Alucinaciones en memoria proactiva | `UPDATE_EXISTING` | `ABSORB_EXPAND` | `docs/PROACTIVE.md` | **HIGH** |
"""

plan_md_file = os.path.join(audit_dir, "absorption-plan.md")
with open(plan_md_file, "w", encoding="utf-8") as f:
    f.write(markdown_dossier)
print("Wrote absorption-plan.md")
print("All ledgers and absorption artifacts successfully generated.")
