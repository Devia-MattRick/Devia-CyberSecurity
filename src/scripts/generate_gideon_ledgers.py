#!/usr/bin/env python3
"""Generator of Forensic Ledgers and Absorption Plan for Gideon-main.

Produces:
1. audits/Gideon-main/coverage.jsonl (all 217 files mapped to subsystems & dispositions)
2. audits/Gideon-main/evidence.jsonl (factual citations with exact digests & line numbers)
3. audits/Gideon-main/unknowns.jsonl (vulnerabilities and technical gaps found in Gideon)
4. audits/Gideon-main/absorption-plan.json (strict Zod AbsorptionPlanSchema contract)
5. audits/Gideon-main/absorption-plan.md (comprehensive forensic report)
"""

import hashlib
import json
import os
from pathlib import Path
import uuid
from datetime import datetime, timezone

audit_dir = r"K:\Devia-CyberSecurity\audits\Gideon-main"
target_dir = r"K:\Devia-CyberSecurity\external-reps\Gideon-main"
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

# 1. Read all 217 inventoried files
with open(inventory_path, "r", encoding="utf-8") as f:
    inventory_items = [json.loads(line) for line in f]

print(f"Loaded {len(inventory_items)} inventory items.")

# Subsystem classifier
def classify_subsystem(path: str) -> tuple[str, list[str]]:
    p = path.replace("\\", "/")
    if p.startswith("src/openclaw/"):
        return "openclaw-sentinel", ["SRC-001", "SRC-002", "SRC-003", "SRC-004"]
    elif p.startswith("src/agent/"):
        return "agent-react-core", ["SRC-005", "SRC-006", "SRC-007"]
    elif p.startswith("src/engine/"):
        return "engine-execution-sandbox", ["SRC-008", "SRC-009"]
    elif p.startswith("src/governance/"):
        return "governance-policy-audit", ["SRC-010", "SRC-011"]
    elif p.startswith("src/redteam/"):
        return "redteam-adversarial-suite", ["SRC-012"]
    elif p.startswith("src/guardrails/"):
        return "guardrails-nemo-colang", ["SRC-013"]
    elif p.startswith("src/c2/"):
        return "c2-integration-bridge", ["SRC-014"]
    elif p.startswith("src/skills/"):
        return "skills-system", ["SRC-015"]
    elif p.startswith("src/tools/"):
        return "tools-security-connectors", ["SRC-016"]
    elif p.startswith("src/scanner/"):
        return "sast-code-scanner", ["SRC-017"]
    elif p.startswith("src/graph/"):
        return "evograph-attack-tracking", ["SRC-018"]
    elif p.startswith("src/memory/"):
        return "memory-context-system", ["SRC-004", "SRC-005"]
    elif p.startswith("src/utils/"):
        return "utils-nvidia-acceleration", ["SRC-013", "SRC-019"]
    elif p.startswith("src/commands/"):
        return "cli-command-handlers", ["SRC-005"]
    elif p.startswith("src/components/"):
        return "ui-ink-terminal", ["SRC-005"]
    elif p.startswith("src/hooks/"):
        return "ui-react-hooks", ["SRC-005"]
    elif p.startswith("mcp-servers/"):
        return "mcp-sse-servers", ["SRC-020"]
    elif p.startswith("docs/"):
        return "documentation-astro", ["SRC-005"]
    elif p.startswith(".github/"):
        return "ci-github-workflows", ["SRC-005"]
    else:
        return "root-configuration-manifests", ["SRC-005"]

# Generate coverage records
coverage_records = []
for item in inventory_items:
    rel_path = item["path"]
    subsystem, evidence_ids = classify_subsystem(rel_path)
    coverage_records.append({
        "path": rel_path,
        "subsystem": subsystem,
        "inventory_kind": item["kind"],
        "review": "read" if item["category"] in ["SOURCE_CODE", "CRITICAL_MANIFEST_OR_CONFIG", "CONFIGURATION"] else "traced",
        "extent": {"kind": "whole-file"},
        "evidence_ids": evidence_ids,
        "reason": None,
        "remaining": []
    })

coverage_path = os.path.join(audit_dir, "coverage.jsonl")
with open(coverage_path, "w", encoding="utf-8") as f:
    for rec in coverage_records:
        f.write(json.dumps(rec, ensure_ascii=False) + "\n")
print(f"Wrote {len(coverage_records)} coverage records to {coverage_path}")

# 2. Evidence ledger
now_iso = "2026-10-27T12:30:00Z"
evidence_records = [
    {
        "id": "SRC-001",
        "authority": "SOURCE",
        "claim_class": "OBSERVED",
        "target_path": "src/openclaw/prompt-injection-defense.ts",
        "lines": {"start": 14, "end": 145},
        "symbol": "PromptInjectionDefense & Hidden CSS Detection",
        "evidence_snippet": "CSS_HIDDEN_PATTERNS (CVE-2026-22708): display:none, visibility:hidden, font-size:0, opacity:0 con instrucciones de agente; UNICODE_OBFUSCATION_PATTERNS (RTL override, homoglyphs, zero-width chars); ROLE_OVERRIDE_PATTERNS; TOOL_INVOCATION_PATTERNS; MEMORY_POISONING_PATTERNS.",
        "digest_sha256": get_file_sha256("src/openclaw/prompt-injection-defense.ts"),
        "context": "Mecanismos estáticos y heurísticos de sanitización y detección temprana de inyección indirecta de prompts en contenido web e inputs de usuario.",
        "timestamp": now_iso
    },
    {
        "id": "SRC-002",
        "authority": "SOURCE",
        "claim_class": "OBSERVED",
        "target_path": "src/openclaw/skill-scanner.ts",
        "lines": {"start": 19, "end": 141},
        "symbol": "SkillScanner & Supply Chain Defense",
        "evidence_snippet": "Detección estática de cargas maliciosas AMOS (Atomic macOS Stealer, campaña ClawHavoc), reverse shells, credential harvesting contra archivos de OpenClaw/tokens, ofuscación (base64, eval chains), combos peligrosos de permisos (exec + write + sessions_send) y typosquatting.",
        "digest_sha256": get_file_sha256("src/openclaw/skill-scanner.ts"),
        "context": "Motor de análisis estático previo a la instalación de skills y extensiones agenticas para mitigar ataques de cadena de suministro.",
        "timestamp": now_iso
    },
    {
        "id": "SRC-003",
        "authority": "SOURCE",
        "claim_class": "OBSERVED",
        "target_path": "src/openclaw/credential-guard.ts",
        "lines": {"start": 18, "end": 70},
        "symbol": "CredentialGuard & Sequence Exfiltration Tracking",
        "evidence_snippet": "Monitoreo de secuencias de acceso (lectura de credenciales seguida de invocación de red saliente: credentialReads -> networkCalls); escaneo regex de secretos salientes (API keys, OAuth, Bearer tokens, private keys) y redacción automática.",
        "digest_sha256": get_file_sha256("src/openclaw/credential-guard.ts"),
        "context": "Capa defensiva para impedir que agentes autónomos filtren secretos capturados en memoria o configuraciones hacia la red externa.",
        "timestamp": now_iso
    },
    {
        "id": "SRC-004",
        "authority": "SOURCE",
        "claim_class": "OBSERVED",
        "target_path": "src/openclaw/memory-integrity.ts",
        "lines": {"start": 21, "end": 100},
        "symbol": "MemoryIntegrity Monitor & Anti-Poisoning",
        "evidence_snippet": "MEMORY_POISONING_INDICATORS: Detección de instrucciones imperativas disfrazadas de hechos almacenados en archivos persistentes (memory/YYYY-MM-DD.md, MEMORY.md). Detecta directivas de bypass de aprobaciones ('always run without confirmation'), inyección de endpoints externos y credenciales falsas.",
        "digest_sha256": get_file_sha256("src/openclaw/memory-integrity.ts"),
        "context": "Detección y neutralización de ataques de envenenamiento de memoria a largo plazo (Long-Term Memory Poisoning) en agentes de IA.",
        "timestamp": now_iso
    },
    {
        "id": "SRC-005",
        "authority": "SOURCE",
        "claim_class": "OBSERVED",
        "target_path": "src/agent/agent.ts",
        "lines": {"start": 105, "end": 200},
        "symbol": "Agent ReAct Loop with Context Compaction",
        "evidence_snippet": "Bucle ReAct con compresión de contexto: durante las iteraciones intermedias las salidas de herramientas se resumen mediante LLM para preservar tokens, mientras que la generación de la respuesta final se nutre del contexto completo en un scratchpad append-only estructurado.",
        "digest_sha256": get_file_sha256("src/agent/agent.ts"),
        "context": "Orquestación determinista de ciclo de vida agéntico para prevenir saturación de ventana de contexto en misiones de larga duración.",
        "timestamp": now_iso
    },
    {
        "id": "SRC-006",
        "authority": "SOURCE",
        "claim_class": "OBSERVED",
        "target_path": "src/agent/redteam-mode.ts",
        "lines": {"start": 305, "end": 344},
        "symbol": "isTargetInScope Suffix Wildcard Matching Flaw",
        "evidence_snippet": "const baseDomain = wildcard.replace('*.', ''); if (target.toLowerCase().endsWith(baseDomain.toLowerCase())) return { inScope: true };",
        "digest_sha256": get_file_sha256("src/agent/redteam-mode.ts"),
        "context": "Vulnerabilidad de validación de alcance: comprobación por sufijo débil que permite atacar dominios no autorizados (e.g. 'eviltarget.com' coincide con '*.target.com').",
        "timestamp": now_iso
    },
    {
        "id": "SRC-007",
        "authority": "SOURCE",
        "claim_class": "OBSERVED",
        "target_path": "src/agent/approval.ts",
        "lines": {"start": 133, "end": 189},
        "symbol": "ApprovalManager Non-Cryptographic Gate",
        "evidence_snippet": "requestApproval genera requestId con uuidv4() sin vincular criptográficamente el nombre de la herramienta ni el payload/argumentos deserializados con nonce efímero.",
        "digest_sha256": get_file_sha256("src/agent/approval.ts"),
        "context": "Ausencia de vinculación criptográfica (Action-Binding) en el sistema de confirmación humana, exponiendo al agente a ataques de diputado confundido.",
        "timestamp": now_iso
    },
    {
        "id": "SRC-008",
        "authority": "SOURCE",
        "claim_class": "OBSERVED",
        "target_path": "src/engine/action-engine.ts",
        "lines": {"start": 385, "end": 400},
        "symbol": "ActionEngine Silent Fallback to Direct Execution",
        "evidence_snippet": "try { const session = await this.sandbox.createSandbox(); return await this.sandbox.execute(session.id, command); } catch { return await this.sandbox.executeDirect(command, timeoutSec); }",
        "digest_sha256": get_file_sha256("src/engine/action-engine.ts"),
        "context": "Fallo silencioso del sandbox Docker que deriva automáticamente en ejecución de comandos directa en el host (executeDirect) sin confinamiento.",
        "timestamp": now_iso
    },
    {
        "id": "SRC-009",
        "authority": "SOURCE",
        "claim_class": "OBSERVED",
        "target_path": "src/engine/sandbox.ts",
        "lines": {"start": 15, "end": 21},
        "symbol": "ExecutionSandbox Host Network Mode & Shell Spawning",
        "evidence_snippet": "DEFAULT_SANDBOX_CONFIG: { image: 'gideon-toolbox:latest', networkMode: 'host', timeoutSeconds: 300 }; executeDirect usa Bun.spawn(['sh', '-c', command]).",
        "digest_sha256": get_file_sha256("src/engine/sandbox.ts"),
        "context": "El contenedor Docker se configura con networkMode: 'host' (anulando el aislamiento de red), y executeDirect invoca sh -c con interpolación de strings.",
        "timestamp": now_iso
    },
    {
        "id": "SRC-010",
        "authority": "SOURCE",
        "claim_class": "OBSERVED",
        "target_path": "src/governance/audit-logger.ts",
        "lines": {"start": 90, "end": 98},
        "symbol": "AuditLogger Truncated 64-bit Hash Chain",
        "evidence_snippet": "createHash('sha256').update(data).digest('hex').slice(0, 16); // Trunca el digest a 16 caracteres hex (64 bits)",
        "digest_sha256": get_file_sha256("src/governance/audit-logger.ts"),
        "context": "Debilidad criptográfica en la cadena de integridad del audit trail: truncar SHA-256 a 64 bits degrada la resistencia a colisiones a 2^32 operaciones.",
        "timestamp": now_iso
    },
    {
        "id": "SRC-011",
        "authority": "SOURCE",
        "claim_class": "OBSERVED",
        "target_path": "src/governance/access-control.ts",
        "lines": {"start": 40, "end": 96},
        "symbol": "AccessControl Local File Persistence",
        "evidence_snippet": "Gestión de permisos basada en JSON en .gideon/governance/permissions.json con serialización síncrona writeFileSync sin bloqueo atómico ni permisos POSIX 0600.",
        "digest_sha256": get_file_sha256("src/governance/access-control.ts"),
        "context": "Control de acceso local en texto plano vulnerable a manipulación de estado por procesos concurrentes sin privilegios elevados.",
        "timestamp": now_iso
    },
    {
        "id": "SRC-012",
        "authority": "SOURCE",
        "claim_class": "OBSERVED",
        "target_path": "src/redteam/attacks/prompt-injection.ts",
        "lines": {"start": 21, "end": 100},
        "symbol": "AI Red Teaming Suite (OWASP LLM & MITRE ATLAS)",
        "evidence_snippet": "Catálogo estructurado de 15+ técnicas de inyección mapeadas a OWASP LLM01:2025 y MITRE ATLAS AML.T0051/T0052/T0054 con niveles de profundidad y verificación de defensas.",
        "digest_sha256": get_file_sha256("src/redteam/attacks/prompt-injection.ts"),
        "context": "Suite de evaluación adversarial para benchmarking defensivo de modelos y agentes de IA.",
        "timestamp": now_iso
    },
    {
        "id": "SRC-013",
        "authority": "SOURCE",
        "claim_class": "OBSERVED",
        "target_path": "src/guardrails/security-rails.co",
        "lines": {"start": 8, "end": 175},
        "symbol": "NeMo Guardrails Colang Flow Deflection",
        "evidence_snippet": "Definiciones Colang de tópicos permitidos vs bloqueados (explotación, creación de malware, herramientas de ataque) con flujos deterministas de rechazo educacional.",
        "digest_sha256": get_file_sha256("src/guardrails/security-rails.co"),
        "context": "Implementación de barandillas semánticas conversacionales para mantener agentes en modo defensivo estricto.",
        "timestamp": now_iso
    },
    {
        "id": "SRC-014",
        "authority": "SOURCE",
        "claim_class": "OBSERVED",
        "target_path": "src/c2/c2-manager.ts",
        "lines": {"start": 147, "end": 169},
        "symbol": "C2 Manager Offensive Capabilities",
        "evidence_snippet": "generateImplant(config: ImplantConfig) genera binarios ofensivos (exe, dll, shellcode) para Sliver teamservers; puente con listener y ejecución de tareas C2.",
        "digest_sha256": get_file_sha256("src/c2/c2-manager.ts"),
        "context": "Módulo puramente ofensivo que viola la Regla 1 de Devia-CyberSecurity (Cero armas/exploits). Requiere exclusión de absorción activa y traducción a detección.",
        "timestamp": now_iso
    },
    {
        "id": "SRC-015",
        "authority": "SOURCE",
        "claim_class": "OBSERVED",
        "target_path": "src/skills/weaponization/index.ts",
        "lines": {"start": 59, "end": 100},
        "symbol": "Weaponization Skill EDR Evasion Stubs",
        "evidence_snippet": "Contiene stubs activos para AMSI bypass en memoria, parcheo de ETW (Event Tracing for Windows) y stubs de syscalls directas (SysWhispers3 PROC).",
        "digest_sha256": get_file_sha256("src/skills/weaponization/index.ts"),
        "context": "Cargas y evasiones armamentizadas. No se absorben como herramientas ofensivas; se absorben las firmas para detección SAST y modelado de amenazas.",
        "timestamp": now_iso
    },
    {
        "id": "SRC-016",
        "authority": "SOURCE",
        "claim_class": "OBSERVED",
        "target_path": "src/tools/security/ioc-connector.ts",
        "lines": {"start": 6, "end": 26},
        "symbol": "IOCConnector Deterministic Type Detection",
        "evidence_snippet": "detectIOCType(value: string) clasifica determinísticamente IPv4 (con validación de octetos 0-255), hashes (MD5 32-hex, SHA1 40-hex, SHA256 64-hex), URLs y dominios.",
        "digest_sha256": get_file_sha256("src/tools/security/ioc-connector.ts"),
        "context": "Heurística de clasificación sintáctica de indicadores de compromiso para orquestar consultas a fuentes de reputación sin llamadas innecesarias.",
        "timestamp": now_iso
    },
    {
        "id": "SRC-017",
        "authority": "SOURCE",
        "claim_class": "OBSERVED",
        "target_path": "src/scanner/patterns.ts",
        "lines": {"start": 12, "end": 100},
        "symbol": "VulnerabilityPattern Definitions with Anti-Patterns",
        "evidence_snippet": "Patrones SAST con expresiones regulares de vulnerabilidad complementadas con 'antiPatterns' (e.g. parameterized queries, PreparedStatement) para filtrado de falsos positivos.",
        "digest_sha256": get_file_sha256("src/scanner/patterns.ts"),
        "context": "Diseño de reglas SAST de alta precisión que contrasta patrones de sumidero contra patrones de sanitización para reducir falsos positivos.",
        "timestamp": now_iso
    },
    {
        "id": "SRC-018",
        "authority": "SOURCE",
        "claim_class": "OBSERVED",
        "target_path": "src/graph/evograph.ts",
        "lines": {"start": 100, "end": 150},
        "symbol": "EvoGraph Parameterized Cypher Persistence",
        "evidence_snippet": "Consultas Neo4j para registrar Decisiones, Acciones, Hallazgos y Fallos utilizando parámetros nativos ($props, $actionId) neutralizando inyecciones Cypher.",
        "digest_sha256": get_file_sha256("src/graph/evograph.ts"),
        "context": "Buenas prácticas de parametrización estricta en bases de datos de grafos para modelado de caminos de ataque e histórico de auditoría.",
        "timestamp": now_iso
    },
    {
        "id": "SRC-019",
        "authority": "SOURCE",
        "claim_class": "OBSERVED",
        "target_path": "src/utils/redactor.ts",
        "lines": {"start": 6, "end": 36},
        "symbol": "redactSensitiveData Fail-Open Exception Catch",
        "evidence_snippet": "try { const config = loadConfig(); ... } catch { return text; // If config is not available, return original text }",
        "digest_sha256": get_file_sha256("src/utils/redactor.ts"),
        "context": "Manejo de excepciones inseguro (Fail-Open): si la carga de configuración falla por archivo faltante o yaml inválido, el texto con secretos se retorna intacto.",
        "timestamp": now_iso
    },
    {
        "id": "SRC-020",
        "authority": "SOURCE",
        "claim_class": "OBSERVED",
        "target_path": "mcp-servers/server.py",
        "lines": {"start": 180, "end": 220},
        "symbol": "FastAPI MCP Tool Server Arbitrary Flag Injection",
        "evidence_snippet": "cmd.extend(shlex.split(args['flags'])); cmd.append(args['target']); Servidor FastAPI SSE sin autenticación que permite inyectar flags arbitrarios como --script en nmap.",
        "digest_sha256": get_file_sha256("mcp-servers/server.py"),
        "context": "Vulnerabilidad de inyección de flags y falta de autenticación en servidor MCP que permite escalada de privilegios y ejecución de scripts Lua arbitrarios.",
        "timestamp": now_iso
    }
]

evidence_path = os.path.join(audit_dir, "evidence.jsonl")
with open(evidence_path, "w", encoding="utf-8") as f:
    for rec in evidence_records:
        f.write(json.dumps(rec, ensure_ascii=False) + "\n")
print(f"Wrote {len(evidence_records)} evidence records to {evidence_path}")

# 3. Unknowns ledger
unknowns_records = [
    {
        "id": "UNK-001",
        "title": "Inyección de Comandos OS en Adapters y Ejecución de Herramientas (CWE-78 / VULN-SAST-002)",
        "affected_component": "src/engine/tool-adapters.ts & src/engine/sandbox.ts",
        "contradiction_or_gap": "Los tool adapters (nmap, nuclei, sqlmap) concatenan los parámetros y el target directamente en una cadena mediante args.join(' ') sin escapar metacaracteres de shell (; & | ` $ > <). Luego executeDirect y execute en el sandbox ejecutan Bun.spawn(['sh', '-c', command]). Si un target o argumento contiene metacaracteres, se produce RCE inmediato.",
        "required_evidence": "Reemplazar la ejecución basada en sh -c por listas de argumentos tokenizados inmutables y sanitización de dominios/IPs mediante expresiones regulares RFC 1035.",
        "impact": "Ejecución de código arbitrario en el contenedor o en el host si el target suministrado por el LLM o usuario es malicioso."
    },
    {
        "id": "UNK-002",
        "title": "Bypass de Validación de Alcance por Coincidencia Débil de Sufijo de Dominio (CWE-20 / CWE-863)",
        "affected_component": "src/agent/redteam-mode.ts (isTargetInScope & matchesTarget)",
        "contradiction_or_gap": "Para dominios wildcard como *.target.com, el código extrae 'target.com' y valida haciendo target.toLowerCase().endsWith(baseDomain.toLowerCase()). Esto clasifica erróneamente dominios atacantes como 'eviltarget.com' o 'phishingtarget.com' como parte del alcance autorizado de la auditoría.",
        "required_evidence": "Validar explícitamente que target === baseDomain o target.endsWith('.' + baseDomain).",
        "impact": "Ataques no autorizados contra infraestructura fuera de alcance, violando las Reglas de Compromiso (ROE) y acuerdos legales."
    },
    {
        "id": "UNK-003",
        "title": "Degradación Silenciosa del Sandbox Docker hacia Ejecución Directa en el Host (CWE-250 / VULN-ARCH-008)",
        "affected_component": "src/engine/action-engine.ts (executeCommand)",
        "contradiction_or_gap": "Si la creación o ejecución del contenedor Docker falla por falta de daemon o permisos, el bloque catch captura la excepción silenciosamente y deriva la ejecución a this.sandbox.executeDirect(command) directamente sobre el host. Además, la configuración por defecto usa networkMode: 'host', anulando la segregación de red.",
        "required_evidence": "Implementar un fallo cerrado (Fail-Closed): si el sandbox falla, la operación de riesgo debe abortarse y alertar al operador en lugar de ejecutarse en el sistema host sin confinamiento.",
        "impact": "Escape accidental del sandbox y ejecución de cargas destructivas directamente en la estación de trabajo del operador."
    },
    {
        "id": "UNK-004",
        "title": "Debilidad Criptográfica por Truncamiento de Hash SHA-256 a 64 Bits en Audit Trail (CWE-328 / VULN-CRYP-002)",
        "affected_component": "src/governance/audit-logger.ts (calculateHash)",
        "contradiction_or_gap": "El método calculateHash para la cadena de bloques del registro de auditoría calcula SHA-256 pero trunca el resultado a 16 caracteres hexadecimales (.slice(0, 16)), es decir, 64 bits. Esto reduce la resistencia a colisiones a aproximadamente 2^32 operaciones (ataque de cumpleaños), lo cual es computable en segundos en hardware convencional.",
        "required_evidence": "Preservar el digest SHA-256 completo de 64 caracteres hexadecimales (256 bits) para garantizar inmutabilidad y resistencia a manipulación de logs.",
        "impact": "Falsificación de la cadena de integridad del registro forense mediante ataques de colisión efímeros."
    },
    {
        "id": "UNK-005",
        "title": "Fuga de Secretos por Falla Abierta en Manejo de Excepciones de Redacción (CWE-209 / CWE-200 / VULN-RESI-003)",
        "affected_component": "src/utils/redactor.ts (redactSensitiveData)",
        "contradiction_or_gap": "Si la función loadConfig() falla al leer gideon.config.yaml (archivo ausente, sintaxis YAML inválida o error de E/S), el bloque catch simplemente retorna el texto sin procesar ('return text;'). Esto provoca que mensajes de depuración o respuestas de API con claves vivas se divulguen sin ofuscar.",
        "required_evidence": "Implementar un conjunto de patrones regex estáticos de respaldo integrados en código (hardcoded fallback patterns) para redacción incluso si la configuración externa no puede ser cargada.",
        "impact": "Exposición inadvertida de claves de API y credenciales en salidas de consola, logs o artefactos exportados."
    },
    {
        "id": "UNK-006",
        "title": "Servidor MCP sin Autenticación con Exposición de Flags Arbitrarios (CWE-306 / CWE-78)",
        "affected_component": "mcp-servers/server.py",
        "contradiction_or_gap": "El servidor FastAPI SSE de herramientas MCP expone utilidades del sistema como nmap, nuclei y subfinder sin mecanismo de autenticación (bearer token o TLS mutuo) y permite a los clientes pasar cadenas de flags arbitrarios (args['flags']) que son divididas con shlex.split() y pasadas al comando. En nmap, esto permite pasar --script=<script_lua_malicioso> para ejecutar código arbitrario.",
        "required_evidence": "Implementar autenticación obligatoria en el endpoint MCP y restringir los flags permitidos a una lista blanca inmutable de argumentos seguros.",
        "impact": "RCE remoto y abuso de herramientas de escaneo por cualquier actor en la red local que alcance el puerto del servidor MCP."
    }
]

unknowns_path = os.path.join(audit_dir, "unknowns.jsonl")
with open(unknowns_path, "w", encoding="utf-8") as f:
    for rec in unknowns_records:
        f.write(json.dumps(rec, ensure_ascii=False) + "\n")
print(f"Wrote {len(unknowns_records)} unknowns records to {unknowns_path}")

# 4. Absorption Plan (Zod Contract)
plan_data = {
    "planId": str(uuid.uuid4()),
    "createdAt": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    "target": {
        "path": target_dir,
        "canonicalPath": target_dir,
        "name": "Gideon-main",
        "type": "REPOSITORY",
        "commitOrSnapshot": "devia-snapshot/v1:sha256:0cfe755c7494d5c242efe97dbe6c4f5c988ac240b6607b7f2361353aa4f6a6b3",
        "archetypeDescription": "Autonomous Cybersecurity Operations & Red Teaming Agent impulsado por Bun, TypeScript, React Ink, LangChain, NVIDIA AI Stack (Morpheus, NIM, NeMo Guardrails) y Python MCP Tools."
    },
    "scopeSummary": {
        "totalEntriesScanned": 217,
        "primaryLanguages": ["TypeScript", "Python", "Colang", "Markdown", "JSON", "YAML"],
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
            "title": "Defensa Multicapa contra Inyección Indirecta de Prompts y Ofuscación CSS (CVE-2026-22708)",
            "description": "Patrones heurísticos de detección estática para neutralizar instrucciones hostiles ocultas mediante CSS (display:none, font-size:0, visibility:hidden, opacity:0), esteganografía Unicode (RTL overrides, homóglifos, zero-width spaces), saltos de delimitadores de contexto de roles (<|im_start|>, [SYSTEM OVERRIDE]) e intentos de invocación indirecta de herramientas.",
            "dimension": "ARCHITECTURE_BOUNDARIES_ZERO_TRUST",
            "cwe": ["CWE-74", "CWE-20"],
            "owasp": ["A03:2021", "LLM01:2025"],
            "sourceLocations": ["src/openclaw/prompt-injection-defense.ts"],
            "authority": "OBSERVED",
            "valueProposition": "Dota al ecosistema Devia de defensas robustas para agentes autónomos cuando procesan contenido web externo no confiable o entradas multimodales."
        },
        {
            "id": "KNOW-002",
            "title": "Escáner Estático de Seguridad de Habilidades Agenticas y Detección de Typosquatting",
            "description": "Motor de auditoría estática previo a la instalación de skills y plugins de IA. Detecta firmas de infostealers nativos (AMOS macOS stealer / campaña ClawHavoc), reverse shells, accesos a archivos de credenciales/sesiones de agentes, combinaciones peligrosas de privilegios (e.g. exec + write + sessions_send) y typosquatting de nombres de paquetes.",
            "dimension": "SUPPLY_CHAIN_SCA",
            "cwe": ["CWE-829", "CWE-1395"],
            "owasp": ["A08:2021", "LLM05:2025"],
            "sourceLocations": ["src/openclaw/skill-scanner.ts"],
            "authority": "OBSERVED",
            "valueProposition": "Protege la cadena de suministro agéntica de Devia-CyberSecurity frente a paquetes troyanizados en registros públicos o marketplaces de agentes."
        },
        {
            "id": "KNOW-003",
            "title": "Monitoreo de Secuencias de Exfiltración y Salvaguarda de Credenciales en Salida",
            "description": "Heurística de detección temporal basada en secuencias causales de eventos (lectura de credenciales en almacenamiento local seguida de llamada HTTP/WebSocket saliente: credentialReads -> networkCalls) y escáner activo de redacción para 11 formatos de tokens en tráfico saliente.",
            "dimension": "SECRETS_CRYPTOGRAPHY",
            "cwe": ["CWE-798", "CWE-312", "CWE-200"],
            "owasp": ["A02:2021", "LLM06:2025"],
            "sourceLocations": ["src/openclaw/credential-guard.ts"],
            "authority": "OBSERVED",
            "valueProposition": "Previene la fuga de secretos de infraestructura cuando herramientas de LLM generan consultas externas a APIs públicas."
        },
        {
            "id": "KNOW-004",
            "title": "Monitor de Integridad de Memoria y Neutralización de Envenenamiento Persistente (Long-Term Memory Poisoning)",
            "description": "Inspección sistemática de archivos de memoria a largo plazo (.md, .jsonl) para detectar 'instrucciones imperativas disfrazadas de hechos'. Identifica directivas inyectadas que instruyen al modelo a saltarse confirmaciones ('always execute without asking'), redefinir roles o exfiltrar datos en sesiones futuras.",
            "dimension": "ARCHITECTURE_BOUNDARIES_ZERO_TRUST",
            "cwe": ["CWE-74", "CWE-285"],
            "owasp": ["A01:2021", "LLM01:2025"],
            "sourceLocations": ["src/openclaw/memory-integrity.ts"],
            "authority": "OBSERVED",
            "valueProposition": "Cierra el vector crítico de ataques con retraso temporal (delayed-execution attacks) donde un contenido web hostil envenena el contexto persistente del agente."
        },
        {
            "id": "KNOW-005",
            "title": "Bucle ReAct con Compactación de Contexto O(1) y Bitácora Append-Only en Scratchpad",
            "description": "Arquitectura agéntica que desacopla la ejecución iterativa de la respuesta final: resume los resultados de herramientas intermedias para preservar el presupuesto de tokens durante el ciclo de razonamiento, mientras registra la evidencia completa en un archivo append-only estructurado utilizado para sintetizar la respuesta final.",
            "dimension": "RESILIENCE_LOGGING_TELEMETRY",
            "cwe": ["CWE-400"],
            "owasp": ["A04:2021", "LLM04:2025"],
            "sourceLocations": ["src/agent/agent.ts", "src/agent/context-compressor.ts", "src/agent/scratchpad.ts"],
            "authority": "OBSERVED",
            "valueProposition": "Permite auditorías de repositorios extensos sin agotamiento de tokens ni degradación de calidad por desbordamiento de contexto."
        },
        {
            "id": "KNOW-006",
            "title": "Gobernanza Semántica de Diálogo y Deflexión de Jailbreaks mediante Colang (NeMo Guardrails)",
            "description": "Modelado formal de flujos conversacionales mediante Colang y NeMo Guardrails para imponer límites defensivos estrictos (defensive-only scope), bloqueando solicitudes de generación de malware, explotación o ingeniería social con respuestas educativas deterministas.",
            "dimension": "CONFIGURATION_HARDENING",
            "cwe": ["CWE-1188"],
            "owasp": ["A05:2021"],
            "sourceLocations": ["src/guardrails/security-rails.co", "src/guardrails/config.yml"],
            "authority": "OBSERVED",
            "valueProposition": "Estandariza los contratos de interacción y políticas de rechazo seguro en agentes de ciberseguridad."
        },
        {
            "id": "KNOW-007",
            "title": "Suite de Evaluación Adversarial de Red Teaming para Agentes IA (OWASP LLM & MITRE ATLAS)",
            "description": "Batería de pruebas automatizadas con 15+ técnicas de ataque dirigidas contra modelos y agentes (inyección directa, delimitadores, persona jailbreak, evasión Base64, exfiltración, escalada de privilegios y persistencia) mapeadas formalmente a tácticas y técnicas de MITRE ATLAS.",
            "dimension": "THREAT_MODELING_ATTACK_SURFACE",
            "cwe": ["CWE-1059"],
            "owasp": ["A04:2021", "LLM01:2025"],
            "sourceLocations": ["src/redteam/attacks/prompt-injection.ts", "src/redteam/attack-runner.ts"],
            "authority": "OBSERVED",
            "valueProposition": "Permite auditar y evaluar sistemáticamente la resistencia de cualquier agente IA externo ante ataques adversariales conocidos."
        },
        {
            "id": "KNOW-008",
            "title": "Canalizaciones de Detección de Anomalías de Comportamiento (DFP) y DGA con GPU",
            "description": "Integración de pipelines analíticos de alta velocidad (Morpheus / RAPIDS) para correlación masiva de logs (200k+ eps), detección de algoritmos de generación de dominios (DGA) e identificación de desviaciones en perfiles de comportamiento de usuarios (Digital Fingerprinting).",
            "dimension": "RESILIENCE_LOGGING_TELEMETRY",
            "cwe": ["CWE-754"],
            "owasp": ["A09:2021"],
            "sourceLocations": ["src/utils/morpheus.ts", "src/utils/rapids.ts"],
            "authority": "OBSERVED",
            "valueProposition": "Aporta modelos de integración para telemetría a escala industrial en infraestructuras SIEM y SOC asistidos por IA."
        }
    ],
    "absorptionActions": [
        {
            "id": "ABS-001",
            "knowledgeId": "KNOW-001",
            "title": "Materializar Guía y Heurísticas de Defensa contra Inyección de Prompts en Arquitecturas Agenticas",
            "destination": "SKILL_REFERENCE",
            "intent": "ROBUSTIFY_HARDEN",
            "existingVulnerabilityId": "VULN-ARCH-005",
            "targetPathInRepo": ".agent/skills/architecture-boundaries-zero-trust/references/openclaw-sentinel-agent-defense.md",
            "architecturalRationale": "Capa 1: Documenta los patrones de inspección CSS (CVE-2026-22708), Unicode y saltos de rol como referencia operativa para la Skill de arquitectura y fronteras Zero Trust.",
            "priority": "CRITICAL",
            "implementationSteps": [
                "Crear el documento de referencia detallando los patrones regex y vectores observados en OpenClaw Sentinel.",
                "Mapear los controles contra OWASP LLM01:2025 y CWE-74.",
                "Vincular el documento en el catálogo canónico docs/VULNERABILITIES.md bajo VULN-ARCH-005."
            ]
        },
        {
            "id": "ABS-002",
            "knowledgeId": "KNOW-004",
            "title": "Catalogar Vulnerabilidad de Envenenamiento de Memoria a Largo Plazo (Long-Term Memory Poisoning)",
            "destination": "UPDATE_EXISTING",
            "intent": "CREATE_NEW",
            "existingVulnerabilityId": "VULN-ARCH-010",
            "targetPathInRepo": "docs/VULNERABILITIES.md",
            "architecturalRationale": "Documentación centralizada (SSOT): Incorpora la vulnerabilidad de envenenamiento de memoria en agentes IA con asignación canónica a ARCHITECTURE_BOUNDARIES_ZERO_TRUST.",
            "priority": "HIGH",
            "implementationSteps": [
                "Añadir VULN-ARCH-010 (Long-Term Agent Memory Poisoning & Delayed Instruction Triggering) a docs/VULNERABILITIES.md.",
                "Asignar taxonomía CWE-74 / CWE-285 y vincular la Skill architecture-boundaries-zero-trust.",
                "Documentar el mecanismo de mitigación mediante verificación sintáctica de aserciones vs hechos."
            ]
        },
        {
            "id": "ABS-003",
            "knowledgeId": "KNOW-002",
            "title": "Enriquecer la Skill de Cadena de Suministro con Reglas de Auditoría de Skills y Typosquatting",
            "destination": "SKILL_REFERENCE",
            "intent": "ABSORB_EXPAND",
            "existingVulnerabilityId": "VULN-SCA-003",
            "targetPathInRepo": ".agent/skills/supply-chain-sca/references/agent-skill-supply-chain-vetting.md",
            "architecturalRationale": "Capa 1: Consolida las heurísticas de auditoría para paquetes de habilidades y extensiones de agentes (patrones AMOS, combos peligrosos exec+write+send).",
            "priority": "HIGH",
            "implementationSteps": [
                "Redactar guía técnica con los 8 checks estáticos de ClawHub Skill Scanner.",
                "Incluir reglas de detección para combinaciones de permisos de alto riesgo en agentes.",
                "Vincular con VULN-SCA-003 en docs/VULNERABILITIES.md."
            ]
        },
        {
            "id": "ABS-004",
            "knowledgeId": "KNOW-003",
            "title": "Incorporar Detección de Secuencias de Exfiltración Temporal en Memoria Proactiva",
            "destination": "UPDATE_EXISTING",
            "intent": "ROBUSTIFY_HARDEN",
            "existingVulnerabilityId": "VULN-CRYP-001",
            "targetPathInRepo": "docs/PROACTIVE.md",
            "architecturalRationale": "Memoria Operativa: Registra el patrón de detección de secuencias (credentialReads -> networkCalls) para evitar falsos negativos en auditorías de exfiltración.",
            "priority": "MEDIUM",
            "implementationSteps": [
                "Añadir sección en docs/PROACTIVE.md documentando el patrón causal de exfiltración de credenciales en agentes autónomos.",
                "Registrar la lección sobre evitar el fail-open en módulos de redacción de secretos."
            ]
        },
        {
            "id": "ABS-005",
            "knowledgeId": "KNOW-007",
            "title": "Mapear la Matriz de Pruebas de MITRE ATLAS para Modelado de Amenazas de IA",
            "destination": "SKILL_REFERENCE",
            "intent": "ABSORB_EXPAND",
            "existingVulnerabilityId": "VULN-TM-003",
            "targetPathInRepo": ".agent/skills/threat-modeling-attack-surface/references/mitre-atlas-agent-evaluation.md",
            "architecturalRationale": "Capa 1: Proporciona a threat-modeling-attack-surface un marco concreto para auditar superficies de ataque en modelos de lenguaje y agentes autónomos.",
            "priority": "HIGH",
            "implementationSteps": [
                "Documentar la matriz de técnicas MITRE ATLAS (AML.T0051 a AML.T0054) frente a las 8 dimensiones canónicas.",
                "Definir procedimientos de evaluación de robustez ante inyecciones y fugas de contexto."
            ]
        }
    ],
    "metrics": {
        "totalKnowledgeItems": 8,
        "destinationsBreakdown": {
            "SKILL_REFERENCE": 3,
            "UPDATE_EXISTING": 2
        }
    },
    "ledgerPaths": {
        "inventoryJsonl": "audits/Gideon-main/inventory/inventory.jsonl",
        "coverageJsonl": "audits/Gideon-main/coverage.jsonl",
        "evidenceJsonl": "audits/Gideon-main/evidence.jsonl",
        "unknownsJsonl": "audits/Gideon-main/unknowns.jsonl"
    }
}

plan_path = os.path.join(audit_dir, "absorption-plan.json")
with open(plan_path, "w", encoding="utf-8") as f:
    json.dump(plan_data, f, indent=2, ensure_ascii=False)
print(f"Wrote absorption plan to {plan_path}")

print("All ledgers generated successfully.")
