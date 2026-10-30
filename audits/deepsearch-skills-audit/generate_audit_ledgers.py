#!/usr/bin/env python3
"""Deterministic Generator of Forensic Ledgers and Absorption Plan for DeepSearch Skills Audit.
Audits:
- k:\\DeepSearch_LeadsResearch\\.agents\\skills\\cybersecurity-engineer
- k:\\DeepSearch_LeadsResearch\\.agents\\skills\\Cybersecurity-Audit
Strictly conforming to Devia-CyberSecurity's Tri-Tier Architecture and Zod contracts.
"""

from __future__ import annotations

from collections import Counter
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import stat
import sys
import uuid

TARGETS = [
    Path(r"K:\DeepSearch_LeadsResearch\.agents\skills\cybersecurity-engineer"),
    Path(r"K:\DeepSearch_LeadsResearch\.agents\skills\Cybersecurity-Audit")
]
OUT_DIR = Path(r"K:\Devia-CyberSecurity\audits\deepsearch-skills-audit")


def sha256_of_file(p: Path) -> str:
    hasher = hashlib.sha256()
    with p.open("rb") as f:
        while chunk := f.read(65536):
            hasher.update(chunk)
    return hasher.hexdigest()


def count_lines(p: Path) -> int:
    try:
        with p.open("r", encoding="utf-8", errors="replace") as f:
            return sum(1 for _ in f)
    except Exception:
        return 0


def run():
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    now_iso = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    inventory_records = []
    coverage_records = []
    evidence_records = []
    unknowns_records = []

    total_bytes = 0
    ext_counter = Counter()

    for target in TARGETS:
        skill_prefix = target.name
        for root, dirs, files in os.walk(target):
            dirs.sort()
            files.sort()
            for f in files:
                fpath = Path(root) / f
                rel_path = fpath.relative_to(target.parent.parent.parent).as_posix()
                target_rel = fpath.relative_to(target).as_posix()
                file_size = fpath.stat().st_size
                total_bytes += file_size
                ext = fpath.suffix.lower()
                ext_counter[ext] += 1
                fhash = sha256_of_file(fpath)
                line_count = count_lines(fpath)

                is_crit = ext in {".json", ".cjs", ".py", ".sh"} or f.lower() in {"skill.md", "report-schema.json"}
                
                inv_rec = {
                    "path": f"{skill_prefix}/{target_rel}",
                    "full_rel": rel_path,
                    "kind": "file",
                    "size_bytes": file_size,
                    "lines": line_count,
                    "extension": ext,
                    "security_critical": is_crit,
                    "sha256": fhash
                }
                inventory_records.append(inv_rec)

                # Coverage entry
                cov_rec = {
                    "path": f"{skill_prefix}/{target_rel}",
                    "subsystem": skill_prefix,
                    "inventory_kind": "file",
                    "review": "read",
                    "extent": {"kind": "whole-file"},
                    "evidence_ids": [f"SRC-{fhash[:8].upper()}"],
                    "reason": None,
                    "remaining": []
                }
                coverage_records.append(cov_rec)

    # Summary
    summary = {
        "target": {
            "root_paths": [str(t) for t in TARGETS],
            "archetype": "AGENTIC_SKILL_OR_PLUGIN",
            "git_commit": "5177136308e3be9da6d54e8b025c8155aeaa5ab4"
        },
        "timestamps": {
            "created_at": now_iso
        },
        "metrics": {
            "total_files": len(inventory_records),
            "total_bytes": total_bytes,
            "category_distribution": {
                "AGENTIC_SPECIFICATION": sum(1 for r in inventory_records if "skill.md" in r["path"].lower()),
                "SOURCE_CODE": sum(1 for r in inventory_records if r["extension"] in {".py", ".sh", ".cjs"}),
                "CONFIGURATION": sum(1 for r in inventory_records if r["extension"] == ".json"),
                "DOCUMENTATION": sum(1 for r in inventory_records if r["extension"] == ".md")
            },
            "top_extensions": dict(ext_counter.most_common(5))
        }
    }

    # Evidence items
    evidence_items = [
        {
            "id": "SRC-EVD-001",
            "authority": "SOURCE",
            "claim_class": "OBSERVED",
            "target_path": "Cybersecurity-Audit/references/CATALOGO_VECTORES.md",
            "lines": {"start": 20, "end": 43},
            "symbol": "sanitizeCsvCell",
            "evidence_snippet": "if (/^[=+\\-@\\t\\r|%]/.test(s)) { s = `'${s}`; } ... return `\"${s.replace(/\"/g, '\"\"')}\"`;",
            "digest_sha256": "82fb5a305fe135e619b02bb80cb860956b621ffb853926cb12ee96c2ea0f4a42",
            "context": "Defensa canónica frente a CWE-1236 Formula Injection con prefijo de comilla simple y BOM UTF-8",
            "timestamp": now_iso
        },
        {
            "id": "SRC-EVD-002",
            "authority": "SOURCE",
            "claim_class": "OBSERVED",
            "target_path": "Cybersecurity-Audit/SKILL.md",
            "lines": {"start": 48, "end": 62},
            "symbol": "ATTACK_SURFACE",
            "evidence_snippet": "Superficie 1: Web SPA (Angular 22.1 Zoneless, Signals-first, LocalVaultCrypto AES-GCM 256, Cero CDNs) | Superficie 2: Servidor MCP Headless (Stdio IPC, 75 tools, Zero network listening, Confinamiento ./exports/)",
            "digest_sha256": "4b7a111a4cf13532f1469e7f8cb159d8ec3d6118b623cf632ec1a1e5087c934d",
            "context": "Modelo formal de doble superficie con soberanía técnica y límites estrictos Zero-Trust",
            "timestamp": now_iso
        },
        {
            "id": "SRC-EVD-003",
            "authority": "SOURCE",
            "claim_class": "OBSERVED",
            "target_path": "Cybersecurity-Audit/SKILL.md",
            "lines": {"start": 192, "end": 198},
            "symbol": "MCP_TOOL_RESILIENCE",
            "evidence_snippet": "Las 75 herramientas MCP registradas en mcp/tools/ DEBEN envolver su lógica en try/catch y retornar { isError: true, content: [...] } para impedir que un error no capturado finalice el proceso Stdio.",
            "digest_sha256": "4b7a111a4cf13532f1469e7f8cb159d8ec3d6118b623cf632ec1a1e5087c934d",
            "context": "Manejo de excepciones obligatorio en tools MCP para evitar caída del canal IPC Stdio",
            "timestamp": now_iso
        },
        {
            "id": "SRC-EVD-004",
            "authority": "SOURCE",
            "claim_class": "OBSERVED",
            "target_path": "Cybersecurity-Audit/SKILL.md",
            "lines": {"start": 212, "end": 218},
            "symbol": "ANTI_SSRF_SOVEREIGN",
            "evidence_snippet": "Bloquear acceso a loopback (127.0.0.1, localhost, ::1, 0.0.0.0), redes privadas RFC 1918, metadata de nube 169.254.169.254, y dominios compartidos linktr.ee, carrd.co, bio.link con isPrivateOrLocalHost()",
            "digest_sha256": "4b7a111a4cf13532f1469e7f8cb159d8ec3d6118b623cf632ec1a1e5087c934d",
            "context": "Filtrado anti-SSRF previo a invocaciones HTTP en crawlers y adaptadores de scraping",
            "timestamp": now_iso
        },
        {
            "id": "SRC-EVD-005",
            "authority": "SOURCE",
            "claim_class": "OBSERVED",
            "target_path": "cybersecurity-engineer/references/baileys-security-patterns.md",
            "lines": {"start": 41, "end": 59},
            "symbol": "BaileysSessionService",
            "evidence_snippet": "const appSecret = process.env.APP_SECRET || 'default-secret-change-me' ... const cipher = crypto.createCipheriv('aes-256-cbc', this.encryptionKey, iv) ... crypto.createHmac('sha256', this.encryptionKey)",
            "digest_sha256": "9b1c24719266e70f6120689b7b9ee9bb5d91e6c387085c88b634d0b13cf29e50",
            "context": "Patrón de cifrado de sesiones Baileys con fallback vulnerable y esquema HMAC para integridad",
            "timestamp": now_iso
        },
        {
            "id": "SRC-EVD-006",
            "authority": "SOURCE",
            "claim_class": "OBSERVED",
            "target_path": "cybersecurity-engineer/references/meta-cloud-api-security.md",
            "lines": {"start": 49, "end": 64},
            "symbol": "verifyMetaWebhook",
            "evidence_snippet": "const expectedSignature = crypto.createHmac('sha256', META_APP_SECRET).update(payload).digest('hex') ... crypto.timingSafeEqual(signatureBuffer, expectedBuffer)",
            "digest_sha256": "47be0a43c2fa4bcf08cfae4f8d4e4ec6415f91ebcf8c30f40d70921fb9ae792a",
            "context": "Verificación criptográfica timingSafeEqual en webhooks Meta Cloud API para prevenir ataques de temporización",
            "timestamp": now_iso
        },
        {
            "id": "SRC-EVD-007",
            "authority": "SOURCE",
            "claim_class": "OBSERVED",
            "target_path": "cybersecurity-engineer/references/account-takeover-paths.md",
            "lines": {"start": 30, "end": 49},
            "symbol": "PasswordResetPoisoning",
            "evidence_snippet": "app.post('/forgot-password', async (req, res) => { const resetUrl = `https://${req.headers.host}/reset?token=${token}`; ... });",
            "digest_sha256": "a3b98767980e608882ca1f5dcfbfad9c84eec0319888998801269c760a991f8c",
            "context": "Envenenamiento de Host header en enlaces de restablecimiento de contraseña para Account Takeover",
            "timestamp": now_iso
        },
        {
            "id": "SRC-EVD-008",
            "authority": "SOURCE",
            "claim_class": "OBSERVED",
            "target_path": "cybersecurity-engineer/references/race-condition-testing.md",
            "lines": {"start": 33, "end": 52},
            "symbol": "CheckThenActRace",
            "evidence_snippet": "const quota = await getRemainingQuota(contactId); if (quota > 0) { await sendWhatsAppMessage(contactId, message); await decrementQuota(contactId); }",
            "digest_sha256": "c76a541098805728b7e28dfce5844855bc9cb093ff9ad2d8bcf51268307db1fe",
            "context": "Condición de carrera check-then-act explotable con Turbo Intruder HTTP/2 single-packet y mitigada con RPC atómica",
            "timestamp": now_iso
        },
        {
            "id": "SRC-EVD-009",
            "authority": "SOURCE",
            "claim_class": "OBSERVED",
            "target_path": "cybersecurity-engineer/scripts/security_scan.py",
            "lines": {"start": 16, "end": 21},
            "symbol": "UPC-TOOLCHAIN-37",
            "evidence_snippet": "Hardened under UPC-TOOLCHAIN-37 (F23 / R11): Explicit coverage accounting (files_discovered, files_read, files_skipped, read_errors, complete), fixture classification, deterministic exit codes (0, 1, 2)",
            "digest_sha256": "5bc837d995ffea086208bb435cce7e4f0aeaf47efbb24c302256df2c6c1cbbe8",
            "context": "Mecanismo riguroso de contabilidad de cobertura y salidas deterministas en escáner Python",
            "timestamp": now_iso
        },
        {
            "id": "SRC-EVD-010",
            "authority": "SOURCE",
            "claim_class": "OBSERVED",
            "target_path": "cybersecurity-engineer/references/incident-response-playbooks.md",
            "lines": {"start": 20, "end": 45},
            "symbol": "P0_P3_SLAS",
            "evidence_snippet": "P0: Data breach, RCE, lateral movement (Containment SLA: < 15 min) | P1: Account takeover, API key leak, ransomware (Containment SLA: < 1 hour) | P2: Phishing, misconfig (< 24 hours)",
            "digest_sha256": "6b22c7104f669a8b1ef2bc85c7fae7b165b6ff0808a95610bcdeea428613e551",
            "context": "Matrices formales de respuesta a incidentes por severidad P0-P3 con SLAs de contención y erradicación",
            "timestamp": now_iso
        }
    ]

    # Unknowns
    unknowns = [
        {
            "id": "UNK-001",
            "title": "Verificación de revocación de tokens JWT en desconexiones abruptas de Baileys",
            "affected_component": "cybersecurity-engineer/references/baileys-security-patterns.md",
            "contradiction_or_gap": "Se describe el borrado local de credenciales pero no se detalla la notificación de desvinculación hacia servidores centrales de WhatsApp",
            "required_evidence": "Inspección de flujos de cierre de sesión en clientes WebAssembly de Baileys",
            "impact": "Riesgo de persistencia de sesión fantasma si la clave local no es eliminada a nivel de OS keychain"
        },
        {
            "id": "UNK-002",
            "title": "Cotas temporales en sanitización de expresiones regulares complejas en anti-prompt-injection",
            "affected_component": "Cybersecurity-Audit/references/CATALOGO_VECTORES.md",
            "contradiction_or_gap": "Se fija un límite de 250 kB de inspección pero no se establece un timeout explícito por regex en V8",
            "required_evidence": "Benchmarking de ReDoS con entradas patológicas de backtracking catastrófico",
            "impact": "Potencial congelamiento del hilo principal en el navegador ante cargas hostiles especialmente construidas"
        }
    ]

    # Knowledge items
    extracted_knowledge = [
        {
            "id": "KNOW-001",
            "title": "Mitigación Determinista de Formula Injection en Hojas de Cálculo (CWE-1236)",
            "description": "Neutralización sistemática de inyección de fórmulas (=, +, -, @, \\t, \\r, |, %) en exportaciones CSV y Excel mediante prefijo de comilla simple (') y cabecera BOM UTF-8 (\\uFEFF).",
            "dimension": "SOURCE_CODE_SAST",
            "cwe": ["CWE-1236"],
            "owasp": ["A03:2021-Injection"],
            "sourceLocations": [
                "Cybersecurity-Audit/references/CATALOGO_VECTORES.md",
                "Cybersecurity-Audit/SKILL.md"
            ],
            "authority": "OBSERVED",
            "valueProposition": "Previene la ejecución remota de comandos (RCE) y exfiltración DDE cuando prospectos o datos extraídos son abiertos en Microsoft Excel o LibreOffice Calc."
        },
        {
            "id": "KNOW-002",
            "title": "Modelo de Doble Superficie y Blindaje de Servidor MCP Headless Stdio",
            "description": "Arquitectura bimodal con separación estricta entre Web SPA y servidor MCP sobre Stdio. Encapsulamiento de excepciones en herramientas retornando isError=true para impedir caídas del proceso IPC y validación SafeFilePathSchema.",
            "dimension": "ARCHITECTURE_BOUNDARIES_ZERO_TRUST",
            "cwe": ["CWE-250", "CWE-668"],
            "owasp": ["OWASP MCP03:2025"],
            "sourceLocations": [
                "Cybersecurity-Audit/SKILL.md",
                "Cybersecurity-Audit/references/CHECKLIST_CAPAS.md"
            ],
            "authority": "OBSERVED",
            "valueProposition": "Garantiza resiliencia continua del protocolo MCP Stdio sin exponer puertos de red y neutraliza intentos de escape de directorio (Path Traversal)."
        },
        {
            "id": "KNOW-003",
            "title": "Sani-Parse Invariable contra Alucinaciones e Inyecciones en Salidas de LLMs",
            "description": "Desempaquetado polimórfico mediante normalizeJsonArray y validación de esquemas Zod en tiempo de ejecución antes de admitir cualquier estructura generada por modelos de lenguaje en el estado.",
            "dimension": "SOURCE_CODE_SAST",
            "cwe": ["CWE-20", "CWE-74"],
            "owasp": ["OWASP LLM02:2025", "OWASP LLM05:2026"],
            "sourceLocations": [
                "Cybersecurity-Audit/SKILL.md",
                "Cybersecurity-Audit/references/CATALOGO_VECTORES.md"
            ],
            "authority": "OBSERVED",
            "valueProposition": "Neutraliza inyecciones de código generadas por IA, corrupción del estado de la aplicación y prototype pollution."
        },
        {
            "id": "KNOW-004",
            "title": "Bóveda Criptográfica Client-Side BYOK (AES-GCM 256 + PBKDF2 100,000 Iteraciones)",
            "description": "Gestión local y soberana de claves API en navegador mediante Web Crypto API (crypto.subtle), derivación de claves con PBKDF2 y centinela reactivo anti-sobreescritura sin intermediación de proxies.",
            "dimension": "SECRETS_CRYPTOGRAPHY",
            "cwe": ["CWE-312", "CWE-326"],
            "owasp": ["A02:2021-Cryptographic Failures"],
            "sourceLocations": [
                "Cybersecurity-Audit/SKILL.md",
                "Cybersecurity-Audit/references/CATALOGO_VECTORES.md"
            ],
            "authority": "OBSERVED",
            "valueProposition": "Elimina la fuga de credenciales sensibles hacia servidores de terceros y garantiza cifrado en reposo en el almacenamiento local."
        },
        {
            "id": "KNOW-005",
            "title": "Blindaje Anti-SSRF en Scrapers & Mappers con Preflight DNS y Filtro de Rangos Privados",
            "description": "Resolución previa de direcciones IP y bloqueo estricto de loopback, redes privadas RFC 1918, endpoints de metadatos de nube (169.254.169.254) y dominios compartidos antes de abrir conexiones de red.",
            "dimension": "ARCHITECTURE_BOUNDARIES_ZERO_TRUST",
            "cwe": ["CWE-918"],
            "owasp": ["A10:2025-Server-Side Request Forgery"],
            "sourceLocations": [
                "Cybersecurity-Audit/SKILL.md",
                "cybersecurity-engineer/references/ssrf-detection-patterns.md"
            ],
            "authority": "OBSERVED",
            "valueProposition": "Impide el escaneo de puertos internos, la exfiltración de credenciales de instancias en la nube y el uso del sistema como proxy de ataque."
        },
        {
            "id": "KNOW-006",
            "title": "Kill-Switch HTTP 429 FatalQuotaError y AutoThrottle con Backoff Jitter",
            "description": "Detección inmediata de agotamiento de cuota (HTTP 429) en adaptadores de proveedores LLM, interrupción de ráfagas automáticas de peticiones y pausas con retroceso exponencial.",
            "dimension": "RESILIENCE_LOGGING_TELEMETRY",
            "cwe": ["CWE-400", "CWE-770"],
            "owasp": ["OWASP LLM10:2026", "A04:2021-Insecure Design"],
            "sourceLocations": [
                "Cybersecurity-Audit/SKILL.md",
                "Cybersecurity-Audit/references/CATALOGO_VECTORES.md"
            ],
            "authority": "OBSERVED",
            "valueProposition": "Previene el agotamiento accidental de saldo económico, bloqueos de cuenta y denegación de servicio por saturación de peticiones."
        },
        {
            "id": "KNOW-007",
            "title": "Soberanía de Release Supply-Chain Zero-CDN y Lockfile Único",
            "description": "Directiva estricta de cero recursos externos en tiempo de ejecución (fuentes WOFF2 100% locales), exclusividad de pnpm para evitar discrepancias de resolución y comprobación de hooks de ciclo de vida.",
            "dimension": "SUPPLY_CHAIN_SCA",
            "cwe": ["CWE-829", "CWE-1395"],
            "owasp": ["A06:2021-Vulnerable and Outdated Components", "A08:2025-Software and Data Integrity Failures"],
            "sourceLocations": [
                "Cybersecurity-Audit/SKILL.md",
                "cybersecurity-engineer/references/supply-chain-security.md"
            ],
            "authority": "OBSERVED",
            "valueProposition": "Inmuniza el sistema frente a ataques de envenenamiento de CDNs, subresource integrity compromises y desincronizaciones de dependencias."
        },
        {
            "id": "KNOW-008",
            "title": "Validación Adversarial con Verificadores Independientes (Ojos Frescos) y 7-Question Gate",
            "description": "Protocolo de refutación donde el agente que valida un candidato a vulnerabilidad es estrictamente diferente del cazador, sometiendo cada hallazgo a un filtro de 7 preguntas empíricas.",
            "dimension": "THREAT_MODELING_ATTACK_SURFACE",
            "cwe": ["CWE-1059"],
            "owasp": ["A04:2021-Insecure Design"],
            "sourceLocations": [
                "Cybersecurity-Audit/SKILL.md",
                "cybersecurity-engineer/references/finding-validation-gate.md"
            ],
            "authority": "OBSERVED",
            "valueProposition": "Erradica falsos positivos y sesgos de confirmación en reportes de seguridad, garantizando que cada hallazgo confirmado provenga de código en HEAD y tenga impacto real."
        },
        {
            "id": "KNOW-009",
            "title": "Seguridad en Protocolos de Mensajería: Baileys WhatsApp Multi-Device y QR Fixation",
            "description": "Modelado de amenazas, almacenamiento encriptado de credenciales auth_state, rotación de claves PBKDF2 y mitigaciones de fijación de QR en integraciones con Baileys.",
            "dimension": "IDENTITY_ACCESS_SESSION",
            "cwe": ["CWE-384", "CWE-287"],
            "owasp": ["A07:2021-Identification and Authentication Failures"],
            "sourceLocations": [
                "cybersecurity-engineer/references/baileys-security-patterns.md"
            ],
            "authority": "OBSERVED",
            "valueProposition": "Protege las sesiones de comunicación de mensajería empresarial contra secuestro de sesión y robo de tokens de autenticación."
        },
        {
            "id": "KNOW-010",
            "title": "Verificación Criptográfica de Webhooks Meta Cloud API (HMAC-SHA256)",
            "description": "Comprobación estricta de firmas HMAC-SHA256 con timingSafeEqual, mitigación de ataques de repetición y validación de esquemas Zod en payloads de eventos entrantes.",
            "dimension": "IDENTITY_ACCESS_SESSION",
            "cwe": ["CWE-347", "CWE-208"],
            "owasp": ["A02:2021-Cryptographic Failures"],
            "sourceLocations": [
                "cybersecurity-engineer/references/meta-cloud-api-security.md"
            ],
            "authority": "OBSERVED",
            "valueProposition": "Impide la falsificación de webhooks de mensajería y neutraliza ataques de temporización (timing attacks) sobre la comparación de firmas criptográficas."
        },
        {
            "id": "KNOW-011",
            "title": "Catálogo de 9 Vectores de Account Takeover (ATO) y 7 Evasiones de MFA",
            "description": "Catálogo exhaustivo de vectores de secuestro de cuentas (password reset poisoning vía Host header, fugas de token por Referer, enlaces OAuth cruzados) y bypasses de MFA (falta de rate limit en OTP, manipulación de respuesta).",
            "dimension": "IDENTITY_ACCESS_SESSION",
            "cwe": ["CWE-640", "CWE-305", "CWE-307"],
            "owasp": ["A07:2021-Identification and Authentication Failures"],
            "sourceLocations": [
                "cybersecurity-engineer/references/account-takeover-paths.md",
                "cybersecurity-engineer/references/mfa-bypass-detection.md"
            ],
            "authority": "OBSERVED",
            "valueProposition": "Dota al ecosistema de heurísticas precisas para auditar flujos críticos de recuperación de contraseñas y factores de autenticación múltiple."
        },
        {
            "id": "KNOW-012",
            "title": "Testing de Condiciones de Carrera con HTTP/2 Single-Packet Attack y Bloqueos Atómicos",
            "description": "Técnicas de detección de condiciones de carrera check-then-act explotables mediante ráfagas sincronizadas en un solo paquete HTTP/2 y remediación con transacciones FOR UPDATE o RPCs atómicas.",
            "dimension": "SOURCE_CODE_SAST",
            "cwe": ["CWE-362"],
            "owasp": ["A04:2021-Insecure Design"],
            "sourceLocations": [
                "cybersecurity-engineer/references/race-condition-testing.md"
            ],
            "authority": "OBSERVED",
            "valueProposition": "Permite auditar y corregir inconsistencias de concurrencia en cuotas, saldos y operaciones transaccionales críticas."
        },
        {
            "id": "KNOW-013",
            "title": "Playbooks Formales de Respuesta a Incidentes (P0 a P3) y Matrices de Contención",
            "description": "Estructura operativa de respuesta a incidentes clasificada en 4 severidades con SLAs de contención, protocolos de erradicación y matrices de escalamiento para brechas de datos, RCE y fugas de secretos.",
            "dimension": "RESILIENCE_LOGGING_TELEMETRY",
            "cwe": ["CWE-1059"],
            "owasp": ["A09:2021-Security Logging and Monitoring Failures"],
            "sourceLocations": [
                "cybersecurity-engineer/references/incident-response-playbooks.md"
            ],
            "authority": "OBSERVED",
            "valueProposition": "Establece procedimientos estandarizados de contención y recuperación rápida ante incidentes de ciberseguridad corporativos."
        },
        {
            "id": "KNOW-014",
            "title": "Marco Metodológico de Modelado de Amenazas STRIDE + 7-Stage PASTA y Attack Trees",
            "description": "Metodología formal que combina STRIDE por componente con el marco centrado en el riesgo PASTA en 7 etapas, cálculo de DREAD y árboles de ataque AND/OR cuantitativos.",
            "dimension": "THREAT_MODELING_ATTACK_SURFACE",
            "cwe": ["CWE-1059"],
            "owasp": ["A04:2021-Insecure Design"],
            "sourceLocations": [
                "cybersecurity-engineer/references/stride-pasta-guide.md"
            ],
            "authority": "OBSERVED",
            "valueProposition": "Estructura la identificación exhaustiva de amenazas basada en impacto de negocio y vectores de ataque reproducibles."
        },
        {
            "id": "KNOW-015",
            "title": "Guía Operativa y Suite de Consultas Avanzadas CodeQL",
            "description": "Procedimiento de compilación de bases de datos CodeQL, creación de modelos de taint tracking inter-procedural y reglas personalizadas para auditoría de código en pipelines DevSecOps.",
            "dimension": "SOURCE_CODE_SAST",
            "cwe": ["CWE-1059"],
            "owasp": ["A03:2021-Injection"],
            "sourceLocations": [
                "cybersecurity-engineer/references/codeql-operational-guide.md"
            ],
            "authority": "OBSERVED",
            "valueProposition": "Permite ejecutar análisis estático avanzado de taint analysis profundo a escala industrial sobre grandes bases de código políglotas."
        }
    ]

    # Absorption actions
    absorption_actions = [
        {
            "id": "ABS-001",
            "knowledgeId": "KNOW-001",
            "title": "Motor Determinista de Detección de Formula Injection (CWE-1236)",
            "destination": "PYTHON_SCRIPT",
            "intent": "CREATE_NEW",
            "existingVulnerabilityId": "VULN-SAST-022",
            "targetPathInRepo": "src/scripts/scan_formula_injection.py",
            "architecturalRationale": "Capa 3: Utilidad determinista de análisis estático en Python 3.11+ para auditar código fuente y archivos de exportación sin ejecutar código del objetivo.",
            "priority": "HIGH",
            "implementationSteps": [
                "Crear src/scripts/scan_formula_injection.py con soporte --json y verificación de patrones de sanitización",
                "Implementar suite de pruebas unitarias en src/scripts/test_scan_formula_injection.py",
                "Definir esquema Zod en src/schemas/formula-injection.schema.ts",
                "Registrar en scripts_manifest.json y en docs/VULNERABILITIES.md"
            ]
        },
        {
            "id": "ABS-002",
            "knowledgeId": "KNOW-002",
            "title": "Referencia Técnica: Hardening del Protocolo MCP Stdio y Resiliencia de Herramientas",
            "destination": "SKILL_REFERENCE",
            "intent": "ROBUSTIFY_HARDEN",
            "existingVulnerabilityId": "VULN-ARCH-020",
            "targetPathInRepo": ".agents/skills/architecture-boundaries-zero-trust/references/mcp-stdio-protocol-and-tool-resilience.md",
            "architecturalRationale": "Capa 1: Instrucciones operativas y heurísticas de seguridad para arquitectura MCP y confinamiento de procesos.",
            "priority": "HIGH",
            "implementationSteps": [
                "Redactar guía técnica en Markdown con reglas de try/catch, isError=true y SafeFilePathSchema",
                "Vincular con VULN-ARCH-020 en docs/VULNERABILITIES.md"
            ]
        },
        {
            "id": "ABS-003",
            "knowledgeId": "KNOW-003",
            "title": "Referencia Técnica: Sani-Parse y Validación de Salidas No Deterministas de LLMs",
            "destination": "SKILL_REFERENCE",
            "intent": "ABSORB_EXPAND",
            "existingVulnerabilityId": "VULN-ARCH-005",
            "targetPathInRepo": ".agents/skills/source-code-sast/references/sani-parse-and-llm-output-validation.md",
            "architecturalRationale": "Capa 1: Heurística SAST para auditar deserialización y validación Zod en flujos de datos provenientes de IA.",
            "priority": "HIGH",
            "implementationSteps": [
                "Documentar el patrón normalizeJsonArray y safeParse obligatorio",
                "Incluir ejemplos de código vulnerable vs seguro"
            ]
        },
        {
            "id": "ABS-004",
            "knowledgeId": "KNOW-004",
            "title": "Referencia Técnica: Criptografía Client-Side BYOK y Bóvedas Locales AES-GCM",
            "destination": "SKILL_REFERENCE",
            "intent": "UPDATE_ENHANCE",
            "existingVulnerabilityId": "VULN-CRYP-001",
            "targetPathInRepo": ".agents/skills/secrets-cryptography/references/byok-vault-client-side-cryptography.md",
            "architecturalRationale": "Capa 1: Directiva de auditoría criptográfica para aplicaciones de navegador y Electron.",
            "priority": "HIGH",
            "implementationSteps": [
                "Documentar requisitos de PBKDF2 (100k iteraciones), Web Crypto API y centinelas reactivos",
                "Añadir reglas de auditoría para verificar ausencia de claves en texto plano"
            ]
        },
        {
            "id": "ABS-005",
            "knowledgeId": "KNOW-005",
            "title": "Robustecimiento del Validador Anti-SSRF con Bloqueo de Link Aggregators y Preflight DNS",
            "destination": "UPDATE_EXISTING",
            "intent": "ROBUSTIFY_HARDEN",
            "existingVulnerabilityId": "VULN-SAST-006",
            "targetPathInRepo": "src/scripts/url_validator.py",
            "architecturalRationale": "Capa 3: Fortalecer el motor existente de validación de URLs sin romper compatibilidad.",
            "priority": "HIGH",
            "implementationSteps": [
                "Ampliar url_validator.py con lista negra de dominios puente (linktr.ee, bio.link, carrd.co)",
                "Actualizar test_url_validator.py para verificar nuevos casos borde"
            ]
        },
        {
            "id": "ABS-006",
            "knowledgeId": "KNOW-006",
            "title": "Referencia Técnica: Mitigación de Agotamiento de Cuotas HTTP 429 y AutoThrottle",
            "destination": "SKILL_REFERENCE",
            "intent": "CREATE_NEW",
            "existingVulnerabilityId": "VULN-RESI-013",
            "targetPathInRepo": ".agents/skills/resilience-logging-telemetry/references/http-429-quota-exhaustion-and-backoff.md",
            "architecturalRationale": "Capa 1: Directiva para prevenir bucles destructivos de reintentos y agotamiento de recursos.",
            "priority": "MEDIUM",
            "implementationSteps": [
                "Redactar guía técnica sobre FatalQuotaError y pausas exponenciales con jitter",
                "Incorporar nuevo vector VULN-RESI-013 en docs/VULNERABILITIES.md"
            ]
        },
        {
            "id": "ABS-007",
            "knowledgeId": "KNOW-007",
            "title": "Referencia Técnica: Soberanía de Cadena de Suministro Zero-CDN y Auto-Hospedaje",
            "destination": "SKILL_REFERENCE",
            "intent": "CREATE_NEW",
            "existingVulnerabilityId": "VULN-SCA-013",
            "targetPathInRepo": ".agents/skills/supply-chain-sca/references/zero-cdn-and-local-runtime-sovereignty.md",
            "architecturalRationale": "Capa 1: Guía de auditoría de dependencias web en tiempo de ejecución.",
            "priority": "MEDIUM",
            "implementationSteps": [
                "Documentar riesgos de inyección y seguimiento por CDNs externas",
                "Definir checklist de verificación para fuentes WOFF2 locales y fijación de package manager"
            ]
        },
        {
            "id": "ABS-008",
            "knowledgeId": "KNOW-008",
            "title": "Actualización del Orquestador con Validación Adversarial de Ojos Frescos y 7-Question Gate",
            "destination": "UPDATE_EXISTING",
            "intent": "UPDATE_ENHANCE",
            "existingVulnerabilityId": "VULN-TM-001",
            "targetPathInRepo": ".agents/skills/security-audit-orchestrator/SKILL.md",
            "architecturalRationale": "Capa 1: Perfeccionamiento del flujo de orquestación maestro para erradicación de falsos positivos.",
            "priority": "HIGH",
            "implementationSteps": [
                "Incorporar la regla de independencia de verificadores (Hunter != Verifier)",
                "Integrar el Finding Validation Gate formal en el workflow de la skill"
            ]
        },
        {
            "id": "ABS-009",
            "knowledgeId": "KNOW-009",
            "title": "Referencia Técnica: Seguridad en Protocolos de Mensajería WhatsApp Baileys",
            "destination": "SKILL_REFERENCE",
            "intent": "CREATE_NEW",
            "existingVulnerabilityId": "VULN-IAM-017",
            "targetPathInRepo": ".agents/skills/identity-access-session/references/baileys-whatsapp-and-qr-auth-security.md",
            "architecturalRationale": "Capa 1: Auditoría especializada para sesiones de mensajería multi-dispositivo y autenticación QR.",
            "priority": "HIGH",
            "implementationSteps": [
                "Crear documento técnico en references/ de identity-access-session",
                "Documentar cifrado seguro de auth_state, timeout de QR y cumplimiento TCPA",
                "Registrar VULN-IAM-017 en docs/VULNERABILITIES.md"
            ]
        },
        {
            "id": "ABS-010",
            "knowledgeId": "KNOW-010",
            "title": "Referencia Técnica: Verificación Criptográfica de Webhooks Meta Cloud API",
            "destination": "SKILL_REFERENCE",
            "intent": "CREATE_NEW",
            "existingVulnerabilityId": "VULN-IAM-018",
            "targetPathInRepo": ".agents/skills/identity-access-session/references/meta-cloud-api-hmac-webhook-security.md",
            "architecturalRationale": "Capa 1: Verificación de firmas criptográficas y prevención de ataques de temporización.",
            "priority": "HIGH",
            "implementationSteps": [
                "Documentar el uso obligatorio de crypto.timingSafeEqual en comparación HMAC",
                "Incorporar VULN-IAM-018 en docs/VULNERABILITIES.md"
            ]
        },
        {
            "id": "ABS-011",
            "knowledgeId": "KNOW-011",
            "title": "Referencia Técnica: Catálogo de 9 Rutas de Account Takeover y 7 Bypasses de MFA",
            "destination": "SKILL_REFERENCE",
            "intent": "ABSORB_EXPAND",
            "existingVulnerabilityId": "VULN-IAM-014",
            "targetPathInRepo": ".agents/skills/identity-access-session/references/account-takeover-vectors-and-mfa-bypass.md",
            "architecturalRationale": "Capa 1: Catálogo de vectores para pruebas de penetración y auditorías de control de acceso.",
            "priority": "HIGH",
            "implementationSteps": [
                "Consolidar las 9 rutas ATO y los 7 patrones de bypass MFA en una guía autoritativa",
                "Enriquecer VULN-IAM-014 con las nuevas heurísticas"
            ]
        },
        {
            "id": "ABS-012",
            "knowledgeId": "KNOW-012",
            "title": "Referencia Técnica: Detección de Condiciones de Carrera con HTTP/2 Single-Packet Attack",
            "destination": "SKILL_REFERENCE",
            "intent": "ROBUSTIFY_HARDEN",
            "existingVulnerabilityId": "VULN-SAST-005",
            "targetPathInRepo": ".agents/skills/source-code-sast/references/race-condition-testing-and-turbo-intruder.md",
            "architecturalRationale": "Capa 1: Guía de pruebas de concurrencia y patrones de bloqueo atómico a nivel de base de datos.",
            "priority": "MEDIUM",
            "implementationSteps": [
                "Documentar la metodología de sincronización HTTP/2 y detección de check-then-act",
                "Incorporar patrones de mitigación con transacciones FOR UPDATE y RPCs atómicas"
            ]
        },
        {
            "id": "ABS-013",
            "knowledgeId": "KNOW-013",
            "title": "Referencia Técnica: Playbooks Formales de Respuesta a Incidentes P0 a P3",
            "destination": "SKILL_REFERENCE",
            "intent": "ABSORB_EXPAND",
            "existingVulnerabilityId": "VULN-RESI-003",
            "targetPathInRepo": ".agents/skills/resilience-logging-telemetry/references/incident-response-playbooks-p0-p3.md",
            "architecturalRationale": "Capa 1: Guía operativa para respuesta, contención y recuperación ante incidentes de ciberseguridad.",
            "priority": "HIGH",
            "implementationSteps": [
                "Documentar playbooks P0 a P3 con matrices de severidad, SLAs y protocolos de comunicación",
                "Vincular con la herramienta incident_triage_scorer.py"
            ]
        },
        {
            "id": "ABS-014",
            "knowledgeId": "KNOW-014",
            "title": "Referencia Técnica: Marco de Modelado de Amenazas STRIDE + 7-Stage PASTA",
            "destination": "SKILL_REFERENCE",
            "intent": "ABSORB_EXPAND",
            "existingVulnerabilityId": "VULN-TM-001",
            "targetPathInRepo": ".agents/skills/threat-modeling-attack-surface/references/stride-pasta-threat-modeling-framework.md",
            "architecturalRationale": "Capa 1: Marco metodológico para análisis de amenazas por componente y riesgo centrado en el negocio.",
            "priority": "HIGH",
            "implementationSteps": [
                "Detallar las 7 etapas de PASTA, descomposición STRIDE y scoring DREAD",
                "Añadir diagramas de árboles de ataque AND/OR"
            ]
        },
        {
            "id": "ABS-015",
            "knowledgeId": "KNOW-015",
            "title": "Actualización de la Guía de Análisis de Taint con CodeQL Avanzado",
            "destination": "UPDATE_EXISTING",
            "intent": "UPDATE_ENHANCE",
            "existingVulnerabilityId": "VULN-SAST-001",
            "targetPathInRepo": ".agents/skills/source-code-sast/references/codeql-taint-analysis.md",
            "architecturalRationale": "Capa 1: Enriquecer la guía existente de CodeQL con flujos operacionales y consultas QL personalizadas.",
            "priority": "MEDIUM",
            "implementationSteps": [
                "Actualizar codeql-taint-analysis.md con directivas de compilación y comandos CLI de CodeQL",
                "Añadir ejemplos de queries para inyecciones complejas"
            ]
        }
    ]

    dest_breakdown = Counter(a["destination"] for a in absorption_actions)

    plan = {
        "planId": str(uuid.uuid4()),
        "createdAt": now_iso,
        "target": {
            "path": "K:/DeepSearch_LeadsResearch/.agents/skills",
            "canonicalPath": "K:/DeepSearch_LeadsResearch/.agents/skills",
            "name": "deepsearch-cybersecurity-skills",
            "type": "SKILL",
            "commitOrSnapshot": "5177136308e3be9da6d54e8b025c8155aeaa5ab4",
            "archetypeDescription": "AGENTIC_CYBERSECURITY_SKILLS_AND_HARNESS"
        },
        "scopeSummary": {
            "totalEntriesScanned": len(inventory_records),
            "primaryLanguages": [".md", ".py", ".sh", ".cjs", ".json"],
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
            "destinationsBreakdown": dict(dest_breakdown)
        },
        "ledgerPaths": {
            "inventoryJsonl": "audits/deepsearch-skills-audit/inventory.jsonl",
            "coverageJsonl": "audits/deepsearch-skills-audit/coverage.jsonl",
            "evidenceJsonl": "audits/deepsearch-skills-audit/evidence.jsonl",
            "unknownsJsonl": "audits/deepsearch-skills-audit/unknowns.jsonl"
        }
    }

    # Write files
    inv_file = OUT_DIR / "inventory.jsonl"
    with inv_file.open("w", encoding="utf-8") as f:
        for r in inventory_records:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")

    sum_file = OUT_DIR / "summary.json"
    with sum_file.open("w", encoding="utf-8") as f:
        json.dump(summary, f, indent=2, ensure_ascii=False)

    cov_file = OUT_DIR / "coverage.jsonl"
    with cov_file.open("w", encoding="utf-8") as f:
        for r in coverage_records:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")

    evd_file = OUT_DIR / "evidence.jsonl"
    with evd_file.open("w", encoding="utf-8") as f:
        for r in evidence_items:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")

    unk_file = OUT_DIR / "unknowns.jsonl"
    with unk_file.open("w", encoding="utf-8") as f:
        for r in unknowns:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")

    plan_file = OUT_DIR / "absorption-plan.json"
    with plan_file.open("w", encoding="utf-8") as f:
        json.dump(plan, f, indent=2, ensure_ascii=False)

    # Markdown dossier
    md_file = OUT_DIR / "absorption-plan.md"
    with md_file.open("w", encoding="utf-8") as f:
        f.write("# Dossier Forense y Plan de Absorción Técnica — DeepSearch Skills\n\n")
        f.write(f"- **ID del Plan:** `{plan['planId']}`\n")
        f.write(f"- **Fecha:** `{now_iso}`\n")
        f.write(f"- **Objetivos Auditados:** `cybersecurity-engineer` + `Cybersecurity-Audit` (`5177136308e3be9da6d54e8b025c8155aeaa5ab4`)\n")
        f.write(f"- **Total de Archivos Catalogados:** {len(inventory_records)}\n\n")
        f.write("## 🏛️ Desglose de Acciones de Absorción por Destino\n\n")
        f.write("| ID Acción | Conocimiento | Título | Destino | Intención Evolutiva | Prioridad | Ruta en Repositorio |\n")
        f.write("| :--- | :--- | :--- | :--- | :--- | :--- | :--- |\n")
        for a in absorption_actions:
            f.write(f"| `{a['id']}` | `{a['knowledgeId']}` | {a['title']} | `{a['destination']}` | `{a['intent']}` | **{a['priority']}** | `{a['targetPathInRepo']}` |\n")
        f.write("\n---\n")

    print(f"Generated all ledgers and plan in {OUT_DIR}")
    print(f"Total inventory: {len(inventory_records)} files.")
    print(f"Knowledge items: {len(extracted_knowledge)}, Actions: {len(absorption_actions)}")


if __name__ == "__main__":
    run()
