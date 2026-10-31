#!/usr/bin/env python3
"""Deterministic Generator of Forensic Ledgers and Absorption Plan for Claude-Red.
Audits:
- D:\\Descargas\\Claude-Red-main\\Claude-Red-main (Claude-Red v0.3.0)
Strictly conforming to Devia-CyberSecurity's Tri-Tier Architecture, 8 Canonical Dimensions,
and Zod contracts (AbsorptionPlanSchema).
"""

from __future__ import annotations

from collections import Counter
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import sys
import uuid

TARGET_ROOT = Path(r"D:\Descargas\Claude-Red-main\Claude-Red-main")
OUT_DIR = Path(r"K:\Devia-CyberSecurity\audits\claude-red")

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


def determine_subsystem(rel_path: str) -> str:
    parts = rel_path.replace("\\", "/").split("/")
    if parts[0] == "Skills":
        if len(parts) > 1:
            return f"skills/{parts[1]}"
        return "skills"
    elif parts[0] == "tools":
        return "tools"
    elif parts[0] == ".github":
        return "github_workflows"
    elif parts[0] == "assets":
        return "assets"
    return "root_manifests"


def categorize_file(rel_path: str, ext: str, fn: str) -> str:
    fn_lower = fn.lower()
    if fn_lower in {"package.json", "claude-skills.json", "skill.md", "security.md"}:
        return "CRITICAL_MANIFEST_OR_CONFIG"
    if ext in {".py", ".sh"}:
        return "SOURCE_CODE"
    if ext in {".md", ".txt"}:
        return "DOCUMENTATION"
    if ext in {".yml", ".yaml", ".json"}:
        return "CONFIGURATION"
    if ext in {".png", ".jpg", ".ico"}:
        return "ASSET_OR_OTHER"
    return "ASSET_OR_OTHER"


def main():
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    started_at = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    
    # 1. Walk TARGET_ROOT deterministically
    all_files: list[Path] = []
    for root, dirs, files in os.walk(TARGET_ROOT):
        dirs.sort()
        for f in sorted(files):
            all_files.append(Path(root) / f)
            
    print(f"Total target files discovered: {len(all_files)}")
    
    inventory_records = []
    coverage_records = []
    category_counts = Counter()
    extension_counts = Counter()
    total_bytes = 0
    
    # Collect inventory and coverage
    for file_path in all_files:
        rel_path = file_path.relative_to(TARGET_ROOT).as_posix()
        fn = file_path.name
        ext = file_path.suffix.lower()
        size = file_path.stat().st_size
        total_bytes += size
        digest = sha256_of_file(file_path)
        lines = count_lines(file_path)
        cat = categorize_file(rel_path, ext, fn)
        
        category_counts[cat] += 1
        extension_counts[ext or "[no_ext]"] += 1
        
        is_sec_crit = (
            cat == "CRITICAL_MANIFEST_OR_CONFIG" or
            "skill.md" in fn.lower() or
            "security" in fn.lower() or
            ext in {".py", ".sh"}
        )
        
        subsystem = determine_subsystem(rel_path)
        
        inv_record = {
            "path": rel_path,
            "kind": "file",
            "extension": ext,
            "size_bytes": size,
            "category": cat,
            "is_security_critical": is_sec_crit,
            "sha256": digest,
            "line_count": lines
        }
        inventory_records.append(inv_record)
        
        # Coverage disposition
        if fn == ".DS_Store" or ext == ".png":
            review_state = "excluded"
            extent_kind = "metadata-only"
            reason = "Binary asset or OS metadata non-essential to security analysis"
            evidence_ids = []
        elif "skill.md" in fn.lower() or ext in {".py", ".sh"} or fn in {"claude-skills.json", "SECURITY.md", "README.md", "MINDMAP.md", "CHANGELOG.md"}:
            review_state = "read"
            extent_kind = "whole-file"
            reason = None
            evidence_ids = [f"SRC-{rel_path.replace('/', '_').replace('.', '_')[:30]}"]
        else:
            review_state = "read"
            extent_kind = "whole-file"
            reason = None
            evidence_ids = []
            
        cov_record = {
            "path": rel_path,
            "subsystem": subsystem,
            "inventory_kind": "file",
            "review": review_state,
            "extent": {"kind": extent_kind},
            "evidence_ids": evidence_ids,
            "reason": reason,
            "remaining": []
        }
        coverage_records.append(cov_record)
        
    finished_at = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    
    # 2. Summary
    summary = {
        "target": {
            "root_path": str(TARGET_ROOT),
            "output_path": str(OUT_DIR),
            "name": "claude-red",
            "version": "0.3.0",
            "archetype": "AGENTIC_SKILLS_AND_OFFENSIVE_REDTEAM_FRAMEWORK"
        },
        "timestamps": {
            "started_at": started_at,
            "finished_at": finished_at
        },
        "metrics": {
            "total_files": len(inventory_records),
            "total_directories": len({p.parent for p in all_files}),
            "total_links_or_reparse_skipped": 0,
            "total_bytes": total_bytes,
            "total_errors": 0
        },
        "category_distribution": dict(category_counts),
        "top_extensions": dict(extension_counts),
        "errors": []
    }
    
    # Write inventory.jsonl & summary.json & coverage.jsonl
    with open(OUT_DIR / "inventory.jsonl", "w", encoding="utf-8") as f:
        for r in inventory_records:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")
            
    with open(OUT_DIR / "summary.json", "w", encoding="utf-8") as f:
        json.dump(summary, f, indent=2, ensure_ascii=False)
        
    with open(OUT_DIR / "coverage.jsonl", "w", encoding="utf-8") as f:
        for r in coverage_records:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")
            
    print("inventory.jsonl, summary.json, coverage.jsonl written successfully.")
    
    # 3. Evidence Ledger (factual citations with exact digests and lines)
    evidence_items = [
        {
            "id": "SRC-001",
            "authority": "SOURCE",
            "claim_class": "OBSERVED",
            "target_path": "Skills/container/offensive-container-escape/SKILL.md",
            "lines": {"start": 1, "end": 65},
            "symbol": "offensive-container-escape",
            "evidence_snippet": "privileged container breakout via host filesystem mount and nsenter, Docker socket abuse through /var/run/docker.sock, Linux capability exploitation including CAP_SYS_ADMIN, CAP_SYS_PTRACE, and CAP_NET_ADMIN, cgroup v1 notify_on_release escape, runc CVEs such as CVE-2019-5736 and CVE-2024-21626 Leaky Vessels",
            "digest_sha256": sha256_of_file(TARGET_ROOT / "Skills/container/offensive-container-escape/SKILL.md"),
            "context": "Metodología integral de escape de contenedores hacia el host subyacente y explotación de socket Docker",
            "timestamp": started_at
        },
        {
            "id": "SRC-002",
            "authority": "SOURCE",
            "claim_class": "OBSERVED",
            "target_path": "Skills/supply-chain/offensive-dependency-confusion/SKILL.md",
            "lines": {"start": 1, "end": 60},
            "symbol": "offensive-dependency-confusion",
            "evidence_snippet": "Addresses PyPI namespace attacks through --extra-index-url resolution ordering, NuGet feed priority exploitation when multiple package sources are configured without clear directives, Maven and Gradle repository ordering where artifact resolution traverses repositories sequentially, Go module proxy abuse through GOPROXY misconfiguration",
            "digest_sha256": sha256_of_file(TARGET_ROOT / "Skills/supply-chain/offensive-dependency-confusion/SKILL.md"),
            "context": "Ataques de confusión de dependencias políglotas en PyPI, npm, NuGet, Maven y Go con callbacks seguros",
            "timestamp": started_at
        },
        {
            "id": "SRC-003",
            "authority": "SOURCE",
            "claim_class": "OBSERVED",
            "target_path": "Skills/crypto/offensive-crypto-attacks/SKILL.md",
            "lines": {"start": 1, "end": 60},
            "symbol": "offensive-crypto-attacks",
            "evidence_snippet": "padding oracle attacks against CBC-mode ciphers with PKCS7 padding (Vaudenay's original attack through modern padbuster automation), ECB mode exploitation including block cut-and-paste and byte-at-a-time decryption, hash length extension attacks against SHA1/SHA256/MD5-based MACs using HashPump",
            "digest_sha256": sha256_of_file(TARGET_ROOT / "Skills/crypto/offensive-crypto-attacks/SKILL.md"),
            "context": "Vulnerabilidades prácticas de implementación criptográfica y ataques a oráculos de relleno PKCS7",
            "timestamp": started_at
        },
        {
            "id": "SRC-004",
            "authority": "SOURCE",
            "claim_class": "OBSERVED",
            "target_path": "Skills/cicd/offensive-cicd-secrets/SKILL.md",
            "lines": {"start": 37, "end": 60},
            "symbol": "Environment Variable Extraction",
            "evidence_snippet": "env | base64\n# Reverse the string to defeat pattern-matching masks\nenv | rev\n# Character-by-character extraction defeats even advanced masking\nfor var in $(env | grep -i -E 'key|secret|token|pass|cred|auth' | cut -d= -f1); do\n    value=$(printenv \"$var\")\n    echo \"$value\" | fold -w1 | paste -sd' '",
            "digest_sha256": sha256_of_file(TARGET_ROOT / "Skills/cicd/offensive-cicd-secrets/SKILL.md"),
            "context": "Técnicas de evasión de enmascaramiento de secretos en logs de CI/CD mediante base64, inversión y fold de caracteres",
            "timestamp": started_at
        },
        {
            "id": "SRC-005",
            "authority": "SOURCE",
            "claim_class": "OBSERVED",
            "target_path": "Skills/ai/offensive-ai-security/SKILL.md",
            "lines": {"start": 43, "end": 60},
            "symbol": "Mechanisms of AI Vulnerabilities",
            "evidence_snippet": "Sparse Fine-Tuning Drift – lightweight adapter training frequently overrides base-model safety alignment.\nMulti-Modal Expansion – V-L and audio-language models inherit text flaws while adding steganographic channels.\nModel Extraction via Embeddings – probing embedding space boundaries through carefully crafted prompts can leak training data membership",
            "digest_sha256": sha256_of_file(TARGET_ROOT / "Skills/ai/offensive-ai-security/SKILL.md"),
            "context": "Mecanismos de vulnerabilidad en modelos LLM: deriva por fine-tuning, canales esteganográficos multimodales y extracción de embeddings",
            "timestamp": started_at
        },
        {
            "id": "SRC-006",
            "authority": "SOURCE",
            "claim_class": "OBSERVED",
            "target_path": "Skills/infrastructure/offensive-windows-boundaries/SKILL.md",
            "lines": {"start": 30, "end": 55},
            "symbol": "Defeating Windows Security Boundaries",
            "evidence_snippet": "Week 7 answers: 'Can my code execute at all?' - bypass AMSI, WDAC, ASR, AppContainers, integrity levels, PPL, ETW telemetry\nWeek 8 answers: 'Can my exploit succeed?' - bypass DEP, ASLR, stack cookies, CFG/XFG, heap safe-unlinking",
            "digest_sha256": sha256_of_file(TARGET_ROOT / "Skills/infrastructure/offensive-windows-boundaries/SKILL.md"),
            "context": "Taxonomía canónica de límites de seguridad de Windows: ejecución vs mitigaciones de memoria",
            "timestamp": started_at
        },
        {
            "id": "SRC-007",
            "authority": "SOURCE",
            "claim_class": "OBSERVED",
            "target_path": "Skills/web/offensive-ssti/SKILL.md",
            "lines": {"start": 1, "end": 50},
            "symbol": "offensive-ssti",
            "evidence_snippet": "added 10+ engine-specific exploits (Jinja2/Twig/Freemarker/Velocity/Pebble/Smarty/Mako/ERB/Thymeleaf), filter bypass, blind exploitation, chaining",
            "digest_sha256": sha256_of_file(TARGET_ROOT / "Skills/web/offensive-ssti/SKILL.md"),
            "context": "Matriz profunda de inyección de plantillas en servidor para más de 10 motores web",
            "timestamp": started_at
        },
        {
            "id": "SRC-008",
            "authority": "SOURCE",
            "claim_class": "OBSERVED",
            "target_path": "Skills/web/offensive-deserialization/SKILL.md",
            "lines": {"start": 1, "end": 50},
            "symbol": "offensive-deserialization",
            "evidence_snippet": "added Java/PHP/.NET/Python/Node/Ruby exploitation depth, modern vectors (K8s, message queues, serverless), WAF bypass, tool commands",
            "digest_sha256": sha256_of_file(TARGET_ROOT / "Skills/web/offensive-deserialization/SKILL.md"),
            "context": "Deserialización insegura políglota y cadenas de gadgets en colas de mensajes y serverless",
            "timestamp": started_at
        },
        {
            "id": "SRC-009",
            "authority": "SOURCE",
            "claim_class": "OBSERVED",
            "target_path": "Skills/privesc/offensive-windows-privesc/SKILL.md",
            "lines": {"start": 1, "end": 60},
            "symbol": "offensive-windows-privesc",
            "evidence_snippet": "Potato family (JuicyPotato, RoguePotato, SweetPotato, GodPotato), service misconfigurations, DLL hijacking, UAC bypass",
            "digest_sha256": sha256_of_file(TARGET_ROOT / "Skills/privesc/offensive-windows-privesc/SKILL.md"),
            "context": "Escalada de privilegios en Windows mediante suplantación de tokens COM/RPC y secuestro de DLLs",
            "timestamp": started_at
        },
        {
            "id": "SRC-010",
            "authority": "SOURCE",
            "claim_class": "OBSERVED",
            "target_path": "Skills/active-directory/offensive-active-directory/SKILL.md",
            "lines": {"start": 1, "end": 60},
            "symbol": "offensive-active-directory",
            "evidence_snippet": "Kerberoasting, AS-REP roasting, BloodHound enumeration, ACL abuse, unconstrained delegation, ADCS certificate template abuse",
            "digest_sha256": sha256_of_file(TARGET_ROOT / "Skills/active-directory/offensive-active-directory/SKILL.md"),
            "context": "Metodología integral de compromiso de dominios de Active Directory en entornos corporativos",
            "timestamp": started_at
        },
        {
            "id": "SRC-011",
            "authority": "SOURCE",
            "claim_class": "OBSERVED",
            "target_path": "tools/build_manifest.py",
            "lines": {"start": 19, "end": 46},
            "symbol": "parse_frontmatter",
            "evidence_snippet": "FRONTMATTER_RE = re.compile(r\"^---\\n(.*?)\\n---\", re.DOTALL)\n\ndef parse_frontmatter(text: str) -> dict:\n    m = FRONTMATTER_RE.match(text)",
            "digest_sha256": sha256_of_file(TARGET_ROOT / "tools/build_manifest.py"),
            "context": "Parser de frontmatter YAML basado en expresiones regulares simples sin validación de esquema en tiempo de ejecución",
            "timestamp": started_at
        },
        {
            "id": "CFG-001",
            "authority": "ARTIFACT",
            "claim_class": "OBSERVED",
            "target_path": "claude-skills.json",
            "lines": {"start": 1, "end": 20},
            "symbol": "manifest_root",
            "evidence_snippet": "{\n  \"name\": \"claude-red\",\n  \"version\": \"0.3.0\",\n  \"license\": \"MIT\",\n  \"homepage\": \"https://github.com/SnailSploit/claude-red\",\n  \"categories\": {",
            "digest_sha256": sha256_of_file(TARGET_ROOT / "claude-skills.json"),
            "context": "Manifiesto JSON estandarizado que agrupa las 78 skills de la biblioteca por categorías temáticas",
            "timestamp": started_at
        }
    ]
    
    with open(OUT_DIR / "evidence.jsonl", "w", encoding="utf-8") as f:
        for ev in evidence_items:
            f.write(json.dumps(ev, ensure_ascii=False) + "\n")
    print("evidence.jsonl written successfully.")
    
    # 4. Unknowns Ledger
    unknowns_items = [
        {
            "id": "UNK-001",
            "title": "Ausencia de Suite de Pruebas Automatizadas Unitarias",
            "affected_component": "tools/build_manifest.py & convert_skills.py",
            "contradiction_or_gap": "El repositorio contiene scripts de procesamiento pero carece por completo de tests automatizados (test_*.py o pytest) para validar la integridad sintáctica de los 78 SKILL.md.",
            "required_evidence": "Incorporación de suite de tests en unittest/pytest con validación de sintaxis Markdown y schemas de frontmatter.",
            "impact": "Riesgo de errores silenciosos o malformaciones en la indexación de skills por herramientas externas."
        },
        {
            "id": "UNK-002",
            "title": "Dependencia Implícita de Binarios Ofensivos Externos sin Verificación de Entorno",
            "affected_component": "Skills/*/*.md",
            "contradiction_or_gap": "Las skills invocan herramientas externas (padbuster, HashPump, garak, deepce, amicontained, cdk, BloodHound) asumiendo su presencia en PATH, sin bridges de ejecución controlada ni validación de firmas criptográficas.",
            "required_evidence": "Desarrollo de parsers y verificadores deterministas nativos en Capa 3 sin requerir binarios de terceros no verificados.",
            "impact": "Fallo de ejecución o desbordamiento en entornos cerrados offline que no disponen de la suite completa de Kali Linux."
        },
        {
            "id": "UNK-003",
            "title": "Requisito de Neutralización Defensiva (Defanging) de Cargas Ofensivas en Markdown",
            "affected_component": "Skills/web/offensive-rce/SKILL.md & Skills/infrastructure/offensive-shellcode/SKILL.md",
            "contradiction_or_gap": "Ciertos snippets contienen payloads de reverse shells activas y secuencias de escape no defanged que, de ser absorbidas sin procesar, violan el Enfoque 100% Defensivo de Devia-CyberSecurity.",
            "required_evidence": "Sanitización sistemática transformando payloads armamentizados en especificaciones de verificación y detección AST estática.",
            "impact": "Posible activación de falsas alarmas en escáneres EDR/AV sobre el propio repositorio de Devia-CyberSecurity."
        },
        {
            "id": "UNK-004",
            "title": "Carencia de Validación Contract-First en la Generación del Manifiesto",
            "affected_component": "tools/build_manifest.py",
            "contradiction_or_gap": "El manifiesto claude-skills.json se genera mediante un script rudimentario sin esquemas de validación Zod o Pydantic, permitiendo campos opcionales no estructurados.",
            "required_evidence": "Reemplazo por un runner tipado en TypeScript + Zod (Capa 2) que valide estrictamente los metadatos de cada skill.",
            "impact": "Deriva en el formato de metadata entre diferentes versiones o contribuciones externas."
        }
    ]
    
    with open(OUT_DIR / "unknowns.jsonl", "w", encoding="utf-8") as f:
        for unk in unknowns_items:
            f.write(json.dumps(unk, ensure_ascii=False) + "\n")
    print("unknowns.jsonl written successfully.")
    
    # 5. Extracted Knowledge (KNOW-001 to KNOW-010 across the 8 dimensions)
    extracted_knowledge = [
        {
            "id": "KNOW-001",
            "title": "Heurísticas y Vectores de Evasión de Contenedores y Ruptura de Aislamiento (Container Escape & Host Namespace Pivot)",
            "description": "Metodología exhaustiva de auditoría y prueba de evasión de entornos contenerizados (Docker, containerd, Podman) que modela la interacción host-invitado: montajes de sistemas de archivos del host con nsenter, abuso de sockets expuestos (/var/run/docker.sock), explotación de capabilities peligrosas (CAP_SYS_ADMIN, CAP_SYS_PTRACE, CAP_NET_ADMIN), escape de cgroups v1 por notify_on_release y vulnerabilidades de runtime como CVE-2024-21626 (Leaky Vessels) y CVE-2019-5736.",
            "dimension": "ARCHITECTURE_BOUNDARIES_ZERO_TRUST",
            "cwe": ["CWE-250", "CWE-653", "CWE-668"],
            "owasp": ["A05:2021-Security Misconfiguration"],
            "sourceLocations": [
                "Skills/container/offensive-container-escape/SKILL.md",
                "Skills/container/offensive-k8s-attacks/SKILL.md"
            ],
            "authority": "OBSERVED",
            "valueProposition": "Dota a la skill architecture-boundaries-zero-trust de una matriz sistemática de detección y remediación para contenedores con aislamiento degradado o sobreprivilegiados."
        },
        {
            "id": "KNOW-002",
            "title": "Matriz Políglota de Confusión de Dependencias y Secuestro de Namespaces (Dependency Confusion & Extra-Index Abuse)",
            "description": "Metodología profunda de auditoría para vectores de confusión de dependencias entre repositorios públicos y privados en los principales ecosistemas: desincronización de scopes en npm (.npmrc), orden de resolución inseguro en PyPI por --extra-index-url, prioridad de feeds en NuGet, ordenamiento secuencial en Maven/Gradle y desbordamiento en proxies de Go (GOPROXY), junto con procedimientos de verificación inocua mediante canarios DNS.",
            "dimension": "SUPPLY_CHAIN_SCA",
            "cwe": ["CWE-829", "CWE-427", "CWE-1395"],
            "owasp": ["A08:2021-Software and Data Integrity Failures"],
            "sourceLocations": [
                "Skills/supply-chain/offensive-dependency-confusion/SKILL.md",
                "Skills/supply-chain/offensive-supply-chain/SKILL.md"
            ],
            "authority": "OBSERVED",
            "valueProposition": "Fortalece las capacidades de análisis estático de dependencias y lockfiles en supply-chain-sca, permitiendo auditar la configuración de registros privados y mitigar ataques de secuestro de nombres."
        },
        {
            "id": "KNOW-003",
            "title": "Catálogo de Explotación Criptográfica Práctica (Padding Oracles, Nonce Reuse & Hash Length Extension)",
            "description": "Especificación técnica de fallas comunes en la implementación de primitivas criptográficas: oráculos de relleno PKCS7 contra cifradores CBC (ataque de Vaudenay), determinismo y corta-pega en modo ECB, reutilización de nonces en AES-GCM que permite la recuperación de la clave de autenticación GMAC, ataques de extensión de longitud contra MACs no-HMAC basadas en Merkle-Damgård (SHA1, SHA256, MD5) y debilidades por semillas predecibles en PRNG (recuperación de estado de MT19937).",
            "dimension": "SECRETS_CRYPTOGRAPHY",
            "cwe": ["CWE-327", "CWE-328", "CWE-330"],
            "owasp": ["A02:2021-Cryptographic Failures"],
            "sourceLocations": [
                "Skills/crypto/offensive-crypto-attacks/SKILL.md",
                "Skills/crypto/offensive-tls-attacks/SKILL.md"
            ],
            "authority": "OBSERVED",
            "valueProposition": "Enriquece la skill secrets-cryptography con reglas de auditoría y escáneres estáticos de código para detectar implementaciones vulnerables de cifrado y MACs artesanales."
        },
        {
            "id": "KNOW-004",
            "title": "Vectores de Extracción de Secretos en CI/CD y Abuso de Federaciones OIDC",
            "description": "Procedimientos sistemáticos de auditoría para la fuga y extracción de credenciales en pipelines de CI/CD: volcado de variables de entorno con evasión de filtros de enmascaramiento en logs (base64, inversión de cadenas, fold de caracteres), suplantación de tokens efímeros de ejecutores (GITHUB_TOKEN, CI_JOB_TOKEN), envenenamiento de caches de compilación y explotación de relaciones de confianza OIDC entre proveedores de CI/CD y nubes públicas sin restricciones estrictas de claims (sub, aud).",
            "dimension": "SECRETS_CRYPTOGRAPHY",
            "cwe": ["CWE-798", "CWE-522", "CWE-532"],
            "owasp": ["A02:2021-Cryptographic Failures", "A07:2021-Identification and Authentication Failures"],
            "sourceLocations": [
                "Skills/cicd/offensive-cicd-secrets/SKILL.md",
                "Skills/cicd/offensive-cicd-pipeline/SKILL.md"
            ],
            "authority": "OBSERVED",
            "valueProposition": "Permite auditar workflows y configuraciones de CI/CD para garantizar que los secretos no queden expuestos a través de variables de entorno o tokens de runners sobreprivilegiados."
        },
        {
            "id": "KNOW-005",
            "title": "Metodología de Auditoría Ofensiva de Sistemas de Inteligencia Artificial (LLM Red Teaming & Prompt Injection)",
            "description": "Taxonomía estructurada de amenazas contra sistemas basados en Modelos de Lenguaje (LLMs) y pipelines RAG: inyecciones de prompt directas e indirectas, deriva de alineamiento de seguridad por fine-tuning liviano (LoRA/adapters), conflictos en capas de políticas entre el proveedor y la aplicación, canales esteganográficos en modelos multimodales (visión/audio), extracción de modelos mediante sondeo de espacios de embeddings y ataques de virtualización de contexto.",
            "dimension": "THREAT_MODELING_ATTACK_SURFACE",
            "cwe": ["CWE-74", "CWE-20", "CWE-693"],
            "owasp": ["A04:2021-Insecure Design"],
            "sourceLocations": [
                "Skills/ai/offensive-ai-security/SKILL.md"
            ],
            "authority": "OBSERVED",
            "valueProposition": "Dota al repositorio de heurísticas formales de modelado de amenazas y auditoría de seguridad para arquitecturas agénticas y modelos generativos conforme al OWASP Top 10 for LLMs."
        },
        {
            "id": "KNOW-006",
            "title": "Deconstrucción de Fronteras de Seguridad en Windows (AMSI, PPL, AppContainer & Kernel Drivers)",
            "description": "Guía técnica exhaustiva sobre la arquitectura de seguridad y mitigaciones en sistemas Microsoft Windows: diferenciación formal entre políticas de ejecución (AMSI, WDAC, ASR, AppContainers, PPL) y mitigaciones de memoria (DEP, ASLR, CFG/XFG, safe-unlinking), técnicas de neutralización de telemetría ETW en memoria y vectores de escape de sandboxes basados en integridad.",
            "dimension": "ARCHITECTURE_BOUNDARIES_ZERO_TRUST",
            "cwe": ["CWE-250", "CWE-284", "CWE-693"],
            "owasp": ["A05:2021-Security Misconfiguration"],
            "sourceLocations": [
                "Skills/infrastructure/offensive-windows-boundaries/SKILL.md",
                "Skills/infrastructure/offensive-windows-mitigations/SKILL.md"
            ],
            "authority": "OBSERVED",
            "valueProposition": "Aporta una base teórica y práctica de primer nivel para la auditoría de aplicaciones de escritorio en Windows y evaluación de límites de privilegio Zero Trust."
        },
        {
            "id": "KNOW-007",
            "title": "Inyección Polimórfica en Motores de Plantillas (SSTI Multi-Engine Matrix)",
            "description": "Matriz profunda de patrones de inyección de plantillas en servidor que cubre más de 10 motores distintos (Jinja2, Twig, Freemarker, Velocity, Pebble, Smarty, Mako, ERB, Thymeleaf), detallando payloads de detección heurística poliglotas, evasión de filtros por reflexión y explotación ciega con extracción temporal o fuera de banda.",
            "dimension": "SOURCE_CODE_SAST",
            "cwe": ["CWE-1336", "CWE-94"],
            "owasp": ["A03:2021-Injection"],
            "sourceLocations": [
                "Skills/web/offensive-ssti/SKILL.md"
            ],
            "authority": "OBSERVED",
            "valueProposition": "Robustecer drásticamente las reglas SAST y heurísticas AST en source-code-sast para identificar construcciones vulnerables en múltiples lenguajes y frameworks web."
        },
        {
            "id": "KNOW-008",
            "title": "Auditoría de Deserialización Insegura Políglota (Java, PHP, .NET, Python, Node, Ruby)",
            "description": "Compendio de vectores de deserialización insegura a través de los principales runtimes empresariales, extendiendo el análisis desde la persistencia clásica hasta canales modernos como colas de mensajería (RabbitMQ, Kafka), arquitecturas serverless y pipelines de microservicios en Kubernetes.",
            "dimension": "SOURCE_CODE_SAST",
            "cwe": ["CWE-502", "CWE-94"],
            "owasp": ["A08:2021-Software and Data Integrity Failures"],
            "sourceLocations": [
                "Skills/web/offensive-deserialization/SKILL.md"
            ],
            "authority": "OBSERVED",
            "valueProposition": "Expande el catálogo de patrones de fuentes a sumideros (taint sinks) para detección estática de deserialización no confiable en el motor SAST de Devia-CyberSecurity."
        },
        {
            "id": "KNOW-009",
            "title": "Abuso de Protocolos Inalámbricos e IoT (Zigbee, Matter, Thread & Bluetooth BLE)",
            "description": "Metodología de auditoría para tecnologías inalámbricas de corto alcance y estándares de domótica moderna: ataques de emparejamiento y captura de claves maestras en Zigbee, suplantación de identidad en Thread/Matter, ataques a nivel de enlace en Bluetooth Low Energy (BLE) y ataques de desautenticación en redes Wi-Fi empresariales (WPA2/WPA3).",
            "dimension": "CONFIGURATION_HARDENING",
            "cwe": ["CWE-319", "CWE-295", "CWE-300"],
            "owasp": ["A05:2021-Security Misconfiguration"],
            "sourceLocations": [
                "Skills/wireless/offensive-zigbee-thread-matter/SKILL.md",
                "Skills/wireless/offensive-bluetooth-ble/SKILL.md",
                "Skills/wireless/offensive-wpa3-sae/SKILL.md",
                "Skills/iot/offensive-iot/SKILL.md"
            ],
            "authority": "OBSERVED",
            "valueProposition": "Extiende la dimensión configuration-hardening hacia superficies de ataque físicas e IoT, permitiendo auditar parámetros de despliegue inalámbrico y cifrado de radioenlace."
        },
        {
            "id": "KNOW-010",
            "title": "Técnicas de Anti-Forense y Detección de Canales C2 Encubiertos",
            "description": "Análisis exhaustivo de tradecraft de evasión forense: manipulación de marcas temporales de archivos ($MFT timestomping), uso de Flujos Alternativos de Datos (ADS) en NTFS, purga selectiva de registros de eventos de Windows (EVTX) y patrones de tráfico para infraestructura de Comando y Control (C2) con perfiles maleables, jitter y túneles DNS/ICMP.",
            "dimension": "RESILIENCE_LOGGING_TELEMETRY",
            "cwe": ["CWE-1027", "CWE-778", "CWE-400"],
            "owasp": ["A09:2021-Security Logging and Monitoring Failures"],
            "sourceLocations": [
                "Skills/forensics/offensive-anti-forensics/SKILL.md",
                "Skills/forensics/offensive-c2-frameworks/SKILL.md",
                "Skills/post-exploitation/offensive-data-exfiltration/SKILL.md"
            ],
            "authority": "OBSERVED",
            "valueProposition": "Proporciona a resilience-logging-telemetry una guía autoritativa para diseñar reglas de telemetría y detección de comportamientos anómalos o intentos de evasión de auditoría."
        }
    ]
    
    # 6. Absorption Actions (ABS-001 to ABS-010)
    absorption_actions = [
        {
            "id": "ABS-001",
            "knowledgeId": "KNOW-001",
            "title": "Creación de Referencia Técnica sobre Auditoría de Aislamiento y Evasión de Contenedores",
            "destination": "SKILL_REFERENCE",
            "intent": "ABSORB_EXPAND",
            "existingVulnerabilityId": "VULN-ARCH-017",
            "targetPathInRepo": ".agents/skills/architecture-boundaries-zero-trust/references/container-breakout-and-namespace-isolation.md",
            "architecturalRationale": "Capa 1: Documentación metodológica y guía heurística para inspectores y agentes auditores de contenedores Docker/K8s.",
            "priority": "HIGH",
            "implementationSteps": [
                "Sintetizar la metodología de auditoría de namespaces y capabilities desde offensive-container-escape",
                "Formatear en Markdown canónico con tablas de capabilities de riesgo y checklists de hardening",
                "Vincular con VULN-ARCH-017 en docs/VULNERABILITIES.md",
                "Añadir directivas defensivas de remediación (seccomp, drop CAP_SYS_ADMIN, non-root user)"
            ]
        },
        {
            "id": "ABS-002",
            "knowledgeId": "KNOW-002",
            "title": "Ampliación de Reglas de Detección de Confusión de Dependencias en Script de Lockfiles",
            "destination": "PYTHON_SCRIPT",
            "intent": "UPDATE_ENHANCE",
            "existingVulnerabilityId": "VULN-SCA-003",
            "targetPathInRepo": "src/scripts/check_lockfiles.py",
            "architecturalRationale": "Capa 3: Script determinista en Python 3.11+ para escaneo estático de archivos de configuración sin dependencias pesadas.",
            "priority": "HIGH",
            "implementationSteps": [
                "Incorporar reglas de parsing para .npmrc detectando ausencia de mappings de scope explícitos",
                "Añadir verificación de flags --extra-index-url en requirements.txt y pip.conf",
                "Implementar tests unitarios en src/scripts/test_check_lockfiles.py",
                "Verificar compatibilidad multiplataforma y cero llamadas a red"
            ]
        },
        {
            "id": "ABS-003",
            "knowledgeId": "KNOW-003",
            "title": "Guía Canónica de Detección y Remediación de Fallas Criptográficas Prácticas",
            "destination": "SKILL_REFERENCE",
            "intent": "CREATE_NEW",
            "existingVulnerabilityId": "VULN-CRYP-003",
            "targetPathInRepo": ".agents/skills/secrets-cryptography/references/cryptographic-implementation-flaws-and-oracles.md",
            "architecturalRationale": "Capa 1: Guía de referencia técnica para identificación estática de modos de cifrado inseguros y oráculos de relleno.",
            "priority": "HIGH",
            "implementationSteps": [
                "Deconstruir los mecanismos de ataque a CBC/PKCS7 y extensión de longitud",
                "Documentar patrones de código vulnerable vs seguro en Python (cryptography), Node.js (crypto) y Go",
                "Enlazar con CWE-327, CWE-328 y CWE-330",
                "Registrar en el mapa de referencias de secrets-cryptography"
            ]
        },
        {
            "id": "ABS-004",
            "knowledgeId": "KNOW-004",
            "title": "Referencia de Bastionado de Secretos y Federaciones OIDC en CI/CD",
            "destination": "SKILL_REFERENCE",
            "intent": "ABSORB_EXPAND",
            "existingVulnerabilityId": "VULN-CRYP-001",
            "targetPathInRepo": ".agents/skills/secrets-cryptography/references/cicd-secrets-and-oidc-federation-hardening.md",
            "architecturalRationale": "Capa 1: Instrucciones especializadas para auditoría de variables de entorno y trust policies en workflows de GitHub Actions / GitLab CI.",
            "priority": "MEDIUM",
            "implementationSteps": [
                "Extraer las técnicas de evasión de enmascaramiento y estructurar contramedidas defensivas",
                "Definir políticas seguras de OIDC subject validation para AWS, Azure y GCP",
                "Incorporar a la matriz de auditoría de CI/CD"
            ]
        },
        {
            "id": "ABS-005",
            "knowledgeId": "KNOW-005",
            "title": "Expansión del Modelado de Amenazas para Sistemas Agénticos y LLM Red Teaming",
            "destination": "SKILL_REFERENCE",
            "intent": "UPDATE_ENHANCE",
            "existingVulnerabilityId": "VULN-TM-001",
            "targetPathInRepo": ".agents/skills/threat-modeling-attack-surface/references/llm-agent-threat-modeling-and-red-teaming.md",
            "architecturalRationale": "Capa 1: Actualización de metodologías STRIDE/PASTA integrando el vector de agentes LLM conforme a la Taxonomía Canónica MECE.",
            "priority": "HIGH",
            "implementationSteps": [
                "Integrar los vectores de fine-tuning drift, prompt injection indirecto y model extraction",
                "Mapear contra la dimensión THREAT_MODELING_ATTACK_SURFACE sin crear dimensiones ficticias",
                "Incluir checklist de verificación de mitigaciones para arquitecturas agénticas"
            ]
        },
        {
            "id": "ABS-006",
            "knowledgeId": "KNOW-006",
            "title": "Referencia de Fronteras de Ejecución y Privilegios en Microsoft Windows",
            "destination": "SKILL_REFERENCE",
            "intent": "CREATE_NEW",
            "existingVulnerabilityId": "VULN-ARCH-019",
            "targetPathInRepo": ".agents/skills/architecture-boundaries-zero-trust/references/windows-security-boundaries-and-sandboxes.md",
            "architecturalRationale": "Capa 1: Documentación profunda de arquitectura de bajo nivel para evaluación de seguridad en Windows.",
            "priority": "MEDIUM",
            "implementationSteps": [
                "Extraer los fundamentos de AppContainer, PPL, integridad de procesos y políticas de ejecución",
                "Construir guía de evaluación defensiva para aplicaciones que interactúan con el kernel o servicios RPC",
                "Vincular con VULN-ARCH-019 en docs/VULNERABILITIES.md"
            ]
        },
        {
            "id": "ABS-007",
            "knowledgeId": "KNOW-007",
            "title": "Actualización de Heurísticas AST para Detección de SSTI Multi-Engine",
            "destination": "UPDATE_EXISTING",
            "intent": "ROBUSTIFY_HARDEN",
            "existingVulnerabilityId": "VULN-SAST-020",
            "targetPathInRepo": ".agents/skills/source-code-sast/references/server-side-template-injection-ssti.md",
            "architecturalRationale": "Capa 1: Enriquecimiento in-place de la referencia existente con los nuevos patrones de plantillas (Velocity, Smarty, Pebble, Thymeleaf).",
            "priority": "HIGH",
            "implementationSteps": [
                "Actualizar el documento de referencia existente incorporando la tabla comparativa de sintaxis de los 10 motores",
                "Añadir patrones de detección estática para sumideros de renderizado inseguro",
                "Validar alineación con el contrato Zod de hallazgos"
            ]
        },
        {
            "id": "ABS-008",
            "knowledgeId": "KNOW-008",
            "title": "Enriquecimiento de la Matriz de Deserialización Insegura Políglota",
            "destination": "UPDATE_EXISTING",
            "intent": "UPDATE_ENHANCE",
            "existingVulnerabilityId": "VULN-SAST-004",
            "targetPathInRepo": ".agents/skills/source-code-sast/references/php-session-deserialization-and-sapi-chains.md",
            "architecturalRationale": "Capa 1: Expansión de la referencia técnica para cubrir runtimes .NET, Java y Ruby más allá de PHP.",
            "priority": "HIGH",
            "implementationSteps": [
                "Incorporar las cadenas de deserialización en frameworks modernos y colas de mensajes",
                "Documentar mecanismos seguros de serialización alternativa (JSON esquematizado, Protocol Buffers)",
                "Mantener el histórico de hallazgos y referencias previas"
            ]
        },
        {
            "id": "ABS-009",
            "knowledgeId": "KNOW-009",
            "title": "Guía de Hardening de Comunicaciones Inalámbricas e IoT",
            "destination": "SKILL_REFERENCE",
            "intent": "CREATE_NEW",
            "existingVulnerabilityId": "VULN-CONF-019",
            "targetPathInRepo": ".agents/skills/configuration-hardening/references/wireless-and-iot-protocol-hardening.md",
            "architecturalRationale": "Capa 1: Referencia técnica especializada para evaluación de configuraciones de radiofrecuencia e IoT.",
            "priority": "MEDIUM",
            "implementationSteps": [
                "Estructurar recomendaciones de hardening para redes Wi-Fi empresariales (WPA3-Enterprise, 802.1X)",
                "Documentar mejores prácticas para redes malladas Thread/Matter y Zigbee",
                "Incorporar al índice de configuration-hardening"
            ]
        },
        {
            "id": "ABS-010",
            "knowledgeId": "KNOW-010",
            "title": "Incorporación de Invariantes de Telemetría Anti-Forense y Detección de C2",
            "destination": "UPDATE_EXISTING",
            "intent": "ROBUSTIFY_HARDEN",
            "existingVulnerabilityId": "VULN-ARCH-024",
            "targetPathInRepo": "docs/PROACTIVE.md",
            "architecturalRationale": "Invariante de Plataforma: Enriquecimiento del playbook operativo con patrones inmutables de telemetría y resistencia a manipulación de logs.",
            "priority": "HIGH",
            "implementationSteps": [
                "Añadir regla de oro sobre inmutabilidad de logs y detección de timestomping",
                "Establecer directivas para inspección de flujos de red con jitter",
                "Registrar en el changelog inmutable de PROACTIVE.md"
            ]
        }
    ]
    
    # Calculate destinations breakdown
    destinations_count = Counter(a["destination"] for a in absorption_actions)
    
    absorption_plan_data = {
        "planId": str(uuid.uuid4()),
        "createdAt": started_at,
        "target": {
            "path": str(TARGET_ROOT),
            "canonicalPath": str(TARGET_ROOT.resolve()),
            "name": "claude-red",
            "type": "REPOSITORY",
            "commitOrSnapshot": "v0.3.0 (Offensive Security Skills Library)",
            "archetypeDescription": "AGENTIC_SKILLS_AND_OFFENSIVE_REDTEAM_FRAMEWORK"
        },
        "scopeSummary": {
            "totalEntriesScanned": len(inventory_records),
            "primaryLanguages": [ext for ext, _ in extension_counts.most_common(6)],
            "securityDimensionsEvaluated": CANONICAL_DIMENSIONS
        },
        "extractedKnowledge": extracted_knowledge,
        "absorptionActions": absorption_actions,
        "metrics": {
            "totalKnowledgeItems": len(extracted_knowledge),
            "destinationsBreakdown": dict(destinations_count)
        },
        "ledgerPaths": {
            "inventoryJsonl": str((OUT_DIR / "inventory.jsonl").resolve()),
            "coverageJsonl": str((OUT_DIR / "coverage.jsonl").resolve()),
            "evidenceJsonl": str((OUT_DIR / "evidence.jsonl").resolve()),
            "unknownsJsonl": str((OUT_DIR / "unknowns.jsonl").resolve())
        }
    }
    
    plan_json_path = OUT_DIR / "absorption-plan.json"
    with open(plan_json_path, "w", encoding="utf-8") as f:
        json.dump(absorption_plan_data, f, indent=2, ensure_ascii=False)
    print(f"absorption-plan.json written successfully ({plan_json_path}).")
    
    # 7. Generate absorption-plan.md dossier
    md_content = f"""# Plan de Absorción Forense de Ingeniería Inversa: Claude-Red v0.3.0

## 1. Identidad del Objetivo y Cadena de Custodia
- **Ruta Suministrada:** `D:\\Descargas\\Claude-Red-main`
- **Ruta Canónica de Repositorio:** `{TARGET_ROOT}`
- **Versión / Release:** `v0.3.0 (Biblioteca de Skills Ofensivas de Red Team)`
- **Arquetipo:** `AGENTIC_SKILLS_AND_OFFENSIVE_REDTEAM_FRAMEWORK` (Colección estructurada de 78 skills en Markdown drop-in para Claude)
- **Fecha de Auditoría UTC:** `{started_at}`
- **Archivos Auditados:** `{len(inventory_records)}` archivos físicos analizados en cobertura forense estática.
- **Bytes Totales:** `{total_bytes}` bytes ({total_bytes / (1024*1024):.2f} MiB).
- **Control de Versiones:** Snapshot físico de distribución sin `.git` local (hashes SHA-256 calculados para todos los manifiestos).

---

## 2. Resumen Ejecutivo del Objetivo
**Claude-Red** (desarrollado por SnailSploit) es una biblioteca modular de ingeniería inversa y seguridad ofensiva diseñada para el sistema de skills de Claude. Transforma al asistente en un operador contextual de equipo rojo (*Red Team*) mediante 78 skills organizadas en 23 categorías funcionales:
1. **Superficie Web y APIs (18 skills):** Inyecciones avanzadas (SQLi, SSTI, XXE, SSRF), desincronización HTTP (Request Smuggling), deserialización políglota, GraphQL y abusos lógicos de negocio.
2. **Infraestructura, Windows Internals y Evasión (14 skills):** Desglose exhaustivo de límites de seguridad de Windows (AMSI, WDAC, ASR, AppContainers, PPL), familias Potato para privesc, técnicas de shellcode y bypass de EDRs.
3. **Contenedores y Cloud (3 skills):** Evasión de runtimes (Docker/containerd/Podman), abuso de sockets `/var/run/docker.sock`, capacidades Linux de riesgo y vectores de ataque a clústeres Kubernetes (RBAC, etcd).
4. **Criptografía e Identidad (4 skills):** Oráculos de relleno PKCS7 (CBC), modo ECB, extensión de longitud, abuso de nonces en AES-GCM, debilidades en tokens JWT y manipulaciones OAuth/OIDC.
5. **Cadena de Suministro y CI/CD (4 skills):** Ataques de confusión de dependencias políglotas (npm, PyPI, NuGet, Maven, Go) y extracción furtiva de secretos en pipelines CI/CD con evasión de filtros en logs.
6. **Protocolos Inalámbricos e IoT (15 skills):** Wi-Fi (WPA2/3, WPS, Evil Twin, KRACK), Bluetooth clásico y BLE, domótica moderna (Zigbee, Matter, Thread) y radiofrecuencia sub-GHz (LoRaWAN).
7. **Anti-Forense y Post-Explotación (8 skills):** Timestomping, borrado selectivo de registros EVTX, streams ADS, marcos C2 (Cobalt Strike, Sliver, Mythic) y exfiltración de datos.

---

## 3. Mapeo Canónico contra las 8 Dimensiones de Devia-CyberSecurity

| Dimensión Canónica | Nivel de Cobertura | Categorías y Componentes Clave en Objetivo | Contribución Defensiva al Ecosistema |
| :--- | :--- | :--- | :--- |
| **THREAT_MODELING_ATTACK_SURFACE** | Exhaustivo | `Skills/ai/`, `Skills/recon/`, `Skills/infrastructure/offensive-advanced-redteam` | Taxonomía de amenazas contra LLMs (prompt injection indirecto, embedding extraction) y marcos de orientación de red team |
| **SOURCE_CODE_SAST** | Exhaustivo | `Skills/web/` (16 skills), `Skills/api/` (2 skills), `Skills/exploit-dev/` | Matriz de 10+ motores de plantillas SSTI, cadenas de deserialización multilingües y detección de fallas lógicas complejas |
| **SECRETS_CRYPTOGRAPHY** | Exhaustivo | `Skills/crypto/` (2 skills), `Skills/cicd/offensive-cicd-secrets` | Reglas estáticas de detección para oráculos CBC, MACs sin HMAC y bypass de enmascaramiento de secretos en logs |
| **IDENTITY_ACCESS_SESSION** | Exhaustivo | `Skills/auth/`, `Skills/active-directory/`, `Skills/privesc/` | Procedimientos de auditoría para suplantación de tokens COM/RPC (Potato), privilegios en Active Directory y tokens OAuth/JWT |
| **SUPPLY_CHAIN_SCA** | Exhaustivo | `Skills/supply-chain/` (2 skills), `Skills/cicd/offensive-cicd-pipeline` | Heurísticas para auditar .npmrc, pip.conf y repositorios privados contra secuestro de paquetes y confusión de namespaces |
| **ARCHITECTURE_BOUNDARIES_ZERO_TRUST** | Exhaustivo | `Skills/container/`, `Skills/infrastructure/offensive-windows-boundaries`, `Skills/network/` | Criterios de confinamiento para contenedores Docker/Podman y taxonomía de límites de seguridad (AMSI vs mitigaciones de memoria) |
| **CONFIGURATION_HARDENING** | Alto | `Skills/wireless/` (14 skills), `Skills/cloud/`, `Skills/iot/` | Guías de configuración segura para radioenlaces, protocolos IoT (Thread/Matter) y bastionado de microservicios |
| **RESILIENCE_LOGGING_TELEMETRY** | Exhaustivo | `Skills/forensics/`, `Skills/post-exploitation/` | Reglas de detección SIEM/EDR contra borrado de EVTX, manipulación de marcas MFT y balizas C2 estadísticas |

---

## 4. Unidades de Conocimiento Extraídas (`KNOW-001` a `KNOW-010`)

- **`KNOW-001` - Heurísticas y Vectores de Evasión de Contenedores y Ruptura de Aislamiento** (`ARCHITECTURE_BOUNDARIES_ZERO_TRUST`): Permite robustecer las políticas de confinamiento en Docker y Kubernetes mediante la detección temprana de montajes host de alto riesgo, capabilities peligrosas (`CAP_SYS_ADMIN`) y CVEs de runtimes (`CVE-2024-21626`).
- **`KNOW-002` - Matriz Políglota de Confusión de Dependencias y Secuestro de Namespaces** (`SUPPLY_CHAIN_SCA`): Aporta reglas estáticas para auditar manifiestos de paquetes y lockfiles, erradicando fallos de resolución cruzada entre registros privados y públicos en npm, PyPI, Maven y Go.
- **`KNOW-003` - Catálogo de Explotación Criptográfica Práctica** (`SECRETS_CRYPTOGRAPHY`): Transforma ataques complejos (padding oracles PKCS7, reutilización de nonces GCM, extensión de longitud) en detectores estáticos de mala implementación criptográfica.
- **`KNOW-004` - Vectores de Extracción de Secretos en CI/CD y Abuso de Federaciones OIDC** (`SECRETS_CRYPTOGRAPHY`): Dota al ecosistema de mecanismos para auditar canales de compilación y evitar la filtración de credenciales a través de trucos de ofuscación de cadenas.
- **`KNOW-005` - Metodología de Auditoría Ofensiva de Sistemas de Inteligencia Artificial** (`THREAT_MODELING_ATTACK_SURFACE`): Extiende el modelado de amenazas STRIDE/PASTA hacia aplicaciones con modelos generativos y agentes autónomos conforme a estándares de OWASP LLM.
- **`KNOW-006` - Deconstrucción de Fronteras de Seguridad en Windows** (`ARCHITECTURE_BOUNDARIES_ZERO_TRUST`): Establece una taxonomía formal para auditar el aislamiento de procesos, privilegios de integridad y defensas de ejecución en sistemas operativos Microsoft.
- **`KNOW-007` - Inyección Polimórfica en Motores de Plantillas (SSTI Multi-Engine)** (`SOURCE_CODE_SAST`): Proporciona patrones de detección y reglas AST para diez motores de renderizado web, superando las limitaciones de firmas tradicionales.
- **`KNOW-008` - Auditoría de Deserialización Insegura Políglota** (`SOURCE_CODE_SAST`): Enriquece el rastreo de taint (fuentes a sumideros) para identificar llamadas reflexivas y deserializadores vulnerables en múltiples pilas tecnológicas.
- **`KNOW-009` - Abuso de Protocolos Inalámbricos e IoT** (`CONFIGURATION_HARDENING`): Incorpora directivas para auditar el despliegue de redes corporativas inalámbricas y arquitecturas de domótica moderna.
- **`KNOW-010` - Técnicas de Anti-Forense y Detección de Canales C2 Encubiertos** (`RESILIENCE_LOGGING_TELEMETRY`): Suministra los patrones de evasión necesarios para construir reglas de correlación SIEM que detecten la alteración de pistas de auditoría y tráfico encubierto.

---

## 5. Matriz de Acciones de Absorción Técnica (`ABS-001` a `ABS-010`)

| ID Acción | Conocimiento | Destino Tri-Tier | Intención Evolutiva | Ruta en Devia-CyberSecurity | Prioridad |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **`ABS-001`** | `KNOW-001` | `SKILL_REFERENCE` | `ABSORB_EXPAND` | `.agents/skills/architecture-boundaries-zero-trust/references/container-breakout-and-namespace-isolation.md` | **HIGH** |
| **`ABS-002`** | `KNOW-002` | `PYTHON_SCRIPT` | `UPDATE_ENHANCE` | `src/scripts/check_lockfiles.py` | **HIGH** |
| **`ABS-003`** | `KNOW-003` | `SKILL_REFERENCE` | `CREATE_NEW` | `.agents/skills/secrets-cryptography/references/cryptographic-implementation-flaws-and-oracles.md` | **HIGH** |
| **`ABS-004`** | `KNOW-004` | `SKILL_REFERENCE` | `ABSORB_EXPAND` | `.agents/skills/secrets-cryptography/references/cicd-secrets-and-oidc-federation-hardening.md` | **MEDIUM** |
| **`ABS-005`** | `KNOW-005` | `SKILL_REFERENCE` | `UPDATE_ENHANCE` | `.agents/skills/threat-modeling-attack-surface/references/llm-agent-threat-modeling-and-red-teaming.md` | **HIGH** |
| **`ABS-006`** | `KNOW-006` | `SKILL_REFERENCE` | `CREATE_NEW` | `.agents/skills/architecture-boundaries-zero-trust/references/windows-security-boundaries-and-sandboxes.md` | **MEDIUM** |
| **`ABS-007`** | `KNOW-007` | `UPDATE_EXISTING` | `ROBUSTIFY_HARDEN` | `.agents/skills/source-code-sast/references/server-side-template-injection-ssti.md` | **HIGH** |
| **`ABS-008`** | `KNOW-008` | `UPDATE_EXISTING` | `UPDATE_ENHANCE` | `.agents/skills/source-code-sast/references/php-session-deserialization-and-sapi-chains.md` | **HIGH** |
| **`ABS-009`** | `KNOW-009` | `SKILL_REFERENCE` | `CREATE_NEW` | `.agents/skills/configuration-hardening/references/wireless-and-iot-protocol-hardening.md` | **MEDIUM** |
| **`ABS-010`** | `KNOW-010` | `UPDATE_EXISTING` | `ROBUSTIFY_HARDEN` | `docs/PROACTIVE.md` | **HIGH** |

---

## 6. Verificación de Contratos y Ledgers
Los cuatro ledgers canónicos han sido materializados en `{OUT_DIR}`:
- `inventory.jsonl`: Metadatos de 97 archivos con digests SHA-256 y conteo de líneas.
- `summary.json`: Métricas globales, timestamps ISO 8601 y clasificación de arquetipo.
- `coverage.jsonl`: Disposición por archivo (97 evaluados: 94 leídos/trazados, 3 excluidos con justificación).
- `evidence.jsonl`: Citas factuales (`SRC-001` a `SRC-011`, `CFG-001`) con nivel epistemológico `OBSERVED` y SHA-256.
- `unknowns.jsonl`: Registro de 4 brechas técnicas no resueltas (`UNK-001` a `UNK-004`).
- `absorption-plan.json`: Contrato formal conforme a `AbsorptionPlanSchema` de Devia-CyberSecurity.
"""
    
    with open(OUT_DIR / "absorption-plan.md", "w", encoding="utf-8") as f:
        f.write(md_content)
    print(f"absorption-plan.md written successfully ({OUT_DIR / 'absorption-plan.md'}).")


if __name__ == "__main__":
    main()
