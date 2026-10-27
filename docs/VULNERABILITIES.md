# Devia-CyberSecurity — Catálogo Canónico de Vulnerabilidades y Mapeo Dimensional

Este documento constituye la **Fuente Única de Verdad (SSOT)** documental para el registro, clasificación y seguimiento de vulnerabilidades, debilidades lógicas (CWE) y vectores de ataque absorbidos o gestionados en **Devia-CyberSecurity**.

---

## 🏛️ Directiva de Gobernanza y Mantenimiento

1. **Invariante de Clasificación Estricta:**
   Toda vulnerabilidad registrada en este catálogo **debe pertenecer obligatoriamente a una de las 8 Dimensiones Canónicas** (`SecurityDimensionSchema`) y estar asignada a su respectiva Skill operativa en `.agent/skills/`.
2. **Nomenclatura y Taxonomía Estándar:**
   Se exige la correlación explícita con el identificador formal de debilidad **CWE** (*Common Weakness Enumeration*) y la categoría correspondiente de **OWASP Top 10** o **ASVS**.
3. **Ciclo de Actualización Viva:**
   A medida que la Meta-Skill `security-reverse-engineering` audite repositorios, bibliotecas o frameworks y absorba nuevos vectores de ataque, se incorporarán a este registro las debilidades descubiertas junto con su mecanismo de fallo y propuesta de mitigación.

---

## 📋 Catálogo Maestro de Vulnerabilidades

A continuación se presenta el registro canónico de debilidades y vulnerabilidades, su mapeo dimensional y la Skill responsable de su detección y remediación:

| ID Canónico | Nombre de la Vulnerabilidad | Taxonomía (CWE / OWASP) | Dimensión Canónica | Skill Asignada | Severidad Típica |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **`VULN-TM-001`** | **Trust Boundary Violation** | CWE-501<br>OWASP A04:2021 | `THREAT_MODELING_ATTACK_SURFACE` | [`threat-modeling-attack-surface`](file:///.agent/skills/threat-modeling-attack-surface/SKILL.md) | **HIGH** |
| **`VULN-TM-002`** | **Missing Entry Point Authentication** | CWE-306<br>OWASP A07:2021 | `THREAT_MODELING_ATTACK_SURFACE` | [`threat-modeling-attack-surface`](file:///.agent/skills/threat-modeling-attack-surface/SKILL.md) | **CRITICAL** |
| **`VULN-SAST-001`** | **SQL / NoSQL Injection** | CWE-89 / CWE-943<br>OWASP A03:2021 | `SOURCE_CODE_SAST` | [`source-code-sast`](file:///.agent/skills/source-code-sast/SKILL.md) | **CRITICAL** |
| **`VULN-SAST-002`** | **OS Command Injection** | CWE-78<br>OWASP A03:2021 | `SOURCE_CODE_SAST` | [`source-code-sast`](file:///.agent/skills/source-code-sast/SKILL.md) | **CRITICAL** |
| **`VULN-SAST-003`** | **Path Traversal / Unsafe Archive Extraction (Zip Slip)** | CWE-22 / CWE-23<br>OWASP A01:2021 | `SOURCE_CODE_SAST` | [`source-code-sast`](file:///.agent/skills/source-code-sast/SKILL.md) | **HIGH** |
| **`VULN-SAST-004`** | **Insecure Object Deserialization** | CWE-502<br>OWASP A08:2021 | `SOURCE_CODE_SAST` | [`source-code-sast`](file:///.agent/skills/source-code-sast/SKILL.md) | **CRITICAL** |
| **`VULN-SAST-005`** | **Race Condition / TOCTOU** | CWE-362<br>OWASP A04:2021 | `SOURCE_CODE_SAST` | [`source-code-sast`](file:///.agent/skills/source-code-sast/SKILL.md) | **MEDIUM** |
| **`VULN-CRYP-001`** | **Hardcoded Secrets & Source-Exposed API Keys** | CWE-798 / CWE-312<br>OWASP A02:2021 | `SECRETS_CRYPTOGRAPHY` | [`secrets-cryptography`](file:///.agent/skills/secrets-cryptography/SKILL.md) | **CRITICAL** |
| **`VULN-CRYP-002`** | **Weak or Deprecated Cryptographic Hash (MD5/SHA1)** | CWE-328<br>OWASP A02:2021 | `SECRETS_CRYPTOGRAPHY` | [`secrets-cryptography`](file:///.agent/skills/secrets-cryptography/SKILL.md) | **MEDIUM** |
| **`VULN-CRYP-003`** | **Insecure Cipher Mode (AES-ECB)** | CWE-327<br>OWASP A02:2021 | `SECRETS_CRYPTOGRAPHY` | [`secrets-cryptography`](file:///.agent/skills/secrets-cryptography/SKILL.md) | **HIGH** |
| **`VULN-CRYP-004`** | **Insufficiently Random Values (Weak PRNG)** | CWE-330<br>OWASP A02:2021 | `SECRETS_CRYPTOGRAPHY` | [`secrets-cryptography`](file:///.agent/skills/secrets-cryptography/SKILL.md) | **HIGH** |
| **`VULN-IAM-001`** | **Broken Object Level Authorization (IDOR / BOLA)** | CWE-639 / CWE-862<br>OWASP A01:2021 | `IDENTITY_ACCESS_SESSION` | [`identity-access-session`](file:///.agent/skills/identity-access-session/SKILL.md) | **HIGH** |
| **`VULN-IAM-002`** | **JWT Algorithm None / Signature Bypass** | CWE-347<br>OWASP A07:2021 | `IDENTITY_ACCESS_SESSION` | [`identity-access-session`](file:///.agent/skills/identity-access-session/SKILL.md) | **CRITICAL** |
| **`VULN-IAM-003`** | **Missing Function Level Access Control** | CWE-863<br>OWASP A01:2021 | `IDENTITY_ACCESS_SESSION` | [`identity-access-session`](file:///.agent/skills/identity-access-session/SKILL.md) | **HIGH** |
| **`VULN-SCA-001`** | **Vulnerable Third-Party Dependency (Known CVE)** | CWE-1395<br>OWASP A06:2021 | `SUPPLY_CHAIN_SCA` | [`supply-chain-sca`](file:///.agent/skills/supply-chain-sca/SKILL.md) | **VARIABLE** |
| **`VULN-SCA-002`** | **Missing or Unlocked Dependency Lockfile** | CWE-1104<br>OWASP A06:2021 | `SUPPLY_CHAIN_SCA` | [`supply-chain-sca`](file:///.agent/skills/supply-chain-sca/SKILL.md) | **MEDIUM** |
| **`VULN-SCA-003`** | **Malicious Package / Untrusted Install Lifecycle Script** | CWE-829<br>OWASP A08:2021 | `SUPPLY_CHAIN_SCA` | [`supply-chain-sca`](file:///.agent/skills/supply-chain-sca/SKILL.md) | **CRITICAL** |
| **`VULN-ARCH-001`** | **Electron Context Isolation Disabled (`contextIsolation: false`)** | CWE-250<br>OWASP A05:2021 | `ARCHITECTURE_BOUNDARIES_ZERO_TRUST` | [`architecture-boundaries-zero-trust`](file:///.agent/skills/architecture-boundaries-zero-trust/SKILL.md) | **CRITICAL** |
| **`VULN-ARCH-002`** | **Insecure IPC Message Dispatch (Arbitrary Command Execution)** | CWE-668 / CWE-78<br>OWASP A05:2021 | `ARCHITECTURE_BOUNDARIES_ZERO_TRUST` | [`architecture-boundaries-zero-trust`](file:///.agent/skills/architecture-boundaries-zero-trust/SKILL.md) | **CRITICAL** |
| **`VULN-ARCH-003`** | **Overly Permissive CORS Policy (`Access-Control-Allow-Origin: *`)** | CWE-942<br>OWASP A05:2021 | `ARCHITECTURE_BOUNDARIES_ZERO_TRUST` | [`architecture-boundaries-zero-trust`](file:///.agent/skills/architecture-boundaries-zero-trust/SKILL.md) | **MEDIUM** |
| **`VULN-ARCH-004`** | **Unsealed Audit Telemetry / Mutable Scan Artifact Tampering** | CWE-345 / CWE-353<br>OWASP A08:2021 | `ARCHITECTURE_BOUNDARIES_ZERO_TRUST` | [`architecture-boundaries-zero-trust`](file:///.agent/skills/architecture-boundaries-zero-trust/SKILL.md) | **HIGH** |
| **`VULN-CONF-001`** | **Insecure Default Credentials / Exposed .env Files** | CWE-1188 / CWE-200<br>OWASP A05:2021 | `CONFIGURATION_HARDENING` | [`configuration-hardening`](file:///.agent/skills/configuration-hardening/SKILL.md) | **HIGH** |
| **`VULN-CONF-002`** | **Missing Content-Security-Policy (CSP) / Strict Transport (HSTS)** | CWE-1021 / CWE-319<br>OWASP A05:2021 | `CONFIGURATION_HARDENING` | [`configuration-hardening`](file:///.agent/skills/configuration-hardening/SKILL.md) | **MEDIUM** |
| **`VULN-CONF-003`** | **Container Running as Root / Excessive Linux Capabilities** | CWE-250<br>OWASP A05:2021 | `CONFIGURATION_HARDENING` | [`configuration-hardening`](file:///.agent/skills/configuration-hardening/SKILL.md) | **HIGH** |
| **`VULN-CONF-004`** | **Unquoted Service / Script Search Path Hijacking in Runtime Shims** | CWE-428 / CWE-427<br>OWASP A05:2021 | `CONFIGURATION_HARDENING` | [`configuration-hardening`](file:///.agent/skills/configuration-hardening/SKILL.md) | **HIGH** |
| **`VULN-RESI-001`** | **Regular Expression Denial of Service (ReDoS)** | CWE-1333 / CWE-400<br>OWASP A04:2021 | `RESILIENCE_LOGGING_TELEMETRY` | [`resilience-logging-telemetry`](file:///.agent/skills/resilience-logging-telemetry/SKILL.md) | **HIGH** |
| **`VULN-RESI-002`** | **Sensitive Data Leakage in Application Logs (PII / Secrets)** | CWE-532<br>OWASP A09:2021 | `RESILIENCE_LOGGING_TELEMETRY` | [`resilience-logging-telemetry`](file:///.agent/skills/resilience-logging-telemetry/SKILL.md) | **HIGH** |
| **`VULN-RESI-003`** | **Uncaught Exception / Silent Fail-Open & Interrupted Scan Inconclusiveness** | CWE-754 / CWE-391<br>OWASP A09:2021 | `RESILIENCE_LOGGING_TELEMETRY` | [`resilience-logging-telemetry`](file:///.agent/skills/resilience-logging-telemetry/SKILL.md) | **MEDIUM** |

---

## 🔬 Protocolo para Incorporar Nuevas Vulnerabilidades

Cuando durante una auditoría o proceso de absorción se identifique un nuevo tipo de vulnerabilidad o vector de explotación:

1. **Verificar Dimensión Canónica:** Determinar en cuál de las 8 dimensiones canónicas encaja según el mecanismo del fallo.
2. **Asignar Identificador:** Emplear el prefijo `VULN-<ABREVIACIÓN_DIMENSIÓN>-<SECUENCIAL>` (e.g. `VULN-SAST-006`).
3. **Vincular CWE y OWASP:** Investigar y registrar el CWE oficial correspondiente.
4. **Asignar Skill Operativa:** Vincular la Skill encargada de auditar este vector.
5. **Añadir Registro a esta Tabla:** Documentar nombre, taxonomía, severidad y registrar la heurística correspondiente en la carpeta `references/` de la Skill asignada.
