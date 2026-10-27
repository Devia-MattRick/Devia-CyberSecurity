# Matriz Canónica de Mapeo Multimarco — Devia-CyberSecurity

Este documento establece la **Fuente Única de Verdad (SSOT)** para la correlación y traducción bidireccional entre las **8 Dimensiones Canónicas** de Devia-CyberSecurity (`SecurityDimensionSchema`), **MITRE ATT&CK Enterprise (v14/v15)**, **NIST Cybersecurity Framework (CSF 2.0)** y **OWASP Top 10 (2025)**.

---

## 🏛️ 1. Taxonomía Unificada de las 8 Dimensiones Canónicas

Toda auditoría, hallazgo (`SecurityFindingSchema`), modelo de amenazas (`ThreatModelSchema`) o regla SAST/SCA debe clasificarse estrictamente dentro de una de las 8 dimensiones autorizadas:

| Dimensión Canónica (`SecurityDimensionSchema`) | Tácticas MITRE ATT&CK | Funciones y Categorías NIST CSF 2.0 | Categorías OWASP Top 10 (2025) | Familias CWE Representativas |
| :--- | :--- | :--- | :--- | :--- |
| **1. `THREAT_MODELING_ATTACK_SURFACE`** | Reconnaissance (`TA0043`), Resource Development (`TA0042`), Initial Access (`TA0001`), Discovery (`TA0007`) | **Identify (ID)**: `ID.AM`, `ID.RA`<br>**Govern (GV)**: `GV.RM` | `A04:2025-Insecure Design` | CWE-1059, CWE-1021, CWE-400 |
| **2. `SOURCE_CODE_SAST`** | Execution (`TA0002`: `T1059`, `T1203`, `T1055`), Defense Evasion (`TA0005`: `T1027`) | **Protect (PR)**: `PR.DS`, `PR.PS`<br>**Detect (DE)**: `DE.AE` | `A03:2025-Injection`<br>`A10:2025-Server-Side Request Forgery` | CWE-89, CWE-79, CWE-78, CWE-918, CWE-502 |
| **3. `SECRETS_CRYPTOGRAPHY`** | Credential Access (`TA0006`: `T1552`, `T1558.003`, `T1003`), Exfiltration (`TA0010`: `T1573`), Impact (`TA0040`: `T1486`) | **Protect (PR)**: `PR.DS` (Data Security) | `A02:2025-Cryptographic Failures` | CWE-798, CWE-327, CWE-330, CWE-321 |
| **4. `IDENTITY_ACCESS_SESSION`** | Privilege Escalation (`TA0004`), Credential Access (`TA0006`: `T1110`, `T1539`), Lateral Movement (`TA0008`: `T1550`, `T1078`) | **Protect (PR)**: `PR.AA` (Identity & Access)<br>**Govern (GV)**: `GV.RR` | `A01:2025-Broken Access Control`<br>`A07:2025-Identification & Auth Failures` | CWE-287, CWE-639, CWE-284, CWE-384 |
| **5. `SUPPLY_CHAIN_SCA`** | Initial Access (`TA0001`: `T1195`), Persistence (`TA0003`: `T1525`) | **Govern (GV)**: `GV.SC`<br>**Protect (PR)**: `PR.PS` | `A06:2025-Vulnerable & Outdated Components`<br>`A08:2025-Software & Data Integrity Failures` | CWE-1104, CWE-494, CWE-1395 |
| **6. `ARCHITECTURE_BOUNDARIES_ZERO_TRUST`** | Lateral Movement (`TA0008`: `T1021`, `T1210`), Command & Control (`TA0011`: `T1071`, `T1090`, `T1105`) | **Protect (PR)**: `PR.IR` (Infrastructure Resilience & Zero Trust) | `A01:2025-Broken Access Control`<br>`A04:2025-Insecure Design` | CWE-1004, CWE-942, CWE-269 |
| **7. `CONFIGURATION_HARDENING`** | Persistence (`TA0003`: `T1547.001`, `T1053.005`, `T1136`), Defense Evasion (`TA0005`: `T1014`, `T1070`) | **Protect (PR)**: `PR.PS` (Platform Security)<br>**Govern (GV)**: `GV.PO` | `A05:2025-Security Misconfiguration` | CWE-16, CWE-276, CWE-1188, CWE-732 |
| **8. `RESILIENCE_LOGGING_TELEMETRY`** | Collection (`TA0009`), Exfiltration (`TA0010`: `T1041`, `T1048`), Impact (`TA0040`: `T1489`, `T1490`, `T1562`) | **Detect (DE)**: `DE.CM`, `DE.AE`<br>**Respond (RS)**: `RS.MA`, `RS.AN`, `RS.MI`<br>**Recover (RC)**: `RC.RP` | `A09:2025-Security Logging & Monitoring Failures` | CWE-778, CWE-117, CWE-400, CWE-754 |

---

## 🗺️ 2. Mapeo de Subdominios Empíricos a las 8 Dimensiones Canónicas

Al auditar repositorios o catálogos externos que utilicen segmentaciones ad-hoc (e.g., los 24 subdominios de habilidades de Anthropic), el agente **debe proyectar obligatoriamente** el análisis a la taxonomía canónica:

| Subdominio Externo | Dimensión Canónica Primaria | Dimensión Secundaria (si aplica) | Enfoque de Auditoría |
| :--- | :--- | :--- | :--- |
| `web-application-security` | `SOURCE_CODE_SAST` | `IDENTITY_ACCESS_SESSION` | Inyecciones, SSRF, IDOR y sanitización de entradas. |
| `api-security` | `IDENTITY_ACCESS_SESSION` | `SOURCE_CODE_SAST` | BOLA/BFLA, autenticación por tokens y transporte seguro. |
| `cloud-security` | `CONFIGURATION_HARDENING` | `ARCHITECTURE_BOUNDARIES_ZERO_TRUST` | Políticas IAM, exposición de recursos (S3) y segmentación de red. |
| `container-security` | `CONFIGURATION_HARDENING` | `SUPPLY_CHAIN_SCA` | Escape de contenedor (`T1611`), escaneo de imágenes y políticas K8s. |
| `devsecops` | `SUPPLY_CHAIN_SCA` | `CONFIGURATION_HARDENING` | Pipelines CI/CD, firmado de artefactos (Sigstore) y análisis SCA. |
| `identity-access-management` | `IDENTITY_ACCESS_SESSION` | `SECRETS_CRYPTOGRAPHY` | Ciclo de vida de identidad, MFA, tokens JWT y contraseñas. |
| `cryptography` | `SECRETS_CRYPTOGRAPHY` | `RESILIENCE_LOGGING_TELEMETRY` | Algoritmos de cifrado, KMS, entropía y certificados. |
| `endpoint-security` | `CONFIGURATION_HARDENING` | `RESILIENCE_LOGGING_TELEMETRY` | Bastionado de SO, servicios innecesarios y telemetría EDR. |
| `network-security` | `ARCHITECTURE_BOUNDARIES_ZERO_TRUST` | `RESILIENCE_LOGGING_TELEMETRY` | Microsegmentación, firewalls, detección de C2 e inspección de tráfico. |
| `zero-trust-architecture` | `ARCHITECTURE_BOUNDARIES_ZERO_TRUST` | `IDENTITY_ACCESS_SESSION` | Verificación explícita, menor privilegio y asunción de brecha. |
| `threat-intelligence` | `THREAT_MODELING_ATTACK_SURFACE` | `RESILIENCE_LOGGING_TELEMETRY` | Actores de amenaza, indicadores de compromiso y modelos de impacto. |
| `threat-hunting` | `RESILIENCE_LOGGING_TELEMETRY` | `THREAT_MODELING_ATTACK_SURFACE` | Búsqueda proactiva de anomalías y reglas de detección Sigma. |
| `soc-operations` | `RESILIENCE_LOGGING_TELEMETRY` | `CONFIGURATION_HARDENING` | Triaje de alertas, SIEM, flujos de respuesta y monitoreo continuo. |
| `malware-analysis` | `SOURCE_CODE_SAST` | `RESILIENCE_LOGGING_TELEMETRY` | Deconstrucción de ejecutables, desofuscación y análisis de comportamiento. |
| `digital-forensics` | `RESILIENCE_LOGGING_TELEMETRY` | `SECRETS_CRYPTOGRAPHY` | Cadena de custodia, extracción de artefactos y volcado de memoria. |
| `incident-response` | `RESILIENCE_LOGGING_TELEMETRY` | `CONFIGURATION_HARDENING` | Contención, erradicación y recuperación ante incidentes. |
| `vulnerability-management` | `THREAT_MODELING_ATTACK_SURFACE` | `SUPPLY_CHAIN_SCA` | Catalogación de CVEs, priorización CVSS/EPSS y planes de parcheo. |
| `penetration-testing` | `THREAT_MODELING_ATTACK_SURFACE` | `SOURCE_CODE_SAST` | Simulación controlada de ataques para descubrir brechas. |
| `red-teaming` | `THREAT_MODELING_ATTACK_SURFACE` | `ARCHITECTURE_BOUNDARIES_ZERO_TRUST` | Emulación holística de adversarios a través de todo el kill-chain. |
| `phishing-defense` | `THREAT_MODELING_ATTACK_SURFACE` | `IDENTITY_ACCESS_SESSION` | Detección de ingeniería social y protección de credenciales. |
| `ransomware-defense` | `RESILIENCE_LOGGING_TELEMETRY` | `SECRETS_CRYPTOGRAPHY` | Resiliencia de backups, mitigación de cifrado no autorizado. |
| `ot-ics-security` | `ARCHITECTURE_BOUNDARIES_ZERO_TRUST` | `CONFIGURATION_HARDENING` | Protocolos industriales (Modbus, SCADA) y segmentación física. |
| `mobile-security` | `SOURCE_CODE_SAST` | `IDENTITY_ACCESS_SESSION` | Seguridad en apps Android/iOS, keystore y canales locales. |
| `compliance-governance` | `CONFIGURATION_HARDENING` | `THREAT_MODELING_ATTACK_SURFACE` | Marcos regulatorios (ISO 27001, SOC 2, HIPAA, NIST CSF 2.0). |

---

## 🔄 3. Tablas de Referencia Cruzada Directa (Crosswalks)

### 3.1. OWASP Top 10 (2025) $\longleftrightarrow$ MITRE ATT&CK
| Categoría OWASP (2025) | Técnicas ATT&CK Vinculadas | Escenario de Ataque Típico |
| :--- | :--- | :--- |
| **A01: Broken Access Control** | `T1078` (Valid Accounts), `T1548` (Abuse Elevation Control) | Escalada de privilegios o consulta de datos de otro tenant (IDOR). |
| **A02: Cryptographic Failures** | `T1557` (Adversary-in-the-Middle), `T1040` (Network Sniffing) | Intercepción de tráfico en texto claro o explotación de claves débiles. |
| **A03: Injection** | `T1190` (Exploit Public-Facing App), `T1059` (Command & Scripting) | Ejecución arbitraria de comandos en el SO o extracción masiva de SQL. |
| **A04: Insecure Design** | `T1195` (Supply Chain Compromise), `T1078` (Valid Accounts) | Omisión de límites de confianza y falta de separación de privilegios. |
| **A05: Security Misconfiguration** | `T1574` (Hijack Execution Flow), `T1190` | Exposición de consolas debug, credenciales por defecto o CORS permissivo. |
| **A06: Vulnerable Components** | `T1190` (Exploit Public-Facing App), `T1195` | Explotación de CVEs conocidas en librerías open-source desactualizadas. |
| **A07: Auth Failures** | `T1110` (Brute Force), `T1539` (Steal Web Session Cookie) | Secuestro de sesión mediante relleno de credenciales o robo de cookies. |
| **A08: Software & Data Integrity** | `T1195` (Supply Chain), `T1554` (Compromise Client Software) | Inyección de paquetes troyanizados en CI/CD o falsificación de firmware. |
| **A09: Logging Failures** | `T1070` (Indicator Removal), `T1562` (Impair Defenses) | Incursión adversaria prolongada sin rastro forense ni alertas activas. |
| **A10: SSRF** | `T1190` (Exploit Public-Facing App), `T1552` (Unsecured Credentials) | Consulta al endpoint de metadatos de la nube (`IMDSv2`) para robar tokens IAM. |

### 3.2. OWASP Top 10 (2025) $\longleftrightarrow$ NIST CSF 2.0
| Categoría OWASP (2025) | Función Primaria NIST CSF 2.0 | Categorías de Control Requeridas |
| :--- | :--- | :--- |
| **A01: Broken Access Control** | **Protect (PR)** | `PR.AA` (Identity & Access Control) |
| **A02: Cryptographic Failures** | **Protect (PR)** | `PR.DS` (Data Security) |
| **A03: Injection** | **Protect (PR)** / **Detect (DE)** | `PR.DS` (Data Security), `DE.AE` (Adverse Event Analysis) |
| **A04: Insecure Design** | **Govern (GV)** / **Protect (PR)** | `GV.RM` (Risk Management Strategy), `PR.PS` (Platform Security) |
| **A05: Security Misconfiguration** | **Protect (PR)** | `PR.PS` (Platform Security), `PR.IR` (Infrastructure Resilience) |
| **A06: Vulnerable Components** | **Identify (ID)** / **Govern (GV)** | `ID.RA` (Risk Assessment), `GV.SC` (Supply Chain Risk) |
| **A07: Auth Failures** | **Protect (PR)** | `PR.AA` (Authentication & Access Control) |
| **A08: Integrity Failures** | **Protect (PR)** / **Govern (GV)** | `PR.DS` (Data Integrity), `GV.SC` (Supply Chain Security) |
| **A09: Logging Failures** | **Detect (DE)** | `DE.CM` (Continuous Monitoring), `DE.AE` (Event Analysis) |
| **A10: SSRF** | **Protect (PR)** / **Detect (DE)** | `PR.DS` (Network Data Security), `DE.AE` (Adverse Event Analysis) |

---

## 🎯 4. Catálogo de Brechas Tácticas de Frontera (*Coverage Gaps*)

Al diseñar auditorías defensivas o modelos de amenazas, el agente debe advertir activamente si el alcance excluye las siguientes zonas ciegas frecuentes:

1. **Ataques a Nivel de Firmware / Pre-OS (`T1542`):** Infección de UEFI, BIOS o BMC. No detectables por escáneres de código estático convencionales. Requieren verificación de firmas Secure Boot y TPM.
2. **Movimiento Lateral Cloud vía Cookies de Sesión (`T1550.001`):** Robo de cookies desde la memoria del navegador en endpoints comprometidos para autenticarse en servicios SaaS/IaaS sin activar MFA.
3. **Adiciones Maliciosas de Hardware (`T1200`):** Inserción de dispositivos físicos rogue (USB Rubber Ducky, implantes de red LAN) que eluden las fronteras lógicas de red.
4. **Canales de Tráfico y Señalización Encubierta (`T1205` / `T1573`):** Modulación de tráfico en protocolos no estándar o tunelización DNS/ICMP para exfiltración sigilosa sin alertar proxies HTTP.

---

## 💻 5. Patrón de Filtrado para Agentes de IA

Para consultar habilidades y clasificar hallazgos de forma determinista sin sobregasto de tokens:

```python
# Consulta determinista con src/scripts/navigator_mapper.py
python src/scripts/navigator_mapper.py project external-reps/mappings/attack-navigator-layer.json --json
```

Todo hallazgo emitido en `findings.json` debe validar el mapeo:
```json
{
  "category": "SOURCE_CODE_SAST",
  "cwe": ["CWE-89"],
  "owasp": ["A03:2025-Injection"],
  "mitreAttack": ["T1190"],
  "nistCsf": ["PR.DS", "DE.AE"]
}
```
