# Plan de Absorción Forense de Ingeniería Inversa: Claude-Red v0.3.0

## 1. Identidad del Objetivo y Cadena de Custodia
- **Ruta Suministrada:** `D:\Descargas\Claude-Red-main`
- **Ruta Canónica de Repositorio:** `D:\Descargas\Claude-Red-main\Claude-Red-main`
- **Versión / Release:** `v0.3.0 (Biblioteca de Skills Ofensivas de Red Team)`
- **Arquetipo:** `AGENTIC_SKILLS_AND_OFFENSIVE_REDTEAM_FRAMEWORK` (Colección estructurada de 78 skills en Markdown drop-in para Claude)
- **Fecha de Auditoría UTC:** `2026-10-31T20:02:14Z`
- **Archivos Auditados:** `97` archivos físicos analizados en cobertura forense estática.
- **Bytes Totales:** `4686684` bytes (4.47 MiB).
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
Los cuatro ledgers canónicos han sido materializados en `K:\Devia-CyberSecurity\audits\claude-red`:
- `inventory.jsonl`: Metadatos de 97 archivos con digests SHA-256 y conteo de líneas.
- `summary.json`: Métricas globales, timestamps ISO 8601 y clasificación de arquetipo.
- `coverage.jsonl`: Disposición por archivo (97 evaluados: 94 leídos/trazados, 3 excluidos con justificación).
- `evidence.jsonl`: Citas factuales (`SRC-001` a `SRC-011`, `CFG-001`) con nivel epistemológico `OBSERVED` y SHA-256.
- `unknowns.jsonl`: Registro de 4 brechas técnicas no resueltas (`UNK-001` a `UNK-004`).
- `absorption-plan.json`: Contrato formal conforme a `AbsorptionPlanSchema` de Devia-CyberSecurity.
