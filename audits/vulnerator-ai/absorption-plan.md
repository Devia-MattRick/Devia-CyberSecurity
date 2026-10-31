# Plan de Absorción Forense de Ingeniería Inversa: Vulnerator-AI v1.7.0

## 1. Identidad del Objetivo y Cadena de Custodia
- **Ruta Objetivo:** `D:\Descargas\vulnerator-ai-master`
- **Ruta Canónica:** `D:\Descargas\vulnerator-ai-master`
- **Versión / Release:** `1.7.0 (Snapshot de Distribución)`
- **Arquetipo:** `AGENTIC_MULTI_CONTAINER_PENTEST_SYSTEM` (Sistema Agéntico Multicontenedor OODA + MCP Kali Pentest Runner)
- **Fecha de Auditoría UTC:** `2026-10-31T05:22:18Z`
- **Archivos Auditados:** `164` archivos, `164` evaluados en cobertura forense.
- **Bytes Totales:** `8956037` bytes (8.54 MiB).

---

## 2. Resumen Ejecutivo del Objetivo
**Vulnerator-AI** es un entorno autónomo de pruebas de penetración y evaluación de seguridad guiado por un bucle OODA (Observe-Orient-Decide-Act) que combina:
1. **ooda-agent (Hermes Agent):** El motor cognitivo que razona sobre el estado de la auditoría y decide los pasos tácticos.
2. **kali-mcp:** Servidor Model Context Protocol que corre dentro de un contenedor Kali Linux y expone herramientas de pentest CLI, recolección cloud (Prowler, ScoutSuite), simulación IAM y ejecución de comandos.
3. **playwright-mcp:** Servidor MCP con navegador Chromium headless para pentesting web interactivo (DOM, SPAs, XSS).
4. **vulnerator-mcp:** Gateway de entrada frontal que envuelve la API de Hermes en el puerto `:8700` con autenticación por token.
5. **Laboratorios Vulnerables de Práctica:** Escenarios CTF realistas para validación de exploits (PHP2Shell, Looney Tunables CVE-2023-4911, SSTI en Flask).

---

## 3. Mapeo Canónico contra las 8 Dimensiones de Devia-CyberSecurity

| Dimensión Canónica | Nivel de Cobertura | Componentes Clave en Objetivo | Contribución al Ecosistema |
| :--- | :--- | :--- | :--- |
| **THREAT_MODELING_ATTACK_SURFACE** | Exhaustivo | `attack-navigation`, `pentest-ooda`, arquitectura 4 contenedores | Ontología ATT&CK como lenguaje de orientación táctica en OODA |
| **SOURCE_CODE_SAST** | Exhaustivo | `scope_guard.py`, `labs/php2shell-lab/CHAINS.md`, `pinguinazo-ssti` | Gate fail-closed determinista y 5 cadenas de explotación PHP avanzadas |
| **SECRETS_CRYPTOGRAPHY** | Alto | `web-pentest/SKILL.md`, `artifact_http.py`, hashing SHA-256 | Redacción de secretos contra fugas en clientes LLM auxiliares |
| **IDENTITY_ACCESS_SESSION** | Exhaustivo | `aws-pacu-privesc`, `aws_simulate.py`, `vulnerator_mcp_server.py` | Matriz de privesc AWS IAM con verificación read-only pre-vuelo |
| **SUPPLY_CHAIN_SCA** | Alto | `plugins/`, `security.yml`, `dependabot.yml`, Dockerfiles | Modelo de confianza de plugins MCP y pipeline de escaneo CI/CD |
| **ARCHITECTURE_BOUNDARIES_ZERO_TRUST** | Exhaustivo | `tool_streaming.py`, `artifact_store.py`, `uname` wrapper | Aislamiento de procesos con killpg atómico y sanitización anti-traversal |
| **CONFIGURATION_HARDENING** | Alto | `scope.json`, `vulnerator_mcp_server.py`, exact healthz | Configuración fail-closed por defecto y protección de endpoints exactos |
| **RESILIENCE_LOGGING_TELEMETRY** | Exhaustivo | `tool_streaming.py` (256KB page), `finding_store.py` (JSONL) | Paginación con doble presupuesto MCP SSE y almacén de evidencia reproducible |

---

## 4. Unidades de Conocimiento Extraídas (`KNOW-001` a `KNOW-009`)

- **`KNOW-001` - Bucle OODA y Navegación Táctica con MITRE ATT&CK como Ontología Agéntica** (THREAT_MODELING_ATTACK_SURFACE): Enriquece el modelado de amenazas y la orquestación agéntica en Devia-CyberSecurity, dotando a los agentes de un marco formal de orientación estratégica para planificar el siguiente vector de análisis y clasificar hallazgos de forma estandarizada.
- **`KNOW-002` - Gate Determinista Fail-Closed de Confinamiento de Objetivos (Scope-Guard)** (SOURCE_CODE_SAST): Aporta una arquitectura de gate fail-closed para verificación de reglas de compromiso (Rules of Engagement), impidiendo la ejecución accidental o inducida de análisis sobre activos fuera de alcance.
- **`KNOW-003` - Cadenas Avanzadas de Explotación PHP2Shell (Session Upload LFI, Handler Mismatch y mod_php OOM RCE)** (SOURCE_CODE_SAST): Amplía drásticamente las heurísticas SAST para auditoría de aplicaciones PHP modernas y legacy, permitiendo detectar vulnerabilidades sutiles de deserialización en sesiones y configuraciones de SAPI inherentemente frágiles.
- **`KNOW-004` - Vector de Fuga de Credenciales en Canales Auxiliares de Modelos Agénticos** (SECRETS_CRYPTOGRAPHY): Establece directivas obligatorias de ofuscación y redacción de credenciales en tiempo de ejecución para agentes LLM, impidiendo la filtración de secretos hacia pipelines de telemetría o compresión conversacional.
- **`KNOW-005` - Matriz de Escalada de Privilegios en AWS IAM y Verificación Read-Only Pre-Vuelo** (IDENTITY_ACCESS_SESSION): Proporciona a la skill de gestión de accesos una batería de reglas de validación formal para permisos IAM y minimiza los falsos positivos mediante pruebas de simulación deterministas sin impacto operacional.
- **`KNOW-006` - Modelo de Confianza y Riesgos de Seguridad en Plugins de Servidores MCP** (SUPPLY_CHAIN_SCA): Fortalece las capacidades de escaneo de dependencias y cadenas de suministro MCP en Devia-CyberSecurity para auditar servidores extensibles e identificar extensiones maliciosas o sobreprivilegiadas.
- **`KNOW-007` - Aislamiento de Procesos Subordinados y Confinamiento Estricto de Rutas de Almacenamiento** (ARCHITECTURE_BOUNDARIES_ZERO_TRUST): Robustece las herramientas deterministas de Capa 3 contra fugas de procesos en memoria, procesos zombies y manipulación de rutas en sistemas multi-tenant o entornos de ejecución compartidos.
- **`KNOW-008` - Bastionado de Interfaces de Diagnóstico y Gateways MCP con Autenticación Fail-Closed** (CONFIGURATION_HARDENING): Eleva los estándares de configuración segura para middlewares y agentes expuestos en redes internas de contenedores, erradicando puertas traseras por rutas de salud mal configuradas.
- **`KNOW-009` - Paginación con Doble Presupuesto de Transporte SSE y Almacén Persistente de Evidencias** (RESILIENCE_LOGGING_TELEMETRY): Previene la denegación de servicio por desbordamiento de búfer en canales de comunicación entre agentes y servidores MCP, asegurando que los hallazgos críticos persistan de forma íntegra e inmutable.

---

## 5. Matriz de Acciones de Absorción Técnica (`ABS-001` a `ABS-008`)

| ID Acción | Conocimiento | Destino Tri-Tier | Intención Evolutiva | Ruta en Devia-CyberSecurity | Prioridad |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **`ABS-001`** | `KNOW-001` | `SKILL_REFERENCE` | `ABSORB_EXPAND` | `.agents/skills/threat-modeling-attack-surface/references/ooda-loop-and-attack-tactical-orientation.md` | **HIGH** |
| **`ABS-002`** | `KNOW-002` | `PYTHON_SCRIPT` | `UPDATE_ENHANCE` | `src/scripts/target_scope_guard.py` | **CRITICAL** |
| **`ABS-003`** | `KNOW-003` | `SKILL_REFERENCE` | `CREATE_NEW` | `.agents/skills/source-code-sast/references/php-session-deserialization-and-sapi-chains.md` | **HIGH** |
| **`ABS-004`** | `KNOW-004` | `UPDATE_EXISTING` | `ROBUSTIFY_HARDEN` | `docs/PROACTIVE.md` | **HIGH** |
| **`ABS-005`** | `KNOW-005` | `SKILL_REFERENCE` | `ABSORB_EXPAND` | `.agents/skills/identity-access-session/references/aws-iam-privilege-escalation-and-simulation.md` | **HIGH** |
| **`ABS-006`** | `KNOW-006` | `SKILL_REFERENCE` | `UPDATE_ENHANCE` | `.agents/skills/architecture-boundaries-zero-trust/references/mcp-plugin-trust-and-process-isolation.md` | **MEDIUM** |
| **`ABS-007`** | `KNOW-007` | `UPDATE_EXISTING` | `ROBUSTIFY_HARDEN` | `src/scripts/hard_exclusions.py` | **HIGH** |
| **`ABS-008`** | `KNOW-008` | `ZOD_SCHEMA` | `CREATE_NEW` | `src/schemas/mcp-paging.schema.ts` | **MEDIUM** |

---

## 6. Verificación de Contratos y Ledgers
Los cuatro ledgers canónicos han sido materializados en `audits/vulnerator-ai/`:
- `inventory.jsonl`: Metadatos de 164 archivos con digests SHA-256 y conteo de líneas.
- `coverage.jsonl`: Disposición epistemológica por archivo con cobertura 100% de subsistemas.
- `evidence.jsonl`: 16 citas factuales estructuradas con nivel OBSERVED y digests verificables.
- `unknowns.jsonl`: 3 incertidumbres identificadas con hipótesis e impacto estimado.
- `absorption-plan.json`: Validado contractualmente contra `AbsorptionPlanSchema` en TypeScript/Zod.
