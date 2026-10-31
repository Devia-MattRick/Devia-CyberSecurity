# Devia-CyberSecurity — Arquitectura del Sistema

Este documento describe la arquitectura técnica, las directivas de diseño y el modelo de capas adoptado en el repositorio **Devia-CyberSecurity**.

---

## 🏛️ Modelo de Tres Capas (Tri-Tier Hybrid Security Engine)

El sistema opera bajo un modelo desacoplado que separa el razonamiento metodológico, la validación estricta de datos y la ejecución de utilidades de bajo nivel:

```
+-------------------------------------------------------------+
|                     CAPA 1: SKILLS (.agents/skills)          |
|  - Razonamiento heurístico y metodológico por dimensión     |
|  - Checklists universales (OWASP, NIST, CWE)                |
|  - Orquestación de revisiones de código y arquitectura      |
+-------------------------------------------------------------+
                              |
                              v
+-------------------------------------------------------------+
|           CAPA 2: MOTOR DE CONTRATOS (TypeScript + Zod + pnpm)  |
|  - Modelos autoritativos de datos (Findings, Reports, TM)   |
|  - Validación de esquemas en tiempo de ejecución            |
|  - Servidores MCP y CLI de orquestación                     |
+-------------------------------------------------------------+
                              |
                              v
+-------------------------------------------------------------+
|         CAPA 3: UTILIDADES POLÍGLOTAS (Python / AST / CLI)  |
|  - Scripts de cálculo de entropía de Shannon (Secretos)     |
|  - Parsers políglotas agnósticos (Tree-sitter / AST)         |
|  - Inspección determinista a nivel de byte y tokens         |
+-------------------------------------------------------------+
```

---

## 🔒 Principio Contract-First con Zod

Toda salida generada por un script, motor o agente debe validar estrictamente contra los esquemas definidos en `src/schemas/`:

1. **`SecurityFindingSchema`**: Define la estructura atómica de un hallazgo de vulnerabilidad, incluyendo ID, severidad, confianza, CWE, vector CVSS, ubicación milimétrica, evidencia, traza de taint (*dataflow*) y propuesta de remediación.
2. **`ThreatModelSchema`**: Modela activos, actores de amenaza, límites de confianza (*trust boundaries*), puntos de entrada y escenarios de amenaza según taxonomía STRIDE.
3. **`AuditReportSchema`**: Agrupa métricas de auditoría, alcance evaluado, resumen ejecutivo y hoja de ruta de remediación por fases.

---

## 🛡️ Las 8 Dimensiones Canónicas

1. **Threat Modeling & Attack Surface**
2. **Source Code Security (SAST)**
3. **Secrets & Cryptographic Posture**
4. **Identity, Access & Session Control**
5. **Supply Chain & Dependencies (SCA)**
6. **Architecture, Boundaries & Zero Trust**
7. **Configuration & Hardening**
8. **Resilience, Logging & Telemetry**

---

## ⚡ Servidor MCP Canónico (Model Context Protocol — Capa 2)

El módulo [`src/mcp/`](file:///k:/Devia-CyberSecurity/src/mcp/) implementa el servidor oficial de ciberseguridad defensiva bajo `@modelcontextprotocol/sdk` (Node 22+ ESM), proyectando las capacidades del repositorio hacia 12+ agentes clientes (Claude Desktop, Cursor, Windsurf, Cline, Roo, Zed y Antigravity).

### 1. Cascada de Descubrimiento Progresivo (Anti-Context Rot)
Para eliminar la saturación del contexto del LLM, el catálogo se organiza en 10 herramientas maestras:
- **`devia_orchestrate_audit`**: Orquestador maestro en 4 fases militares (reconocimiento, ingesta, auditoría y reporte).
- **`devia_search_tools`**: Primitiva de búsqueda léxica offline BM25 en <4ms para descubrir motores especializados y referencias.
- **8 Herramientas Dimensionales**: `devia_threat_modeling`, `devia_source_sast`, `devia_secrets_crypto`, `devia_identity_access`, `devia_supply_chain`, `devia_zero_trust_arch`, `devia_config_hardening`, `devia_resilience_telemetry`.
- **Tool Pinning (Anti Rug-Pull):** Generación de digest SHA-256 inmutable de las signaturas registradas para verificar integridad.

### 2. Resiliencia de Procesos OS (Axiomas de mcptoon)
- **Drenado asíncrono en chunks de 4096 bytes:** Evita deadlocks por saturación de pipes de 4KB en Windows.
- **Preservación de Tail Diagnóstico:** Captura de los últimos 4096 bytes de `stderr` ante excepciones.
- **Terminación en Árbol:** Empleo de `taskkill /PID <PID> /T /F` en Windows ante timeouts (default: 60s) para erradicar procesos huérfanos.
- **Invariante Stdio:** Manejo integral en `try/catch` con retorno `{ isError: true }` garantizando continuidad de sesión.

### 3. Tokenomics BPE & TOON v1.1
- Formateo tabular de arreglos homogéneos de hallazgos mediante TOON v1.1 (`[N] col1, col2, col3:`), logrando entre 45% y 53% de ahorro en tokens BPE frente a JSON plano.

### 4. Protocolo Lossless CCR & Paginación Doble Presupuesto
- Todo resultado que exceda 1.200 tokens o 1 MiB se almacena en `.cache/ccr/<handle>.json` con digest SHA-256 de 12 caracteres.
- Se registra en la cadena forense inmutable (`.cache/ccr/forensic_chain.jsonl`).
- Al cliente se entrega un resumen ejecutivo destilado en TOON con su handle de auditoría correspondiente.

### 5. Blindaje ante la Tríada Letal
- **ZWSP Defanging (`GHSA-g5f9-3xfg-p9mf`):** Inserción de Zero-Width Space (`\u200b`) en delimitadores estructurales de chat (`<|im_start|>`, `<|eot_id|>`, `[INST]`) presentes en código externo auditado.
- **Purga de Contrabando Unicode:** Remoción de controles bidireccionales Trojan Source (`\u202E`) y tags stego.

