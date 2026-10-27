# Devia-CyberSecurity — Arquitectura del Sistema

Este documento describe la arquitectura técnica, las directivas de diseño y el modelo de capas adoptado en el repositorio **Devia-CyberSecurity**.

---

## 🏛️ Modelo de Tres Capas (Tri-Tier Hybrid Security Engine)

El sistema opera bajo un modelo desacoplado que separa el razonamiento metodológico, la validación estricta de datos y la ejecución de utilidades de bajo nivel:

```
+-------------------------------------------------------------+
|                     CAPA 1: SKILLS (.agent/skills)          |
|  - Razonamiento heurístico y metodológico por dimensión     |
|  - Checklists universales (OWASP, NIST, CWE)                |
|  - Orquestación de revisiones de código y arquitectura      |
+-------------------------------------------------------------+
                              |
                              v
+-------------------------------------------------------------+
|           CAPA 2: MOTOR DE CONTRATOS (TypeScript + Zod)     |
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
