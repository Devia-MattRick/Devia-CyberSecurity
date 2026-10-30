---
name: source-code-sast
description: Análisis estático de seguridad de código fuente (SAST), detección de inyecciones (SQL, Command, Code, Path), deserialización insegura, race conditions, fallos lógicos y trazabilidad de taint (fuente a sumidero).
---

# Source Code Security (SAST)

**Dimensión Canónica:** `SOURCE_CODE_SAST` (Dimensión 2)

---

## 🎯 Objetivo Delegado y Asignado

Esta Skill gobierna la dimensión de **Seguridad de Código Fuente (SAST)**. Su responsabilidad primordial es:
1. Auditar estáticamente el código fuente de cualquier lenguaje o framework para identificar vulnerabilidades lógicas y de implementación.
2. Detectar inyecciones críticas (SQL/NoSQL Injection, OS Command Injection, Code Injection/eval, Path Traversal / LFI / RFI).
3. Realizar análisis de propagación de datos (*Taint Analysis*), rastreando flujos de datos no confiables desde fuentes de entrada (*Sources*) hasta sumideros de ejecución sensibles (*Sinks*).
4. Detectar deserialización insegura de objetos (e.g. `pickle`, `yaml.load`, deserializadores binarios sin esquemas).
5. Identificar condiciones de carrera (*Race Conditions / TOCTOU*), manejo inseguro de punteros o memoria, y evasión de validaciones de entrada.
6. Mapear cada hallazgo contra CWE Top 25 y generar reportes conformes a `SecurityFindingSchema`.

---

## 📂 Organización Interna

- `references/`: Catálogos de sumideros (*sinks*) por lenguaje, patrones de inyección y guías de taint analysis (19 referencias técnicas).
  - [`code-evidence-and-root-cause-reasoning.md`](references/code-evidence-and-root-cause-reasoning.md): Estándar de evidencia estructurada en código, los 7 roles semánticos (`CodeEvidenceRole`), razonamiento conectivo y política de `ruleId`.
  - [`cwe-1236-csv-formula-injection.md`](references/cwe-1236-csv-formula-injection.md): Detección y mitigación de Formula Injection y comandos DDE en CSV/Excel.
  - [`sani-parse-and-llm-output-validation.md`](references/sani-parse-and-llm-output-validation.md): Protocolo Sani-Parse Invariable para salidas no deterministas de modelos de IA.
  - [`race-condition-testing-and-turbo-intruder.md`](references/race-condition-testing-and-turbo-intruder.md): Testing de condiciones de carrera con HTTP/2 Single-Packet Attack y bloqueos atómicos.

---

## 🛠️ Herramientas de Capa 3 Asignadas (`src/scripts/`)

Esta Skill consume y orquesta los siguientes motores de análisis determinista en Python 3.11+:

| Script Ejecutable | Contrato Zod (Capa 2) | Rol y Capacidades | Test Unitario |
| :--- | :--- | :--- | :--- |
| [`src/scripts/differential_exploit_verifier.py`](file:///k:/Devia-CyberSecurity/src/scripts/differential_exploit_verifier.py) | [`finding.schema.ts`](file:///k:/Devia-CyberSecurity/src/schemas/finding.schema.ts) | Verificación diferencial no destructiva de inyecciones (SQLi, SSTI, Command Injection). | [`test_differential_exploit_verifier.py`](file:///k:/Devia-CyberSecurity/src/scripts/test_differential_exploit_verifier.py) |
| [`src/scripts/attack_vector_assessment_engine.py`](file:///k:/Devia-CyberSecurity/src/scripts/attack_vector_assessment_engine.py) | [`exploit-path-assessment.schema.ts`](file:///k:/Devia-CyberSecurity/src/schemas/exploit-path-assessment.schema.ts) | Evaluación estática de rutas de ataque, análisis de impacto y severidad de sumideros. | [`test_attack_vector_assessment_engine.py`](file:///k:/Devia-CyberSecurity/src/scripts/test_attack_vector_assessment_engine.py) |
| [`src/scripts/poc_safety_linter.py`](file:///k:/Devia-CyberSecurity/src/scripts/poc_safety_linter.py) | [`roe-enforcement.schema.ts`](file:///k:/Devia-CyberSecurity/src/schemas/roe-enforcement.schema.ts) | Linter estricto de seguridad para scripts de prueba de concepto; prohíbe subprocesos inseguros y cargas hostiles. | [`test_poc_safety_linter.py`](file:///k:/Devia-CyberSecurity/src/scripts/test_poc_safety_linter.py) |
| [`src/scripts/scan_formula_injection.py`](file:///k:/Devia-CyberSecurity/src/scripts/scan_formula_injection.py) | [`formula-injection.schema.ts`](file:///k:/Devia-CyberSecurity/src/schemas/formula-injection.schema.ts) | Escaneo determinista de Formula Injection en CSV/Excel (CWE-1236), verificación de prefijo de comilla simple y BOM UTF-8. | [`test_scan_formula_injection.py`](file:///k:/Devia-CyberSecurity/src/scripts/test_scan_formula_injection.py) |

