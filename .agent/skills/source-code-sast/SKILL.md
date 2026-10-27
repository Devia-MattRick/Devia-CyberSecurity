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

- `references/`: Catálogos de sumideros (*sinks*) por lenguaje, patrones de inyección y guías de taint analysis.
  - [`code-evidence-and-root-cause-reasoning.md`](references/code-evidence-and-root-cause-reasoning.md): Estándar de evidencia estructurada en código, los 7 roles semánticos (`CodeEvidenceRole`), razonamiento conectivo y política de `ruleId`.
- `scripts/`: Parsers de AST, escáneres de patrones basados en regex y validadores de flujos.
