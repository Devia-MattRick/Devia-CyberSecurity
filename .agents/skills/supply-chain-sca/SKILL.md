---
name: supply-chain-sca
description: Análisis de composición de software (SCA), auditoría de dependencias directas y transitivas, verificación de versiones bloqueadas en lockfiles, detección de vulnerabilidades conocidas (CVEs), paquetes maliciosos/huérfanos y cumplimiento de licencias.
---

# Supply Chain & Dependencies (SCA)

**Dimensión Canónica:** `SUPPLY_CHAIN_SCA` (Dimensión 5)

---

## 🎯 Objetivo Delegado y Asignado

Esta Skill gobierna la dimensión de **Seguridad de la Cadena de Suministro y Dependencias (SCA)**. Su responsabilidad primordial es:
1. Analizar exhaustivamente manifiestos de dependencias (`package.json`, `pnpm-lock.yaml`, `pyproject.toml`, `requirements.txt`, `Cargo.lock`, `go.sum`, etc.).
2. Identificar dependencias directas y transitivas con versiones vulnerables conocidas (mapeo contra bases de datos de CVEs, OSV y GitHub Security Advisories).
3. Verificar la presencia e integridad de lockfiles deterministas para prevenir ataques de *Dependency Confusion* y *Typosquatting*.
4. Detectar scripts de ciclo de vida peligrosos en dependencias de terceros (e.g. scripts `postinstall` no auditados en ecosistema npm).
5. Identificar bibliotecas huérfanas, sin mantenimiento o con cambios anómalos de propiedad/mantenedor.
6. Auditar licencias de software de componentes de código abierto para evitar riesgos de contaminación legal o incompatibilidad.

---

## 📂 Organización Interna

- `references/`: Catálogos de advisories, guías de auditoría de SBOM (Software Bill of Materials) y taxonomía de licencias OSS (6 referencias técnicas).
  - [`package-integrity-and-patch-risk-rubric.md`](references/package-integrity-and-patch-risk-rubric.md): Verificación de manifiestos de integridad de distribución (`integrity.json`) y rúbrica de evaluación de riesgo operacional de parches (`assess-patch-risk`).

---

## 🛠️ Herramientas de Capa 3 Asignadas (`src/scripts/`)

Esta Skill consume y orquesta los siguientes motores de análisis determinista en Python 3.11+:

| Script Ejecutable | Contrato Zod (Capa 2) | Rol y Capacidades | Test Unitario |
| :--- | :--- | :--- | :--- |
| [`src/scripts/check_lockfiles.py`](file:///k:/Devia-CyberSecurity/src/scripts/check_lockfiles.py) | [`finding.schema.ts`](file:///k:/Devia-CyberSecurity/src/schemas/finding.schema.ts) | Verificación estática determinista de integridad de lockfiles (npm, pnpm, yarn, poetry, cargo) y detección de hooks de instalación maliciosos. | [`test_check_lockfiles.py`](file:///k:/Devia-CyberSecurity/src/scripts/test_check_lockfiles.py) |
