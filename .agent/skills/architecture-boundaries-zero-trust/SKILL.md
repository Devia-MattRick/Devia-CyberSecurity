---
name: architecture-boundaries-zero-trust
description: Evaluación de la arquitectura de sistemas, fronteras de aislamiento (offline vs cloud), comunicación inter-proceso (IPC), seguridad en aplicaciones desktop (Electron/fuses), políticas Zero Trust, principio de menor privilegio y configuración de CORS/CSP.
---

# Architecture, Boundaries & Zero Trust

**Dimensión Canónica:** `ARCHITECTURE_BOUNDARIES_ZERO_TRUST` (Dimensión 6)

---

## 🎯 Objetivo Delegado y Asignado

Esta Skill gobierna la dimensión de **Arquitectura, Límites de Confianza y Zero Trust**. Su responsabilidad primordial es:
1. Evaluar las fronteras de aislamiento del sistema: verificar la soberanía de aplicaciones locales/offline frente a fugas inadvertidas de datos hacia la nube.
2. Auditar mecanismos de comunicación inter-proceso (IPC, sockets locales, named pipes) para evitar escalada de privilegios locales o inyección de comandos.
3. Evaluar aplicaciones de escritorio empaquetadas (e.g. Electron): auditar flags de seguridad (`nodeIntegration: false`, `contextIsolation: true`, `sandbox: true`, mitigación de Electron fuses).
4. Verificar políticas de aislamiento web y del navegador: Content Security Policy (CSP), Cross-Origin Resource Sharing (CORS), Cross-Origin Embedder/Opener Policies (COOP/COEP).
5. Aplicar principios estrictos de Zero Trust: verificación explícita de confianza en cada salto de red, segmentación microarquitectónica y principio de mínimo privilegio (*Least Privilege*).

---

## 📂 Organización Interna

- `references/`: Guías de hardening para Electron, matrices de políticas CSP/CORS y arquitecturas Zero Trust de referencia.
  - [`sealed-scan-contracts-and-projections.md`](references/sealed-scan-contracts-and-projections.md): Principio de paquetes sellados inmutables (`scan-manifest.json`), separación de SSOT vs proyecciones y mitigación de `VULN-ARCH-004`.
- `scripts/`: Analizadores de configuración de runtime de navegadores y herramientas de inspección de límites IPC.
