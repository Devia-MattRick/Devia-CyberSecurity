---
name: threat-modeling-attack-surface
description: Auditoría y modelado de amenazas sistemático (STRIDE, PASTA), identificación de activos críticos, actores de amenaza, flujos de datos, límites de confianza y catalogación exhaustiva de la superficie de ataque expuesta.
---

# Threat Modeling & Attack Surface

**Dimensión Canónica:** `THREAT_MODELING_ATTACK_SURFACE` (Dimensión 1)

---

## 🎯 Objetivo Delegado y Asignado

Esta Skill gobierna la dimensión de **Modelado de Amenazas y Superficie de Ataque**. Su responsabilidad primordial es:
1. Identificar sistemáticamente todos los activos de información críticos del sistema auditado y clasificar su nivel de sensibilidad.
2. Identificar y clasificar actores de amenaza relevantes (*Anonymous Remote, Authenticated User, Privileged Insider, Supply Chain Dependency, Local Process*).
3. Mapear los límites de confianza (*Trust Boundaries*) y flujos de datos inter-componente.
4. Catalogar exhaustivamente los puntos de entrada (*Entry Points*) de la aplicación (APIs HTTP, CLI, WebSockets, IPC, variables de entorno, sockets).
5. Evaluar escenarios de amenaza estructurados bajo la metodología STRIDE (Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, Elevation of Privilege) y mapear contra `ThreatModelSchema` de Devia-CyberSecurity.

---

## 📂 Organización Interna

- `references/`: Guías de metodologías de modelado (STRIDE, PASTA), catálogos de superficies y checklists.
  - [`target-snapshots-and-investigation-packets.md`](references/target-snapshots-and-investigation-packets.md): Snapshots deterministas de workspaces, huellas primarias de hallazgos y formulación de paquetes de investigación.
- `scripts/`: Utilidades para escaneo de endpoints, análisis de rutas y generación de diagramas DFD.
  - Utilidad de Capa 3: [`src/scripts/target_snapshot.py`](file:///k:/Devia-CyberSecurity/src/scripts/target_snapshot.py).
