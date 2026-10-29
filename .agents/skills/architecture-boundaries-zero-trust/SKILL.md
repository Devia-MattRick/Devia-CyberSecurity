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

- `references/`: Guías de hardening para Electron, matrices de políticas CSP/CORS y arquitecturas Zero Trust de referencia (25 referencias técnicas).
  - [`ztna-and-microsegmentation-architecture.md`](references/ztna-and-microsegmentation-architecture.md): Arquitectura de acceso Zero Trust (ZTNA), lenguaje de políticas Cedar y microsegmentación de cargas de trabajo.
  - [`sealed-scan-contracts-and-projections.md`](references/sealed-scan-contracts-and-projections.md): Principio de paquetes sellados inmutables (`scan-manifest.json`), separación de SSOT vs proyecciones y mitigación de `VULN-ARCH-004`.
  - [`docker-sandbox-daemon-isolation-and-opa-probe.md`](references/docker-sandbox-daemon-isolation-and-opa-probe.md): Aislamiento estricto de daemons Docker y sondas OPA contra escapes (`VULN-ARCH-009`).
  - [`agentic-system-security-mcp.md`](references/agentic-system-security-mcp.md): Modelo de autoridad efectiva y barreras de herramientas MCP (`VULN-ARCH-011`).

---

## 🛠️ Herramientas de Capa 3 Asignadas (`src/scripts/`)

Esta Skill consume y orquesta los siguientes motores de análisis determinista en Python 3.11+:

| Script Ejecutable | Contrato Zod (Capa 2) | Rol y Capacidades | Test Unitario |
| :--- | :--- | :--- | :--- |
| [`src/scripts/mcp_tool_poisoning_scanner.py`](file:///k:/Devia-CyberSecurity/src/scripts/mcp_tool_poisoning_scanner.py) | [`mcp-audit.schema.ts`](file:///k:/Devia-CyberSecurity/src/schemas/mcp-audit.schema.ts) | Auditoría de esquemas Model Context Protocol (MCP); detecta tool poisoning y rug pulls mediante digests inmutables. | [`test_mcp_tool_poisoning_scanner.py`](file:///k:/Devia-CyberSecurity/src/scripts/test_mcp_tool_poisoning_scanner.py) |
| [`src/scripts/c2_beaconing_detector.py`](file:///k:/Devia-CyberSecurity/src/scripts/c2_beaconing_detector.py) | [`threat-hunt.schema.ts`](file:///k:/Devia-CyberSecurity/src/schemas/threat-hunt.schema.ts) | Detección estadística de patrones de balizamiento C2 y jitter en flujos de red. | [`test_c2_beaconing_detector.py`](file:///k:/Devia-CyberSecurity/src/scripts/test_c2_beaconing_detector.py) |
| [`src/scripts/deception_canary_auditor.py`](file:///k:/Devia-CyberSecurity/src/scripts/deception_canary_auditor.py) | [`deception-posture.schema.ts`](file:///k:/Devia-CyberSecurity/src/schemas/deception-posture.schema.ts) | Auditoría de postura de tecnologías de engaño, canarios de credenciales y regla Deny-All. | [`test_deception_canary_auditor.py`](file:///k:/Devia-CyberSecurity/src/scripts/test_deception_canary_auditor.py) |
| [`src/scripts/threat_detection_engine.py`](file:///k:/Devia-CyberSecurity/src/scripts/threat_detection_engine.py) | [`threat-detection.schema.ts`](file:///k:/Devia-CyberSecurity/src/schemas/threat-detection.schema.ts) | Motor de correlación y detección de amenazas avanzadas en logs de red. | [`test_threat_detection_engine.py`](file:///k:/Devia-CyberSecurity/src/scripts/test_threat_detection_engine.py) |
| [`src/scripts/url_validator.py`](file:///k:/Devia-CyberSecurity/src/scripts/url_validator.py) | [`scan-contract.schema.ts`](file:///k:/Devia-CyberSecurity/src/schemas/scan-contract.schema.ts) | Validador estricto anti-SSRF; realiza DNS preflight, bloqueo de rangos privados y seguimiento manual de redirecciones. | [`test_url_validator.py`](file:///k:/Devia-CyberSecurity/src/scripts/test_url_validator.py) |
| [`src/scripts/hard_exclusions.py`](file:///k:/Devia-CyberSecurity/src/scripts/hard_exclusions.py) | [`scan-contract.schema.ts`](file:///k:/Devia-CyberSecurity/src/schemas/scan-contract.schema.ts) | Filtrado determinista $O(1)$ de rutas no confiables, dependencias y binarios para limitar la superficie de auditoría. | [`test_hard_exclusions.py`](file:///k:/Devia-CyberSecurity/src/scripts/test_hard_exclusions.py) |

