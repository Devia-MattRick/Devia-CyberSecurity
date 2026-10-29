---
name: configuration-hardening
description: Auditoría de configuraciones de despliegue, infraestructura como código (IaC), contenedores (Docker), variables de entorno, flags de compilación, permisos de sistema de archivos y establecimiento de valores seguros por defecto.
---

# Configuration & Hardening

**Dimensión Canónica:** `CONFIGURATION_HARDENING` (Dimensión 7)

---

## 🎯 Objetivo Delegado y Asignado

Esta Skill gobierna la dimensión de **Configuración y Bastionado (Hardening)**. Su responsabilidad primordial es:
1. Auditar archivos de configuración del sistema y despliegue (Dockerfiles, `docker-compose.yml`, manifiestos de Kubernetes, Terraform, Helm charts).
2. Verificar la gestión de variables de entorno y archivos `.env`: evitar la inclusión de valores sensibles en repositorios o imágenes de contenedor.
3. Evaluar configuraciones de seguridad en servidores web y proxies inversos (Nginx, Caddy, Apache): cabeceras HSTS, X-Content-Type-Options, X-Frame-Options, desactivación de banners de versión del servidor.
4. Auditar flags de compilación y empaquetado: habilitación de protecciones en binarios (PIE, Stack Canaries, FORTIFY_SOURCE, RELRO, ASLR/DEP).
5. Revisar permisos en el sistema de archivos (evitar permisos excesivos `777` o `chmod +s` en ejecutables sensibles) y asegurar principios de *Secure by Default*.

---

## 📂 Organización Interna

- `references/`: Benchmarks de bastionado (CIS Benchmarks), guías de hardening de Docker/Kubernetes y plantillas de configuración segura (16 referencias técnicas).
  - [`windows-defender-asr-and-exploit-protection.md`](references/windows-defender-asr-and-exploit-protection.md): Endurecimiento de endpoints Windows, matriz de 16 GUIDs de reglas ASR de Defender y prevención de robo LSASS.
  - [`tls-1-3-and-cipher-hardening.md`](references/tls-1-3-and-cipher-hardening.md): Configuración de TLS 1.3 (RFC 8446), suites de cifrado modernas AEAD y protección anti-repetición 0-RTT.
  - [`hids-fim-and-wazuh-hardening.md`](references/hids-fim-and-wazuh-hardening.md): Detección de intrusiones en host (HIDS), monitorización de integridad FIM y prevención de fuga de secretos en diffs (`nodiff`).
  - [`runtime-preflight-and-path-isolation.md`](references/runtime-preflight-and-path-isolation.md): Bastionado de wrappers y scripts de ejecución en Windows, mitigación de PATH/DLL hijacking (`VULN-CONF-004`) y preflight de capacidades.
  - [`docker-container-hardening.md`](references/docker-container-hardening.md): Bastionado de contenedores Docker, usuario no privilegiado y `read-only root filesystem`.
  - [`cloud-cis-benchmarks-and-iac-hardening.md`](references/cloud-cis-benchmarks-and-iac-hardening.md): Evaluación de seguridad en infraestructura como código y benchmarks CIS.
  - [`vulnerability-aging-sla-and-exception-tracking.md`](references/vulnerability-aging-sla-and-exception-tracking.md): Ciclo de vida y SLAs de mitigación de vulnerabilidades de configuración.

---

## 🛠️ Herramientas de Capa 3 Asignadas (`src/scripts/`)

Esta Skill consume y orquesta los siguientes motores de análisis determinista en Python 3.11+:

| Script Ejecutable | Contrato Zod (Capa 2) | Rol y Capacidades | Test Unitario |
| :--- | :--- | :--- | :--- |
| [`src/scripts/endpoint_hardening_auditor.py`](file:///k:/Devia-CyberSecurity/src/scripts/endpoint_hardening_auditor.py) | [`endpoint-hardening.schema.ts`](file:///k:/Devia-CyberSecurity/src/schemas/endpoint-hardening.schema.ts) | Motor determinista de auditoría de Microsoft Defender, matriz de 16 reglas ASR y mitigaciones de kernel con salida Zod. | [`test_endpoint_hardening_auditor.py`](file:///k:/Devia-CyberSecurity/src/scripts/test_endpoint_hardening_auditor.py) |

