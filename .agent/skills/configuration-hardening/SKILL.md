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

- `references/`: Benchmarks de bastionado (CIS Benchmarks), guías de hardening de Docker/Kubernetes y plantillas de configuración segura.
  - [`runtime-preflight-and-path-isolation.md`](references/runtime-preflight-and-path-isolation.md): Bastionado de wrappers y scripts de ejecución en Windows, mitigación de PATH/DLL hijacking (`VULN-CONF-004`) y preflight de capacidades.
- `scripts/`: Escáneres de Dockerfile / docker-compose, verificadores de cabeceras HTTP y linters de configuración.
