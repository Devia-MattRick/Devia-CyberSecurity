# Guía Canónica de Bastionado de Contenedores Docker e Infraestructura IaC

Este documento establece los principios obligatorios y reglas de auditoría para el bastionado (*hardening*) de contenedores **Dockerfile** y orquestación **Docker Compose** en **Devia-CyberSecurity**.

---

## 🐳 1. Reglas Maestras de Auditoría para Dockerfile

### Regla 1.1: Ejecución como Usuario No Privilegiado (CWE-250 / VULN-CONF-003)
- **Severidad:** `HIGH`
- **Mecanismo de Fallo:** Por defecto, los contenedores ejecutan sus procesos como el usuario `root` del contenedor ($UID = 0$). Si una vulnerabilidad de escape o inyección de comandos ocurre en la aplicación, el atacante obtiene privilegios de superusuario dentro del contenedor, facilitando escapes hacia el host.
- **Patrón de Auditoría:**
  ```regex
  ^USER\s+
  ```
  *Invariante:* Todo Dockerfile de producción debe declarar explícitamente una directiva `USER` no root tras la fase de preparación de paquetes.
- **Ejemplo Vulnerable vs Seguro:**
  ```dockerfile
  # ❌ VULNERABLE: Se ejecuta como root (UID 0)
  FROM node:20-alpine
  WORKDIR /app
  COPY . .
  CMD ["node", "dist/server.js"]

  # ✅ SEGURO: Usuario dedicado sin privilegios
  FROM node:20-alpine
  WORKDIR /app
  COPY package*.json ./
  RUN npm ci --only=production
  COPY dist/ dist/
  RUN addgroup -S appgroup && adduser -S appuser -G appgroup && chown -R appuser:appgroup /app
  USER appuser
  CMD ["node", "dist/server.js"]
  ```

---

### Regla 1.2: Fijación Inmutable de Imágenes Base (CWE-1104 / VULN-SCA-005)
- **Severidad:** `MEDIUM` / `HIGH`
- **Mecanismo de Fallo:** Utilizar etiquetas flotantes (`FROM node:latest`, `FROM python`) o sin tag provoca reconstrucciones no deterministas y exposición inmediata a vulnerabilidades de upstream o paquetes troyanizados.
- **Patrón Seguro:** Fijar versión SemVer exacta y digest criptográfico SHA-256:
  ```dockerfile
  # ❌ VULNERABLE: Tag flotante
  FROM python:latest

  # ✅ SEGURO: Versión fijada con digest SHA-256
  FROM python:3.12.2-slim-bookworm@sha256:4d603a1f81d1134a6ddcb14ec8707be9e5e7ec9df3448fdb3ffcb7f9b8893d93
  ```

---

### Regla 1.3: Cero Secretos en Capas de Imagen (CWE-798 / VULN-CRYP-001)
- **Severidad:** `CRITICAL`
- **Mecanismo de Fallo:** Pasar credenciales mediante `ARG` o `ENV` persiste los valores en el historial de capas de la imagen (`docker history`), siendo extraíbles por cualquier usuario con acceso al registro o imagen.
- **Patrón Seguro:** Utilizar montajes de secretos de BuildKit que operan en memoria RAM sin persistir en el sistema de archivos:
  ```dockerfile
  # ❌ VULNERABLE: Credencial en build arg o ENV
  ARG GITHUB_TOKEN
  ENV DATABASE_PASSWORD=secret
  RUN echo "token=${GITHUB_TOKEN}" > /root/.npmrc

  # ✅ SEGURO: BuildKit Secret Mount
  RUN --mount=type=secret,id=npmrc,target=/root/.npmrc npm ci
  ```

---

### Regla 1.4: Contención Estricta de Contexto (`.dockerignore`) (CWE-200 / VULN-CONF-001)
- **Severidad:** `HIGH`
- **Mecanismo de Fallo:** La instrucción `COPY . .` sin un archivo `.dockerignore` copia archivos `.env`, directorios `.git`, claves `.pem`, credenciales locales y dependencias del host a la imagen de producción.
- **Lista de Exclusiones Mínima Obligatoria en `.dockerignore`:**
  ```text
  .git
  .gitignore
  .env
  .env.*
  *.pem
  *.key
  credentials.json
  node_modules
  __pycache__
  dist
  docker-compose*.yml
  Dockerfile
  ```

---

### Regla 1.5: Adopción de COPY sobre ADD (CWE-829 / CWE-494)
- **Severidad:** `MEDIUM`
- **Mecanismo de Fallo:** `ADD` descomprime automáticamente archivos `.tar` (riesgo Zip Slip) y puede descargar URLs remotas sin verificación criptográfica de integridad.
- **Regla:** Emplear exclusivamente `COPY` para archivos locales y comandos explícitos `curl` con verificación de hash SHA-256 si se requieren descargas.

---

## 🚢 2. Reglas Maestras de Auditoría para Docker Compose

### Regla 2.1: Prohibición de Modo Privilegiado (`privileged: true`) (CWE-250)
- **Severidad:** `CRITICAL`
- **Mecanismo de Fallo:** `privileged: true` deshabilita los perfiles AppArmor/seccomp, expone todos los dispositivos del host (`/dev`) y otorga todas las capacidades de Linux, permitiendo escape inmediato al host.

### Regla 2.2: Prohibición de Montaje del Socket de Docker (`docker.sock`) (CWE-250)
- **Severidad:** `CRITICAL`
- **Mecanismo de Fallo:** Montar `/var/run/docker.sock` dentro de un contenedor equivale a otorgar privilegios de superusuario (`root`) en la máquina anfitriona, ya que el contenedor puede ordenar al daemon de Docker crear contenedores anfitriones con montajes de root.

### Regla 2.3: Aislamiento de Puertos y Enlaces de Red (CWE-1188 / VULN-CONF-001)
- **Severidad:** `HIGH`
- **Mecanismo de Fallo:** Exponer bases de datos o servicios internos mediante `"5432:5432"` o `"6379:6379"` enlaza los puertos en `0.0.0.0` (todas las interfaces de red públicas).
- **Patrón Seguro:** Vincular exclusivamente a loopback local (`127.0.0.1:5432:5432`) o prescindir de publicación de puertos usando redes internas privadas de Docker.

### Regla 2.4: Mínimo Privilegio de Capacidades de Linux (`cap_drop`)
- **Patrón Seguro:**
  ```yaml
  services:
    web:
      image: myapp:1.0.0
      cap_drop:
        - ALL
      cap_add:
        - NET_BIND_SERVICE
      read_only: true
      tmpfs:
        - /tmp:noexec,nosuid,size=64M
      security_opt:
        - no-new-privileges:true
  ```
