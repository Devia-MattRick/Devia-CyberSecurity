# Bastionado de Wrappers de Ejecución y Preflight de Runtime en Windows

Este documento detalla los principios y heurísticas de auditoría para mitigar el secuestro de rutas de búsqueda de binarios (**PATH / DLL Hijacking**) y asegurar scripts wrapper y launchers en plataformas Windows y entornos de agentes autónomos.

---

## 🏛️ Vector de Amenaza: Búsqueda No Calificada de Ejecutables (CWE-427 / CWE-428)

En Windows, cuando un script por lotes (`.bat`, `.cmd`) o un binario invoca un comando sin comillas o sin una ruta absoluta canónica (e.g. `node script.js` o `python tool.py`), el sistema operativo busca en el siguiente orden:
1. El directorio de trabajo actual (`working directory`).
2. Los directorios listados en la variable `PATH`.

Si el directorio de trabajo actual es controlado por el usuario, contiene código no confiable o es compartido por múltiples usuarios, un atacante puede depositar un archivo malicioso `node.exe` o `python.exe` en ese directorio, logrando **Ejecución Arbitraria de Código (RCE)** en el contexto de privilegios del proceso que invoca el wrapper.

---

## 🛡️ Lecciones de Ingeniería Inversa (Codex Security Launcher)

La deconstrucción de `launch_codex_security_mcp.cmd` en Codex Security v0.1.32 evidencia las siguientes directivas de bastionado defensivo:

### 1. Desvinculación del Directorio de Trabajo No Seguro
Antes de resolver o invocar el runtime, el launcher neutraliza el directorio de trabajo para no dejarlo anclado a rutas de usuario ni permitir secuestro:
```cmd
if "%~d0"=="" (cd /d "%SystemRoot%") else (cd /d "%~d0\")
if errorlevel 1 exit /b 1
```

### 2. Probing Escalonado de Runtimes Autorizados
En lugar de invocar `node` a ciegas, se evalúan rutas específicas canónicas en orden de menor a mayor privilegio y se verifica la existencia física del binario (`bin\node.exe`):
1. Variables de entorno dedicadas (`%LOCALAPPDATA%\OpenAI\Codex\runtimes\...`).
2. Rutas aisladas en cachés autorizados (`%XDG_CACHE_HOME%\...`).
3. Variables de configuración explícita (`%CODEX_MCP_NODE_PATH%`).

### 3. Resolución Única y Absoluta de PATH
Si se recurre a `PATH`, se sanitizan comillas y se extrae la ruta absoluta única antes de la invocación:
```cmd
set "SEARCH_PATH=%PATH:"=%"
for %%I in (node.exe) do set "TARGET_NODE=%%~$SEARCH_PATH:I"
if defined TARGET_NODE goto run
```

### 4. Invocación Segura Entrecomillada
Toda invocación final encapsula tanto el ejecutable como los scripts con comillas dobles estrictas para prevenir división de argumentos por espacios en blanco (*Unquoted Path*):
```cmd
"%TARGET_NODE%" "%SCRIPT_PATH%" %*
```

---

## 📋 Checklist de Auditoría para Launchers y Wrappers

- [ ] ¿El script cambia el directorio de trabajo a una ubicación segura del sistema (`%SystemRoot%`) antes de ejecutar?
- [ ] ¿Todos los ejecutables y rutas a scripts están debidamente entrecomillados?
- [ ] ¿Se realiza validación de existencia (`if exist`) antes de transferir control a un binario externo?
- [ ] ¿Se previene la inyección de parámetros mediante `%*` no sanitizado si el comando interpreta flags peligrosas?
