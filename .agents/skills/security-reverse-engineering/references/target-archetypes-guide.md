# Guía de Ingeniería Inversa Forense por Arquetipo de Objetivo

Este documento establece las directivas y técnicas forenses específicas para auditar y deconstruir cada arquetipo de objetivo, extrayendo sus prácticas y vectores de seguridad sin ejecutar código no confiable.

---

## 🎯 Los 5 Arquetipos Canónicos de Auditoría

```
┌────────────────────────────────────────────────────────────────────────┐
│                        ARQUETIPOS DE OBJETIVO                          │
├────────────────────────┬───────────────────────┬───────────────────────┤
│ 1. Repositorios Source │ 2. Skills & Plugins IA│ 3. Apps Empaquetadas  │
├────────────────────────┼───────────────────────┼───────────────────────┤
│ 4. Binarios Compilados │ 5. APIs & Protocolos  │                       │
└────────────────────────┴───────────────────────┴───────────────────────┘
```

---

### Arquetipo 1: Repositorio de Código Fuente Completo (*Source Code Repository*)

- **Naturaleza:** Árbol de código fuente que contiene monolitos, microservicios, bibliotecas o proyectos políglotas.
- **Fase de Reconocimiento:**
  1. Identificar manifiestos de proyecto y lockfiles:
     - JavaScript/TypeScript: `package.json`, `pnpm-lock.yaml`, `package-lock.json`, `yarn.lock`.
     - Python: `pyproject.toml`, `requirements.txt`, `Pipfile`, `poetry.lock`.
     - Rust: `Cargo.toml`, `Cargo.lock`.
     - Go: `go.mod`, `go.sum`.
     - Java/Kotlin: `pom.xml`, `build.gradle`, `build.gradle.kts`.
     - C/C++: `CMakeLists.txt`, `Makefile`, `meson.build`.
  2. Localizar las raíces de composición (*Composition Roots*) y puntos de entrada principales (`main`, `index`, `server`, `app`).
  3. Deslindar código de primera parte (*First-party code*) de dependencias vendored o generadas (`vendor/`, `third_party/`, `dist/`, `.gen/`).
- **Análisis de Seguridad y Absorción:**
  - Extraer arquitectura de validación de entradas (Zod, Pydantic, Joi, validadores manuales).
  - Trazar los flujos de taint desde controladores/rutas hasta operaciones de persistencia o llamadas de sistema.
  - Evaluar dependencias contra bases de datos de vulnerabilidades (SCA).

---

### Arquetipo 2: Skills, Plugins y Agentes de IA (*Agentic Systems & Skills*)

- **Naturaleza:** Paquetes agenticos que contienen definiciones de skills (`SKILL.md`), plugins (`plugin.json`), reglas operativas (`AGENTS.md`, `.cursorrules`), herramientas MCP y scripts de asistencia.
- **Fase de Reconocimiento:**
  1. Inspeccionar el frontmatter YAML de cada `SKILL.md` (`name`, `description`, `version`, `metadata`).
  2. Mapear la jerarquía de directorios:
     - `references/`: Documentación técnica especializada y guías operativas.
     - `scripts/`: Herramientas auxiliares invocadas por el agente.
     - `agents/`: Configuraciones de subagentes o perfiles LLM.
  3. Identificar herramientas MCP integradas o requeridas, así como permisos de ejecución declarados (`EnableWriteTools`, `EnableMCPTools`).
- **Análisis de Seguridad y Absorción:**
  - Evaluar riesgos de *Prompt Injection* (indirecto o directo) y fuga de variables de entorno sensibles en prompts.
  - Verificar si las instrucciones del agente violan límites de soberanía (e.g. invocar APIs pagadas de terceros o ejecutar código no validado).
  - **Oportunidad de Absorción:** Extraer las mejores heurísticas, checklists y flujos de razonamiento para adaptarlos a Capa 1 de Devia-CyberSecurity (`.agents/skills/`).

---

### Arquetipo 3: Aplicaciones Empaquetadas y Desktop (*Packaged & Desktop Apps*)

- **Naturaleza:** Aplicaciones de escritorio distribuidas como paquetes o instaladores (Electron, ASAR, CLI empaquetado, PyInstaller).
- **Fase de Reconocimiento:**
  1. Para paquetes Electron:
     - Localizar y desarchivar `app.asar` (mediante herramientas estáticas de lectura de cabecera ASAR sin ejecutar código).
     - Inspeccionar `package.json` embebido para localizar `main.js` y scripts de precarga (*preload scripts*).
     - Revisar *Electron fuses* para determinar si la depuración o el soporte de Node.js en renderers fue deshabilitado.
  2. Para binarios PyInstaller:
     - Inspeccionar la estructura del `CArchive` y extraer módulos `.pyc` para desensamblado de bytecode.
- **Análisis de Seguridad y Absorción:**
  - Verificar configuraciones críticas de Electron:
    ```javascript
    webPreferences: {
      nodeIntegration: false,      // Debe ser false
      contextIsolation: true,       // Debe ser true
      sandbox: true,                // Debe ser true
      enableRemoteModule: false     // Debe ser false
    }
    ```
  - Auditar la superficie de `ipcRenderer` e `ipcMain` para detectar invocaciones de comandos del sistema operativo desde renderers no confiables.

---

### Arquetipo 4: Binarios y Bibliotecas Compiladas (*Compiled Binaries & Native Code*)

- **Naturaleza:** Archivos ejecutables o librerías dinámicas en formato ELF (Linux), PE/COFF (Windows) o Mach-O (macOS).
- **Fase de Reconocimiento:**
  1. Inspeccionar metadatos de encabezado sin ejecución:
     - Arquitectura y endianness (x86-64, ARM64, MIPS, RISC-V).
     - Secciones del binario (`.text`, `.data`, `.rodata`, `.rsrc`, `.reloc`).
  2. Extraer tabla de símbolos exportados e importados (funciones de libc, Win32 API, OpenSSL).
  3. Extraer cadenas de caracteres legibles (ASCII y UTF-16LE) asociadas a URLs, rutas de archivos o mensajes de error.
- **Análisis de Seguridad y Absorción:**
  - Evaluar mitigaciones activas en el binario:
    - Stack Protection (*Canaries* / GS)
    - Data Execution Prevention (DEP / NX)
    - Address Space Layout Randomization (ASLR / PIE)
    - Control Flow Guard (CFG) / SafeSEH
  - Detectar el uso de llamadas peligrosas a la API del sistema (`system`, `popen`, `strcpy`, `sprintf`, `VirtualAlloc` con RWX).

---

### Arquetipo 5: Especificaciones, APIs y Protocolos (*Contracts & Protocols*)

- **Naturaleza:** Archivos de definición de interfaz como OpenAPI (Swagger), AsyncAPI, GraphQL schemas, archivos `.proto` (Protocol Buffers) o definiciones WSDL.
- **Fase de Reconocimiento:**
  1. Cargar y parsear las especificaciones con parsers JSON/YAML estáticos.
  2. Identificar tipos de datos, validaciones de esquema, límites de tamaño, valores por defecto y mecanismos de seguridad declarados (`securitySchemes`: OAuth2, Bearer, ApiKey).
- **Análisis de Seguridad y Absorción:**
  - Comprobar la rigurosidad de los esquemas: ¿permiten propiedades arbitrarias (`additionalProperties: true`)?
  - Identificar endpoints que carecen de declaración de autenticación.
  - **Oportunidad de Absorción:** Traducir contratos abiertos en esquemas Zod rigurosos para Capa 2 (`src/schemas/`) en Devia-CyberSecurity.
