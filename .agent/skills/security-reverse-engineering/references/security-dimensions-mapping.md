# Mapeo de Dimensiones de Seguridad y Taxonomías Universales

Este documento proporciona la guía canónica para clasificar cada práctica, metodología, vulnerabilidad o arquitectura descubierta durante la ingeniería inversa en las **8 Dimensiones Canónicas de Devia-CyberSecurity** y sus taxonomías internacionales equivalentes (CWE, OWASP, ASVS, MITRE ATT&CK).

---

## 🛡️ Las 8 Dimensiones Canónicas

```
+-----------------------------------------------------------------------------------+
|                           DEVIA-CYBERSECURITY TAXONOMY                            |
+-----------------------------------------+-----------------------------------------+
| 1. Threat Modeling & Attack Surface     | 5. Supply Chain & Dependencies (SCA)    |
| 2. Source Code Security (SAST)          | 6. Architecture, Boundaries & Zero Trust|
| 3. Secrets & Cryptographic Posture      | 7. Configuration & Hardening            |
| 4. Identity, Access & Session Control   | 8. Resilience, Logging & Telemetry      |
+-----------------------------------------+-----------------------------------------+
```

---

### Dimensión 1: Threat Modeling & Attack Surface (`THREAT_MODELING_ATTACK_SURFACE`)
- **Propósito:** Identificar sistemáticamente activos críticos, actores de amenaza, límites de confianza (*trust boundaries*), puntos de entrada y superficies expuestas.
- **Taxonomías Asociadas:**
  - STRIDE (Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, Elevation of Privilege)
  - OWASP Top 10: A04:2021 / A04:2025 (Insecure Design)
  - NIST CSF 2.0: Identify (`ID.AM`, `ID.RA`), Govern (`GV.RM`)
  - MITRE ATT&CK: Reconnaissance (`TA0043`), Resource Development (`TA0042`), Initial Access (`TA0001`), Discovery (`TA0007`)
  - CWE: CWE-1059 (Incomplete Documentation of Architecture), CWE-658 (Defects in Design), CWE-1021
- **Indicadores Forenses en el Target:**
  - Rutas de API expuestas (REST, GraphQL, gRPC, WebSockets).
  - Parámetros de CLI, IPC listeners (Electron `ipcRenderer.send`, named pipes), listeners de red.
  - Puertos abiertos, servicios en segundo plano, daemon workers.
  - Flujo de datos entre componentes no autenticados y procesos de alto privilegio.
- **Potencial de Absorción en Devia:**
  - Generación de modelos formales en Zod (`ThreatModelSchema`).
  - Heurísticas de descubrimiento de puntos de entrada para motores de auditoría.

---

### Dimensión 2: Source Code Security (SAST) (`SOURCE_CODE_SAST`)
- **Propósito:** Análisis estático profundo de vulnerabilidades lógicas, inyecciones, fallas de validación y control de flujo.
- **Taxonomías Asociadas:**
  - CWE Top 25: CWE-89 (SQL Injection), CWE-78 (OS Command Injection), CWE-79 (XSS), CWE-22 (Path Traversal), CWE-502 (Insecure Deserialization), CWE-362 (Race Conditions), CWE-918 (Server-Side Request Forgery).
  - OWASP Top 10: A03:2021 / A03:2025 (Injection), A10:2025 (Server-Side Request Forgery - SSRF).
  - NIST CSF 2.0: Protect (`PR.DS`, `PR.PS`), Detect (`DE.AE`).
  - MITRE ATT&CK: Execution (`TA0002`: `T1059`, `T1203`, `T1055`), Defense Evasion (`TA0005`: `T1027`).
- **Indicadores Forenses en el Target:**
  - Funciones de ejecución dinámica: `eval()`, `Function()`, `exec()`, `spawn()`, `subprocess.Popen()`.
  - Consultas concatenadas a bases de datos (SQL, NoSQL, LDAP).
  - Manejo de rutas mediante concatenación de strings (`path.join(__dirname, userInput)` sin sanitizar).
  - Serialización no segura (e.g. `pickle.loads()`, `yaml.load()` sin SafeLoader, `JSON.parse` sin validación Zod).
  - URLs remotas solicitadas sin allowlist estricta (vectores SSRF hacia endpoints de metadatos `169.254.169.254`).
- **Potencial de Absorción en Devia:**
  - Reglas de inspección estática (AST en Capa 3 o heurísticas en Capa 1).
  - Nuevas pruebas de taint analysis (*dataflow validation*).

---

### Dimensión 3: Secrets & Cryptographic Posture (`SECRETS_CRYPTOGRAPHY`)
- **Propósito:** Detección de secretos embebidos, credenciales hardcodeadas, manejo de entropía y algoritmos criptográficos obsoletos o defectuosos.
- **Taxonomías Asociadas:**
  - CWE: CWE-798 (Use of Hard-coded Credentials), CWE-327 (Use of a Broken or Risky Cryptographic Algorithm), CWE-328 (Use of Weak Hash), CWE-330 (Insufficiently Random Values), CWE-321.
  - OWASP Top 10: A02:2021 / A02:2025 (Cryptographic Failures).
  - NIST CSF 2.0: Protect (`PR.DS` - Data Security: encryption at rest and in transit).
  - MITRE ATT&CK: Credential Access (`TA0006`: `T1552`, `T1558.003`, `T1003`), Exfiltration (`TA0010`: `T1573`), Impact (`TA0040`: `T1486`).
- **Indicadores Forenses en el Target:**
  - Tokens de API, private keys SSH/RSA, passwords en código fuente o commits.
  - Strings de alta entropía de Shannon (UUIDs, JWT secrets, Base64 de longitud fija).
  - Uso de algoritmos deprecados: MD5, SHA-1, DES, 3DES, RC4, AES en modo ECB.
  - Generadores pseudoaleatorios no criptográficos (`math/rand`, `Math.random()`) usados para tokens o nonces.
- **Potencial de Absorción en Devia:**
  - Algoritmos matemáticos de entropía de Shannon implementados en Python 3.11 (`src/scripts/`).
  - Reglas de escaneo de patrones regex y heurísticas de falsos positivos.

---

### Dimensión 4: Identity, Access & Session Control (`IDENTITY_ACCESS_SESSION`)
- **Propósito:** Evaluación de mecanismos de autenticación, autorización (RBAC, ABAC), gestión de sesiones y prevención de escalada de privilegios.
- **Taxonomías Asociadas:**
  - CWE: CWE-287 (Improper Authentication), CWE-862 (Missing Authorization), CWE-863 (Incorrect Authorization), CWE-384 (Session Fixation), CWE-613 (Insufficient Session Expiration), CWE-639 (IDOR/BOLA).
  - OWASP Top 10: A01:2021 / A01:2025 (Broken Access Control), A07:2021 / A07:2025 (Identification and Authentication Failures).
  - NIST CSF 2.0: Protect (`PR.AA`), Govern (`GV.RR`).
  - MITRE ATT&CK: Privilege Escalation (`TA0004`: `T1068`, `T1134`), Credential Access (`TA0006`: `T1110`, `T1539`), Lateral Movement (`TA0008`: `T1550`, `T1078`).
- **Indicadores Forenses en el Target:**
  - Middlewares de autenticación y verificación de tokens (JWT, OAuth, Cookies).
  - Verificación de roles en endpoints críticos (IDOR / BOLA: ¿se valida que el recurso pertenece al usuario solicitante?).
  - Almacenamiento de tokens en cliente (`localStorage` vs `HttpOnly SameSite cookies`).
  - Políticas de revocación de sesiones, rotación de claves y timeout de inactividad.
- **Potencial de Absorción en Devia:**
  - Checklists de verificación de control de acceso para Skills.
  - Modelos de validación de tokens y sesiones.

---

### Dimensión 5: Supply Chain & Dependencies (SCA) (`SUPPLY_CHAIN_SCA`)
- **Propósito:** Análisis de componentes de terceros, versiones bloqueadas, dependencias transitivas, licencias y paquetes huérfanos o maliciosos.
- **Taxonomías Asociadas:**
  - CWE: CWE-1395 (Dependency on Vulnerable Third-Party Component), CWE-1104 (Use of Unmaintained Third-Party Components), CWE-494 (Download of Code Without Integrity Check).
  - OWASP Top 10: A06:2021 / A06:2025 (Vulnerable and Outdated Components), A08:2025 (Software and Data Integrity Failures).
  - NIST CSF 2.0: Govern (`GV.SC`), Protect (`PR.PS`).
  - MITRE ATT&CK: Initial Access / Persistence (`TA0001` / `TA0003`: `T1195` Supply Chain Compromise, `T1525` Implant Internal Image).
- **Indicadores Forenses en el Target:**
  - Manifiestos de dependencias (`package.json`, `pnpm-lock.yaml`, `requirements.txt`, `Cargo.lock`, `go.mod`).
  - Dependencias con rangos laxos (`^`, `*`, `latest`) o sin lockfile determinista.
  - Módulos con scripts de instalación sospechosos (`postinstall` en npm).
  - Componentes dependientes de APIs de pago no soberanas o servicios externos no declarados.
  - Ausencia de firmas criptográficas (Sigstore, Cosign) o atestaciones SBOM.
- **Potencial de Absorción en Devia:**
  - Parsers deterministas de lockfiles en Python o TypeScript.
  - Listas de bloqueo y heurísticas de integridad de cadena de suministro.


---

### Dimensión 6: Architecture, Boundaries & Zero Trust (`ARCHITECTURE_BOUNDARIES_ZERO_TRUST`)
- **Propósito:** Revisión del aislamiento entre componentes, comunicación inter-proceso (IPC), separación de privilegios, políticas Zero Trust y fronteras offline/cloud.
- **Taxonomías Asociadas:**
  - CWE: CWE-250 (Execution with Unnecessary Privileges), CWE-668 (Exposure of Resource to Wrong Sphere), CWE-942 (Overly Permissive CORS), CWE-269, CWE-1004.
  - OWASP Top 10: A01:2025 (Broken Access Control), A04:2025 (Insecure Design).
  - NIST CSF 2.0: Protect (`PR.IR` - Technology Infrastructure Resilience & Zero Trust microsegmentation).
  - MITRE ATT&CK: Lateral Movement (`TA0008`: `T1021`, `T1210`), Command & Control (`TA0011`: `T1071`, `T1090`, `T1105`), Container Escape (`T1611`).
- **Indicadores Forenses en el Target:**
  - En Electron / Desktop: flags como `nodeIntegration: true`, `contextIsolation: false`, `webSecurity: false`.
  - Políticas CORS (`Access-Control-Allow-Origin: *` con credenciales).
  - En arquitecturas locales: conexiones ocultas de telemetría a servidores de terceros (*data exfiltration*).
  - Ejecución de procesos con privilegios de root/administrador cuando no es indispensable.
- **Potencial de Absorción en Devia:**
  - Reglas de hardening arquitectónico y esquemas de validación de fronteras.
  - Modelos de verificación Zero Trust.

---

### Dimensión 7: Configuration & Hardening (`CONFIGURATION_HARDENING`)
- **Propósito:** Verificación de archivos de despliegue, variables de entorno, cabeceras HTTP de seguridad, permisos de sistema de archivos y valores por defecto seguros.
- **Taxonomías Asociadas:**
  - CWE: CWE-16 (Configuration), CWE-276 (Incorrect Default Permissions), CWE-1188 (Insecure Default Initialization), CWE-732.
  - OWASP Top 10: A05:2021 / A05:2025 (Security Misconfiguration).
  - NIST CSF 2.0: Protect (`PR.PS` - Platform Security), Govern (`GV.PO`).
  - MITRE ATT&CK: Persistence (`TA0003`: `T1547.001`, `T1053.005`, `T1136`), Defense Evasion (`TA0005`: `T1014`, `T1070`).
- **Indicadores Forenses en el Target:**
  - Cabeceras ausentes: Content-Security-Policy (CSP), Strict-Transport-Security (HSTS), X-Frame-Options.
  - Archivos `.env`, `.env.example`, `docker-compose.yml`, configuraciones de Kubernetes con puertos expuestos o credenciales default.
  - Flags de depuración activados en producción (`DEBUG=True`, `source-maps` expuestos).
- **Potencial de Absorción en Devia:**
  - Checklists de hardening y scripts de escaneo de configuraciones de despliegue.

---

### Dimensión 8: Resilience, Logging & Telemetry (`RESILIENCE_LOGGING_TELEMETRY`)
- **Propósito:** Prevención de denegación de servicio (DoS), control de fugas de datos en logs, manejo controlado de excepciones y trazabilidad de eventos de seguridad.
- **Taxonomías Asociadas:**
  - CWE: CWE-400 (Uncontrolled Resource Consumption / DoS), CWE-532 (Insertion of Sensitive Information into Log File), CWE-778 (Insufficient Logging), CWE-754 (Improper Check for Unusual or Exceptional Conditions), CWE-117.
  - OWASP Top 10: A09:2021 / A09:2025 (Security Logging and Monitoring Failures).
  - NIST CSF 2.0: Detect (`DE.CM`, `DE.AE`), Respond (`RS.MA`, `RS.AN`, `RS.MI`), Recover (`RC.RP`).
  - MITRE ATT&CK: Collection (`TA0009`), Exfiltration (`TA0010`: `T1041`, `T1048`), Impact (`TA0040`: `T1489`, `T1490`, `T1562`).
- **Indicadores Forenses en el Target:**
  - Operaciones no acotadas en memoria o CPU (e.g. `Regex DoS` con cuantificadores anidados `(a+)+$`).
  - Falta de rate limiting en endpoints de login o procesamiento de pagos.
  - Logs que imprimen objetos enteros de request que contienen contraseñas o datos PII (`console.log(req.body)`).
  - Bloques `try/catch` vacíos o que tragan excepciones críticas silenciando fallos de seguridad.
- **Potencial de Absorción en Devia:**
  - Heurísticas de ReDoS y escáneres de desbordamiento de recursos en Python/TypeScript.
  - Estándares de sanitización de logging forense.


---

## 🔒 Axioma de Taxonomía Cerrada MECE y Mapeo Universal de Vectores Emergentes

### Decisión de Arquitectura: La Frontera Inmutable de 8 Dimensiones
En **Devia-CyberSecurity**, la SSOT autoritativa de clasificación es `SecurityDimensionSchema = z.enum([...])` en `src/schemas/finding.schema.ts`.
**Queda terminantemente prohibido inventar o añadir nuevas dimensiones ad-hoc** al auditar o absorber conocimiento externo.

Cualquier vector tecnológico nuevo o emergente se fundamenta en principios universales de computación (validación de entradas, límites de confianza, secretos, identidades, recursos o dependencias) y **debe mapearse obligatoriamente** a las 8 dimensiones canónicas según la siguiente tabla de mapeo universal:

| Vector Tecnológico Emergente | Mecanismo Técnico del Vector | Dimensión Canónica Asignada |
| :--- | :--- | :--- |
| **IA / LLM: Prompt Injection** | Inyección de instrucciones no confiables en el prompt del modelo. | `SOURCE_CODE_SAST` o `THREAT_MODELING_ATTACK_SURFACE` |
| **IA / LLM: Training Data / Model Poisoning** | Contaminación de datasets o pesos de modelos de terceros. | `SUPPLY_CHAIN_SCA` |
| **IA / LLM: Model Theft / API Key Exposure** | Extracción de pesos de modelos locales o claves de API. | `SECRETS_CRYPTOGRAPHY` |
| **IA / LLM: Insecure Tool Calling / Agency** | Ejecución no acotada de comandos del sistema desde el agente. | `ARCHITECTURE_BOUNDARIES_ZERO_TRUST` |
| **IA / LLM: DoS por Context Window Saturation** | Agotamiento deliberado de tokens de contexto o memoria GPU. | `RESILIENCE_LOGGING_TELEMETRY` |
| **Cloud / Serverless: Políticas IAM hiper-permisivas** | Roles con `Action: "*"` o asunción de roles cruzados inseguros. | `IDENTITY_ACCESS_SESSION` |
| **Cloud / Serverless: Buckets / Storage públicos** | Almacenamiento S3 / Blob con acceso público inadvertido. | `CONFIGURATION_HARDENING` |
| **Web3 / Smart Contracts: Reentrancy / Integer Flaws** | Fallos lógicos en funciones de transferencia o llamadas externas. | `SOURCE_CODE_SAST` |
| **IoT / Hardware: JTAG / UART Debug Pins Expuestos** | Interfaces de depuración física conectadas a shell de root. | `ARCHITECTURE_BOUNDARIES_ZERO_TRUST` |
| **Firmware: Credenciales o Hardcoded Keys en Flash** | Claves criptográficas o credenciales quemadas en el binario. | `SECRETS_CRYPTOGRAPHY` |
