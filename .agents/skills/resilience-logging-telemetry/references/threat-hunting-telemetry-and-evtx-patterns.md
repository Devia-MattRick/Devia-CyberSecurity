# Telemetría Forense en Registros de Eventos Windows (EVTX) y Reglas Sigma

Este documento establece la **Guía Operativa de Telemetría Forense de Eventos y Caza Proactiva** para la Skill **`resilience-logging-telemetry`** en **Devia-CyberSecurity**.

---

## 🏛️ Contexto y Amenaza

- **Taxonomía:** CWE-778 (Insufficient Logging), CWE-1059 (Incomplete Documentation / Event Omission)
- **MITRE ATT&CK:** T1059 (Command and Scripting Interpreter), T1053 (Scheduled Task/Job), T1547 (Boot or Logon Autostart Execution)
- **Vulnerabilidad Canónica:** `VULN-RESI-003`
- **Dimensión:** `RESILIENCE_LOGGING_TELEMETRY`

El análisis de registros de eventos en endpoints Windows (archivos `.evtx`) requiere técnicas de filtrado y correlación de alta fidelidad para aislar actividad maliciosa oculta entre cientos de miles de eventos rutinarios del sistema operativo.

---

## 🔍 Matriz Canónica de Event IDs de Alta Fidelidad

| Proveedor / Canal | Event ID | Nombre del Evento | Relevancia Táctica y Vectores Auditados |
| :--- | :---: | :--- | :--- |
| **Security** | **4624** | Successful Logon | Tipo de inicio de sesión: `Type 3` (Red / DCOM / SMB), `Type 10` (RDP), `Type 9` (NewCredentials). |
| **Security** | **4688** | Process Creation | Exige activación de *Include command line in process creation events*. Rastrear LOLBins. |
| **Security** | **4662** | Directory Service Object Access | Acceso a replicación Active Directory (`DS-Replication-Get-Changes-All`) $\to$ **DCSync**. |
| **Security** | **4697 / 7045** | Service Installed | Instalación de nuevos servicios con rutas a ejecutables en `%TEMP%` o con `cmd.exe /c`. |
| **Security** | **4728 / 4732 / 4756**| Member Added to Group | Adición de cuentas a grupos de alta autoridad (`Domain Admins`, `Enterprise Admins`). |
| **Sysmon** | **1** | Process Creation | Árbol genealógico completo (ParentImage, ParentCommandLine, Hashes SHA-256). |
| **Sysmon** | **3** | Network Connection | Asociación unívoca entre proceso (`Image`) y conexión saliente (`DestinationIp:Port`). |
| **Sysmon** | **7** | Image Loaded | Carga de bibliotecas DLL dinámicas; detección de DLL Hijacking y DLL Sideloading. |
| **Sysmon** | **8 / 10** | CreateRemoteThread / ProcessAccess | Inyección de procesos (Process Hollowing, Mimikatz accediendo a `lsass.exe`). |
| **Sysmon** | **11** | FileCreate | Creación de artefactos en disco; webshells en raíces web o scripts en directorios Startup. |
| **Sysmon** | **12 / 13 / 14** | Registry Event | Persistencia en claves Run/RunOnce, IFEO, extensiones Shell o secuestro de COM. |
| **Sysmon** | **19 / 20 / 21** | WMI Event Consumer/Filter | Creación de suscripciones WMI (`CommandLineEventConsumer`) para persistencia fileless. |
| **Sysmon** | **22** | DNSEvent | Resolución DNS por proceso; detección de DGA y balizamiento DNS por ejecutables no estándar. |
| **PowerShell** | **4104** | Script Block Logging | Captura completa del bloque de script evaluado antes de la ejecución, neutralizando encoding. |

---

## ⚡ Estrategia de Caza de Alta Velocidad con Reglas Sigma

1. **Compilación de Reglas Sigma a Consultas Nativas:**
   - En lugar de parsear archivos `.evtx` secuencialmente con scripts lentos, compilar reglas Sigma estandarizadas hacia filtros XPath deterministas o índices estructurados (Chainsaw / Hayabusa).
   - Filtrar primero por el canal y Event ID en el kernel de Windows para reducir la superficie de evaluación en un 95%.

2. **Detección de LOLBins en Sysmon EID 1 / Security 4688:**
   - Monitorear ejecutables legítimos de Microsoft ejecutando switches de descarga o ejecución indirecta:
     - `certutil.exe -urlcache -split -f http...`
     - `mshta.exe javascript:...` o `mshta.exe vbscript:...`
     - `regsvr32.exe /s /u /i:http... scrobj.dll`
     - `rundll32.exe javascript:...`
     - `bitsadmin.exe /transfer ...`

3. **Análisis de Bloques de Script PowerShell (EID 4104):**
   - El registro 4104 almacena el código desofuscado tras la primera capa de evaluación de la AMSI.
   - Heurísticas de búsqueda:
     - Cadenas sospechosas: `Net.WebClient`, `DownloadString`, `Invoke-Expression`, `IEX`, `[Convert]::FromBase64String`.
     - Intento de bypass de AMSI: manipulación de `AmsiUtils` o `amsiInitFailed`.
     - Reflexión: `[AppDomain]::CurrentDomain.DefineDynamicAssembly`.

---

## 📋 Checklist de Hardening de Telemetría

- [ ] ¿Está habilitada la directiva *Audit Process Creation* con *Include command line in process creation events* (GPO)?
- [ ] ¿Está desplegado Sysmon con una configuración basada en SwiftOnSecurity o Florían Roth?
- [ ] ¿Está habilitado *PowerShell Script Block Logging* (EID 4104) de forma obligatoria en la flota?
- [ ] ¿Se audita la escritura en la partición ESP y directorios `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup`?
- [ ] ¿Se supervisa el Event ID 4662 en controladores de dominio para la detección temprana de DCSync?
