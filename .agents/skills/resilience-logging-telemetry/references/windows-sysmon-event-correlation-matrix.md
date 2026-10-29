# Matriz Canónica de Telemetría Host: Windows Event IDs y Sysmon para Detección de Amenazas

Este documento establece la especificación técnica autoritativa para la recolección, filtrado y correlación de eventos de seguridad en sistemas Windows (Active Directory, servidores miembro y estaciones de trabajo) combinando **Windows Security Event Logs** y **Microsoft Sysmon**.

---

## 🏛️ 1. Matriz de Eventos Canónicos de Windows Security (EVTX)

| Event ID | Canal / Proveedor | Técnica MITRE ATT&CK | Descripción y Foco de Caza |
| :--- | :--- | :--- | :--- |
| **4624** | Security | T1078, T1021 | Inicio de sesión exitoso. Crítico: `LogonType = 3` (Network) con NTLM vs Kerberos, y discrepancias entre `IpAddress` y `TargetUserName`. |
| **4625** | Security | T1110 | Inicio de sesión fallido. Monitoreo de fuerza bruta y password spraying por código de sub-estado (`0xC000006A`, `0xC0000234`). |
| **4688** | Security | T1059, T1218 | Creación de procesos con auditoría de línea de comandos activada (*Process Creation with CommandLine*). |
| **4768** | Security | T1558.003 | Solicitud de Ticket Granting Ticket (TGT) Kerberos. Auditoría de tipos de cifrado y cuentas de servicio. |
| **4769** | Security | T1558.001 | Solicitud de Ticket Granting Service (TGS). Foco en **Kerberoasting** y **Golden Ticket** (solicitudes sin TGT previo o con etype `0x17` RC4). |
| **4771** | Security | T1558.004 | Fallo de pre-autenticación Kerberos. Indicador primario de AS-REP Roasting cuando `Pre-Authentication Type = 0`. |
| **4776** | Security | T1557.001 | Validación de credenciales NTLM por el Controlador de Dominio. Detección de retransmisión NTLM. |
| **4662** | Security | T1003.006 | Operación sobre objeto de Directorio Activo. Acceso con máscara `0x100` para `DS-Replication-Get-Changes-All` (**DCSync**). |
| **4672** | Security | T1078.002 | Asignación de privilegios especiales (`SeDebugPrivilege`, `SeImpersonatePrivilege`, `SeTcbPrivilege`). |
| **7045** | System | T1543.003 | Instalación de nuevo servicio de Windows (Pivote de herramientas como PsExec, Cobalt Strike beacon, o binarios sospechosos). |

---

## 🛡️ 2. Matriz de Eventos Canónicos de Sysmon

| Event ID | Nombre del Evento | Foco de Detección e Invariantes |
| :--- | :--- | :--- |
| **Event 1** | `ProcessCreate` | Línea de comandos completa, hashes SHA-256 del binario, proceso padre (`ParentImage`), firma digital y contexto de integridad. |
| **Event 3** | `NetworkConnect` | Conexiones de red TCP/UDP salientes iniciadas por binarios inesperados (`rundll32.exe`, `regsvr32.exe`, `mshta.exe`, `powershell.exe`). |
| **Event 7** | `ImageLoaded` | Carga de módulos DLL en memoria. Monitoreo de DLL Hijacking, sideloading y carga de `samlib.dll`, `vaultcli.dll` o `wdigest.dll`. |
| **Event 8** | `CreateRemoteThread` | Creación de un hilo de ejecución en el espacio virtual de otro proceso (`SourceImage != TargetImage`). Indicador directo de inyección. |
| **Event 10** | `ProcessAccess` | Apertura de un descriptor sobre otro proceso con máscaras de acceso de alto privilegio. |
| **Event 11** | `FileCreate` | Creación de archivos ejecutables, scripts en carpetas temporales (`C:\Users\*\AppData\Local\Temp\`) o canarios de ransomware. |
| **Event 13** | `RegistryEvent` | Mutación de claves de registro de persistencia (Run, RunOnce, Winlogon, Image File Execution Options). |
| **Event 22** | `DnsQuery` | Consultas DNS originadas por procesos locales; detección de balizamiento C2 y túneles DNS con entropía. |
| **Event 25** | `ProcessTampering` | Detección determinista de vaciado de procesos (**Process Hollowing**) y manipulación de PE headers en memoria. |

---

## 🔬 3. Heurísticas y Reglas de Correlación Multievento

### 3.1. Detección de Forja de Golden Ticket (T1558.001)
Un Golden Ticket falsificado mediante `mimikatz` u `impacket` omite la fase de emisión formal de TGT por el DC o degrada la criptografía:
1. **Regla de TGS Huérfano:** Si se registra un Event 4769 (TGS) para una cuenta de usuario sin que exista un Event 4768 (TGT) correspondiente en los 600 minutos previos emitido por el mismo DC.
2. **Degradación Criptográfica Anómala:** El `TicketEncryptionType` en Event 4769 es `0x17` (RC4-HMAC) en un entorno que exige AES (`0x11` / `0x12`).
3. **Duración Imposible del Ticket:** La diferencia entre `StartTime` y `EndTime` en el ticket Kerberos supera la directiva de dominio (típicamente 10 horas), situándose frecuentemente en 10 años por defecto en Mimikatz.

### 3.2. Detección de Inyección de Procesos (T1055) mediante Sysmon Event 10
Para inyectar código en un proceso remoto (e.g. `lsass.exe`, `explorer.exe`, `spoolsv.exe`), el atacante invoca `OpenProcess` con privilegios de escritura de memoria:
- **Máscaras Críticas de `GrantedAccess`:**
  - `0x1F0FFF` o `0x001F0FFF`: `PROCESS_ALL_ACCESS` (Control total).
  - `0x0020`: `PROCESS_VM_WRITE` (Permiso para escribir en la memoria virtual del proceso destino).
  - `0x0008`: `PROCESS_VM_OPERATION` (Permiso para manipular páginas de memoria virtual).
- **Correlación Inmediata:** Si a una apertura con `0x0020` o `0x1F0FFF` le sucede un Sysmon Event 8 (`CreateRemoteThread`) o llamada a `VirtualAllocEx` desde el proceso origen, se cataloga como inyección de código demostrada (**CRITICAL**).

### 3.3. Detección de Retransmisión NTLM (NTLM Relay - T1557.001)
Un atacante que captura un challenge-response NTLM lo retransmite hacia múltiples servidores SMB/LDAP:
- **Correlación Temporal Multidestino:** Un mismo usuario (`TargetUserName`) registra eventos exitosos 4624 (`LogonType = 3`) autenticados por NTLM contra $\ge 3$ equipos diferentes en una ventana temporal $\le 120$ segundos, proviniendo todos de la misma IP cliente (`IpAddress`).
- **Discrepancia IP-Hostname:** El nombre de la estación reportado en el evento difiere del registro DNS inverso o del catálogo corporativo para la IP de origen.

---

## ⚙️ 4. Formato de Salida y Gobernanza Contract-First

Todas las alertas derivadas de la correlación de eventos host deben validarse contra `ThreatDetectionReportSchema` (`src/schemas/threat-detection.schema.ts`) y canalizarse a través de `ThreatDetectionEngine` (`src/scripts/threat_detection_engine.py`), garantizando:
- Hash de evidencia e inmutabilidad de marcas de tiempo UTC.
- Enlace determinista con la técnica MITRE ATT&CK correspondiente.
- Mapeo unívoco hacia la dimensión canónica `RESILIENCE_LOGGING_TELEMETRY`.
