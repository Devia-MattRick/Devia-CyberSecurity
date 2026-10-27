# Matriz Purple Team de Telemetría, Monitoreo y Detección Defensiva

Este documento establece la **Guía Operativa de Telemetría Defensiva y Reglas de Detección** para la dimensión `RESILIENCE_LOGGING_TELEMETRY` dentro de **Devia-CyberSecurity**.

---

## 🏛️ 1. Metodología Purple Team en Remediación y Telemetría

Un reporte de auditoría completo **no debe limitarse a indicar un fallo en el código fuente**. Para toda vulnerabilidad identificada, el especialista defensivo debe proporcionar las contramedidas de detección y telemetría requeridas por los equipos de SOC y Threat Hunting para detectar intentos de explotación en runtime (*Purple Teaming Alignment*).

```
+---------------------------------------------------------------------------------------+
|                              CICLO DEFENSIVO PURPLE TEAM                              |
+------------------------------+---------------------------+----------------------------+
| 1. Simulación / Vector Táctico| 2. Fuente de Telemetría   | 3. Regla de Detección / SIEM |
| (MITRE ATT&CK T1xxx)         | (Logs, Sysmon, CloudTrail)| (Sigma, EQL, Splunk SPL)   |
+------------------------------+---------------------------+----------------------------+
```

---

## 📊 2. Matriz de Telemetría por Táctica de MITRE ATT&CK

| Táctica ATT&CK | Técnicas Clave | Fuentes de Telemetría Primarias | Event IDs / Fuentes Clave | Regla de Detección Recomendada (Sigma / EDR) |
| :--- | :--- | :--- | :--- | :--- |
| **Initial Access (`TA0001`)** | `T1190` (Exploit Public-Facing App), `T1566` (Phishing) | Web Server Access Logs, WAF Logs, Email Gateway (DMARC/DKIM/SPF) | HTTP Status 500/400 con payloads anómalos; WAF block events; Sysmon Event 1 | Detección de patrones SQLi/XSS en URI/Body; Ejecución de procesos hijos desde `w3wp.exe`, `nginx`, `httpd`. |
| **Execution (`TA0002`)** | `T1059.001` (PowerShell), `T1055` (Process Injection) | Process Creation Logs (EDR/Sysmon), PowerShell Script Block Logging | Windows Security ID 4688, Sysmon Event 1, PowerShell Event 4104 | Detección de flags `-enc`, `-w hidden`, `-nop`, `IEX` o llamadas a APIs Win32 (`VirtualAllocEx`, `WriteProcessMemory`). |
| **Persistence (`TA0003`)** | `T1547.001` (Registry Run Keys), `T1053.005` (Scheduled Tasks) | Registry Monitoring, Task Scheduler Logs, Crontab / Systemd Unit Logs | Sysmon Event 12/13 (Registry), Windows Event 4698/4702 (Task created), Linux `/etc/cron*` | Modificación no autorizada de claves `CurrentVersion\Run`; Creación de tareas con llamadas a cmd/powershell. |
| **Privilege Escalation (`TA0004`)** | `T1068` (Exploitation), `T1134` (Token Manipulation) | OS Security Audit Logs, Kernel Event Tracing, Sudo logs | Windows Security Event 4672 (Admin logon), 4673 (Privileged Service), Linux `sudo` failure | Invocación de `sudo` sin contraseña; Cambios de SID de usuario en procesos secundarios. |
| **Defense Evasion (`TA0005`)** | `T1070` (Indicator Removal), `T1027` (Obfuscation), `T1014` (Rootkit) | Audit Log Integrity, Driver Load Events, Antivirus Tampering Logs | Windows Security Event 1102 (Log cleared), Sysmon Event 6 (Driver loaded) | Vaciado manual de registros de eventos (`wevtutil cl`); Carga de drivers sin firma WHQL válida. |
| **Credential Access (`TA0006`)** | `T1003.001` (LSASS Dump), `T1110` (Brute Force), `T1552` (Unsecured Creds) | Process Access Logs (LSASS handle), Auth Logs, Cloud KMS Audit | Sysmon Event 10 (Process access `lsass.exe`), Windows Event 4625 (Logon failed), AWS KMS `Decrypt` | Acceso a memoria de `lsass.exe` con `PROCESS_VM_READ`; Picos de fallos de autenticación $>10/\text{min}$ por IP. |
| **Discovery (`TA0007`)** | `T1046` (Network Service Discovery), `T1087` (Account Discovery) | Firewall Logs, NetFlow/VPC Flow Logs, Active Directory Queries | NetFlow spikes, Windows Event 4661 (SAM Account query) | Ráfagas de conexiones TCP SYN a múltiples puertos internos; Enumeración masiva de grupos de dominio. |
| **Lateral Movement (`TA0008`)** | `T1021.002` (SMB Shares), `T1550` (Pass-the-Hash) | SMB/RPC Audit, Kerberos Ticket Logs, SSH Auth Logs | Windows Event 4624 (Logon Type 3: Network, NTLM auth), Sysmon Event 3 (Network connect) | Autenticación NTLM en red interna entre estaciones de trabajo (anomalía workstation-to-workstation). |
| **Command and Control (`TA0011`)** | `T1071.001` (Web Protocols), `T1090` (Proxy), `T1105` (Ingress Tool) | DNS Query Logs, Web Proxy Logs, Egress Firewall | DNS Event 22, Zeek/Bro HTTP/TLS logs, JA3/JA3S fingerprinting | Consultas DNS con alta entropía (DNS tunneling); Conexiones periódicas regulares (*beaconing* jitter $<5\%$). |
| **Exfiltration (`TA0010`)** | `T1041` (Exfil Over C2), `T1567` (Exfil to Cloud Storage) | Network DLP Logs, Proxy Egress Metrics, S3 API Logs | NetFlow bytes-out ratios, Cloudflare/Proxy outbound large uploads | Cargas de datos inusuales ($>100\text{ MB}$) hacia proveedores de almacenamiento cloud no autorizados. |
| **Impact (`TA0040`)** | `T1486` (Data Encrypted for Impact), `T1489` (Service Stop) | File System High-Frequency Events, Service Control Manager Logs | Sysmon Event 11 (File create/modify burst), Windows System Event 7036 (Service stopped) | Ráfagas de renombrado masivo de archivos con nuevas extensiones; Detención de servicios VSS (`vssadmin delete shadows`). |

---

## 🛠️ 3. Reglas Sigma de Ejemplo para Hallazgos SAST

Al emitir un hallazgo de inyección de comandos o SSRF, incorporar en la remediación la regla de monitoreo correlacionada:

### Ejemplo A: Detección de Explotación RCE / Inyección de Comandos (CWE-78 / T1059)
```yaml
title: Shell Spawned from Web Server Worker Process
id: a1b2c3d4-e5f6-7890-abcd-1234567890ef
status: production
description: Detecta el lanzamiento de una shell interactiva o intérprete de comandos desde un proceso de servidor web.
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    ParentImage|endswith:
      - '\w3wp.exe'
      - '\httpd.exe'
      - '\nginx.exe'
      - '\node.exe'
    Image|endswith:
      - '\cmd.exe'
      - '\powershell.exe'
      - '\bash.exe'
      - '\sh.exe'
  condition: selection
level: critical
tags:
  - attack.execution
  - attack.t1059
```

### Ejemplo B: Detección de Intento de SSRF hacia Endpoint de Metadatos Cloud (CWE-918 / T1190)
```yaml
title: Outbound Request to Cloud Instance Metadata Service (IMDS)
id: f1e2d3c4-b5a6-0987-fedc-9876543210fe
status: production
description: Detecta conexiones HTTP no autorizadas dirigidas a la IP interna de metadatos desde contenedores de backend.
logsource:
  category: network_connection
  product: linux
detection:
  selection:
    DestinationIp:
      - '169.254.169.254'
      - 'fd00:ec2::254'
    DestinationPort: 80
  filter_authorized:
    Image|endswith:
      - '/usr/bin/amazon-ssm-agent'
  condition: selection and not filter_authorized
level: high
tags:
  - attack.initial_access
  - attack.t1190
  - attack.t1552
```

---

## 🔒 4. Directivas de Prevención de Ruido en Telemetría (Hardening)

1. **Sanitización de Datos Sensibles (CWE-532):**
   Las reglas de logging **jamás** deben capturar en texto claro contraseñas, tokens JWT, números de tarjetas o datos de identidad personal (PII). Todo registro de payload de auditoría debe ofuscar tokens mediante hashes SHA-256 o máscaras de caracteres.
2. **Resiliencia ante Inundación de Logs (CWE-400):**
   Configurar límites de tasa (*rate limiting*) a nivel de agente de telemetría (Syslog/Fluentbit/Logstash) para prevenir que una tormenta de eventos adversos sature el disco local o degrade la red interna.
