# Guía Canónica de Artefactos Forenses y Telemetría de Endpoint

Este documento constituye la referencia metodológica canónica para la identificación, recolección quiescente y análisis de artefactos forenses del sistema operativo (Windows y Linux), memoria volátil y telemetría de red dentro de la dimensión **`RESILIENCE_LOGGING_TELEMETRY`**.

---

## 🏛️ 1. Taxonomía de Artefactos de Endpoint

| Origen del Artefacto | Mecanismo del SO | Ubicación Típica | Indicadores Forenses Revelados | Taxonomía MITRE / CWE |
| :--- | :--- | :--- | :--- | :--- |
| **`WINDOWS_AMCACHE`** | Inventario de compatibilidad de aplicaciones | `C:\Windows\appcompat\Programs\Amcache.hve` | Rutas de binarios no instalados, hashes SHA-1 históricos, marcas de tiempo de compilación y primer arranque. | T1059 / T1204<br>CWE-532 |
| **`WINDOWS_PREFETCH`** | Optimización de memoria en arranque | `C:\Windows\Prefetch\*.pf` | Ejecución comprobada de binarios (`.exe`), contador de ejecuciones, últimas 8 marcas de tiempo y DLLs cargadas. | T1059 / T1036<br>CWE-754 |
| **`WINDOWS_REGISTRY`** | Claves de persistencia y UserAssist | `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run`<br>`HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist` | Persistencia en inicio (`Run/RunOnce`), historial de ejecución en Explorer (claves ROT13), dispositivos USB recientes. | T1547.001 / T1082<br>CWE-200 |
| **`WINDOWS_SHIMCACHE`** | Compatibilidad de aplicaciones (AppCompatCache) | `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache` | Evidencia de existencia histórica de binarios, incluso si fueron eliminados del disco antes del análisis. | T1070.004<br>CWE-754 |
| **`WINDOWS_MFT`** | Master File Table (NTFS) | `$MFT` en raíz de volumen | Creación, modificación, acceso y cambio de metadatos ($STANDARD_INFORMATION vs $FILE_NAME), timestomping. | T1070.006<br>CWE-345 |
| **`WINDOWS_LNK_JUMPLIST`**| Accesos directos y listas de salto | `%APPDATA%\Microsoft\Windows\Recent\`<br>`AutomaticDestinations\*.automaticDestinations-ms` | Rutas de destino, números de serie de volumen, direcciones MAC y fechas de acceso a documentos. | T1204.002<br>CWE-200 |
| **`LINUX_AUDIT_LOG`** | Daemon de auditoría del kernel (auditd) | `/var/log/audit/audit.log` | Syscalls críticas (`execve`, `ptrace`, `connect`, `chmod`), UID/GID efectivo y argumentos ejecutados. | T1059.004<br>CWE-778 |
| **`LINUX_SYSTEM_JOURNAL`**| Registro centralizado systemd | `/var/log/journal/` | Unidades de servicio creadas/modificadas, timers efímeros, reinicios anómalos y fallos de autenticación PAM. | T1543.002<br>CWE-778 |
| **`MEMORY_VOLATILITY`** | Volcado de memoria RAM (LiME / Raw) | Volcado `.raw`, `.dmp` | Procesos ocultos (`pslist` vs `psscan`), inyecciones de código (`malfind`), sockets sin enlazar y descriptores. | T1055 / T1057<br>CWE-119 |

---

## 🔬 2. Heurísticas Deterministas de Análisis

### 2.1. Detección de Timestomping ($STANDARD_INFORMATION vs $FILE_NAME)
- **El Vector:** Los atacantes modifican las marcas de tiempo en el atributo `$STANDARD_INFORMATION` de NTFS mediante APIs de usuario para camuflar binarios maliciosos entre archivos legítimos del sistema.
- **La Heurística:** Comparar siempre el atributo `$STANDARD_INFORMATION` con `$FILE_NAME`. Dado que `$FILE_NAME` solo puede ser mutado por el kernel del sistema de archivos NTFS, cualquier discrepancia donde `$STANDARD_INFORMATION` sea anterior a `$FILE_NAME` o contenga sub-segundos en cero (`.0000000`) es evidencia flagrante de timestomping (`T1070.006`).

### 2.2. Inspección de UserAssist con ROT13
- Las subclaves de `UserAssist` en el registro almacenan los nombres de los ejecutables codificados en ROT13 para mantener estadísticas de uso de la shell de Windows.
- La estructura de valores binarios incluye:
  - Offset `0x04`: Contador de ejecuciones (Entero de 32 bits little-endian).
  - Offset `0x3c`: Marca de tiempo FILETIME de 64 bits de la última ejecución.

### 2.3. Desambiguación de Prefetch Hash en Windows 10/11
- En Windows 10 y 11, el hash de 8 caracteres hexadecimales appended al nombre del archivo (`POWERSHELL.EXE-<HASH>.pf`) se calcula a partir de la ruta absoluta del ejecutable usando una variante de hashing propietaria de Microsoft.
- Si dos archivos `POWERSHELL.EXE` residen en rutas distintas (e.g. `C:\Windows\System32\` vs `C:\Users\Public\`), generarán dos archivos `.pf` independientes con hashes distintos. Un archivo Prefetch fuera de la ruta estándar de sistema denota ejecución de señuelos o binarios renombrados (*Masquerading* - `T1036.003`).

---

## 🛡️ 3. Protocolo de Cadena de Custodia y No-Ejecución

1. **Montaje en Solo Lectura (`ro`):**
   Toda imagen de disco, partición montada o archivo `.hve` debe abrirse exclusivamente con flags de solo lectura (`os.O_RDONLY` o montaje loopback `-o ro,noexec`).
2. **Cálculo de Checksum SHA-256 Pre-Análisis:**
   Antes de procesar un archivo de evidencia forense, calcular y registrar su hash criptográfico. Cualquier discrepancia posterior anula la admisibilidad y veracidad de la investigación.
3. **Normalización a Contrato Zod (`ForensicInvestigationReportSchema`):**
   Los hallazgos deben canalizarse mediante el runner determinista `src/scripts/forensic_artifact_parser.py` para certificar la conformidad con los tipos autoritativos en Capa 2.
