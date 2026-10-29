# Detección de Intrusiones en Host (HIDS) y Monitorización de Integridad de Archivos (FIM)

Esta guía técnica describe la metodología de despliegue, configuración y auditoría de sistemas de detección de intrusiones basados en host (HIDS) y monitorización de integridad de archivos (FIM) mediante Wazuh, OSSEC y utilidades nativas en **Devia-CyberSecurity**.

---

## 🏛️ 1. Objetivos de Seguridad y Requisitos de Cumplimiento

La monitorización de integridad de archivos (FIM) es un control crítico exigido por estándares como **PCI-DSS (Requisito 11.5)** y **NIST SP 800-53 (Control SI-7)**. Su objetivo es detectar en tiempo real:
1. Modificaciones no autorizadas en binarios del sistema (`/bin`, `/sbin`, `C:\Windows\System32`).
2. Adición de scripts maliciosos en directorios de persistencia (cron jobs, systemd units, carpetas Startup).
3. Alteración de archivos de configuración críticos (`/etc/passwd`, `/etc/sudoers`, `/etc/ssh/sshd_config`).
4. Reemplazo de controladores o bibliotecas dinámicas compartidas (DLL hijacking, LD_PRELOAD).

---

## ⚙️ 2. Rutas Críticas y Parámetros de Inspección por Sistema Operativo

### Linux (Wazuh `syscheck` / AIDE)
Configurar inspección en tiempo real (`realtime="yes"` o auditoría de inodos con `auditd`):
```xml
<!-- Monitorización estricta de binarios y configuraciones -->
<syscheck>
  <directories check_all="yes" realtime="yes">/etc,/usr/bin,/usr/sbin,/bin,/sbin</directories>
  <directories check_all="yes" realtime="yes">/var/spool/cron,/etc/cron*</directories>
  <ignore>/etc/mtab</ignore>
  <ignore>/etc/hosts.deny</ignore>
  <nodiff>/etc/ssl/private.key</nodiff> <!-- Prevenir que el diff de cambios divulgue claves en logs -->
</syscheck>
```

### Windows (Wazuh `syscheck` / Defender FIM)
```xml
<syscheck>
  <directories check_all="yes" realtime="yes">C:\Windows\System32\drivers\etc</directories>
  <directories check_all="yes" realtime="yes">C:\Windows\System32\GroupPolicy</directories>
  <windows_registry check_all="yes">HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run</windows_registry>
  <windows_registry check_all="yes">HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunOnce</windows_registry>
</syscheck>
```

---

## 🛡️ 3. Prevención de Fugas de Secretos en Diff de Integridad (`nodiff`)

> [!CAUTION]
> Cuando FIM está configurado con `report_changes="yes"`, el agente genera un diff unificado de los archivos modificados y lo transmite al SIEM/Manager. Si un archivo que contiene credenciales o claves privadas (`id_rsa`, `.env`, certificados) es modificado, el contenido del secreto se filtrará en texto plano hacia los registros de eventos (`VULN-CRYP-001`).

**Regla de Mitigación Obligatoria:**  
Declarar siempre directivas `<nodiff>` para cualquier ruta sensible o patrón de clave privada en la configuración de `syscheck`.

---

## 📊 4. Correlación y Clasificación de Alertas

El parser determinista debe clasificar las alertas según severidad:
- **Nivel 12+ (Crítico):** Modificación de binarios de sistema o adición de llaves SSH en cuentas de root.
- **Nivel 7-11 (Alto):** Cambios en archivos de configuración administrativa (`sudoers`, políticas PAM).
- **Nivel 3-6 (Medio):** Creación de archivos en directorios temporales compartidos (`/tmp`, `C:\Windows\Temp`).
