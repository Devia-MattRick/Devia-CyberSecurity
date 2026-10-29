# Auditoría de Operaciones Kerberos: Pass-the-Ticket, Golden/Silver Tickets y Degradación Criptográfica

Este documento establece la **Guía Operativa y Metodología de Auditoría para Ataques y Persistencia basados en Kerberos** dentro de la Skill **`identity-access-session`** de **Devia-CyberSecurity**.

---

## 🏛️ Contexto y Amenaza

- **Taxonomía:** CWE-287 (Improper Authentication), CWE-327 (Use of a Broken or Risky Cryptographic Algorithm), CWE-269 (Improper Privilege Management)
- **MITRE ATT&CK:** T1558 (Steal or Forge Kerberos Tickets), T1558.001 (Golden Ticket), T1558.002 (Silver Ticket), T1558.003 (Kerberoasting), T1550.003 (Pass the Ticket)
- **Vulnerabilidad Canónica:** `VULN-IAM-001`, `VULN-CRYP-002`
- **Dimensión:** `IDENTITY_ACCESS_SESSION` & `SECRETS_CRYPTOGRAPHY`

---

## 🔍 1. Mecánica de los Tickets Kerberos y Formatos de Artefactos

En entornos de Active Directory, la autenticación y autorización se delega a través de dos tipos principales de tickets emitidos por el KDC (Key Distribution Center):
1. **Ticket Granting Ticket (TGT):** Obtenido tras el intercambio `AS-REQ / AS-REP`. Cifrado con la clave secreta de la cuenta `krbtgt` del dominio.
2. **Service Ticket (TGS):** Obtenido tras el intercambio `TGS-REQ / TGS-REP` presentando un TGT válido. Cifrado con la clave secreta de la cuenta de servicio asociada al SPN solicitado.

### Formatos de Artefactos Forenses:
- **Formato Kirbi (`.kirbi`):** Estructura binaria ASN.1 codificada según el mensaje `KRB-CRED` (RFC 4120). Utilizado predominantemente por herramientas en Windows (Mimikatz, Rubeus).
- **Formato CCACHE (`.ccache` / `krb5cc_*`):** Estructura binaria de caché de credenciales utilizada por implementaciones Kerberos en Linux/Unix (MIT Kerberos, Heimdal) e Impacket.

---

## ⚡ 2. Vectores de Explotación y Persistencia

### 2.1. Pass-the-Ticket (PtT - T1550.003)
Un atacante que compromete una estación de trabajo o servidor extrae tickets TGT/TGS residentes en la memoria del proceso LSASS (`LsaCallAuthenticationPackage`) y los inyecta en su propia sesión de inicio de sesión (`KerbSubmitTicketMessage` / `ticket::ptt`).
- **Característica:** No requiere conocer la contraseña en texto plano ni el hash NTLM del usuario suplantado.
- **Invariante de Seguridad:** Los tickets Kerberos no están vinculados criptográficamente al hardware o a la dirección IP de origen en la configuración por defecto de Active Directory.

### 2.2. Golden Ticket (T1558.001)
Forja de un TGT arbitrario utilizando el hash NTLM o clave AES-256 de la cuenta `krbtgt`.
- **Alcance:** Otorga privilegios de Domain Admin o Enterprise Admin indefinidos (con tiempos de vida configurables de hasta 10 años).
- **Detección:** Event ID 4768 en el DC donde el ticket TGT solicitado no corresponde a una petición de preautenticación previa o tiene una duración anómala superior a la directiva de dominio (habitualmente 10 horas).

### 2.3. Silver Ticket (T1558.002)
Forja de un TGS para un servicio específico (e.g. `cifs/server`, `http/sharepoint`, `MSSQLSvc/db01`) utilizando la clave secreta de la cuenta de servicio del equipo.
- **Característica:** El ticket se presenta directamente al servidor final sin interactuar con el Controlador de Dominio, lo que genera cero telemetría en los logs del DC.

---

## 🔒 3. Auditoría de Suites Criptográficas y Degradación (CWE-327)

Uno de los vectores más críticos en Active Directory es la degradación voluntaria hacia suites obsoletas en los intercambios Kerberos:

| Tipo de Cifrado (etype) | Algoritmo | Estado de Seguridad | Riesgo de Explotación |
| :---: | :---: | :---: | :---: |
| **0x17 (23)** | **RC4-HMAC-MD5** | **CRÍTICO / OBSOLETO** | Vulnerable a cracking offline a alta velocidad (Kerberoasting) y ataques de colisión MD5. |
| **0x12 (18)** | **AES256-CTS-HMAC-SHA1-96** | **RECOMENDADO** | Estándar robusto; resistencia matemática elevada contra fuerza bruta. |
| **0x11 (17)** | **AES128-CTS-HMAC-SHA1-96** | **ACEPTABLE** | Alternativa segura de 128 bits. |
| **0x01 / 0x03** | **DES-CBC-CRC / MD5** | **INACEPTABLE** | Roto criptográficamente; deshabilitado por defecto en Windows Server 2008 R2+. |

### Regla Heurística de Detección:
En el Event ID 4769 (*A Kerberos service ticket was requested*):
- Si `TicketOptions` contiene `0x40810000` y `TicketEncryptionType` es `0x17` para una cuenta que soporta AES $\to$ alerta de **intento deliberado de degradación para Kerberoasting**.

---

## 🛡️ 4. Matriz de Remediación y Hardening

1. **Rotación Doble de la Cuenta `krbtgt`:**
   - La mitigación de un Golden Ticket exige rotar la contraseña de `krbtgt` **dos veces consecutivas**, separadas por un intervalo equivalente a la vida máxima del ticket (e.g. 10 a 24 horas), para invalidar tanto la clave activa como la clave histórica almacenada.
2. **Deshabilitar Cifrado RC4 en Kerberos:**
   - Habilitar directiva GPO: `Network security: Configure encryption types allowed for Kerberos -> AES128_HMAC_SHA1, AES256_HMAC_SHA1, Future encryption types`.
3. **Proteger Cuentas Sensibles con Protected Users:**
   - Añadir todos los administradores al grupo de seguridad global **`Protected Users`**:
     - Deshabilita NTLM.
     - Impide el almacenamiento de claves DES y RC4 en caché.
     - Reduce la vida útil máxima de los tickets TGT a 4 horas no renovables.
4. **Habilitar Credential Guard:**
   - Aislar el proceso LSASS mediante seguridad basada en virtualización (VBS), impidiendo la extracción de tickets en memoria incluso para atacantes con privilegios `SYSTEM` locales.
