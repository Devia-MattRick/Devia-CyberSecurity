# Detección de Ataques DCSync y Coerción de Autenticación NTLM en Active Directory

Este documento establece la **Guía de Caza y Detección de Primitivas de Abuso de Protocolos Active Directory (MS-DRSR y Coerción NTLM)** para la Skill **`identity-access-session`** en **Devia-CyberSecurity**.

---

## 🏛️ Contexto y Amenaza

- **Taxonomía:** CWE-287 (Improper Authentication), CWE-269 (Improper Privilege Management)
- **MITRE ATT&CK:** T1003.006 (OS Credential Dumping: DCSync), T1187 (Forced Authentication / Coercion), T1557.001 (Adversary-in-the-Middle: LLMNR/NBT-NS Poisoning and Relay)
- **Vulnerabilidad Canónica:** `VULN-IAM-003`
- **Dimensión:** `IDENTITY_ACCESS_SESSION`

---

## 🔍 1. Anatomía y Detección del Ataque DCSync (MS-DRSR)

El ataque DCSync (popularizado por herramientas como Mimikatz o Impacket `secretsdump`) simula el comportamiento de un controlador de dominio (DC) legítimo utilizando el protocolo **Directory Replication Service Remote Protocol (MS-DRSR)** para solicitar los hashes de contraseñas (NTLM y claves Kerberos) de cualquier cuenta del dominio, incluido `krbtgt`.

### GUIDs Críticos de Replicación en Active Directory:
Para que una cuenta pueda ejecutar DCSync, debe poseer tres derechos de control extendidos sobre el objeto raíz del dominio (`CN=Configuration` o `DC=domain,DC=com`):
1. **`DS-Replication-Get-Changes`:** `1131f6aa-9c07-11d1-f79f-00c04fc2dcd2`
2. **`DS-Replication-Get-Changes-All`:** `1131f6ad-9c07-11d1-f79f-00c04fc2dcd2` *(Permite replicar secretos y hashes de contraseñas)*
3. **`DS-Replication-Get-Changes-In-Filtered-Set`:** `89e95b76-444d-4c62-991a-7ac0ef40058a`

### Telemetría de Detección Heurística:
- **Evento Clave:** **Security Event ID 4662** en el Controlador de Dominio.
- **Criterio de Alerta:**
  - `ObjectServer`: `DS`
  - `ObjectType`: `{19195a5b-6da0-11d0-afd3-00c04fd930c9}` (objeto dominio)
  - `Properties`: Contiene `{1131f6ad-9c07-11d1-f79f-00c04fc2dcd2}`
  - **Condición Anómala:** El `SubjectUserName` **NO** es una cuenta de máquina de Controlador de Dominio (terminada en `$` perteneciente al grupo *Domain Controllers*). Si un usuario estándar o servicio invoca esta GUID, se trata de un DCSync activo.

---

## ⚡ 2. Ataques de Coerción de Autenticación NTLM

Los ataques de coerción obligan a una máquina remota (generalmente un DC o servidor de infraestructura) a iniciar una autenticación NTLM saliente hacia un servidor controlado por el atacante, para posteriormente retransmitir (*relay*) esa sesión hacia un servicio sensible que no exija firma digital (e.g. AD CS Web Enrollment o LDAP).

### Vectores Principales de Coerción RPC:
1. **PetitPotam (MS-EFSR):** Abuso de la función `EfsRpcOpenFileRaw` del Encrypting File System Remote Protocol.
2. **ShadowCoerce (MS-FSRVP):** Invocación de `IsPathSupported` en el File Server Remote VSS Protocol.
3. **DFSCoerce (MS-DFSNM):** Invocación de `NetrDfsRemoveStdRoot` en el Distributed File System Namespace Management.
4. **PrinterBug (MS-RPRN):** Invocación de `RpcRemoteFindFirstPrinterChangeNotificationEx` en el Print System Remote Protocol.

### Detección en Tráfico de Red y Eventos:
- Conexiones entrantes al puerto RPC **135 (Endpoint Mapper)** seguidas de un enlace dinámico hacia las interfaces UUID de EFSR (`df1941c5-fe89-4e79-bf10-463657acf44d`) o FSRVP (`a8e0653c-2744-4389-a61d-7373df8b2292`).
- En el servidor de destino (AD CS o LDAP), Event ID 4624 con `LogonType: 3`, `AuthenticationPackage: NTLM`, donde la IP de origen no coincide con la identidad de la cuenta de máquina autenticada.

---

## 🛡️ Controles de Hardening y Mitigación

1. **Eliminar Derechos de Replicación Delegados:**
   - Auditar periódicamente la raíz del dominio para garantizar que solo `Domain Controllers` y `Enterprise Domain Controllers` tengan asignado `DS-Replication-Get-Changes-All`.
2. **Exigir Firma Obligatoria (Signing):**
   - Habilitar **SMB Signing** obligatorio en todos los servidores y clientes (`Microsoft network server: Digitally sign communications (always)`).
   - Habilitar **LDAP Signing** y **LDAP Channel Binding** (CWE-319) en los Controladores de Dominio.
3. **Aislar AD CS de Relevos NTLM:**
   - Deshabilitar autenticación NTLM en los endpoints HTTP de AD CS (Enrollment web), exigiendo Kerberos o autenticación mediante certificados cliente.
4. **Deshabilitar o Restringir NTLM en Toda la Organización:**
   - Configurar directivas GPO para restringir tráfico NTLM (`Network security: Restrict NTLM: Outgoing NTLM traffic to remote servers -> Deny all`).
