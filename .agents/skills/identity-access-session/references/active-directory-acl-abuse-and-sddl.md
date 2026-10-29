# Abuso de ACLs y Permisos SDDL en Active Directory (Active Directory ACL Abuse)

Esta referencia técnica capacita al agente en la identificación, modelado y remediación de rutas de ataque y escalada de privilegios basadas en Listas de Control de Acceso (ACLs) mal configuradas en **Active Directory** bajo la dimensión **`IDENTITY_ACCESS_SESSION`**.

---

## 🏛️ 1. Modelo de Seguridad de Objetos en Active Directory

En Active Directory (AD), cada objeto (usuarios, grupos, equipos, OUs, GPOs) está protegido por un **Descriptor de Seguridad binario** (`nTSecurityDescriptor`), el cual contiene una **Lista de Control de Acceso Discrecional (DACL)** compuesta por múltiples **Entradas de Control de Acceso (ACEs)**.

La representación canónica en texto de un descriptor es el **Security Descriptor Definition Language (SDDL)**:
```
D:(A;;GA;;;S-1-5-21-XXX-5001)(A;;WD;;;S-1-5-21-XXX-5002)
   │ │  │     └─────────────── SID del beneficiario (Trustee)
   │ │  └──────────────────── Derechos de acceso (GA = GenericAll, WD = WriteDACL)
   │ └─────────────────────── Flags de herencia (opcionales)
   └───────────────────────── Tipo de ACE (A = Allow, D = Deny)
```

---

## ⚠️ 2. Las 6 Máscaras de Acceso de Alto Riesgo

| Derecho / Máscara SDDL | Valor Hexadecimal | Impacto de Seguridad | Ruta de Explotación Típica |
| :--- | :--- | :--- | :--- |
| **`GenericAll` (`GA`)** | `0x10000000` | Control total sobre el objeto. | Resetear contraseñas de usuarios privilegiados, modificar membresía de grupos administradores, agregar SPNs para Kerberoasting. |
| **`WriteDACL` (`WD`)** | `0x00040000` | Permiso para modificar la DACL del objeto. | El atacante se auto-concede `GenericAll` en la DACL y luego ejecuta la escalada completa. |
| **`WriteOwner` (`WO`)** | `0x00080000` | Permiso para tomar posesión del objeto. | El atacante cambia el propietario del objeto a su cuenta, lo cual le otorga el derecho inherente de modificar la DACL (`WriteDACL`). |
| **`GenericWrite` (`GW`)** | `0x40000000` | Escritura en todos los atributos del objeto. | Escribir en `scriptPath` para ejecución de scripts de inicio de sesión o modificar `msDS-AllowedToActOnBehalfOfOtherIdentity` (RBCD). |
| **`WriteProperty` (`WP`)** | `0x00000020` | Escritura en atributos específicos. | Modificar `member` en grupos protegidos o `userAccountControl` para deshabilitar preautenticación Kerberos. |
| **`ExtendedRight` (`CR`)** | `0x00000100` | Control de derechos extendidos. | Restablecimiento de contraseña forzado (`User-Force-Change-Password` - GUID `{00299570-246d-11d0-a768-00aa006e0529}`). |

---

## 🔍 3. Detección Determinista y Rutas de Abuso

### 3.1. Delegación Restringida Basada en Recursos (RBCD)
- Si un usuario no administrativo tiene permiso `GenericWrite` o `WriteProperty` sobre una cuenta de equipo de Active Directory, puede poblar el atributo binario:
  `msDS-AllowedToActOnBehalfOfOtherIdentity`.
- Al configurar este descriptor para confiar en una cuenta de equipo controlada por el atacante, este último puede forjar un ticket de servicio Kerberos (S4U2Self / S4U2Proxy) para cualquier usuario hacia ese equipo, logrando ejecución de código como `SYSTEM` en el host.

### 3.2. SIDs de Cuentas Administrativas Conocidas
Al auditar ACEs, las entradas concedidas a los siguientes identificadores son legítimas por diseño. Toda concesión concedida a SIDs fuera de este conjunto debe ser auditada como potencial anomalía (`VULN-IAM-001`):

- `S-1-5-18`: Local System
- `S-1-5-32-544`: Builtin Administrators
- `S-1-5-9`: Enterprise Domain Controllers
- RID `-512`: Domain Admins
- RID `-519`: Enterprise Admins

---

## 🛡️ 4. Guía de Remediación y Hardening de DACLs

1. **Principio de Mínimo Privilegio en Delegaciones de OUs:**
   Evitar el asistente clásico de delegación de Active Directory con opciones genéricas ("Administrar todas las cuentas de usuario"). Delegar exclusivamente atributos específicos requeridos (e.g. solo `telephoneNumber` o `department`).
2. **Protección AdminSDHolder:**
   Verificar periódicamente la plantilla `CN=AdminSDHolder,CN=System,DC=...`. Cada 60 minutos el proceso `SDProp` sobrescribe las DACLs de todas las cuentas protegidas con esta plantilla; asegurar que no contenga ACEs huérfanas o no autorizadas.
3. **Auditoría Automatizada Offline:**
   Analizar exportaciones LDAP periódicas mediante `src/scripts/forensic_artifact_parser.py` para verificar que ninguna cuenta fuera de `ADMIN_SIDS` posea máscaras `0x10000000` o `0x00040000` sobre grupos privilegiados.
