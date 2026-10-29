# Despliegue de Honeytokens en Active Directory y Detección de Kerberoasting

Este documento establece las directivas técnicas para implementar señuelos de engaño (*Honeytokens*) en **Active Directory (AD)**, configurando trampas contra ataques de **Kerberoasting** (*Honeyroasting*), robo de credenciales en GPO (*cpassword traps*) y detección de reconocimiento gráfico con BloodHound.

---

## 🎯 1. Principios de Realismo en Cuentas Señuelo AD

Para que una cuenta trampa engañe a operadores humanos y herramientas automatizadas (Rubeus, Mimikatz, BloodHound, CrackMapExec), debe cumplir con las siguientes directivas de credibilidad (investigaciones de Trimarc y SpecterOps):

1. **Atributo `AdminCount = 1`:** Marca la cuenta como si hubiera pertenecido a un grupo administrativo protegido por el proceso `SDProp` (Domain Admins, Enterprise Admins). Los atacantes priorizan estas cuentas para ataques de Kerberoasting.
2. **Nomenclatura Creíble de Servicio:** Utilizar nombres verosímiles que coincidan con la convención de la organización (`svc_sqlbackup`, `svc_exchange_legacy`, `admin.maintenance`, `veeam_proxy`).
3. **Antigüedad Artificial del Password:** Configurar `pwdLastSet` en una fecha distante en el pasado (e.g. 8-10 años). Los atacantes buscan cuentas con contraseñas antiguas asumiendo que utilizan hashes débiles o contraseñas simples.
4. **SPNs Atractivos para Kerberoasting:** Asociar Service Principal Names de servicios de alto valor:
   - `MSSQLSvc/sql-prod-01.corp.internal:1433`
   - `HTTP/sharepoint.corp.internal`
   - `TERMSRV/rds-gateway.corp.internal`
5. **Cifrado Kerberos Débil Declarado:** Configurar la cuenta permitiendo `RC4_HMAC_MD5` en `msDS-SupportedEncryptionTypes` para que el atacante solicite tickets con cifrado débil fácilmente crackeable.

---

## 🛡️ 2. Eventos de Seguridad Críticos en Windows Event Log

Cualquier interacción con una cuenta honeytoken es inherently sospechosa y debe generar una alerta de severidad crítica en el SIEM:

| Event ID | Canal / Origen | Significado Forense | Técnica ATT&CK Asociada |
| :--- | :--- | :--- | :--- |
| **`4769`** | Windows Security | Solicitud de ticket Kerberos TGS contra el SPN señuelo. | `T1558.003` (Kerberoasting / Honeyroasting) |
| **`4768`** | Windows Security | Solicitud de ticket Kerberos TGT (intento de AS-REP Roasting). | `T1558.004` (AS-REP Roasting) |
| **`4625`** | Windows Security | Inicio de sesión fallido con las credenciales trampa. | `T1110.003` (Password Spraying / Decoy GPO) |
| **`4662`** | Windows Security | Acceso de lectura al DACL de la cuenta (SACL activada). | `T1087.002` (Account Discovery) |
| **`5136`** | Directory Service | Modificación de un objeto señuelo o directiva GPO trampa. | `T1484.001` (Group Policy Modification) |

---

## 🍯 3. Trampas de Contraseña en GPO (*cpassword Decoys*)

Las preferencias de directiva de grupo (*Group Policy Preferences - GPP*) históricamente permitían almacenar contraseñas de cuentas locales cifradas con una clave AES estática publicada por Microsoft en MSDN (`4e9906e8...`). Los atacantes buscan rutinariamente archivos `Groups.xml` en la carpeta `SYSVOL` para extraer el atributo `cpassword`.

### Arquitectura de la Trampa:
1. Se crea una GPO señuelo (`CN={...},CN=Policies,CN=System,DC=...`) en `SYSVOL`.
2. Se introduce un archivo `Groups.xml` conteniendo un usuario señuelo `admin_local_backup` y un valor `cpassword` cifrado con la clave conocida.
3. Se monitoriza el Event ID `4625` en todos los controladores de dominio y estaciones de trabajo: si alguien intenta iniciar sesión con la contraseña recuperada de `SYSVOL`, se identifica inmediatamente al atacante.

---

## 🩸 4. Rutas Falsas de BloodHound (*Deceptive Attack Paths*)

Los atacantes utilizan herramientas de análisis de grafos (BloodHound / SharpHound) para trazar caminos de escalada de privilegios hacia el grupo `Domain Admins`.

Podemos plantar relaciones falsas de control en Active Directory:
- Conceder permisos ficticios de escritura sobre el objeto señuelo (`GenericAll` o `WriteDacl`) a grupos no privilegiados como `Domain Users`.
- Cuando el atacante analiza el grafo, identifica el camino señuelo como la ruta de menor resistencia para comprometer el dominio. Al intentar modificar el objeto, el controlador registra el Event ID `5136` y notifica al SOC antes de que el adversario explore otras rutas.
