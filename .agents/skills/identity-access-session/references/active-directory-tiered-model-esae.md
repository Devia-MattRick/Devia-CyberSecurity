# Modelo de Administración Escalonada de Active Directory (ESAE Tier 0/1/2) y Arquitectura PAW

Esta referencia técnica describe el diseño, la partición de privilegios y las heurísticas de auditoría para el modelo **ESAE (Enhanced Security Admin Environment)** y **Privileged Access Workstations (PAWs)** en **Devia-CyberSecurity**.

---

## 🏛️ 1. Arquitectura de las Tres Capas Administrativas (Tier 0 / Tier 1 / Tier 2)

El modelo de administración escalonada previene el movimiento lateral y el robo de credenciales de alto privilegio (Pass-the-Hash, Kerberoasting, Golden Tickets) al impedir que credenciales de mayor nivel se autentiquen o dejen material de sesión en equipos de menor nivel:

```
[ Tier 0: Identidad y Control de Dominio ]
   - Domain Controllers, PKI/CA, ADFS, Entra Connect, Tier 0 Admins.
   - Administración exclusiva desde: PAW Tier 0.
        │ (Prohibido logon a Tier 1 o Tier 2)
        ▼
[ Tier 1: Cargas de Trabajo y Servidores ]
   - Servidores miembros, bases de datos empresariales, clústeres Hyper-V/ESXi.
   - Administración exclusiva desde: PAW Tier 1.
        │ (Prohibido logon a Tier 2)
        ▼
[ Tier 2: Estaciones de Trabajo y Usuarios ]
   - Laptops corporativas, puestos de trabajo de usuario, Help Desk.
   - Administrado por: Cuentas de Help Desk / Workstation Admins locales.
```

---

## 🚫 2. Reglas Inmutables de Separación de Niveles

1. **Cuentas Dedicadas por Nivel:**  
   Un administrador nunca debe usar la misma cuenta para tareas de diferentes niveles. Un operador debe tener:
   - `admin.t0.nombre` para controladores de dominio.
   - `admin.t1.nombre` para administración de servidores.
   - `nombre` para correo electrónico, navegación web y trabajo de oficina.
2. **Denegación de Derechos de Inicio de Sesión (Logon Rights Restrictions):**  
   Configurar directivas GPO para forzar:
   - *Deny log on locally*, *Deny log on through Remote Desktop Services*, y *Deny log on as a batch job* para cuentas Tier 0 en todos los equipos Tier 1 y Tier 2.
3. **Cuentas Protegidas y Silos de Directivas de Autenticación:**  
   Incorporar cuentas Tier 0 en el grupo global `Protected Users`, deshabilitando autenticación NTLM, cifrado débil RC4 en Kerberos y delegación no restringida.

---

## 💻 3. Requisitos Autoritativos de PAWs vs Antipatrones Heurísticos

> [!WARNING]
> Comprobar el cumplimiento de PAW basándose únicamente en prefijos de nombre de equipo (`cn=PAW*`) constituye una heurística frágil (`VULN-ARCH-025`) que induce a falsos certificados de seguridad.

### Verificación Concluyente de PAW:
Una estación de trabajo solo es una PAW certificada si cumple empíricamente con:
1. **Pertenencia a Unidad Organizativa (OU) dedicada y aislada**, con herencia de GPO bloqueada hacia directivas generales.
2. **Arranque Seguro (Secure Boot) y Attestación TPM 2.0 activa**.
3. **Virtualization-Based Security (VBS)** y **Credential Guard** activos (`LsaCfgFlags = 1`), impidiendo el volcado de memoria de LSASS incluso por administradores locales.
4. **Acceso a Internet restringido o bloqueado**: navegación web y correo electrónico prohibidos en la estación física de administración.
