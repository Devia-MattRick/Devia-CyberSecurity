# Auditoría de Identidad en la Nube y Escalada de Privilegios en Microsoft Entra ID

Este documento describe la metodología de auditoría en **Devia-CyberSecurity** para evaluar superficies de ataque, relaciones de pertenencia ocultas y vectores de escalada de privilegios en **Microsoft Entra ID (Azure AD)**, entornos híbridos y el abuso de **Shadow Credentials** mediante herramientas forenses como **ROADtools** y **ROADtx**.

---

## 🏛️ Taxonomía y Mapeo Dimensional

- **Dimensión Canónica:** `IDENTITY_ACCESS_SESSION`
- **Skill Responsable:** [`identity-access-session`](file:///.agents/skills/identity-access-session/SKILL.md)
- **Vulnerabilidades Asociadas:**
  - [`VULN-IAM-001`: Broken Object Level Authorization (IDOR / BOLA)](file:///docs/VULNERABILITIES.md)
  - [`VULN-IAM-003`: Missing Function Level Access Control](file:///docs/VULNERABILITIES.md)
  - [`VULN-IAM-007`: Missing Entry Point Authentication](file:///docs/VULNERABILITIES.md)
- **Taxonomía:** CWE-285 (Improper Authorization), CWE-269 (Improper Privilege Management), OWASP A01:2021/2025, MITRE T1078.004 / T1484.002

---

## 🌐 1. Reconstrucción y Análisis del Grafo de Identidades con ROADtools

Las interfaces web estándar ocultan relaciones transitivas complejas entre usuarios, grupos dinámicos, service principals y asignaciones de roles de Azure RBAC. El volcado forense de la base de datos de Entra ID permite auditar estas rutas de ataque:

```bash
# 1. Autenticación y volcado de la estructura del tenant en una base SQLite local
roadrecon auth --username auditor@corp.onmicrosoft.com --password "$AUDITOR_PASS"
roadrecon gather

# 2. Análisis gráfico de rutas de escalada en la interfaz local
roadrecon gui --port 8080
```

### Consultas SQL Forenses de Alto Valor sobre `roadrecon.db`:
```sql
-- Identificar Service Principals con roles privilegiados asignados (Global Admin, Privileged Role Admin)
SELECT sp.displayName, sp.appId, r.displayName AS roleName
FROM ServicePrincipals sp
JOIN DirectoryRoles r ON sp.id = r.memberId
WHERE r.displayName IN ('Global Administrator', 'Privileged Role Administrator', 'Application Administrator');

-- Identificar usuarios que son propietarios (Owners) de aplicaciones con permisos de Microsoft Graph de alto impacto (AppRoleAssignment: RoleManagement.ReadWrite.Directory)
SELECT u.userPrincipalName, a.displayName AS applicationName
FROM Users u
JOIN ApplicationOwners ao ON u.id = ao.userId
JOIN Applications a ON ao.applicationId = a.id;
```

---

## ⚡ 2. Vectores Críticos de Escalada en Entra ID

### A. Abuso de Tokens PRT (Primary Refresh Token)
El Primary Refresh Token es emitido por Entra ID a dispositivos unidos a Azure AD (Azure AD Joined o Hybrid Joined). Permite inicio de sesión único (SSO):
- **Vía de Abuso:** Si un endpoint cliente es comprometido, un atacante local con privilegios de usuario estándar puede solicitar tokens de acceso para cualquier recurso federado mediante el agente SSO de Windows (`ROADtx` / `browser-prt`), saltándose las restricciones de MFA y políticas de acceso condicional no basadas en cumplimiento estricto.

### B. Ataque de Shadow Credentials (`msDS-KeyCredentialLink`)
En entornos híbridos sincronizados con Azure AD Connect o Active Directory on-premise:
- **Mecanismo:** Si un atacante compromete una cuenta con permisos `GenericWrite` o `WriteProperty` sobre un objeto de usuario o equipo objetivo, puede inyectar una clave pública RSA alternativa en el atributo `msDS-KeyCredentialLink` del objeto.
- **Impacto:** Permite autenticarse como dicho usuario o controlador de dominio solicitando un ticket TGT de Kerberos mediante PKINIT sin alterar la contraseña del usuario ni generar alertas de reseteo de credenciales.

---

## 🛡️ 3. Controles Defensivos y Hardening

1. **Restricción de Consentimiento de Aplicaciones:**
   Desactivar el consentimiento de usuarios para aplicaciones no verificadas. Todas las solicitudes de permisos de Graph API que involucren lectura/escritura en el directorio deben requerir aprobación explícita de un Administrador de Roles Privilegiados.
2. **Protección de Dispositivos y PRT:**
   Exigir hardware TPM 2.0 para el anclaje criptográfico de claves PRT (*TPM-bound PRT*). Un PRT vinculado a hardware no puede ser extraído ni utilizado fuera del chip TPM de ese equipo físico.
3. **Auditoría Continua de `msDS-KeyCredentialLink`:**
   Monitorizar eventos de modificación en Active Directory (Event ID 5136) que apunten al atributo `msDS-KeyCredentialLink`. Cualquier adición fuera del proceso formal de aprovisionamiento de Windows Hello for Business debe ser tratada como un incidente de severidad CRITICAL.
