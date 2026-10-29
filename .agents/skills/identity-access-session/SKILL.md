---
name: identity-access-session
description: Auditoría de mecanismos de autenticación, control de acceso y autorización (RBAC, ABAC), prevención de escalada de privilegios (vertical/horizontal, IDOR/BOLA) y gestión segura del ciclo de vida de sesiones y tokens (JWT, OAuth, cookies).
---

# Identity, Access & Session Control

**Dimensión Canónica:** `IDENTITY_ACCESS_SESSION` (Dimensión 4)

---

## 🎯 Objetivo Delegado y Asignado

Esta Skill gobierna la dimensión de **Control de Identidad, Acceso y Sesiones**. Su responsabilidad primordial es:
1. Auditar los esquemas de autenticación del sistema (OAuth2, OpenID Connect, SAML, autenticación basada en contraseñas o claves API).
2. Evaluar mecanismos de autorización y control de acceso: Role-Based Access Control (RBAC), Attribute-Based Access Control (ABAC) y políticas de menor privilegio.
3. Detectar vectores de escalada de privilegios vertical (usuario raso a administrador) y horizontal (acceso a recursos de otros usuarios mediante Insecure Direct Object References - IDOR / BOLA).
4. Analizar la seguridad en el manejo de tokens y sesiones: validación de firmas JWT (algoritmo `none`, manipulación de claims, verificación de `exp`/`nbf`), rotación de refresh tokens y revocación efectiva.
5. Auditar el almacenamiento de credenciales y sesiones en clientes (cookies con atributos `HttpOnly`, `Secure`, `SameSite=Strict` frente a almacenamiento en `localStorage`/`sessionStorage`).

---

## 📂 Organización Interna

- `references/`: Checklists de verificación de autenticación/autorización, guías de auditoría de JWT y matrices de permisos RBAC (13 referencias técnicas).
  - [`phishing-resistant-mfa-and-fatigue-defense.md`](references/phishing-resistant-mfa-and-fatigue-defense.md): Evaluación de robustez MFA, detección de ataques de fatiga (prompt bombing) y principio obligatorio de fallo cerrado (`VULN-IAM-014`).
  - [`active-directory-tiered-model-esae.md`](references/active-directory-tiered-model-esae.md): Partición de privilegios Active Directory (ESAE Tier 0/1/2) y directivas autoritativas para Privileged Access Workstations (PAWs).
  - [`multitenant-and-sibling-guard-auditing.md`](references/multitenant-and-sibling-guard-auditing.md): Metodología de auditoría de diferencias de guardias entre operaciones hermanas (*sibling operations*) y aislamiento estricto multinquilino.
  - [`rls-deep-audit-guide.md`](references/rls-deep-audit-guide.md): Auditoría profunda de políticas Row-Level Security (RLS) y optimización InitPlan $O(1)$.
  - [`role-mining-and-entitlement-optimization.md`](references/role-mining-and-entitlement-optimization.md): Minería algorítmica de roles, detección de explosión de roles y optimización RBAC.

---

## 🛠️ Herramientas de Capa 3 Asignadas (`src/scripts/`)

Esta Skill consume y orquesta los siguientes motores de análisis determinista en Python 3.11+:

| Script Ejecutable | Contrato Zod (Capa 2) | Rol y Capacidades | Test Unitario |
| :--- | :--- | :--- | :--- |
| [`src/scripts/role_mining_analyzer.py`](file:///k:/Devia-CyberSecurity/src/scripts/role_mining_analyzer.py) | [`role-mining.schema.ts`](file:///k:/Devia-CyberSecurity/src/schemas/role-mining.schema.ts) | Minería algorítmica determinista de roles RBAC, detección de explosión de roles y privilegios excesivos. | [`test_role_mining_analyzer.py`](file:///k:/Devia-CyberSecurity/src/scripts/test_role_mining_analyzer.py) |

