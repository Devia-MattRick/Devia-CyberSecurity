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

- `references/`: Checklists de verificación de autenticación/autorización, guías de auditoría de JWT y matrices de permisos RBAC.
  - [`multitenant-and-sibling-guard-auditing.md`](references/multitenant-and-sibling-guard-auditing.md): Metodología de auditoría de diferencias de guardias entre operaciones hermanas (*sibling operations*) y aislamiento estricto multinquilino.
- `scripts/`: Herramientas de análisis de decodificación y validación de tokens JWT, escáneres de middlewares de autorización.
