# Guía de Auditoría de Seguridad para Workload Identity Federation (OIDC)

Este documento establece los principios de arquitectura, fronteras de confianza y directivas de auditoría para la eliminación de credenciales permanentes de nube en pipelines CI/CD mediante **Federación de Identidad OIDC (OpenID Connect)** dentro de **Devia-CyberSecurity**.

---

## 🏛️ 1. Fronteras de Confianza en OIDC Workload Federation

En lugar de almacenar credenciales de nube permanentes (e.g. `AWS_ACCESS_KEY_ID`, `GCP_SA_KEY`) dentro de los secretos de GitHub Actions, GitLab CI o runners de CI/CD, la plataforma de integración emite un token JWT firmado (OIDC token) que se presenta ante el proveedor cloud para obtener credenciales temporales efímeras:

```
[CI/CD Runner] ──(1. Solicita Token OIDC)──> [Proveedor CI OIDC (GitHub/GitLab)]
     │                                                    │
     │ <──(2. Retorna JWT OIDC firmado con claims)────────┘
     │
     └──(3. Presenta JWT + Rol Deseado)──> [Cloud Provider STS (AWS/GCP/Azure)]
                                                  │ (Valida emisor, audiencia y política de confianza)
     <──(4. Retorna Credenciales Efímeras)────────┘
```

> [!CRITICAL]
> **Axioma de Separación de Políticas:**  
> La validación de que un token proviene de un emisor de confianza (`iss`) NO autoriza automáticamente el acceso a producción. Deben configurarse y auditarse dos directivas independientes:
> 1. **Trust Policy (Directiva de Confianza):** Define *qué cargas de trabajo externas específicas* tienen autorización para intercambiar su token por credenciales.
> 2. **Permissions Policy (Directiva de Permisos):** Define *qué recursos y acciones exactas* dentro de la nube pueden ser ejercidas por esas credenciales.

---

## 🛡️ 2. Reglas Maestras de Auditoría y Bastionado

### 2.1. Restricción Estricta del Sujeto (`sub`) y Audiencia (`aud`)
- **Vulnerabilidad de Multitenencia Compartida:** Confiar únicamente en el emisor de GitHub (`https://token.actions.githubusercontent.com`) sin filtrar el sujeto (`sub`) permite que cualquier usuario o repositorio en GitHub asuma el rol en la cuenta de nube de la víctima.
- **La Regla Operativa:**  
  La directiva de confianza de la nube debe exigir coincidencia exacta en:
  1. `iss`: `https://token.actions.githubusercontent.com`
  2. `aud`: La audiencia esperada por el proveedor (e.g. `sts.amazonaws.com` o la entidad de federation pool).
  3. `sub`: Debe anclarse al repositorio, rama y entorno exactos:  
     `repo:org-name/repo-name:environment:production` o `repo:org-name/repo-name:ref:refs/heads/main`.
  4. **Prohibición de Comodines Amplios:** Queda terminantemente prohibido utilizar wildcards como `repo:org-name/*:*` o `sub: *` en roles con permisos de producción.

### 2.2. Uso de Identificadores Inmutables de Repositorio
- **Riesgo de Renombrado / Secuestro de Nombres:** Si la política de confianza se basa exclusivamente en nombres en texto plano (`repo:org/repo`), y una organización cambia de nombre o elimina el repositorio, un atacante que registre el nombre anterior puede heredar el acceso federado.
- **Patrón Seguro:** Emplear identificadores inmutables suministrados por el proveedor de CI (`repository_id`, `repository_owner_id`) como condiciones de validación en la directiva de confianza.

### 2.3. Segregación entre Ramas y Entornos de Ejecución
- Los flujos de despliegue a producción deben estar estrictamente acotados a ramas protegidas (`main`, `release/*`) o entornos protegidos con aprobaciones manuales (*Environment Protection Rules*).
- **Aislamiento de Pull Requests:** Los flujos activados por eventos `pull_request` (código no confiable de contribuidores o forks) jamás deben tener permiso para solicitar tokens OIDC con acceso a roles de infraestructura productiva (`id-token: write` no debe asignarse a jobs que ejecutan código de PRs externas).

### 2.4. Duración Mínima de Credenciales y Procedimientos de Revocación
- **Tiempo de Vida Efímero:** Solicitar siempre la duración de sesión más corta soportada que permita completar el job (típicamente 15 a 60 minutos). Prohibido solicitar tokens con tiempos de vida de 12 horas para tareas de build cortas.
- **Revocación de Sesiones Activas:** La eliminación de la relación de confianza (trust policy) no revoca automáticamente las credenciales temporales ya emitidas. En caso de incidente de seguridad, se debe invocar explícitamente la API de revocación de sesiones del proveedor cloud (e.g. `aws iam put-role-policy` con condición `aws:CurrentTime < RevokeTime`).

---

## 🔍 Checklist de Verificación para CI/CD y Cloud IAM

- [ ] ¿Se eliminaron todos los secretos estáticos de larga duración de la configuración del repositorio (`AWS_SECRET_ACCESS_KEY`, etc.)?
- [ ] ¿El permiso `id-token: write` está configurado a nivel de job específico y no de forma global en todo el workflow?
- [ ] ¿La directiva de confianza (Trust Policy) exige explícitamente el emisor (`iss`), la audiencia (`aud`) y el sujeto (`sub`) exactos?
- [ ] ¿Se previene la ejecución de jobs federados en eventos de pull requests no confiables (`pull_request_target` o PRs externas)?
- [ ] ¿El rol cloud aplica el principio de menor privilegio, separando identidades de lectura/despliegue de identidades de administración?
- [ ] ¿Están habilitados los logs de auditoría en la nube (AWS CloudTrail, GCP Cloud Audit Logs) para trazar cada intercambio OIDC hacia el commit SHA y actor del CI?
