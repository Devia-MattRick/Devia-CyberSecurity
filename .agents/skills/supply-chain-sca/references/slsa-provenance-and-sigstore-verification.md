# Verificación de Procedencia de Compilación SLSA y Firmas Sigstore

Este documento establece la metodología de auditoría en **Devia-CyberSecurity** para evaluar la integridad y autenticidad de artefactos binarios, contenedores y dependencias utilizando **SLSA v1.0 (Supply-chain Levels for Software Artifacts)** y el ecosistema **Sigstore** (`cosign`, `rekor`, `fulcio`).

---

## 🏛️ Taxonomía y Mapeo Dimensional

- **Dimensión Canónica:** `SUPPLY_CHAIN_SCA`
- **Skill Responsable:** [`supply-chain-sca`](file:///.agents/skills/supply-chain-sca/SKILL.md)
- **Vulnerabilidades Asociadas:**
  - [`VULN-SCA-004`: Software & Data Integrity Failure in CI/CD Artifacts](file:///docs/VULNERABILITIES.md)
  - [`VULN-SCA-008`: Cascading Unpinned Remote Dependency Cloning](file:///docs/VULNERABILITIES.md)
  - [`VULN-SCA-009`: Bundling of Opaque, Unverified Pre-Compiled Binaries](file:///docs/VULNERABILITIES.md)
- **Taxonomía:** CWE-353 (Missing Support for Integrity Check), CWE-494, OWASP A08:2021/2025, MITRE T1195.002

---

## 📜 1. Niveles de Procedencia SLSA v1.0 (Build Track)

| Nivel SLSA | Requisitos de Compilación | Garantía de Seguridad | Resistencia ante Ataques |
| :--- | :--- | :--- | :--- |
| **SLSA Build L1** | Generación automatizada de procedencia básica que enumera dependencias y comandos de compilación. | Saber cómo se compiló el artefacto. | Ninguna contra manipulaciones maliciosas del compilador o runner. |
| **SLSA Build L2** | Servicio de compilación alojado (e.g. GitHub Actions, Google Cloud Build) con procedencia firmada criptográficamente. | Garantía de que la compilación ocurrió en un runner gestionado y no en la máquina local de un desarrollador. | Previene la alteración posterior del artefacto compilado. |
| **SLSA Build L3** | Plataforma de compilación aislada y hermética; parámetros no manipulables por el código del repositorio; procedencia verificada por entidad confiable. | El código fuente y las dependencias declaradas son las únicas que influyeron en la salida binaria. | Resiste ataques al runner de CI y compromisos de infraestructura de compilación. |

---

## 🔑 2. Verificación de Firmas sin Clave (Keyless Signatures) con Sigstore

Sigstore elimina la necesidad de gestionar y proteger claves privadas estáticas de larga duración mediante certificados X.509 de corta duración emitidos por **Fulcio** vinculados a identidades OIDC de GitHub Actions / GitLab, registrados en el log de transparencia inmutable **Rekor**:

```bash
# 1. Verificación de firma de contenedor Docker keyless
cosign verify \
  --certificate-identity-regexp "https://github.com/Devia-CyberSecurity/.*" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  ghcr.io/devia-cybersecurity/auditor-agent:v1.2.0

# 2. Verificación de atestación de procedencia SLSA (in-toto predicate)
cosign verify-attestation \
  --type https://slsa.dev/provenance/v1 \
  --certificate-identity "https://github.com/Devia-CyberSecurity/devia-engine/.github/workflows/release.yml@refs/tags/v1.2.0" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  ghcr.io/devia-cybersecurity/auditor-agent:v1.2.0 | jq '.payload | @base64d | fromjson'

# 3. Verificación de binarios independientes con slsa-verifier
slsa-verifier verify-artifact \
  --provenance-path build.provenance.json \
  --source-uri github.com/Devia-CyberSecurity/devia-cli \
  --source-tag v1.2.0 \
  ./dist/devia-cli-linux-amd64
```

---

## 🔍 3. Detección de Falsificaciones e Inconsistencias en Atestaciones

Al auditar la procedencia de un artefacto:

1. **Discrepancia de Digest SHA-256:**
   El digest del archivo descargado debe coincidir exactamente con el campo `subject[].digest.sha256` de la atestación in-toto. Si el hash difiere, el artefacto fue reemplazado post-compilación (*Tampered Artifact*).
2. **Commit SHA Inmutable vs Tag Mutable:**
   La procedencia confiable vincula el commit SHA inmutable (`vcs.commit = "a1b2c3..."`) y no únicamente el tag git, el cual puede ser re-apuntado por un mantenedor comprometido.
3. **Inclusión en Rekor:**
   Verificar que la marca de tiempo de la firma y el certificado estén debidamente anclados en el log de transparencia pública de Rekor para prevenir firmas retroactivas con identidades caducadas.

---

## 📋 4. Checklist de Auditoría de Procedencia (SCA)

- [ ] ¿Los artefactos binarios distribuidos incluyen su correspondiente atestación SLSA o firma cosign?
- [ ] ¿El pipeline de CI/CD utiliza identidades OIDC fijadas y restringe los permisos del token (`permissions: id-token: write`) únicamente al paso de firma?
- [ ] ¿Las políticas de Kubernetes (Admission Controllers como Kyverno o Sigstore Policy Controller) bloquean la ejecución de pods cuyas imágenes no tengan firma válida?
- [ ] ¿Se audita periódicamente la ausencia de binarios compilados opacos commiteados directamente en el repositorio de código fuente?
