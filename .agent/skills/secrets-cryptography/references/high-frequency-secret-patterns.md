# Catálogo de Expresiones Regulares de Alta Frecuencia para Detección de Secretos

> **Dimensión:** `SECRETS_CRYPTOGRAPHY`  
> **Taxonomía:** CWE-798 / CWE-312 / OWASP A02:2021  
> **Origen de Absorción:** `security-audit/Cybersecurity-Audit/references/CATALOGO_VECTORES.md` (Acción `ABS-008`)  
> **Vulnerabilidad Asociada:** `VULN-CRYP-001` (Hardcoded Secrets & Source-Exposed API Keys)  

---

## 🧭 Criterios de Detección y Reducción de Falsos Positivos

El escaneo de secretos por expresiones regulares genera habitualmente falsos positivos causados por:
1. Claves públicas por diseño (e.g., Supabase Anon Key en clientes frontend donde RLS protege los datos).
2. Tokens estándar de prueba en specs y suites de testing (e.g. JWT estándar de `jwt.io` con payload `sub: "1234567890"`).
3. Nombres de funciones o variables que contienen la palabra `secret` o `password` pero no asignan valores literales.

*Directiva Canónica de Devia-CyberSecurity:*
> [!IMPORTANT]
> Todo escaneo debe combinar **coincidencia de patrones regex específicos de proveedor** con el **cálculo de entropía de Shannon ($\ge 4.5$ bits/carácter para cadenas Base64/Hex)** y verificar que la ruta no pertenezca a la allowlist de tokens públicos por diseño.

---

## 📋 Catálogo Maestro de Patrones Regex Calibrados

| Familia de Secreto | Patrón Regex Optimizado | Severidad | Comentario / Exclusiones |
| :--- | :--- | :---: | :--- |
| **AWS Access Key ID** | `\b(AKIA[0-9A-Z]{16})\b` | **CRITICAL** | Identificador estándar de cuenta IAM de AWS. |
| **GitHub Personal Access Token** | `\b(ghp_[A-Za-z0-9]{36})\b` o `\b(github_pat_[A-Za-z0-9]{22}_[A-Za-z0-9]{59})\b` | **CRITICAL** | Tokens clásicos y fine-grained de GitHub. |
| **Google Cloud API Key** | `\b(AIza[0-9A-Za-z\-_]{35})\b` | **HIGH** | Clave de API de GCP/Firebase. |
| **Cadena de Conexión PostgreSQL** | `postgres(?:ql)?:\/\/[^:]+:[^@]+@[^\/]+\/\S+` | **CRITICAL** | Cadena con usuario, password y host de DB. |
| **JSON Web Token (JWT)** | `\beyJ[A-Za-z0-9\-_]+\.eyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_.+/=]*\b` | **HIGH** | Discriminar Supabase anon key pública (`eyJ...iss: supabase`). |
| **Claves Privadas (RSA/EC/SSH)** | `-----BEGIN (RSA\|EC\|OPENSSH\|PRIVATE) KEY-----` | **CRITICAL** | Bloques de certificados y llaves privadas en código. |
| **Stripe Live Secret Key** | `\b(sk_live_[A-Za-z0-9]{24,})\b` | **CRITICAL** | Claves secretas de pasarelas de pago de producción. |
| **Stripe Webhook Secret** | `\b(whsec_[A-Za-z0-9]{32,})\b` | **HIGH** | Clave para validación HMAC de webhooks. |
| **Slack / Discord Bot Token** | `\b(xox[baprs]-[0-9A-Za-z]{10,48})\b` | **CRITICAL** | Tokens de integración de mensajería empresarial. |
| **Asignación de Password Hardcodeada** | `(?i)(password\|passwd\|pwd)[\s]*[=:]\s*['"][^'"]{8,}['"]` | **HIGH** | Excluir fixtures de pruebas unitarias (`dummy-password`). |

---

## 🛡️ Protocolo ante Identificación de un Secreto

1. **Nunca Probar la Clave en Remoto:** Queda estrictamente prohibido realizar peticiones HTTP hacia APIs de proveedores (AWS, Stripe, GitHub) para "verificar si está activa".
2. **Cálculo de Entropía:** Validar la cadena con Shannon Entropy para confirmar aleatoriedad real.
3. **Redacción Factual:** En los reportes de auditoría, anonimizar el secreto exponiendo únicamente los primeros 4 y últimos 4 caracteres (e.g. `AKIA************1234`).
4. **Remediación:** Rotación inmediata del secreto en la consola del proveedor e invalidación en el historial git mediante `git-filter-repo` o BFG Repo-Cleaner.
