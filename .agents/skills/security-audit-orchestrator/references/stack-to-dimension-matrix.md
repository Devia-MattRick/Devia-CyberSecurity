# Matriz de Mapeo Stack Tecnológico ↔ 8 Dimensiones Canónicas

Esta referencia técnica describe la matriz canónica de correlación entre los componentes del stack tecnológico de un repositorio objetivo y las **8 Dimensiones Canónicas de Auditoría**, sus Skills operativas, referencias técnicas especializadas y herramientas de Capa 3.

---

## 🧭 Principio de Universalidad y Límites

El marco **Devia-CyberSecurity** no inventa dimensiones nuevas cuando audita tecnologías emergentes (e.g. IA/LLM, Web3, Mobile, Cloud-Native). En su lugar, proyecta cada componente tecnológico sobre las 8 dimensiones cerradas mediante las siguientes reglas formales:

---

## 📊 Matriz Canónica de Activación por Componente de Stack

### 1. Lenguajes y Runtimes

| Lenguaje / Runtime | Dimensiones Involucradas | Skills Relevantes | Referencias Clave | Scripts Sugeridos |
| :--- | :--- | :--- | :--- | :--- |
| **JavaScript / TypeScript / Node.js** | • `SOURCE_CODE_SAST`<br>• `SUPPLY_CHAIN_SCA`<br>• `SECRETS_CRYPTOGRAPHY` | `source-code-sast`<br>`supply-chain-sca`<br>`secrets-cryptography` | • `prototype-pollution-and-property-injection.md`<br>• `package-integrity-and-patch-risk-rubric.md`<br>• `source-exposed-secrets-standard.md` | `check_lockfiles.py`<br>`scan_secrets.py`<br>`differential_exploit_verifier.py` |
| **Python (Django / FastAPI / Flask)** | • `SOURCE_CODE_SAST`<br>• `SUPPLY_CHAIN_SCA`<br>• `CONFIGURATION_HARDENING` | `source-code-sast`<br>`supply-chain-sca`<br>`configuration-hardening` | • `legacy-python-eval-injection.md`<br>• `web-framework-sast-patterns.md` | `check_lockfiles.py`<br>`scan_secrets.py`<br>`attack_vector_assessment_engine.py` |
| **Go (Golang)** | • `SOURCE_CODE_SAST`<br>• `SUPPLY_CHAIN_SCA`<br>• `RESILIENCE_LOGGING_TELEMETRY` | `source-code-sast`<br>`supply-chain-sca`<br>`resilience-logging-telemetry` | • `codeql-taint-analysis.md`<br>• `sensitive-logging-and-exception-hardening.md` | `check_lockfiles.py`<br>`target_snapshot.py` |
| **Rust** | • `SOURCE_CODE_SAST`<br>• `SUPPLY_CHAIN_SCA`<br>• `SECRETS_CRYPTOGRAPHY` | `source-code-sast`<br>`supply-chain-sca`<br>`secrets-cryptography` | • `package-integrity-and-patch-risk-rubric.md`<br>• `post-quantum-cryptography-migration.md` | `check_lockfiles.py`<br>`scan_secrets.py` |
| **Java / Kotlin (Spring Boot)** | • `SOURCE_CODE_SAST`<br>• `IDENTITY_ACCESS_SESSION`<br>• `SUPPLY_CHAIN_SCA` | `source-code-sast`<br>`identity-access-session`<br>`supply-chain-sca` | • `web-framework-sast-patterns.md`<br>• `multi-role-authz-matrix-idor.md` | `check_lockfiles.py`<br>`differential_exploit_verifier.py` |
| **C# / .NET (ASP.NET Core)** | • `SOURCE_CODE_SAST`<br>• `IDENTITY_ACCESS_SESSION`<br>• `CONFIGURATION_HARDENING` | `source-code-sast`<br>`identity-access-session`<br>`configuration-hardening` | • `web-framework-sast-patterns.md`<br>• `windows-defender-asr-and-exploit-protection.md` | `endpoint_hardening_auditor.py`<br>`scan_secrets.py` |
| **PHP (Laravel / Symfony / WordPress)** | • `SOURCE_CODE_SAST`<br>• `SECRETS_CRYPTOGRAPHY` | `source-code-sast`<br>`secrets-cryptography` | • `web-framework-sast-patterns.md`<br>• `source-exposed-secrets-standard.md` | `differential_exploit_verifier.py`<br>`scan_secrets.py` |
| **Solidity / EVM Smart Contracts** | • `SOURCE_CODE_SAST`<br>• `IDENTITY_ACCESS_SESSION` | `source-code-sast`<br>`identity-access-session` | • `smart-contract-evm-audit-checklist.md` | `attack_vector_assessment_engine.py` |

---

### 2. Frameworks Frontend y Web

| Framework | Dimensiones Involucradas | Referencias Clave | Vectores Principales (`VULN-*`) |
| :--- | :--- | :--- | :--- |
| **Angular (SPA / SSR)** | • `SOURCE_CODE_SAST`<br>• `ARCHITECTURE_BOUNDARIES_ZERO_TRUST` | • `angular-spa-ssr-hydration-security.md`<br>• `subresource-integrity-and-mixed-content.md` | `VULN-SAST-016` (DomSanitizer bypass, TransferState SSR collision) |
| **React / Next.js** | • `SOURCE_CODE_SAST`<br>• `CONFIGURATION_HARDENING` | • `web-framework-sast-patterns.md`<br>• `prototype-pollution-and-property-injection.md` | `VULN-SAST-018` (Server Actions exposure, Prototype pollution) |
| **Vue.js / Nuxt** | • `SOURCE_CODE_SAST` | • `web-framework-sast-patterns.md` | `VULN-SAST-016` (`v-html` injections) |
| **Electron Desktop** | • `ARCHITECTURE_BOUNDARIES_ZERO_TRUST`<br>• `CONFIGURATION_HARDENING` | • `electron-ipc-hardening.md` | `VULN-ARCH-008` (contextIsolation: false, nodeIntegration: true) |

---

### 3. Autenticación, Sesión y Autorización

| Mecanismo | Dimensión | Skill | Referencias Clave |
| :--- | :--- | :--- | :--- |
| **JWT / Bearer Tokens** | `IDENTITY_ACCESS_SESSION` | `identity-access-session` | • `stateless-cookie-session-generation-revocation.md`<br>• `multi-role-authz-matrix-idor.md` |
| **OAuth 2.0 / OIDC** | `IDENTITY_ACCESS_SESSION` | `identity-access-session` | • `workload-identity-federation-oidc.md` |
| **Active Directory / LDAP / Kerberos** | `IDENTITY_ACCESS_SESSION` | `identity-access-session` | • `active-directory-tiered-model-esae.md`<br>• `entra-id-and-shadow-credentials-audit.md` |
| **Passkeys / WebAuthn** | `IDENTITY_ACCESS_SESSION` | `identity-access-session` | • `passkey-webauthn-security-guide.md` |
| **PostgreSQL RLS / Multi-tenant** | `IDENTITY_ACCESS_SESSION` | `identity-access-session` | • `rls-deep-audit-guide.md`<br>• `multitenant-and-sibling-guard-auditing.md` |

---

### 4. Inteligencia Artificial, LLMs y Sistemas Agénticos

| Vector Tecnológico | Dimensión | Referencias Clave | Scripts Sugeridos |
| :--- | :--- | :--- | :--- |
| **Model Context Protocol (MCP)** | • `ARCHITECTURE_BOUNDARIES_ZERO_TRUST`<br>• `THREAT_MODELING_ATTACK_SURFACE` | • `agentic-system-security-mcp.md`<br>• `mcp-tool-poisoning-and-rug-pull-defense.md` | `mcp_tool_poisoning_scanner.py` (`VULN-ARCH-011`) |
| **Agentes Autónomos & Tool Calling** | • `ARCHITECTURE_BOUNDARIES_ZERO_TRUST` | • `openclaw-sentinel-agent-defense.md`<br>• `llm-guardrails-and-semantic-boundaries.md` | `prompt_injection_detector.py` (`VULN-TM-004`) |
| **RAG & Memorias Persistentes** | • `THREAT_MODELING_ATTACK_SURFACE` | • `mitre-atlas-agent-evaluation.md`<br>• `llm-chain-ast-and-context-summarization.md` | `risk_assessment_engine.py` |

---

### 5. Infraestructura, Contenedores y CI/CD

| Componente | Dimensión | Referencias Clave | Scripts Sugeridos |
| :--- | :--- | :--- | :--- |
| **Docker / Podman** | `CONFIGURATION_HARDENING` | • `docker-container-hardening.md`<br>• `docker-sandbox-daemon-isolation-and-opa-probe.md` | `endpoint_hardening_auditor.py` |
| **Kubernetes (K8s)** | `CONFIGURATION_HARDENING` | • `container-runtime-threats-and-falco-hardening.md` | `endpoint_hardening_auditor.py` |
| **GitHub Actions / GitLab CI** | `ARCHITECTURE_BOUNDARIES_ZERO_TRUST` | • `ci-cd-agentic-security-boundaries.md` | `hard_exclusions.py` |
| **Terraform / IaC** | `CONFIGURATION_HARDENING` | • `cloud-cis-benchmarks-and-iac-hardening.md` | `endpoint_hardening_auditor.py` |
| **Nginx / Proxies Inversos** | `CONFIGURATION_HARDENING` | • `web-infrastructure-audit-matrix.md`<br>• `tls-1-3-and-cipher-hardening.md` | `url_validator.py` |

