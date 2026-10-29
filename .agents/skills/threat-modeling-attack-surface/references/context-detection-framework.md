# Marco Heurístico de Detección de Contexto Tecnológico y Superficie de Ataque

> **Dimensión:** `THREAT_MODELING_ATTACK_SURFACE`  
> **Taxonomía:** CWE-1059 / OWASP A04:2021  
> **Origen de Absorción:** `security-audit/SKILL.md` (Acción `ABS-001`)  
> **Vulnerabilidad Asociada:** `VULN-TM-001` (Trust Boundary Violation)  

---

## 🧭 Propósito y Principios Operativos

Antes de desplegar escáneres estáticos pesados o ejecutar análisis de amenazas en profundidad, el agente auditor debe **perfilar automáticamente el repositorio objetivo** para identificar:
1. Lenguajes y gestores de paquetes activos.
2. Tipo de arquitectura (Web SPA/SSR, API REST/GraphQL, CLI, Desktop Electron, IaC, Microservicios).
3. Frameworks subyacentes y decoradores de enrutamiento.
4. Presencia de contenedores, pipelines de CI/CD y descriptores de infraestructura.
5. Superficie expuesta de autenticación y sesiones.

Esta delimitación previa reduce el tiempo de auditoría en más de un 60%, erradica falsos positivos derivados de herramientas no aplicables y previene el sobregasto innecesario de tokens.

---

## 🔍 Heurísticas Deterministas de Perfilado

### 1. Detección de Lenguajes y Gestores de Dependencias
```bash
# Búsqueda determinista de manifiestos primarios
find . -maxdepth 2 -name "package.json" -o -name "requirements.txt" -o -name "Pipfile" \
     -o -name "pyproject.toml" -o -name "pom.xml" -o -name "build.gradle" -o -name "go.mod" \
     -o -name "Gemfile" -o -name "composer.json" -o -name "Cargo.toml" -o -name "*.csproj"
```

### 2. Detección de Arquetipos y Superficie Expuesta
| Arquetipo | Indicadores de Detección | Límites de Confianza Clave |
| :--- | :--- | :--- |
| **Web SPA / SSR** | `src/views`, `templates/`, `routes/`, Angular `routes.ts`, Next.js `app/` o `pages/` | Entradas del usuario en DOM, almacenamiento local (localStorage), cabeceras CORS/CSP. |
| **API REST / GraphQL** | OpenAPI `openapi.yaml`, GraphQL `schema.graphql`, controladores con `@Get`, `@Post`, FastAPI `@app` | Endpoints no autenticados, autorización BOLA/IDOR, deserialización de payloads. |
| **Desktop (Electron)** | `main.ts`, `preload.ts`, presencia de `electron` en `package.json` | Canales IPC (`ipcRenderer` $\to$ `ipcMain`), aislamiento de contexto (`contextIsolation`), acceso a FS. |
| **Infraestructura (IaC)** | `*.tf`, `*.tfvars`, `docker-compose.yml`, `k8s/`, Helm charts | Exposición de puertos públicos, credenciales por defecto, privilegios `root` en contenedores. |
| **Librería / SDK** | `index.ts` o `setup.py` sin entrypoints de ejecución ni servidores | Métodos públicos exportados, asunciones sobre sanitización de llamadas aguas arriba. |

### 3. Identificación Rápida de Superficie de Autenticación
Inspeccionar patrones léxicos de autenticación y tokens para mapear los entry points de identidad:
```bash
grep -rnE "(jwt|oauth|saml|session|cookie|bearer|passport|bcrypt|argon2|supabase\.auth)" \
     --include="*.ts" --include="*.py" --include="*.go" --include="*.java" src/
```

---

## 🗺️ Matriz de Activación Modular

| Contexto Detectado | Módulos Obligatorios Devia-CyberSecurity | Enfoque Específico |
| :--- | :--- | :--- |
| **Todo Objetivo** | `THREAT_MODELING_ATTACK_SURFACE`, `SOURCE_CODE_SAST`, `RESILIENCE_LOGGING_TELEMETRY` | Inventario base, trazabilidad de entradas a sumideros y compuerta de validación. |
| **Contenedores / IaC** | `+ CONFIGURATION_HARDENING` | Permisos de contenedores, capabilities de Linux, red aislada. |
| **APIs / Microservicios** | `+ IDENTITY_ACCESS_SESSION` | BOLA/IDOR, validación de schemas Zod/Pydantic, control de flujo. |
| **Dependencias Externas** | `+ SUPPLY_CHAIN_SCA` | CVEs conocidos, bloqueo estricto de lockfiles, scripts de instalación. |
| **Manejo de Credenciales** | `+ SECRETS_CRYPTOGRAPHY` | Escaneo de entropía de Shannon, algoritmos obsoletos y fugas en logs. |
| **Desktop / Multi-proceso** | `+ ARCHITECTURE_BOUNDARIES_ZERO_TRUST` | Separación de privilegios, validación tipada de IPC y fuses. |

---

## 📊 4. Cuantificación de Postura de Seguridad: Erradicación del Scoring Lineal Plano

Al perfilar y modelar el riesgo global de un repositorio objetivo, debe evitarse el antipatrón identificado en herramientas agenticas externas como Cyber Neo:

### El Antipatrón Lineal Saturante (CWE-1026)
```python
# ❌ ANTIPATRÓN: Fórmula plana lineal
risk_score = min(100, (critical * 25) + (high * 10) + (medium * 3) + (low * 1))
```
- **Defecto:** Un proyecto con 4 vulnerabilidades críticas satura inmediatamente en 100 puntos. Un proyecto masivamente comprometido con 40 vulnerabilidades críticas obtiene exactamente el mismo score (100). Esto ciega al analista y al CISO respecto a la severidad relativa y distorsiona el seguimiento histórico.

### El Estándar Devia-CyberSecurity: Modelo Multiplicativo Normalizado (SIF)
Conforme a [`docs/PROACTIVE.md`](file:///docs/PROACTIVE.md) sección 3.16, se adopta la propagación multiplicativa normalizada (0.0 a 10.0):
$$\text{node\_risk} = \text{base\_risk} \times \text{exposure\_factor} \times \text{exploitability} \times (1 - \text{control\_effectiveness}) \times \text{privilege\_amplifier}$$
- **Beneficio Operativo:** Incorpora atenuación matemática por efectividad de controles existentes, amplificación por privilegios del componente y preserva la capacidad discriminante sin saturaciones planas prematuras.

