# Protocolo de Auditoría Forense de Grado Militar y Estándar de Gating

Este documento establece el **Protocolo Operativo de Grado Militar** para la ejecución de auditorías de ciberseguridad sobre repositorios externos en **Devia-CyberSecurity**. Define las reglas inmutables de transición de fases, los criterios de pausa estratégica (*Strategic Gating*), los estándares de cálculo de puntuación (Score 0-100) y las directivas de evidencia determinista.

---

## 🏛️ Las 5 Leyes Inmutables de la Auditoría Militar

1. **Soberanía y Cero Ejecución Hostil:**  
   El repositorio auditado se trata como dato no confiable (*untrusted data*). Queda estrictamente prohibido ejecutar scripts de construcción, tests o scripts de ciclo de vida (`npm install`, `setup.py`, `cargo build`, migraciones de DB) en la máquina anfitriona sin aislamiento o autorización expresa.
2. **Exhaustividad Determinista:**  
   Ningún componente, subdirectorio, script o archivo de configuración queda excluido sin una justificación registrada formalmente en `coverage.json`.
3. **Gating Estratégico Obligatorio:**  
   El avance a través de las 4 fases de auditoría exige una pausa explícita con informe de situación (*SitRep*) y confirmación del operador humano. Prohibido ejecutar un pipeline monolítico sin puntos de control.
4. **Evidencia Inmutable en Siete Roles Semánticos:**  
   Todo hallazgo SAST debe demostrarse empíricamente trazando la cadena de custodia del dato:
   $$\text{user\_input} \longrightarrow \text{entrypoint} \longrightarrow \text{propagation} \longrightarrow \text{root\_control} \longrightarrow \text{sink} \longrightarrow \text{outcome} \quad [\text{vs } \text{expected\_control}]$$
5. **Contract-First y Cero Falsos Positivos Obvios:**  
   Cada reporte debe validar contra `AuditReportSchema` (`src/schemas/report.schema.ts`). Cualquier afirmación debe sustentarse en código verificado (`CONFIRMED` o `HIGH`), descartando especulaciones no reproducibles.

---

## 🛑 Plantillas Canónicas de Pausa Estratégica (Strategic Gating)

El agente debe emitir exactamente estas plantillas al finalizar cada fase antes de solicitar autorización para continuar:

### Pausa 1: Conclusión de Fase 1 (Reconocimiento y Mapeo)
```markdown
### 🛑 SITREP FASE 1: Reconocimiento de Stack y Mapeo Dimensional
- 🎯 **Objetivo:** `<Ruta / Nombre del Repositorio>`
- 🔢 **Archivos Totales Inspeccionados:** `<N>` archivos
- 💻 **Stack Tecnológico Identificado:**
  - **Lenguajes:** `[TypeScript, Python, etc.]`
  - **Frameworks:** `[Express, FastAPI, etc.]`
  - **Bases de Datos & ORM:** `[PostgreSQL, Prisma, etc.]`
  - **Autenticación & Sesión:** `[JWT, Cookies HTTP-Only, etc.]`
  - **Infraestructura & CI/CD:** `[Docker, GitHub Actions, etc.]`
- 🛡️ **Dimensiones & Skills Activadas:**
  - `[DIMENSIÓN]` $\to$ `Skill: <nombre-skill>`
- ⚙️ **Herramientas de Capa 3 Preparadas:** `<script_1.py>`, `<script_2.py>`
- 📚 **Referencias Técnicas Relevantes:** `<referencia_1.md>`, `<referencia_2.md>`

❓ **Confirmación Requerida:** ¿Deseas validar este alcance y autorizar el paso a la **Fase 2: Lectura e Ingesta Recursiva de Conocimiento**?
```

### Pausa 2: Conclusión de Fase 2 (Ingesta de Conocimiento)
```markdown
### 🛑 SITREP FASE 2: Ingesta Recursiva y Calibración Heurística
- 📚 **Skills y Referencias Asimiladas:** `<N>` documentos técnicos leídos en profundidad.
- 🎯 **Vectores de Amenaza Priorizados:** `[VULN-SAST-001, VULN-CRYP-001, VULN-SCA-001, ...]`
- 🔍 **Sumideros y Puntos de Inyección Calibrados:**
  - Sumideros SQL / NoSQL identificados para el ORM en uso.
  - Endpoints de autenticación y middlewares de control de acceso.
  - Archivos de configuración y variables de entorno a inspeccionar.

❓ **Confirmación Requerida:** Todo el conocimiento específico del stack ha sido calibrado. ¿Autorizas el inicio de la **Fase 3: Auditoría Forense Exhaustiva Línea por Línea**?
```

### Pausa 3: Conclusión de Fase 3 (Auditoría Forense)
```markdown
### 🛑 SITREP FASE 3: Conclusión de Auditoría Forense
- 📊 **Cobertura Alcanzada:** `<N>` archivos auditados (100% de la superficie objetivo).
- 🚨 **Hallazgos Preliminares Detectados:**
  - 🔴 **Críticos:** `<C>`
  - 🟠 **Altos:** `<H>`
  - 🟡 **Medios:** `<M>`
  - 🔵 **Bajos / Informativos:** `<L>`
- ⚡ **Áreas de Mayor Riesgo:** `<Módulo A>`, `<Controlador B>`, `<Configuración C>`

❓ **Confirmación Requerida:** Se han extraído todas las evidencias y trazas de taint. ¿Deseas consolidar el informe final en la **Fase 4: Generación de Informe, Score y Remediación**?
```

---

## 🧮 Cálculo Matemático del Devia Security Health Score (0 - 100)

El reporte final incluye un índice cuantitativo determinista de la salud de seguridad del repositorio auditado:

$$\text{HealthScore} = \max\left(0, 100 - \sum_{i} \left( W_{\text{sev}(i)} \times C_{\text{conf}(i)} \right)\right)$$

### Ponderación de Severidad ($W_{\text{sev}}$)
- **CRITICAL:** 25 puntos por vulnerabilidad.
- **HIGH:** 15 puntos por vulnerabilidad.
- **MEDIUM:** 5 puntos por vulnerabilidad.
- **LOW:** 1 punto por vulnerabilidad.
- **INFORMATIONAL:** 0 puntos (no penaliza el score).

### Factor de Confianza ($C_{\text{conf}}$)
- **CONFIRMED (Confirmada empíricamente con PoC o traza directa):** $1.0$
- **HIGH (Alta probabilidad / sink sin sanitizador comprobado):** $0.9$
- **MEDIUM (Condición teórica dependiente de entorno):** $0.6$
- **LOW:** $0.3$

### Escala de Calificación de Postura
| Rango de Score | Postura / Estado | Significado Operativo |
| :--- | :--- | :--- |
| **90 – 100** | 🟢 **Excelente (Hardened)** | Código con controles maduros, sin vulnerabilidades críticas ni altas. |
| **75 – 89** | 🟡 **Buena / Aceptable** | Riesgo bajo; hallazgos medios corregibles sin compromiso sistémico. |
| **50 – 74** | 🟠 **Comprometida (Moderate Risk)** | Presencia de fallos graves (Auth, Inyecciones, Fugas de secretos). |
| **0 – 49** | 🔴 **Crítica (Insecure / Breached)** | Múltiples fallos críticos explotables; riesgo inminente de compromiso total. |

---

## 📋 Estructura Estándar del Informe Final (Fase 4)

Todo informe producido debe respetar el siguiente formato canónico:

1. **Encabezado Ejecutivo:**
   - Nombre del Proyecto y Ruta.
   - Fecha y Hora UTC.
   - **Devia Security Health Score:** `<Score>/100` (`[Excelente | Buena | Comprometida | Crítica]`).
   - Resumen ejecutivo de la postura.
2. **Tabla Maestra de Hallazgos:**
   - ID (`VULN-*`), CWE, OWASP, Severidad, Archivo:Línea, Estado.
3. **Fichas Técnicas por Vulnerabilidad:**
   - Mecanismo de fallo.
   - Evidencia de código (7 roles semánticos).
   - Bloque comparativo: **Código Vulnerable vs Código Bastionado**.
4. **Hoja de Ruta de Mitigación (Actionable Roadmap):**
   - **Hotfixes Inmediatos (< 24 horas):** Parches para hallazgos Críticos y Altos.
   - **Corto Plazo (< 7 días):** Endurecimiento de dependencias y configuraciones.
   - **Medio / Largo Plazo (< 30 días):** Mejoras de arquitectura y Zero Trust.

