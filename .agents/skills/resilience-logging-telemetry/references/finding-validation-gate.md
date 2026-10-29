# Protocolo de Validación de Hallazgos: 7-Question Gate & Exploit Chaining

> **Dimensión:** `RESILIENCE_LOGGING_TELEMETRY`  
> **Taxonomía:** CWE-754 / CWE-391 / OWASP A09:2021  
> **Origen de Absorción:** `security-audit/cybersecurity-engineer/references/finding-validation-gate.md` (Acción `ABS-002`)  
> **Vulnerabilidad Asociada:** `VULN-RESI-003` (Silent Fail-Open & Interrupted Scan Inconclusiveness)  

---

## 🏛️ Propósito y Filosofía Defensiva

El valor de una auditoría de seguridad reside en la **certeza de su evidencia y la demostración factual de impacto**. Los escáneres estáticos y análisis ingenuos producen un alto volumen de hallazgos teóricos ("falta validación", "cabecera ausente", "podría ser explotable") que saturan los equipos de desarrollo y restan credibilidad a la auditoría.

Este protocolo establece una **compuerta terminal de 7 preguntas (*7-Question Gate*)** y una **Lista de No-Reporte Solitario (*Never-Submit List*)** que todo agente de Devia-CyberSecurity debe aplicar antes de certificar un hallazgo como confirmado.

---

## 🛑 1. El Filtro Terminal: 7-Question Gate

Antes de registrar cualquier hallazgo en `findings.json` o en reportes formales, responder estrictamente a las siguientes 7 preguntas. **Una sola respuesta negativa ("NO") DESCALIFICA el hallazgo de inmediato o lo degrada a INFO/Hardening**:

| # | Pregunta de Control | Si la respuesta es NO $\implies$ Acción |
| :-: | :--- | :--- |
| **Q1** | ¿Un atacante o usuario no confiable puede alcanzar este código y detonarlo AHORA mediante una petición real (HTTP, IPC, CLI, Evento)? | **DESCARTAR / KILL:** No es alcanzable en tiempo de ejecución. |
| **Q2** | ¿El impacto resultante compromete confidencialidad, integridad o disponibilidad de activos reales? | **DESCARTAR / KILL:** Ausencia de impacto técnico comprobable. |
| **Q3** | ¿El recurso afectado se encuentra dentro del alcance y frontera de confianza auditada? | **DESCARTAR / KILL:** Fuera de scope técnico. |
| **Q4** | ¿La vulnerabilidad opera sin requerir privilegios administrativos o acceso previo que el atacante no pueda obtener legítimamente? | **DESCARTAR / KILL:** Requiere privilegios ya comprometidos. |
| **Q5** | ¿El comportamiento NO está explícitamente diseñado y documentado como *by-design* o *public by design* (e.g. Supabase anon key)? | **DESCARTAR / KILL:** Comportamiento esperado por arquitectura. |
| **Q6** | ¿Se puede estructurar la evidencia de código en los 7 roles canónicos (`entrypoint` $\to$ `propagation` $\to$ `sink`) sin vacíos especulativos? | **DESCARTAR / KILL:** Falta de trazabilidad demostrada. |
| **Q7** | ¿El hallazgo NO pertenece a la lista de "Nunca Reportar Solo" (*Never-Submit List*) sin una cadena de explotación asociada? | **DESCARTAR / KILL:** Problema de hardening reportado erróneamente como vulnerabilidad crítica. |

---

## 🚫 2. Lista de "Nunca Reportar Solo" (*Never-Submit List*)

Los siguientes 15 hallazgos **NUNCA deben reportarse como vulnerabilidades independientes**. Solo son válidos si forman parte demostrada de una **cadena de explotación (*Exploit Chain*)**:

1. **Cabeceras HTTP de seguridad faltantes** (`CSP`, `HSTS`, `X-Frame-Options`) $\to$ Hardening.
2. **GraphQL Introspection habilitada** $\to$ Información pública, no vulnerabilidad directa.
3. **Banner / Version disclosure sin CVE conocido** $\to$ Informativo.
4. **Clickjacking en páginas sin formularios sensibles ni acciones de mutación** $\to$ Sin impacto.
5. **CORS `*` en endpoints públicos de solo lectura sin credenciales** $\to$ Comportamiento normal en APIs públicas.
6. **Logout CSRF** $\to$ Molestia menor, sin compromiso de seguridad.
7. **Self-XSS** $\to$ Requiere que el usuario se ataque a sí mismo; no explotable remotamente.
8. **Open Redirect aislado** $\to$ Riesgo de phishing, pero no vulnera datos del sistema por sí solo.
9. **SSRF DNS-only sin recepción de tráfico HTTP/TCP ni exfiltración** $\to$ No confirmado.
10. **Host Header Injection sin envenenamiento de caché ni reseteo de contraseña** $\to$ Sin impacto real.
11. **Enumeración de correos electrónicos en login estándar** $\to$ Informativo.
12. **Divulgación de Stack Trace sin secretos ni credenciales** $\to$ Informativo / depuración.
13. **Cookie sin flag `HttpOnly` en tokens que no manejan sesión de usuario** $\to$ Hardening.
14. **Ausencia de rate limiting en endpoints no autenticados de solo lectura** $\to$ DoS no trivial.
15. **Invocación de `console.log` en entornos frontend sin datos PII** $\to$ Higiene de código, no fuga de datos.

---

## ⛓️ 3. Matriz de Cadenas de Explotación Condicionadas (*Exploit Chaining*)

Los hallazgos de la lista anterior adquieren validez y severidad elevada cuando se encadenan con otros primitivos:

| Primitivo Base | + Primitivo de Cadena | = Resultado Técnico | Severidad Final |
| :--- | :--- | :--- | :---: |
| **Open Redirect** | + Flujo OAuth (`redirect_uri` permisivo) | Robo de código OAuth / Account Takeover (ATO) | **CRITICAL** |
| **CORS `*` con `supportsCredentials: true`** | + Endpoint con PII o datos de sesión | Exfiltración de datos cross-origin autenticada | **HIGH** |
| **Self-XSS** | + CSRF en endpoint de perfil | Stored XSS persistente hacia la víctima | **HIGH** |
| **SSRF DNS** | + Endpoint de metadatos de Cloud (169.254.169.254) | Robo de credenciales de instancia IAM | **CRITICAL** |
| **Email Enumeration** | + Reset de password sin rate limit | Secuestro masivo de cuentas por fuerza bruta | **HIGH** |
| **IDOR Read-Only** | + Endpoint de exportación masiva | Exfiltración masiva de base de datos de clientes | **CRITICAL** |
