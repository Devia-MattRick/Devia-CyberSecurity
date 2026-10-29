# Matriz Multirrol de Autorización y Detección Diferencial de IDOR / BOLA / BFLA

Este documento establece las directivas y metodologías operativas para auditar controles de acceso y detectar de forma determinista vulnerabilidades de **IDOR** (*Insecure Direct Object Reference* / BOLA - CWE-639) y **BFLA** (*Broken Function Level Authorization* - CWE-863) mediante **pruebas diferenciales multirrol**.

---

## 🏛️ 1. El Desafío de la Autorización en Escaneo Autónomo

Los escáneres automatizados y modelos de lenguaje presentan sus mayores índices de falsos negativos en fallos de autorización lógica:
- Un LLM evaluando una respuesta individual no puede determinar si ver los datos de `order_id=1042` es legítimo o ilegítimo sin conocer la identidad del solicitante.
- Analizar el código cliente o inferir permisos por nombres de rol en la UI viola el **Axioma de Confianza Cero en Código Cliente** (`docs/PROACTIVE.md` Sección 3.9).

### Solución: La Matriz Diferencial Multirrol
En lugar de especular sobre la validez de una respuesta, se re-ejecuta de manera determinista la **misma solicitud** a través de **3 identidades formalmente contrastadas**:

```mermaid
flowchart TD
    Req["Solicitud Candidata sobre Objeto Protegido<br>(e.g. GET /api/documents/1042)"] --> R1["1. Identidad Rol A (Propietario / Primario)"]
    Req --> R2["2. Identidad Rol B (Usuario Secundario)"]
    Req --> R3["3. Identidad Anónima (Sin Credenciales)"]
    
    R1 --> Resp1["Respuesta Rol A<br>(HTTP 200 + Datos de 1042)"]
    R2 --> Resp2["Respuesta Rol B"]
    R3 --> Resp3["Respuesta Anónimo"]
    
    Resp1 & Resp2 & Resp3 --> Diff{"Motor Diferencial"}
    Diff -->|Resp2 == Resp1| IDOR["VULN-IAM-001 (IDOR / BOLA)<br>Violación Horizontal Confirmada"]
    Diff -->|Resp3 == Resp1| BFLA["VULN-IAM-003 (BFLA / Auth Bypass)<br>Violación Vertical Confirmada"]
    Diff -->|Resp2,3 in (401, 403)| Safe["Acceso Correctamente Restringido"]
```

---

## 👥 2. Las 3 Identidades Canónicas de la Matriz

Para cada punto final o acción bajo evaluación, la matriz orquesta solicitudes con las siguientes credenciales:

| Identidad | Origen de Credenciales | Rol Evaluado | Tipo de Brecha Detectada |
| :--- | :--- | :--- | :--- |
| **Rol A** | Sesión principal autenticada (`Cookie` o `Authorization`) o captura HAR de usuario 1. | Propietario legítimo del recurso. | Establece la línea base de éxito y contenido esperado. |
| **Rol B** | Segunda cuenta de igual o menor privilegio, o captura HAR de usuario 2. | Usuario no autorizado para el recurso de Rol A. | **IDOR / BOLA (CWE-639):** Escalada horizontal de privilegios. |
| **Anónimo** | Petición limpia sin cabeceras `Cookie`, `Authorization` ni tokens. | Usuario no autenticado / público. | **BFLA / Auth Bypass (CWE-863 / CWE-306):** Escalada vertical o falta de control. |

---

## 🔍 3. Heurísticas y Reglas de Decisión Diferencial

El motor de decisión evalúa los siguientes criterios sobre las respuestas obtenidas:

### 3.1. Detección de IDOR / BOLA (Rol B vs Rol A)
- **Confirmación Positiva:**
  1. `Status(Rol B) == Status(Rol A) == 200 OK`.
  2. El cuerpo de la respuesta de Rol B contiene los identificadores únicos o datos confidenciales solicitados por Rol A (e.g., email, saldos, PII).
  3. La similitud estructural (Levenshtein / SimHash) entre ambas respuestas supera el 90%.
- **Falsos Positivos a Descartar:**
  - Respuestas genéricas vacías (`{ "data": [] }`) o listas paginadas donde Rol B ve únicamente sus propios objetos.
  - Mensajes de error formateados con código 200 (`{ "error": "Unauthorized" }`). Se exige inspección semántica del cuerpo.

### 3.2. Detección de BFLA y Bypass de Autenticación (Anónimo vs Rol A)
- **Confirmación Positiva:**
  1. Solicitud anónima retorna `200 OK` sobre una ruta que requiere privilegios administrativos o de sesión.
  2. Modificaciones de estado (POST/PUT/DELETE) ejecutadas anónimamente alteran efectivamente el recurso.
- **Falsos Positivos a Descartar:**
  - Redirecciones 302 hacia `/login` que devuelven código 200 en la página de destino (analizar la cadena de redirección con `FollowRedirects: false`).

---

## 🛠️ 4. Reglas de Bastionado en la Ejecución de Pruebas

1. **Aislamiento de Sesiones:** Las cabeceras de autorización de Rol A jamás deben propagarse o reutilizarse inadvertidamente en las solicitudes de Rol B o Anónimo.
2. **Desactivación de Redirecciones:** Todas las peticiones deben ejecutarse con `follow_redirects = False`. Un código `302 Found` con cabecera `Location: /login` es una denegación exitosa; seguirla y recibir `200 OK` en el login conduce a falsos positivos.
3. **Saneamiento de Mutaciones:** En endpoints destructivos (`DELETE`, cancelaciones, reseteos), utilizar identificadores efímeros creados específicamente para la prueba, impidiendo la alteración de datos reales del operador.
