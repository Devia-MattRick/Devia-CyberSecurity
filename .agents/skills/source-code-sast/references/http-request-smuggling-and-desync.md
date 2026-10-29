# Guía de Auditoría y Bastionado contra HTTP Request Smuggling y Desincronización

Esta referencia técnica describe los principios de análisis estático (SAST), modelado de fronteras y remediación arquitectónica para vulnerabilidades de **HTTP Request Smuggling y Desincronización Proxy-Backend**, catalogada como **`VULN-SAST-017`** en **Devia-CyberSecurity**.

---

## 🏛️ Contexto y Mecanismo del Fallo

En arquitecturas web modernas, un servidor proxy inverso, CDN o API Gateway reenvía peticiones HTTP a servidores backend a través de conexiones TCP persistentes (HTTP Keep-Alive). Para delimitar dónde termina una petición y comienza la siguiente dentro del flujo de bytes TCP continuo, la especificación HTTP/1.1 (RFC 7230) define dos mecanismos:

1. **`Content-Length` (CL):** Especifica la longitud exacta en bytes del cuerpo del mensaje.
2. **`Transfer-Encoding: chunked` (TE):** Divide el cuerpo en bloques precedidos por su tamaño hexadecimal hasta un bloque terminal de longitud 0.

Cuando el proxy perimetral (Frontend) y el servidor de aplicaciones (Backend) discrepan sobre cuál cabecera priorizar o cómo interpretar cabeceras malformadas u ofuscadas, se produce una **desincronización HTTP**:

- **CL.TE:** El Frontend procesa `Content-Length` y el Backend procesa `Transfer-Encoding`. Una parte del cuerpo procesado por el Frontend queda como remanente sin leer en el búfer del Backend, interpretándose como el inicio de la siguiente petición de un usuario inocente.
- **TE.CL:** El Frontend procesa `Transfer-Encoding` y el Backend procesa `Content-Length`.
- **TE.TE:** Ambos servidores soportan `Transfer-Encoding`, pero uno de ellos puede ser inducido a ignorarlo mediante ofuscaciones en la cabecera (e.g. `Transfer-Encoding: xchunked`, espacios o tabulaciones antes del valor).
- **H2.CL / H2.TE:** Degradación de protocolo (HTTP/2 downgrade a HTTP/1.1 en el backend) donde el proxy acepta peticiones HTTP/2 válidas pero las inyecta en HTTP/1.1 hacia el backend con cabeceras `content-length` o `transfer-encoding` maliciosas.

---

## 🔍 Taxonomía y Mapeo Multimarco

| Estándar / Marco | Identificador | Denominación Oficial |
| :--- | :--- | :--- |
| **CWE** | **CWE-444** | Inconsistent Interpretation of HTTP Requests ('HTTP Request/Response Smuggling') |
| **OWASP Top 10** | **A04:2021/2025** | Insecure Design |
| **OWASP ASVS** | **V13.1.4** | Verify that the application and all reverse proxies strictly adhere to RFC 7230 |
| **MITRE ATT&CK** | **T1190** | Exploit Public-Facing Application |
| **Devia Catalog** | **`VULN-SAST-017`** | HTTP Request Smuggling & Transfer-Encoding Desynchronization |

---

## ⚙️ Invariantes de Seguridad y Directivas de RFC 7230

El estándar canónico **RFC 7230 §3.3.3 (Message Body Length)** establece dos invariantes obligatorios para cualquier servidor o intermediario conforme:

1. > *"If a message is received with both a Transfer-Encoding and a Content-Length header field, the Transfer-Encoding overrides the Content-Length."*  
   Cualquier intermediario **debe eliminar la cabecera `Content-Length`** antes de reenviar el mensaje a un backend sobre HTTP/1.1.
2. > *"If a message is received with both a Transfer-Encoding and a Content-Length header field, and the Transfer-Encoding is not chunked, or if multiple Transfer-Encoding fields appear, the message MUST be handled as an error (e.g., 400 Bad Request)."*

---

## 💻 Código Vulnerable vs Configuración Segura

### Antipatrón Vulnerable: Reenvío Ciego en Proxy Inverso Node.js
```typescript
// VULNERABLE: Reenvía cabeceras ambiguas sin normalización
import http from "node:http";

const proxy = http.createServer((clientReq, clientRes) => {
  // Peligro: Reenvía tanto Content-Length como Transfer-Encoding al backend
  const options = {
    hostname: "backend-service.internal",
    port: 8080,
    path: clientReq.url,
    method: clientReq.method,
    headers: clientReq.headers // Headers no normalizados!
  };
  const backendReq = http.request(options, (backendRes) => {
    clientRes.writeHead(backendRes.statusCode!, backendRes.headers);
    backendRes.pipe(clientRes);
  });
  clientReq.pipe(backendReq);
});
```

### Patrón Seguro: Validación Estricta de Cabeceras y Descarte de Ambigüedad
```typescript
// SEGURO: Validación conforme a RFC 7230 §3.3.3
import http from "node:http";

function normalizeHeaders(headers: http.IncomingHttpHeaders): http.OutgoingHttpHeaders {
  const cleanHeaders = { ...headers };

  const hasCL = "content-length" in cleanHeaders;
  const hasTE = "transfer-encoding" in cleanHeaders;

  if (hasCL && hasTE) {
    // Regla RFC 7230: Rechazar peticiones ambiguas con 400 Bad Request
    throw new SecurityException("Ambiguous request: both Content-Length and Transfer-Encoding present");
  }

  // Descartar cabeceras duplicadas o valores múltiples no autorizados
  if (Array.isArray(cleanHeaders["content-length"])) {
    throw new SecurityException("Duplicate Content-Length headers rejected");
  }

  return cleanHeaders;
}
```

### Configuración Hardened en Nginx
```nginx
# Hardening de Nginx contra Request Smuggling
# Descartar cabeceras inválidas o ambiguas por defecto
ignore_invalid_headers on;

# Forzar HTTP/2 de extremo a extremo hacia backends que lo soporten
proxy_http_version 1.1;

# Desactivar reutilización de conexión con backend si la autenticación es por sesión
proxy_set_header Connection "";
```

---

## 🔬 Oráculo de Verificación Determinista (Sin Explotación Armada)

Un oráculo de verificación SAST determinista evalúa la configuración o el código fuente sin emitir payloads dañinos:

1. **Inspección de Configuración:** Comprobar si el reverse proxy (HAProxy, Nginx, Envoy, Cloudflare) tiene habilitado el rechazo estricto de cabeceras RFC 7230.
2. **Sondeo Diferencial Pasivo:** Enviar una petición con cabecera dual `Content-Length: 4` y `Transfer-Encoding: chunked` al endpoint de health-check.
   - **Resultado Seguro:** Respuesta `400 Bad Request`.
   - **Resultado Vulnerable:** Respuesta `200 OK` (indica que el proxy toleró la ambigüedad y la propagó aguas abajo).

---

## ✅ Checklist de Auditoría para Evaluadores de Devia-CyberSecurity

- [ ] Las conexiones perimetrales frontend-backend operan sobre **HTTP/2 de extremo a extremo** cuando es técnicamente viable.
- [ ] El reverse proxy rechaza con código `400 Bad Request` cualquier petición que contenga simultáneamente `Content-Length` y `Transfer-Encoding`.
- [ ] El servidor rechaza peticiones con múltiples cabeceras `Content-Length` con valores divergentes.
- [ ] No se permiten caracteres de espacio en blanco, tabulaciones o saltos de línea dentro de los nombres de cabecera HTTP.
- [ ] Las cabeceras de salto a salto (`Connection`, `Keep-Alive`, `Upgrade`) se eliminan antes de reenviar el flujo al backend.
