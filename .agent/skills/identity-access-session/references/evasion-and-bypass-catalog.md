# Catálogo de Vectores de Evasión y Técnicas de Bypass en Autenticación y Control de Acceso

> **Dimensión:** `IDENTITY_ACCESS_SESSION`  
> **Taxonomía:** CWE-639 / CWE-918 / CWE-347 / CWE-307 / OWASP A01 & A07  
> **Origen de Absorción:** `security-audit/Cybersecurity-Audit/references/CATALOGO_VECTORES.md` (Acción `ABS-004`)  
> **Vulnerabilidad Asociada:** `VULN-IAM-002` (JWT Signature Bypass & Token Manipulation)  

---

## 🧭 Introducción

Los mecanismos defensivos modernos suelen implementar filtros superficiales basados en expresiones regulares, listas negras de palabras o validaciones parciales de cabeceras. Este documento condensa los vectores de evasión más frecuentes observados en auditorías reales para diseñar pruebas defensivas rigurosas.

---

## 🔓 1. Técnicas de Bypass en IDOR y Control de Acceso (CWE-639)

1. **Recolección Pasiva de UUIDs (*UUID Harvesting*):** Confiar en que los UUIDv4 son "inadivinables" no protege si se exponen en listas públicas, logs de auditoría o respuestas de error de endpoints secundarios.
2. **Manipulación de Métodos HTTP (*Method Tampering*):** Si `GET /api/v1/resource/123` valida pertenencia pero `PUT`, `PATCH` o `DELETE` sobre el mismo recurso asumen autorización previa en middleware.
3. **Contaminación de Parámetros HTTP (HPP):** Duplicar parámetros (`?user_id=attacker&user_id=victim`) para engañar parsers que toman el primer parámetro mientras la base de datos procesa el segundo.
4. **Discrepancia de Versiones de API:** Endpoints antiguos (`/v1/`) que siguen activos en producción y no implementan los controles de tenant añadidos en `/v2/`.
5. **Rutas Secundarias de Sincronización:** Métodos de actualización por lotes (`batch_update`, `sync_records`, `import`) que omiten la cláusula `WHERE tenant_id = current_tenant`.

---

## 🌐 2. Técnicas de Evasión en SSRF (CWE-918)

Los validadores de URLs que comprueban cadenas literales como `"127.0.0.1"` o `"localhost"` son fácilmente eludibles mediante representaciones alternativas de IP:

| Técnica de Evasión | Payload de Ejemplo | Interpretación del Sistema |
| :--- | :--- | :--- |
| **IPv6 Loopback** | `http://[::1]:8080/` | Conexión local a través de la pila IPv6. |
| **IPv4-mapped IPv6** | `http://[::ffff:127.0.0.1]/` | Traducción automática a interfaz loopback. |
| **Representación Decimal (Dword)** | `http://2130706433/` | Equivale a $127 \times 2^{24} + 1 = 127.0.0.1$. |
| **Representación Hexadecimal** | `http://0x7f000001/` | Hexadecimal para $127.0.0.1$. |
| **Formato Corto (Short IP)** | `http://127.1/` | Expandido por libc a $127.0.0.1$. |
| **DNS Rebinding** | Dominio que resuelve a IP pública (TTL 0) y luego a `127.0.0.1` | Burla la validación en tiempo de resolución. |
| **Redirección Abierta (Redirect Chain)** | URL externa autorizada que emite un `302 Found` hacia `http://169.254.169.254/` | Exfiltración de credenciales en servicios cloud. |

*Defensa Canónica:* Resolver la dirección IP mediante DNS **antes** de abrir el socket, validar que la IP resuelta no pertenezca a ningún rango privado (`127.0.0.0/8`, `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `169.254.0.0/16`, `::1/128`, `fc00::/7`), deshabilitar el seguimiento automático de redirecciones (`redirect: 'error'`) y aplicar timeout estricto $\le 10$ s.

---

## 🔑 3. Las 8 Clases de Ataque a Tokens JWT (CWE-347)

1. **`alg: none` Bypass:** Manipulación del encabezado del token cambiando `{"alg": "HS256"}` por `{"alg": "none"}` o `"None"` y eliminando la firma terminal.
2. **Confusión de Claves Asimétricas a Simétricas (RS256 $\to$ HS256):** Si el servidor usa verificación pública (RS256), un atacante toma la clave pública PEM (conocida) y firma un token forjado con algoritmo simétrico `HS256`. Si la librería no valida el algoritmo esperado, verifica la firma exitosamente.
3. **Path Traversal en parámetro `kid` (Key ID):** Inyectar `kid: "../../../dev/null"` o una ruta vacía para forzar a la librería a utilizar una clave vacía o predecible en disco.
4. **Inyección en URLs de Verificación (`jku` / `x5u`):** Proporcionar una URL maliciosa controlada por el atacante en la cabecera `jku` para que el servidor descargue claves falsas.
5. **Confusión de Claves EC $\to$ HMAC:** Ataques de degradación de curvas elípticas hacia HMAC.
6. **Reutilización de Tokens Expirados por Tolerancia Excesiva de Reloj (*Clock Skew*):** Aceptación de tokens expirados cuando la librería tiene configurado un skew $> 5$ minutos.
7. **Exposición de Tokens en Almacenamiento No Seguro:** Almacenar tokens de refresco de larga duración en `localStorage` del navegador donde son accesibles ante cualquier vector XSS.
8. **Inyección de Claims en Tokens No Verificados:** Confiar en claims decodificados sin verificar la firma previa.

---

## 🛡️ 4. Umbrales y Patrones de Evasión en MFA (CWE-307)

Para que un mecanismo de autenticación multifactor sea seguro ante fuerza bruta y race conditions:

| Vector de Ataque | Mecanismo del Fallo | Regla Inmutable de Remediación |
| :--- | :--- | :--- |
| **Fuerza Bruta de OTP** | Códigos de 6 dígitos sin bloqueo de intentos ($10^6$ combinaciones). | **$\le 5$ intentos permitidos por challenge en 15 minutos (900s TTL)**. Bloqueo progresivo (15m $\to$ 1h $\to$ 24h). |
| **Reutilización de Códigos** | El OTP no se invalida inmediatamente tras el primer uso exitoso. | Eliminación atómica inmediata del challenge en base de datos. |
| **Validación Client-Side** | La interfaz frontend decide si el usuario ingresó el código correcto. | El token de sesión `aal2` solo se emite y valida en el servidor. |
| **Race Condition en OTP** | Múltiples peticiones concurrentes con códigos distintos al mismo tiempo. | Actualización transaccional con lock: `UPDATE challenges SET used=true WHERE id=? AND used=false RETURNING id;`. |
| **Códigos de Respaldo Débiles** | Códigos numéricos cortos. | Alfanuméricos $\ge 16$ caracteres, de un solo uso (*single-use*) con hash criptográfico almacenado. |
