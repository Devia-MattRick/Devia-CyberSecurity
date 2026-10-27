# Matriz Canónica: 33 Controles de Auditoría y Bastionado de Infraestructura Web

**Dimensión Canónica:** `CONFIGURATION_HARDENING`  
**Taxonomías:** CWE-693 (Protection Mechanism Failure), CWE-1021 (Improper Restriction of Rendered UI Layers), CWE-319 (Cleartext Transmission), CWE-350 (Reliance on Untrusted Inputs), OWASP A05:2021 (Security Misconfiguration)  
**Skill Asignada:** [`configuration-hardening`](file:///.agent/skills/configuration-hardening/SKILL.md)  
**Origen:** Absorción forense de Web Audit Orchestrator (`web-audit-orchestrator/references/check-cwe-mapping.md`)  

---

## 🏛️ 1. Propósito y Alcance

Esta matriz formaliza el marco integral de auditoría de configuración para servicios y perímetros web expuestos. Evalúa 33 controles discretos organizados en 4 dominios (Seguridad, Red, Metadatos y Reconocimiento), correlacionando cada comprobación con identificadores formales de debilidad (CWE), estándares de la industria (OWASP Top 10) y especificaciones técnicas (RFCs).

---

## 🛡️ 2. Dominio 1: Controles de Seguridad Perimetral (`SEC-01` a `SEC-10`)

| Check ID | Control / Mecanismo | CWE Asociados | OWASP Top 10 | Estándar RFC | Severidad Típica |
| :--- | :--- | :--- | :--- | :--- | :---: |
| **`SEC-01`** | **Cadena de Certificados TLS/SSL:** Validez temporal, autoridad emisora (CA), SANs y revocación (OCSP). | CWE-295, CWE-327 | A02:2021 / A07:2021 | RFC 5280, RFC 8446 | **HIGH** |
| **`SEC-02`** | **Atributos de Seguridad en Cookies:** Flags `Secure`, `HttpOnly` y atributo `SameSite=Lax|Strict`. | CWE-614, CWE-315 | A05:2021 / A01:2021 | RFC 6265bis | **MEDIUM-HIGH** |
| **`SEC-03`** | **Encabezados HTTP Defensivos:** CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy. | CWE-693, CWE-1021 | A05:2021 | RFC 6797, RFC 7034 | **MEDIUM-HIGH** |
| **`SEC-04`** | **HSTS (HTTP Strict Transport Security):** Forzado de HTTPS con `includeSubDomains` y `preload`. | CWE-319, CWE-311 | A02:2021 / A05:2021 | RFC 6797 | **HIGH** |
| **`SEC-05`** | **Validación DNSSEC:** Firmas criptográficas RRSIG y cadena de confianza DS contra ataques de suplantación. | CWE-345, CWE-346 | A05:2021 | RFC 4033, RFC 4035 | **MEDIUM** |
| **`SEC-06`** | **Fuga de Información en Headers:** Ocultación de banners `Server`, `X-Powered-By`, `X-AspNet-Version`. | CWE-200, CWE-693 | A05:2021 | RFC 7231 | **LOW-MEDIUM** |
| **`SEC-07`** | **Reputación e Inteligencia de Amenazas:** Detección en listas de malware, phishing y dominios bloqueados. | CWE-834, CWE-937 | A01:2021 / A09:2021 | — | **CRITICAL** |
| **`SEC-08`** | **Detección y Postura WAF:** Presencia de cortafuegos de aplicación web y reglas activas de filtrado. | CWE-345, CWE-693 | A05:2021 | — | **MEDIUM** |
| **`SEC-09`** | **Políticas de Divulgación `security.txt`:** Presencia de archivo canónico de contacto y claves de reporte. | CWE-778, CWE-200 | A05:2021 | RFC 9116 | **LOW** |
| **`SEC-10`** | **Cipher Suites y Criptografía Débil:** Prohibición de TLS 1.0/1.1, suites CBC, 3DES, RC4 y exportación. | CWE-327, CWE-326 | A02:2021 | RFC 8446, RFC 7540 | **HIGH** |

---

## 🌐 3. Dominio 2: Infraestructura de Red y Correo (`NET-01` a `NET-10`)

| Check ID | Control / Mecanismo | CWE Asociados | OWASP Top 10 | Estándar RFC | Severidad Típica |
| :--- | :--- | :--- | :--- | :--- | :---: |
| **`NET-01`** | **Geolocalización y Detalles de IP:** ASN, proveedor de hosting y exposición de IPs de origen (Bypass CDN). | CWE-200 | A01:2021 | RFC 1035 | **INFO** |
| **`NET-02`** | **Registros DNS Públicos:** Análisis de registros A, AAAA, CNAME, MX, TXT y NS huérfanos (Subdomain Takeover). | CWE-350, CWE-345 | A05:2021 | RFC 1035 | **MEDIUM** |
| **`NET-03`** | **Códigos de Estado y Manejo HTTP:** Respuestas estándar frente a métodos no soportados (TRACE, OPTIONS). | CWE-200 | A05:2021 | RFC 7231 | **LOW** |
| **`NET-04`** | **Superficie de Puertos Expuestos:** Escaneo de servicios de gestión accesibles en puertos no estándar (22, 3389, 8080). | CWE-200, CWE-284 | A05:2021 | — | **HIGH** |
| **`NET-05`** | **Trazabilidad de Red (Traceroute):** Saltos intermedios y exposición de topología interna. | CWE-200 | A01:2021 | RFC 1393 | **INFO** |
| **`NET-06`** | **Soporte DNS cifrado (DoH / DoT):** Resolución segura de nombres para mitigar escuchas e intercepciones. | CWE-345 | A05:2021 | RFC 8484, RFC 7858 | **LOW** |
| **`NET-07`** | **Datos de Registro WHOIS:** Privacidad de contacto del registrante y fechas de expiración del dominio. | CWE-200 | A01:2021 | RFC 3912 | **INFO** |
| **`NET-08`** | **Autenticación de Correo (SPF + DMARC):** Políticas estrictas contra spoofing y suplantación de identidad. | CWE-350 | A05:2021 | RFC 7208, RFC 7489 | **MEDIUM-HIGH** |
| **`NET-09`** | **Firma Criptográfica DKIM & ARC:** Verificación de integridad de mensajes salientes y preservación en tránsito. | CWE-350 | A05:2021 | RFC 6376, RFC 8617 | **MEDIUM** |
| **`NET-10`** | **Cortafuegos Perimetral y CDN:** Protección activa contra ataques DDoS en capas L3/L4 y L7. | CWE-410 | A05:2021 | RFC 7231 | **MEDIUM** |

---

## 🗂️ 4. Dominio 3: Metadatos y Cadena de Redirección (`META-01` a `META-04`)

| Check ID | Control / Mecanismo | CWE Asociados | OWASP Top 10 | Estándar RFC | Severidad Típica |
| :--- | :--- | :--- | :--- | :--- | :---: |
| **`META-01`** | **Cadena de Redirecciones:** Prevención de bucles infinitos, downgrade a HTTP o redirecciones abiertas (Open Redirect). | CWE-601, CWE-602 | A01:2021 | RFC 7231 | **MEDIUM-HIGH** |
| **`META-02`** | **Auditoría de `robots.txt`:** Detección de divulgación de rutas sensibles, paneles admin o backups en directivas. | CWE-200, CWE-538 | A01:2021 | RFC 9309 | **LOW** |
| **`META-03`** | **Mapeo de `sitemap.xml`:** Inventario de endpoints indexados e incoherencias de cobertura. | CWE-200 | A01:2021 | sitemaps.org | **INFO** |
| **`META-04`** | **Inspección de Enlaces Externos:** Enlaces a sitios caídos susceptibles a secuestro (*Broken Link Hijacking*). | CWE-200 | A01:2021 | — | **INFO** |

---

## 🔍 5. Dominio 4: Reconocimiento y Huellas Tecnológicas (`RECON-01` a `RECON-09`)

| Check ID | Control / Mecanismo | CWE Asociados | OWASP Top 10 | Severidad Típica |
| :--- | :--- | :--- | :--- | :---: |
| **`RECON-01`** | **Identificación de Tech Stack:** Huellas de servidores web, frameworks, bibliotecas JS desactualizadas. | CWE-200 | A05:2021 | **LOW-MEDIUM** |
| **`RECON-02`** | **Metadatos Sociales y OpenGraph:** Exposición involuntaria de datos internos en tags de previsualización. | CWE-200 | A05:2021 | **INFO** |
| **`RECON-03`** | **Características y Capacidades Web:** Detección de APIs de navegador activas (WebSockets, WebRTC, Service Workers). | CWE-200 | A05:2021 | **INFO** |
| **`RECON-04`** | **Captura de Fotograma Visual (Screenshot):** Verificación de previsualizaciones y fallos de renderizado. | — | — | **INFO** |
| **`RECON-05`** | **Métricas de Rendimiento y Calidad (Lighthouse):** Detección de bibliotecas con vulnerabilidades conocidas (SCA). | CWE-410, CWE-710 | A05:2021 | **LOW** |
| **`RECON-06`** | **Huella de Carbono Digital:** Métricas de transferencia de datos y consumo de ancho de banda. | — | — | **INFO** |
| **`RECON-07`** | **Archivos Históricos (Wayback Machine):** Localización de endpoints deprecados o secretos expuestos en el pasado. | CWE-200 | A01:2021 | **INFO** |
| **`RECON-08`** | **Rango y Reputación de Dominio:** Tráfico relativo y antigüedad del dominio para modelado de riesgo. | — | — | **INFO** |
| **`RECON-09`** | **Puntuación Cuantificada de Cabeceras:** Evaluación determinista de la postura global de seguridad HTTP. | — | A05:2021 | **INFO** |

---

## 🛠️ 6. Patrones de Bastionado Seguro (*Hardening Recipes*)

### 6.1. Encabezados HTTP Defensivos Obligatorios (Nginx / Express / Edge)
```nginx
# Protección estricta contra MIME-sniffing, clickjacking y downgrade de protocolo
add_header X-Content-Type-Options "nosniff" always;
add_header X-Frame-Options "DENY" always;
add_header Referrer-Policy "strict-origin-when-cross-origin" always;
add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;
add_header Content-Security-Policy "default-src 'self'; script-src 'self'; object-src 'none'; frame-ancestors 'none'; base-uri 'self';" always;
add_header Permissions-Policy "geolocation=(), microphone=(), camera=()" always;
server_tokens off;
```

### 6.2. Bastionado de Cookies de Sesión
```typescript
const sessionCookieOptions: CookieOptions = {
  httpOnly: true,     // Inaccesible desde JavaScript (mitiga XSS)
  secure: true,       // Transmisión exclusiva sobre HTTPS
  sameSite: 'lax',    // Mitiga CSRF en navegaciones cross-site
  maxAge: 3600 * 1000 // Expiración acotada de 1 hora
};
```

### 6.3. Registro DMARC Restrictivo (DNS)
```dns
_dmarc.dominio.com. IN TXT "v=DMARC1; p=reject; sp=reject; rua=mailto:dmarc-reports@dominio.com; pct=100; aspf=s; adkim=s"
```
