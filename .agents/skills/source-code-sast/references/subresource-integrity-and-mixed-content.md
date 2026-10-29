# Subresource Integrity (SRI) y Prevención de Contenido Mixto en Aplicaciones Web

Este documento establece la guía técnica de análisis estático (SAST) y arquitectura segura para la validación de integridad en recursos de terceros y la erradicación de contenido mixto en **Devia-CyberSecurity**.

---

## 🏛️ 1. Definición y Vectores de Riesgo

### 1.1. Subresource Integrity (SRI - W3C Recommendation)
Subresource Integrity permite que los navegadores comprueben criptográficamente que los recursos servidos por redes de distribución de contenido (CDNs) o terceros no hayan sido manipulados o troyanizados:
- **Vector de Riesgo (CWE-353 / CWE-829):** Si un atacante compromete el servidor CDN o ejecuta un ataque de DNS Spoofing, puede inyectar código JavaScript malicioso en todos los clientes que cargan la biblioteca.
- **Mecanismo de Mitigación:** El atributo `integrity` fija el hash SHA-256, SHA-384 o SHA-512 del recurso.

### 1.2. El Antipatrón de Bloqueo por Falta de Atributo `crossorigin`
Un fallo recurrente en implementaciones frontend consiste en añadir el hash `integrity` sin incluir el atributo `crossorigin="anonymous"`:
```html
<!-- VULNERABLE / BLOQUEADO POR NAVEGADORES -->
<script src="https://cdn.example.com/lib.js" integrity="sha384-..." ></script>
```
> [!IMPORTANT]
> Los navegadores modernos exigen que los recursos cross-origin con verificación SRI se soliciten utilizando el protocolo CORS. Si se omite `crossorigin`, el navegador bloquea la carga del script por completo por razones de seguridad, rompiendo la aplicación para el usuario final.

---

## 🔍 2. Detección Estática SAST (Reglas y Expresiones Regulares)

### 2.1. Identificación de Scripts de Terceros sin SRI
Al auditar plantillas HTML, componentes Astro, JSX/TSX o vistas de servidor:
1. Extraer todas las etiquetas `<script src="...">`.
2. Verificar si el dominio de la URL en `src` difiere del dominio del sitio analizado (terceros).
3. Evaluar la presencia del atributo `integrity`:
   ```regex
   \bintegrity\s*=\s*["']sha(256|384|512)-[A-Za-z0-9+/=]+["']
   ```
4. **Alerta:** Todo script de terceros con versión fija (e.g. `cdn.jsdelivr.net/npm/vue@3.2.0/dist/vue.js`) que carezca de hash SRI debe reportarse como **MEDIUM** (`VULN-SCA-001` / CWE-829).

### 2.2. Reglas de Validación de Atributo CORS para SRI
```typescript
function validateScriptTag(scriptElement: CheerioElement): { isVulnerable: boolean; reason?: string } {
  const src = scriptElement.attribs['src'];
  const integrity = scriptElement.attribs['integrity'];
  const crossorigin = scriptElement.attribs['crossorigin'];
  const isModule = scriptElement.attribs['type']?.trim().toLowerCase() === 'module';

  if (integrity && !crossorigin && !isModule) {
    return {
      isVulnerable: true,
      reason: "Script con atributo integrity carece de crossorigin='anonymous' y será bloqueado por los navegadores."
    };
  }
  return { isVulnerable: false };
}
```

---

## 🛡️ 3. Taxonomía de Contenido Mixto (Mixed Content)

El contenido mixto ocurre cuando una página servida sobre HTTPS (`https://`) realiza peticiones a recursos a través de HTTP inseguro (`http://`). Se subdivide en dos categorías con severidad diferenciada:

| Categoría | Elementos Afectados | Impacto Técnico | Severidad |
| :--- | :--- | :--- | :--- |
| **Contenido Mixto Activo** | `<script src>`, `<link rel="stylesheet">`, `<iframe>`, `<object data>`, CSS `@import`, `fetch()` / `XHR` | **Ejecución de Código Arbitrario (MitM):** Un atacante en red puede interceptar la respuesta HTTP e inyectar JavaScript en el origen HTTPS seguro. | **CRITICAL / HIGH** (CWE-311 / CWE-319) |
| **Contenido Mixto Pasivo** | `<img src>`, `<audio src>`, `<video src>`, `<source src>`, CSS `url()` | **Espionaje y Defacement:** Permite a un atacante rastrear la actividad del usuario o sustituir imágenes legítimas por contenido fraudulento. | **MEDIUM** (CWE-319) |
| **Formularios Inseguros** | `<form action="http://...">`, `<button formaction="http://...">` | **Fuga de Credenciales:** Envío de contraseñas o datos sensibles en texto claro al someter el formulario. | **HIGH** (CWE-319) |

---

## 🔒 4. Mitigaciones Arquitectónicas Recomendadas

### 4.1. Cabecera Content Security Policy (CSP)
La directiva más efectiva a nivel de cabecera HTTP consiste en forzar al navegador a reescribir todas las peticiones inseguras a HTTPS antes de emitirlas a la red:
```http
Content-Security-Policy: upgrade-insecure-requests;
```

### 4.2. Directiva `require-sri-for` / `integrity-policy`
En entornos de alta seguridad (finanzas, salud), configurar políticas de integridad para requerir SRI de forma estricta:
```html
<meta http-equiv="Content-Security-Policy" content="require-sri-for script style;">
```

---

## 📋 5. Checklist de Auditoría SAST

- [ ] Todos los scripts y hojas de estilo de CDNs externas incluyen atributo `integrity` con hash SHA-384 o SHA-512.
- [ ] Todo recurso externo con `integrity` incluye explícitamente `crossorigin="anonymous"`.
- [ ] No existen referencias cableadas con esquema `http://` en scripts, iframes o estilos dentro de páginas servidas por HTTPS.
- [ ] Todos los formularios `<form>` tienen atributo `action` apuntando a URLs relativas o HTTPS.
- [ ] La cabecera `Content-Security-Policy` contiene la directiva `upgrade-insecure-requests`.
