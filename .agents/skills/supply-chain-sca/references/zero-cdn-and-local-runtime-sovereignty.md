# Soberanía de Cadena de Suministro: Zero-CDN y Auto-Hospedaje de Recursos

> **ID de Vulnerabilidad:** `VULN-SCA-013`  
> **Taxonomía:** CWE-829 (*Inclusion of Functionality from Untrusted Control Sphere*) / CWE-1395 (*Dependency on Vulnerable Third-Party Component*) / OWASP Top 10 A06:2021/2025 / OWASP Top 10 A08:2025  
> **Dimensión:** `SUPPLY_CHAIN_SCA`  
> **Skill:** `supply-chain-sca`  

---

## 1. El Riesgo de Dependencias en CDNs Públicas en Tiempo de Ejecución

Cargar scripts, estilos o fuentes tipográficas desde Content Delivery Networks (CDNs) de terceros (e.g. `cdn.jsdelivr.net`, `cdnjs.cloudflare.com`, `fonts.googleapis.com`) en aplicaciones empresariales o de escritorio introduce tres vectores de fallo críticos:
1. **Compromiso de la Cadena de Suministro (Supply Chain Poisoning):** Si la CDN es vulnerada o un paquete es secuestrado (*RepoJacking* o *Typosquatting*), el atacante puede inyectar código JavaScript malicioso ejecutado con los privilegios del origen de la aplicación.
2. **Fuga de Metadatos y Violación de Privacidad (GDPR):** Cada petición hacia una CDN externa expone la dirección IP del usuario, cabeceras `Referer` y patrones de uso a proveedores de infraestructura extranjeros sin consentimiento explícito.
3. **Punto Único de Fallo (SPOF) y Falta de Operación Offline:** Si la conexión a la CDN es bloqueada por firewalls corporativos o interrupciones de red, la interfaz se degrada o no inicia.

---

## 2. La Directiva de Gobernanza Zero-CDN

En sistemas con directiva soberana **Zero-CDN**:
- **Cero Tags `<script>` o `<link>` a Dominios Externos:** El archivo `index.html` debe carecer de cualquier referencia a URLs externas.
- **Auto-Hospedaje Local de Tipografías:** El 100% de las fuentes (e.g. Inter, JetBrains Mono) deben residir empaquetadas localmente en formato `.woff2` dentro de `src/assets/fonts/` o equivalente.
- **Fijación Estricta de Gestor de Paquetes (`packageManager`):** Se debe forzar una versión inmutable del gestor de dependencias (e.g. `pnpm@10.x`) en `package.json` para evitar divergencias en la resolución del árbol de dependencias transitivas.

---

## 3. Configuración Segura de Fuentes Locales

```css
/* src/styles/fonts.css — 100% Auto-hospedado y soberano */
@font-face {
  font-family: 'Inter';
  font-style: normal;
  font-weight: 400 700;
  font-display: swap;
  src: url('/assets/fonts/inter-latin-variable.woff2') format('woff2');
  unicode-range: U+0000-00FF, U+0131, U+0152-0153;
}

@font-face {
  font-family: 'JetBrains Mono';
  font-style: normal;
  font-weight: 400 600;
  font-display: swap;
  src: url('/assets/fonts/jetbrains-mono-latin-variable.woff2') format('woff2');
  unicode-range: U+0000-00FF, U+0131, U+0152-0153;
}
```

---

## 4. Checklist de Auditoría SCA

- [ ] ¿El archivo `index.html` carece por completo de enlaces hacia dominios externos (`cdnjs`, `unpkg`, `fonts.googleapis.com`)?
- [ ] ¿Las fuentes web están descargadas y versionadas localmente en formato `.woff2`?
- [ ] ¿Si existen dependencias externas que requieren CDNs, se implementa obligatoriamente Subresource Integrity (`integrity="sha384-..."` y `crossorigin="anonymous"`)?
- [ ] ¿El archivo `package.json` declara un `packageManager` específico y un lockfile correspondiente verificado?
