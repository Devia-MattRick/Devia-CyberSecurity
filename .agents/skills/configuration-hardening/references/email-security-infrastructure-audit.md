# Auditoría Integral de Infraestructura y Configuración de Correo Electrónico (SPF, DKIM, DANE, MTA-STS)

Este documento establece la metodología canónica, los límites normativos RFC y los procedimientos de auditoría determinista para la evaluación de la postura de seguridad del correo electrónico en **Devia-CyberSecurity**.

---

## 🏛️ 1. Taxonomía de Controles y Fundamento Técnico

El correo electrónico carece intrínsecamente de autenticación en la capa SMTP base. Los mecanismos modernos de autenticación operan a través del Sistema de Nombres de Dominio (DNS) y extensiones criptográficas:

| Mecanismo | Estándar RFC | Función Principal | Vector de Falla Auditado |
| :--- | :--- | :--- | :--- |
| **SPF (Sender Policy Framework)** | RFC 7208 | Autorización de IPs emisoras de correo. | Exceso de búsquedas DNS ($>10$), directivas `+all` o ausencia de registro. |
| **DKIM (DomainKeys Identified Mail)** | RFC 6376 | Firma criptográfica de cabeceras y cuerpo. | Claves RSA obsoletas ($<1024$ o $<2048$ bits) o selectores no descubiertos. |
| **DMARC** | RFC 7489 | Política de alineación y reporte (SPF/DKIM). | Políticas débiles (`p=none`), falta de reporte `rua`/`ruf` o desalineación de subdominios. |
| **MTA-STS** | RFC 8461 | Cifrado obligatorio TLS en tránsito SMTP. | Modo laxo (`testing`, `none`), certificados inválidos o falta de política. |
| **DANE para SMTP** | RFC 7672 | Anclaje de certificados TLS mediante DNSSEC. | Registros TLSA tipo 52 ausentes o DNSSEC sin delegación firmada. |
| **BIMI / TLS-RPT** | RFC 8460 / Draft | Identidad visual de marca y telemetría TLS. | Registros `v=bimi1` o `v=tlsrptv1` malformados. |

---

## 🔍 2. Auditoría de SPF y Límite de 10 Consultas DNS (RFC 7208)

### El Riesgo de DoS y Amplificación
El estándar RFC 7208 estipula que la evaluación de un registro SPF **no debe requerir más de 10 consultas DNS acumuladas** (`include`, `a`, `mx`, `ptr`, `exists`, `redirect`). Si la cadena de inclusiones excede 10 lookups, los servidores receptores abortan la validación con `PermError`, lo cual puede provocar:
1. Rechazo legítimo de correos corporativos.
2. Degradación a fallo abierto (*Fail-Open*) en receptores mal configurados, permitiendo suplantación de identidad (spoofing).

### Algoritmo Determinista de Conteo Recursivo de Lookups
```typescript
const LOOKUP_TERMS = ['include', 'redirect', 'a', 'mx', 'ptr', 'exists'];

async function countSpfLookups(record: string, followed = new Set<string>()): Promise<number> {
  let count = 0;
  for (const term of record.toLowerCase().split(' ')) {
    const bare = '+-~?'.includes(term[0]) ? term.slice(1) : term;
    const name = bare.split(':')[0].split('=')[0].split('/')[0];
    if (!LOOKUP_TERMS.includes(name)) continue;
    
    count += 1;
    const target = bare.slice(name.length + 1);
    if ((name === 'include' || name === 'redirect') && !target.includes('%') && !followed.has(target)) {
      followed.add(target);
      const childSpf = await resolveSpfRecord(target);
      count += await countSpfLookups(childSpf, followed);
    }
  }
  return count;
}
```

> [!WARNING]
> Un conteo de búsquedas DNS $\ge 10$ debe clasificarse como hallazgo de severidad **MEDIUM** bajo `CONFIGURATION_HARDENING` (CWE-20 / RFC 7208 violation).

---

## 🔑 3. Descubrimiento de Selectores DKIM y Criptoanálisis de Claves RSA

### Descubrimiento Sistemático de Selectores
A diferencia de SPF o DMARC, los registros DKIM residen en subdominios indocumentados con la estructura:
$$\text{selector}._\text{domainkey}.\text{domain}$$
Un auditor debe probar de forma concurrente el conjunto canónico de selectores utilizados por los principales proveedores mundiales:
- **Genéricos:** `default`, `selector1`, `selector2`, `k1`, `k2`, `k3`, `s1`, `s2`, `dkim`, `mail`.
- **Google Workspace:** `google`.
- **Microsoft 365 / Outlook:** `selector1`, `selector2`.
- **ProtonMail:** `protonmail`, `protonmail2`, `protonmail3`.
- **Fastmail:** `fm1`, `fm2`, `fm3`.
- **Brevo / Sendinblue:** `brevo1`, `brevo2`.
- **Hostinger:** `hostingermail-a`, `hostingermail-b`, `hostingermail-c`.

### Validación Criptográfica del Tamaño de Clave (Node.js / Python)
Un registro DKIM almacena la clave pública codificada en Base64 bajo el parámetro `p=`:
```typescript
import crypto from 'crypto';

function evaluateDkimKeyBits(base64PublicKey: string): { bits: number | null; isWeak: boolean } {
  try {
    const derBuffer = Buffer.from(base64PublicKey, 'base64');
    const pubKey = crypto.createPublicKey({ key: derBuffer, format: 'der', type: 'spki' });
    const bits = pubKey.asymmetricKeyDetails?.modulusLength ?? null;
    return {
      bits,
      isWeak: bits !== null && bits < 2048 // RSA < 2048 bits se considera débil
    };
  } catch {
    return { bits: null, isWeak: true };
  }
}
```

> [!CRITICAL]
> Claves DKIM RSA de 512 bits o 1024 bits son factorizables en tiempos accesibles mediante computación distribuida o en la nube (CWE-326). Todo registro DKIM con longitud de módulo menor a 2048 bits debe clasificarse como `VULN-CRYP-002` (High / Medium).

---

## 🔒 4. MTA-STS y DANE: Protección contra Ataques Man-in-the-Middle (MitM) en SMTP

### MTA-STS (Mail Transfer Agent Strict Transport Security - RFC 8461)
1. **Registro DNS:** `_mta-sts.<domain>` debe contener `v=STSv1; id=<timestamp_or_hash>`.
2. **Archivo de Política:** Debe servirse estrictamente sobre HTTPS en:
   `https://mta-sts.<domain>/.well-known/mta-sts.txt`
3. **Invariantes Requeridos:**
   - Cabecera HTTPS válida con certificado público de confianza.
   - `version: STSv1`
   - `mode: enforce` (el modo `testing` o `none` no protege contra degradación STARTTLS).
   - `mx: <hostname>` coincidente con los registros MX del dominio.
   - `max_age: >= 604800` (mínimo 1 semana).

### DANE para SMTP (RFC 7672)
1. **Prerrequisito Inmutable:** La zona DNS del dominio debe estar firmada criptográficamente mediante **DNSSEC** (`delegationSigned: true`).
2. **Registro TLSA:** Consulta del tipo 52 en:
   `_25._tcp.<mx_exchange>`
3. **Verificación de Autenticidad:** La respuesta debe contener el flag `AD` (Authenticated Data) habilitado por el resolver.

---

## 📋 5. Checklist de Verificación para Auditorías

- [ ] Registro SPF existe y su política terminal es restrictiva (`-all` o `~all`).
- [ ] El conteo recursivo de consultas DNS de SPF es $\le 10$.
- [ ] Registro DMARC publicado en `_dmarc.<domain>` con `p=reject` o `p=quarantine`.
- [ ] Si el objetivo es un subdominio, verificar si hereda la política del dominio organizativo raíz.
- [ ] Correo electrónico cuenta con selectores DKIM descubiertos y claves RSA $\ge 2048$ bits.
- [ ] Detección de política MTA-STS activa y en modo `enforce`.
- [ ] Existencia de registros de telemetría de fallos TLS (`_smtp._tls.<domain>` con `v=TLSRPTv1`).
- [ ] Comprobación de anclaje DANE TLSA sobre intercambiadores MX con soporte DNSSEC.
