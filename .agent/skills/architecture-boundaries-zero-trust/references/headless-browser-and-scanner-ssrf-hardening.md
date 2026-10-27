# Blindaje Anti-SSRF y Hardening de Navegadores Headless en Motores de Escaneo y Auditoría

Este documento establece las directivas canónicas de arquitectura segura, mitigación contra SSRF y confinamiento de navegadores headless (Chromium / Puppeteer) en herramientas y plataformas de auditoría en **Devia-CyberSecurity**.

---

## 🏛️ 1. La Trampa de los Escáneres Web: De Herramienta Defensiva a Proxy de Ataque

Las aplicaciones de reconocimiento web y OSINT (como se analizó en `web-check`) frecuentemente intentan procesar cualquier URL que un operador suministra. Si la aplicación carece de controles rigurosos de frontera de red, se convierte en un arma de doble filo:

```
[Atacante Externo] ──> [API de Escaneo /api/ports?url=10.0.0.1] ──> [Intranet Corporativa / AWS IMDS]
                       (Actúa como Proxy SSRF no autenticado)
```

### Los 5 Antipatrones Críticos Identificados en web-check

1. **Apertura Indiscriminada de Sockets TCP Crudos (`ports.js` - VULN-SAST-012):**
   Conectar sockets `net.Socket` contra puertos sensibles (22, 3306, 5432, 8080) sin comprobar si el host destino es una IP privada (`127.0.0.1`, `10.0.0.0/8`, `192.168.0.0/16`, `172.16.0.0/12`, `169.254.169.254`). Permite a cualquier atacante remoto utilizar la aplicación como un escáner de puertos de la red interna del anfitrión.
2. **Exfiltración de Intranet vía Captura de Pantalla Headless (`screenshot.js` - VULN-SAST-013):**
   Navegar con Chromium hacia URLs internas y devolver la imagen renderizada en Base64 al cliente externo, divulgando paneles de administración internos, consolas de monitoreo o metadatos de nube.
3. **Ejecución de Chromium con `--no-sandbox` como Usuario `root` en Docker (`Dockerfile` - VULN-ARCH-017):**
   Al no declarar un usuario no privilegiado (`USER node`), el contenedor ejecuta el runtime y los subprocesos como `root`. Para eludir la negativa de Chromium a correr como root, los desarrolladores desactivan el sandbox (`--no-sandbox`). Cualquier vulnerabilidad de renderizado en el navegador permite un escape completo a ejecución de código como root en el host.
4. **Bypass de Filtros por Omisión de Resolución DNS (DNS Rebinding):**
   Validar únicamente cadenas literales de texto (`target === 'localhost'`) sin resolver el nombre de dominio a una dirección IP antes de emitir la conexión. Un atacante configura `evil.com` para que apunte a `127.0.0.1` o `169.254.169.254`, eludiendo completamente filtros sintácticos.
5. **Seguimiento Descontrolado de Redirecciones HTTP (`_common/http.js` - VULN-CONF-006):**
   Configurar `redirect: 'follow'` en clientes HTTP automáticos. El servidor atacante en alcance devuelve un salto `302 Found` con `Location: http://169.254.169.254/latest/meta-data/`, saltándose cualquier control previo sobre la URL inicial.

---

## 🛡️ 2. Patrón Seguro de Validación Pre-Flight con Resolución DNS Estricta

Para evitar SSRF, toda herramienta que realice peticiones de red o conexiones socket DEBE resolver el nombre de dominio y contrastar la IP resultante contra la lista canónica de exclusiones antes de cualquier conexión:

```typescript
import dns from 'dns/promises';
import ipaddr from 'ipaddr.js';

const DISALLOWED_RANGES = [
  'unspecified',
  'broadcast',
  'multicast',
  'linkLocal',
  'loopback',
  'private',
  'carrierGradeNat'
];

export async function validateHostForNetworkAccess(hostname: string): Promise<string> {
  // 1. Normalizar y eliminar punto final de FQDN
  const cleanHost = hostname.toLowerCase().trim().replace(/\.$/, '');

  // 2. Rechazar nombres de loopback obvios
  if (cleanHost === 'localhost' || cleanHost.endsWith('.local') || cleanHost.endsWith('.internal')) {
    throw new SecurityException(`Host interno o no enrutable rechazado: ${cleanHost}`);
  }

  // 3. Resolución DNS Pre-Flight (IPv4 e IPv6)
  const addresses = await dns.resolve(cleanHost).catch(async () => {
    return [(await dns.lookup(cleanHost)).address];
  });

  if (!addresses.length) {
    throw new SecurityException(`No se pudo resolver el host: ${cleanHost}`);
  }

  // 4. Validar cada IP resuelta
  for (const addr of addresses) {
    const ip = ipaddr.parse(addr);
    const range = ip.range();

    if (DISALLOWED_RANGES.includes(range)) {
      throw new SecurityException(`Dirección IP denegada (${range}): ${addr}`);
    }

    // 5. Bloquear explícitamente Cloud Metadata IMDS (IPv4 e IPv6)
    if (addr === '169.254.169.254' || addr.startsWith('169.254.') || addr.startsWith('fd00:ec2:')) {
      throw new SecurityException(`Endpoint de metadatos cloud IMDS bloqueado: ${addr}`);
    }
  }

  return cleanHost;
}
```

---

## 🐳 3. Hardening de Contenedores Docker para Navegadores Headless

### Principio Fundamental: Jamás Ejecutar Chromium como Root
1. **Crear Usuario sin Privilegios:**
   ```dockerfile
   # Crear usuario de sistema dedicado
   RUN groupadd -r scanner && useradd -r -g scanner -G audio,video scanner \
       && mkdir -p /home/scanner/Downloads \
       && chown -R scanner:scanner /home/scanner \
       && chown -R scanner:scanner /app
   
   USER scanner
   ```
2. **Preservar el Sandbox de Chromium:**
   Queda terminantemente prohibido utilizar `--no-sandbox` en entornos de producción. Para permitir que Chromium cree su espacio de nombres de usuario sin requerir `root`, configurar perfiles `seccomp` apropiados o ejecutar con capacidades acotadas:
   ```yaml
   security_opt:
     - seccomp:unconfined # O preferiblemente un perfil seccomp ajustado a Chrome
   ```
3. **Aislamiento de Red Egress a Nivel de Kernel (`nftables` / Docker Network):**
   Configurar una red interna aislada sin acceso a la interfaz de loopback del host ni a la subred de metadatos:
   ```bash
   iptables -A DOCKER-USER -d 169.254.169.254 -j DROP
   iptables -A DOCKER-USER -d 10.0.0.0/8 -j DROP
   iptables -A DOCKER-USER -d 192.168.0.0/16 -j DROP
   ```

---

## 🔒 4. Salvaguardas para Navegación con Puppeteer

Al automatizar capturas de pantalla o extracción de cookies:
```typescript
const page = await browser.newPage();

// Interceptar y validar cada petición emitida por la página
await page.setRequestInterception(true);
page.on('request', async (req) => {
  const url = req.url();
  try {
    const parsed = new URL(url);
    if (!['http:', 'https:'].includes(parsed.protocol)) {
      return req.abort(); // Bloquear file://, gopher://, chrome://
    }
    // Validar destino antes de permitir la conexión
    await validateHostForNetworkAccess(parsed.hostname);
    req.continue();
  } catch {
    req.abort();
  }
});
```

---

## 📋 5. Checklist de Verificación para Agentes y Escáneres

- [ ] Todas las conexiones de red salientes validan la IP resultante mediante resolución DNS pre-flight.
- [ ] No existen sockets TCP crudos que se conecten directamente a IPs no autorizadas.
- [ ] Los subprocesos de navegadores headless operan bajo un usuario sin privilegios (`USER scanner`).
- [ ] Se erradicaron las banderas `--no-sandbox` y `--disable-setuid-sandbox` en producción.
- [ ] El cliente HTTP rechaza o revalida las redirecciones intermedias (301/302).
- [ ] Las APIs de escaneo exigen autenticación y no exponen políticas CORS con comodín (`*`).
