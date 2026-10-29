# Endurecimiento de Seguridad en Capa de Transporte: TLS 1.3 y Suites de Cifrado Modernas

Esta referencia técnica consolida los requisitos autoritativos para la configuración, validación y auditoría de canales seguros mediante **TLS 1.3 (RFC 8446)** y suites de cifrado modernas en **Devia-CyberSecurity**.

---

## 🏛️ 1. Principios Criptográficos Inmutables de TLS 1.3

1. **Eliminación de Suites de Cifrado Obsoletas:**
   TLS 1.3 erradica por diseño el soporte para algoritmos obsoletos y vulnerables:
   - Eliminados: RSA key exchange estático (sin Perfect Forward Secrecy).
   - Eliminados: CBC mode ciphers (vulnerables a padding oracles como BEAST, POODLE, Lucky13).
   - Eliminados: RC4, 3DES, MD5, SHA-1.
2. **Perfect Forward Secrecy (PFS) Obligatorio:**
   Todo intercambio de claves debe operar mediante ECDHE (Elliptic Curve Diffie-Hellman Ephemeral) o DHE, garantizando que el compromiso futuro de la clave privada de largo plazo del servidor no permita descifrar sesiones pasadas grabadas.
3. **Cifrado Autenticado con Datos Asociados (AEAD):**
   Todas las suites TLS 1.3 son estrictamente AEAD (AES-GCM, ChaCha20-Poly1305, AES-CCM), impidiendo ataques de manipulación de integridad de texto cifrado.

---

## 🔒 2. Suites de Cifrado Canónicas

### Suites Exclusivas de TLS 1.3 (RFC 8446)
- `TLS_AES_256_GCM_SHA384` (Máxima seguridad recomendada)
- `TLS_CHACHA20_POLY1305_SHA256` (Óptimo para clientes sin aceleración hardware AES)
- `TLS_AES_128_GCM_SHA256` (Estándar de alto rendimiento)

### Suites de Compatibilidad Restringida TLS 1.2 (Solo si es indispensable)
- `ECDHE-ECDSA-AES256-GCM-SHA384`
- `ECDHE-RSA-AES256-GCM-SHA384`
- `ECDHE-ECDSA-CHACHA20-POLY1305`
- `ECDHE-RSA-CHACHA20-POLY1305`

> [!WARNING]
> Deshabilitar explícitamente TLS 1.0 y TLS 1.1 en todos los servidores web, APIs y proxies reversos.

---

## 🛡️ 3. Protección contra Repetición en 0-RTT (Early Data)

La característica 0-RTT de TLS 1.3 permite enviar datos en el primer paquete del handshake al reanudar sesiones, pero **no ofrece protección contra ataques de repetición (Replay Attacks)**.

### Reglas de Auditoría Defensiva:
1. **Deshabilitar 0-RTT** en endpoints que ejecuten mutaciones de estado (POST, PUT, DELETE, transferencias de fondos o autenticación).
2. Si 0-RTT está activo en servidores perimetrales (Cloudflare, Nginx), exigir encabezado `Early-Data: 1` y validar que la aplicación rechace peticiones no idempotentes recibidas con datos tempranos:
   ```nginx
   # Nginx Early Data Protection
   proxy_set_header Early-Data $ssl_early_data;
   ```
   En la aplicación: Si `$ssl_early_data == "1"` y el método es no idempotente (`POST`), devolver HTTP `425 Too Early`.

---

## 🔍 4. Verificación de Canales con OpenSSL

Para auditar de forma determinista un servidor sin herramientas invasivas:

```bash
# Probar soporte TLS 1.3 y verificar cipher negociado
openssl s_client -connect <host>:443 -tls1_3 -brief < /dev/null

# Confirmar que TLS 1.0 y 1.1 son rechazados
openssl s_client -connect <host>:443 -tls1 < /dev/null
openssl s_client -connect <host>:443 -tls1_1 < /dev/null
```
