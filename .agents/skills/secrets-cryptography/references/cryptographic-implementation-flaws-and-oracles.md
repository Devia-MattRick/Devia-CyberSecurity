# Catálogo de Fallas de Implementación Criptográfica y Ataques a Oráculos (Cryptographic Implementation Flaws & Oracles)

Este documento establece las directivas y patrones de evaluación estática y dinámica para detectar debilidades en la implementación práctica de primitivas criptográficas (**Cifradores de Bloque**, **Modos de Operación**, **MACs** y **PRNGs**), erradicando fallos catastróficos que anulan la confidencialidad e integridad del sistema.

---

## 🏛️ Taxonomía y Mapeo Multimarco

| Marco de Seguridad | Identificador | Denominación Oficial |
| :--- | :--- | :--- |
| **Dimensión Canónica** | `SECRETS_CRYPTOGRAPHY` | Criptografía, Secretos y Gestión de Entropía |
| **Catálogo Devia** | [`VULN-CRYP-003`](file:///docs/VULNERABILITIES.md) | Insecure Cipher Mode (AES-ECB & CBC Padding Oracles) |
| **Catálogo Devia** | [`VULN-CRYP-004`](file:///docs/VULNERABILITIES.md) | Insufficiently Random Values (Weak PRNG State Recovery) |
| **CWE** | [`CWE-327`](https://cwe.mitre.org/data/definitions/327.html) | Use of a Broken or Risky Cryptographic Algorithm |
| **CWE** | [`CWE-328`](https://cwe.mitre.org/data/definitions/328.html) | Use of Weak Hash |
| **CWE** | [`CWE-330`](https://cwe.mitre.org/data/definitions/330.html) | Use of Insufficiently Random Values |
| **CWE** | [`CWE-208`](https://cwe.mitre.org/data/definitions/208.html) | Observable Timing Discrepancy |
| **OWASP Top 10** | `A02:2021` | Cryptographic Failures |
| **MITRE ATT&CK** | `T1552` | Unsecured Credentials |

---

## 🔍 1. Principio Fundamental: Primitivas vs Implementación

> [!IMPORTANT]
> **Axioma Criptográfico de Implementación:**  
> La casi totalidad de las brechas criptográficas modernas **NO** ocurren por debilidades matemáticas en los algoritmos base (como AES o SHA-256), sino por el **mal uso de los modos de operación, esquemas de relleno (*padding*), reutilización de nonces, comparaciones no constantes y generadores pseudoaleatorios predecibles**.

---

## ⚠️ 2. Catálogo de Fallas Críticas de Implementación

### 2.1. Ataques a Oráculos de Relleno en Modo CBC (Padding Oracle Attack - Vaudenay)
- **Mecanismo:** En modo Cipher Block Chaining (CBC) con relleno PKCS#7, el descifrado valida el formato de relleno del último bloque antes de procesar el texto plano. Si la aplicación revela directa o indirectamente (mediante códigos HTTP 500 vs 200, mensajes de error distintos o diferencias de tiempo) si el relleno es válido, actúa como un **oráculo criptográfico**.
- **Impacto:** Permite a un atacante con acceso al texto cifrado descifrar bloque por bloque el contenido original sin conocer la clave secreta $K$, y forjar textos cifrados arbitrarios válidos.
- **Detección SAST:**
  ```python
  # Antipatrón Vulnerable:
  from Crypto.Cipher import AES
  cipher = AES.new(key, AES.MODE_CBC, iv) # CBC sin autenticación HMAC posterior
  decrypted = unpad(cipher.decrypt(data), 16) # Lanza excepción detectable por el cliente
  ```
- **Remediación:** Abandonar CBC sin autenticar. Migrar mandatoriamente a cifrado autenticado con datos asociados (**AEAD**), preferentemente **AES-GCM** o **ChaCha20-Poly1305**.

---

### 2.2. Determinismo y Ataques de Corta-Pega en Modo ECB (Electronic Codebook)
- **Mecanismo:** ECB cifra cada bloque de 16 bytes de forma totalmente independiente utilizando la misma clave:
  $$C_i = E_K(P_i)$$
  Bloques idénticos de texto plano producen bloques idénticos de texto cifrado. Carece por completo de difusión y seguridad semántica (IND-CPA).
- **Impacto:** Permite deducir patrones visuales o estructurales de los datos (e.g. el pingüino de Tux) y realizar ataques de transposición (*cut-and-paste*), intercambiando bloques de permisos o IDs de usuario sin romper la clave.
- **Remediación:** Prohibir terminantemente `AES.MODE_ECB`. Utilizar siempre esquemas AEAD.

---

### 2.3. Catástrofe de Reutilización de Nonce en AES-GCM (Nonce-Reuse Disaster)
- **Mecanismo:** AES-GCM combina el modo Counter (CTR) para confidencialidad con un multiplicador sobre el cuerpo finito $\text{GF}(2^{128})$ (GHASH) para integridad. Si se reutiliza el mismo Nonce/IV (generalmente de 96 bits) con la misma clave secreta en dos mensajes distintos:
  1. La operación XOR de los textos cifrados revela el XOR de los textos planos:
     $$C_1 \oplus C_2 = P_1 \oplus P_2$$
  2. Mediante la resolución de raíces polinómicas sobre $\text{GF}(2^{128})$, se puede recuperar directamente la clave de autenticación $H = E_K(0^{128})$.
- **Impacto:** Una vez obtenida $H$, el atacante puede forjar etiquetas de autenticación (MAC tags) para cualquier mensaje arbitrario, destruyendo la integridad del canal.
- **Remediación:**
  - Emplear nonces deterministas de 96 bits generados por un contador monotónico estricto o generadores criptográficos de 12 bytes (`secrets.token_bytes(12)`).
  - Si no se puede garantizar la no-repetición de nonces por volumen masivo, migrar a **AES-GCM-SIV** (RFC 8452, Synthetic Initialization Vector), resistente a la reutilización accidental de nonces.

---

### 2.4. Ataque de Extensión de Longitud en Funciones Hash Merkle-Damgård
- **Mecanismo:** Las funciones hash basadas en la construcción Merkle-Damgård (**MD5**, **SHA-1**, **SHA-256**, **SHA-512**) procesan datos en bloques secuenciales donde la salida de cada bloque es el estado interno del siguiente.
  Si un desarrollador construye una MAC artesanal mediante concatenación:
  $$\text{MAC}(M) = H(\text{secret} \parallel M)$$
  Un atacante que conoce $\text{len}(\text{secret})$, $M$ y el valor hash puede añadir datos maliciosos adicionales ($M \parallel \text{padding} \parallel M'$) y continuar el cálculo del hash desde el estado previo, generando una firma válida **sin conocer el secreto**.
- **Remediación:**
  - Prohibir construcciones artesanales $H(\text{key} \parallel \text{data})$.
  - Utilizar **HMAC** formal (RFC 2104: $\text{HMAC}(K, M) = H((K \oplus \text{opad}) \parallel H((K \oplus \text{ipad}) \parallel M))$).
  - Alternativamente, emplear primitivas no vulnerables a extensión de longitud (SHA-3, BLAKE3 o KMAC).

---

### 2.5. Recuperación de Estado en Generadores Pseudoaleatorios Débiles (Weak PRNG)
- **Mecanismo:** Algoritmos como **Mersenne Twister** (`MT19937`, utilizado por defecto en `random` de Python, `Math.random` en V8 y PHP `rand()`) están diseñados para simulación estadística rápida, no para seguridad criptográfica. Observando **624 números consecutivos de 32 bits**, un atacante puede invertir la función de templado (*temper function*) y reconstruir el estado interno completo del generador, prediciendo la totalidad de tokens futuros o pasados.
- **Remediación:**
  - En Python: Usar exclusivamente el módulo `secrets` (`secrets.token_hex()`, `secrets.token_bytes()`).
  - En Node.js: Usar `crypto.randomBytes()` o `crypto.getRandomValues()`.
  - En Go: Usar `crypto/rand`.

---

### 2.6. Canales Laterales Temporales (Timing Attacks en Comparación de Secretos)
- **Mecanismo:** La comparación estándar de cadenas (`==`, `strcmp`, `memcmp`) finaliza en el primer byte discordante (*early-exit*). Midiendo las variaciones en microsegundos del tiempo de respuesta, un atacante remoto puede inferir los caracteres del token o firma uno a uno.
- **Remediación:** Usar funciones de comparación en tiempo constante:
  - Python: `hmac.compare_digest(token_a, token_b)`
  - Node.js: `crypto.timingSafeEqual(buf_a, buf_b)`
  - Go: `subtle.ConstantTimeCompare(a, b)`

---

## 🛡️ 3. Blueprints de Implementación Segura

### 3.1. Cifrado Autenticado con Datos Asociados (AES-256-GCM en Python)

```python
# Blueprint Seguro en Python (cryptography >= 42.0)
from os import urandom
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

class SecureVaultCipher:
    def __init__(self, key: bytes):
        if len(key) != 32:
            raise ValueError("La clave debe tener exactamente 256 bits (32 bytes)")
        self.aesgcm = AESGCM(key)

    def encrypt(self, plaintext: bytes, associated_data: bytes = b"") -> bytes:
        # Nonce de 96 bits (12 bytes) generado criptográficamente para cada operación
        nonce = urandom(12)
        # AESGCM.encrypt concatena automáticamente el tag de autenticación (16 bytes) al final
        ciphertext = self.aesgcm.encrypt(nonce, plaintext, associated_data)
        # Retornar nonce prepended al ciphertext+tag
        return nonce + ciphertext

    def decrypt(self, payload: bytes, associated_data: bytes = b"") -> bytes:
        if len(payload) < 28: # 12 bytes nonce + 16 bytes mínimo de tag
            raise ValueError("Cifrado malformado o incompleto")
        nonce = payload[:12]
        ciphertext = payload[12:]
        # Verifica la etiqueta de integridad en tiempo constante antes de emitir plaintext
        return self.aesgcm.decrypt(nonce, ciphertext, associated_data)
```

---

### 3.2. Cifrado Autenticado en Node.js (Crypto Nativo)

```typescript
// Blueprint Seguro en TypeScript / Node.js
import crypto from 'node:crypto';

export class SecureCryptoService {
  private static readonly ALGORITHM = 'aes-256-gcm';
  private static readonly IV_LENGTH = 12;
  private static readonly TAG_LENGTH = 16;

  public static encrypt(plaintext: Buffer, key: Buffer): Buffer {
    if (key.length !== 32) throw new Error('Clave inválida: se requieren 32 bytes');
    const iv = crypto.randomBytes(this.IV_LENGTH);
    const cipher = crypto.createCipheriv(this.ALGORITHM, key, iv);
    const encrypted = Buffer.concat([cipher.update(plaintext), cipher.final()]);
    const authTag = cipher.getAuthTag();
    return Buffer.concat([iv, authTag, encrypted]);
  }

  public static decrypt(payload: Buffer, key: Buffer): Buffer {
    if (payload.length < this.IV_LENGTH + this.TAG_LENGTH) {
      throw new Error('Payload criptográfico truncado');
    }
    const iv = payload.subarray(0, this.IV_LENGTH);
    const authTag = payload.subarray(this.IV_LENGTH, this.IV_LENGTH + this.TAG_LENGTH);
    const ciphertext = payload.subarray(this.IV_LENGTH + this.TAG_LENGTH);

    const decipher = crypto.createDecipheriv(this.ALGORITHM, key, iv);
    decipher.setAuthTag(authTag);
    // Lanza excepción si el tag de integridad no coincide (fail-closed)
    return Buffer.concat([decipher.update(ciphertext), decipher.final()]);
  }
}
```

---

## 📋 4. Checklist de Auditoría de Criptografía

El auditor debe verificar obligatoriamente en cada punto de cifrado:

- [ ] **Modo Seguro:** Prohibido el uso de `ECB` y `CBC` no autenticado. Todos los cifradores emplean `AES-GCM` o `ChaCha20-Poly1305`.
- [ ] **Unicidad de Nonce:** Los nonces de cifradores de flujo/GCM tienen longitud adecuada ($\ge 96\text{ bits}$) y nunca se repiten para una misma clave.
- [ ] **MACs Formales:** Las firmas de mensajes emplean `HMAC-SHA256` o `KMAC`, erradicando concatenaciones $H(\text{secret} \parallel \text{msg})$.
- [ ] **Generadores CSPRNG:** Todos los tokens, IVs, nonces y saltos provienen de `secrets` (Python), `crypto.randomBytes` (Node.js) o `crypto/rand` (Go), nunca de `random` o `Math.random`.
- [ ] **Comparación Segura:** Todas las validaciones de hashes, contraseñas o tokens comparan en tiempo constante (`hmac.compare_digest` o `timingSafeEqual`).
- [ ] **Longitud de Claves:** Claves simétricas $\ge 256\text{ bits}$ y RSA $\ge 3072\text{ bits}$ (o migración a Ed25519 / P-384).
