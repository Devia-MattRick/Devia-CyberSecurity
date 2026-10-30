# Criptografía Client-Side BYOK y Bóvedas Locales AES-GCM 256-bit

> **ID de Vulnerabilidad:** `VULN-CRYP-001`  
> **Taxonomía:** CWE-312 (*Cleartext Storage of Sensitive Information*) / CWE-326 (*Inadequate Encryption Strength*) / OWASP Top 10 A02:2021/2025  
> **Dimensión:** `SECRETS_CRYPTOGRAPHY`  
> **Skill:** `secrets-cryptography`  

---

## 1. El Principio BYOK Soberano (Bring Your Own Key)

En aplicaciones que operan bajo el modelo **BYOK (Bring Your Own Key)**, el usuario proporciona sus propias claves de API para proveedores de IA (Gemini, OpenAI, Anthropic). Para mantener una postura **Zero-Trust & Zero-Leak**:
1. **Cero Servidores Intermedios:** Las claves jamás deben transmitirse a un backend propio o proxy intermediario.
2. **Cero Texto Plano en Almacenamiento Local:** Guardar claves en texto plano en `localStorage` o `sessionStorage` las expone a cualquier script inyectado vía XSS o extensiones maliciosas del navegador.
3. **Cifrado en Reposo con Web Crypto API:** Se debe utilizar la API criptográfica estándar del navegador (`window.crypto.subtle`) con algoritmos simétricos autenticados.

---

## 2. Arquitectura de la Bóveda Criptográfica Local (`LocalVaultCrypto`)

```
[Clave de API en Memoria]
            │
            ▼
[Derivación de Clave Maestra]
PBKDF2-HMAC-SHA256 (100,000 iteraciones) + Salt Criptográfico Único
            │
            ▼
[Cifrado Autenticado AES-GCM 256-bit]
Generación de IV aleatorio de 12 bytes + Tag de Autenticación de 16 bytes
            │
            ▼
[Persistencia Segura en IndexedDB / localStorage]
Estructura Serializada: { salt: base64, iv: base64, ciphertext: base64 }
```

### Implementación Canónica en TypeScript
```typescript
export class LocalVaultCrypto {
  private static readonly ITERATIONS = 100000;
  private static readonly KEY_LENGTH = 256;

  public static async deriveKey(passphrase: string, salt: Uint8Array): Promise<CryptoKey> {
    const encoder = new TextEncoder();
    const keyMaterial = await window.crypto.subtle.importKey(
      'raw',
      encoder.encode(passphrase),
      { name: 'PBKDF2' },
      false,
      ['deriveKey']
    );

    return window.crypto.subtle.deriveKey(
      {
        name: 'PBKDF2',
        salt: salt as BufferSource,
        iterations: this.ITERATIONS,
        hash: 'SHA-256'
      },
      keyMaterial,
      { name: 'AES-GCM', length: this.KEY_LENGTH },
      false,
      ['encrypt', 'decrypt']
    );
  }

  public static async encryptSecret(secret: string, masterPass: string): Promise<string> {
    const salt = window.crypto.getRandomValues(new Uint8Array(16));
    const iv = window.crypto.getRandomValues(new Uint8Array(12));
    const key = await this.deriveKey(masterPass, salt);
    
    const encoded = new TextEncoder().encode(secret);
    const ciphertext = await window.crypto.subtle.encrypt(
      { name: 'AES-GCM', iv: iv as BufferSource },
      key,
      encoded
    );

    return JSON.stringify({
      salt: Array.from(salt),
      iv: Array.from(iv),
      data: Array.from(new Uint8Array(ciphertext))
    });
  }
}
```

---

## 3. Centinela Anti-Sobreescritura (Reactive Sentinel)

Un error frecuente en SPAs con estado reactivo (Angular Signals, Pinia, Redux) es la sobreescritura accidental de claves durante la hidratación inicial: un efecto reactivo que vigila el estado de configuración detecta una clave vacía antes de que la bóveda termine de descifrarse y sobreescribe el almacenamiento con valores en blanco.

**Línea de Defensa:**  
Implementar un centinela `isVaultReady` o `isHydrated` como señal reactiva booleana. Todo efecto de sincronización hacia el almacenamiento debe validar `if (!this.isVaultReady()) return;` antes de ejecutar escrituras.

---

## 4. Checklist de Auditoría

- [ ] ¿Las claves de API se cifran mediante AES-GCM 256-bit con derivación PBKDF2 de al menos 100,000 iteraciones?
- [ ] ¿Existe ausencia de claves de API en texto plano dentro de `localStorage` o cookies?
- [ ] ¿Las llamadas a consola (`console.log`, `console.error`) filtran o eliminan las cabeceras `Authorization` y `x-goog-api-key`?
- [ ] ¿Los efectos reactivos de guardado validan el centinela de inicialización para prevenir sobreescrituras en blanco?
