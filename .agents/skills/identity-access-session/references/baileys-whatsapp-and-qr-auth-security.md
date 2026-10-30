# Seguridad en Protocolos de Mensajería: Baileys WhatsApp Multi-Device y QR Fixation

> **ID de Vulnerabilidad:** `VULN-IAM-017`  
> **Taxonomía:** CWE-384 (*Session Fixation*) / CWE-287 (*Improper Authentication*) / OWASP Top 10 A07:2021/2025  
> **Dimensión:** `IDENTITY_ACCESS_SESSION`  
> **Skill:** `identity-access-session`  

---

## 1. Superficie de Ataque en Integraciones con Baileys

La biblioteca Baileys interactúa directamente con los WebSockets de WhatsApp Web sin depender de navegadores Selenium o Puppeteer. Esta arquitectura expone una superficie de ataque única:
1. **Fijación y Replay de Código QR:** Códigos QR mostrados a usuarios que pueden ser interceptados o generados por un atacante para vincular cuentas de WhatsApp no autorizadas.
2. **Exposición de Credenciales `auth_state` en Disco:** Los tokens de sesión (`creds.json`, claves pre-compartidas Noise protocol) almacenados en disco sin cifrado robusto permiten el secuestro completo de la sesión.
3. **Falta de Rotación o Revocación:** Sesiones desvinculadas desde el teléfono que continúan respondiendo localmente o viceversa.
4. **Riesgos de Cumplimiento TCPA / WhatsApp Business:** Envío masivo sin control de consentimientos (opt-in) que provoca bloqueos de cuenta (bans) y contingencias legales.

---

## 2. Almacenamiento Seguro del `auth_state`

### Antipatrón Vulnerable
```typescript
// VULNERABLE — Clave estática y salt fijo
const appSecret = process.env.APP_SECRET || 'default-secret-change-me';
const key = crypto.pbkdf2Sync(machineId + appSecret, 'baileys-salt', 100000, 32, 'sha256');
const cipher = crypto.createCipheriv('aes-256-cbc', key, iv);
```

### Implementación Canónica y Segura
```typescript
import * as crypto from 'crypto';
import { safeStorage } from 'electron'; // O DPAPI / Keychain nativo

export class SecureBaileysSessionManager {
  // 1. Usar safeStorage del sistema operativo para derivar clave maestra
  public static async encryptSessionPayload(sessionJson: string): Promise<Buffer> {
    const rawBuffer = Buffer.from(sessionJson, 'utf-8');
    if (safeStorage.isEncryptionAvailable()) {
      return safeStorage.encryptString(sessionJson);
    }
    
    // Fallback con salt aleatorio almacenado y PBKDF2
    const salt = crypto.randomBytes(16);
    const key = crypto.pbkdf2Sync(process.env.APP_MASTER_KEY!, salt, 250000, 32, 'sha256');
    const iv = crypto.randomBytes(12);
    const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
    
    const encrypted = Buffer.concat([cipher.update(rawBuffer), cipher.final()]);
    const tag = cipher.getAuthTag();
    
    // Estructura: [salt (16)] + [iv (12)] + [tag (16)] + [encrypted]
    return Buffer.concat([salt, iv, tag, encrypted]);
  }
}
```

---

## 3. Mitigación de Fijación de Código QR

1. **Timeout Estricto de QR:** Un código QR generado para vinculación DEBE expirar en un máximo de **45 a 60 segundos**.
2. **Generación One-Time:** Al escanear el QR, invalidar de inmediato el canal de visualización para impedir segundos escaneos.
3. **Confirmación Visual:** Mostrar al usuario el número telefónico vinculado reportado por el evento `connection.update` antes de habilitar el envío de mensajes.

---

## 4. Checklist de Auditoría

- [ ] ¿Los archivos `auth_state` de Baileys se almacenan cifrados mediante AES-GCM 256 o safeStorage nativo?
- [ ] ¿Se eliminan completamente las credenciales locales cuando se detecta el código `DisconnectReason.loggedOut`?
- [ ] ¿Los códigos QR caducan en menos de 60 segundos y se regeneran con nuevos nonces criptográficos?
- [ ] ¿Existen colas con rate-limiting y retroceso exponencial para prevenir suspensiones de cuenta por spam?
