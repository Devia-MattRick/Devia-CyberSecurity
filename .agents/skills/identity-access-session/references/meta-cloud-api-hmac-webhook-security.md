# Verificación Criptográfica de Webhooks Meta Cloud API (HMAC-SHA256)

> **ID de Vulnerabilidad:** `VULN-IAM-018`  
> **Taxonomía:** CWE-347 (*Improper Verification of Cryptographic Signature*) / CWE-208 (*Observable Timing Discrepancy*) / OWASP Top 10 A02:2021/2025  
> **Dimensión:** `IDENTITY_ACCESS_SESSION`  
> **Skill:** `identity-access-session`  

---

## 1. El Riesgo de Ataques de Temporización en Validación de Firmas

Los webhooks de la API de Meta Cloud (WhatsApp Business Platform) envían una cabecera de firma criptográfica:
```http
X-Hub-Signature-256: sha256=d3b07384d113edec49eaa6238ad5ff00...
```
Si el servidor valida la firma mediante operadores de igualdad estándar de strings (`signature === expectedSignature`), un atacante remoto puede inferir byte a byte la firma correcta mediante un **ataque de canal lateral por temporización (timing attack)**, falsificando mensajes de clientes entrantes o estados de entrega.

---

## 2. Implementación Canónica con `crypto.timingSafeEqual`

```typescript
import * as crypto from 'crypto';
import { Request, Response, NextFunction } from 'express';

const META_APP_SECRET = process.env.META_APP_SECRET!;

export function verifyMetaWebhookMiddleware(req: Request, res: Response, next: NextFunction) {
  const signature = req.headers['x-hub-signature-256'] as string;
  if (!signature) {
    return res.status(401).json({ error: 'Missing X-Hub-Signature-256 header' });
  }

  // IMPORTANTE: req.rawBody debe contener el buffer crudo recibido antes de cualquier JSON.parse
  const rawBody = (req as any).rawBody as Buffer;
  if (!rawBody) {
    return res.status(500).json({ error: 'Raw body required for HMAC verification' });
  }

  const expectedSignatureHex = crypto
    .createHmac('sha256', META_APP_SECRET)
    .update(rawBody)
    .digest('hex');

  const cleanSignatureHex = signature.replace(/^sha256=/, '');
  const signatureBuffer = Buffer.from(cleanSignatureHex, 'hex');
  const expectedBuffer = Buffer.from(expectedSignatureHex, 'hex');

  // Comprobación de longitud antes de timingSafeEqual para evitar excepciones
  if (signatureBuffer.length !== expectedBuffer.length) {
    return res.status(403).json({ error: 'Invalid webhook signature length' });
  }

  // Comparación en tiempo constante insensible a ataques de canal lateral
  const isValid = crypto.timingSafeEqual(signatureBuffer, expectedBuffer);
  if (!isValid) {
    return res.status(403).json({ error: 'Invalid webhook signature' });
  }

  next();
}
```

---

## 3. Prevención de SSRF en Descarga de Medios de Meta

Cuando un webhook notifica la llegada de una imagen, audio o documento, entrega una URL de descarga:
```json
{
  "messages": [{
    "type": "image",
    "image": { "id": "123456", "mime_type": "image/jpeg" }
  }]
}
```
**Regla de Oro Anti-SSRF:**  
Jamás consultar una URL provista en el cuerpo del webhook. Primero consultar el endpoint de metadatos oficial de Meta (`https://graph.facebook.com/v21.0/{media_id}`) con el Bearer Token del backend, y luego descargar el archivo validando que el dominio destino pertenezca exclusivamente a la CDN autorizada de Meta (`*.fbcdn.net`, `lookaside.fbsbx.com`).

---

## 4. Checklist de Auditoría

- [ ] ¿La comparación de la firma HMAC se realiza obligatoriamente mediante `crypto.timingSafeEqual`?
- [ ] ¿La firma se calcula sobre el buffer binario crudo (`rawBody`) y no sobre un JSON re-serializado?
- [ ] ¿Las URLs de descarga de medios se validan contra una lista blanca estricta de dominios de Meta?
