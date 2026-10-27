# Guía de Auditoría de Seguridad para Passkeys y WebAuthn (FIDO2)

Este documento establece los principios canónicos, la arquitectura de referencia y las heurísticas de auditoría para implementaciones de autenticación sin contraseña basadas en **Passkeys / WebAuthn (FIDO2)** dentro de **Devia-CyberSecurity**.

---

## 🏛️ 1. Modelo de Seguridad y Componentes de WebAuthn

WebAuthn ([W3C Recommendation](https://www.w3.org/TR/webauthn-3/)) es una API del navegador que permite a las aplicaciones web autenticar usuarios mediante criptografía de clave pública de forma resistente al phishing.

```
[Usuario] ↔ [Autenticador (FIDO2 / Roaming o Platform)] ↔ [Cliente (Navegador/App)] ↔ [Relying Party (Backend RP)]
```

- **Relying Party (RP):** La aplicación backend que registra y valida credenciales. Almacena exclusivamente la clave pública y el `credentialId`.
- **Autenticador:** Chip TPM, enclave seguro (FaceID/TouchID/Windows Hello) o llave de seguridad de hardware (YubiKey) que almacena la clave privada en un hardware aislado.
- **Passkey:** Credencial WebAuthn reconocible del lado del cliente (*discoverable credential*), que puede ser bound a un dispositivo (*device-bound*) o sincronizada entre dispositivos mediante un proveedor de credenciales (Apple Keychain, Google Password Manager, 1Password).
- **User Handle:** Identificador interno único y opaco de la cuenta de usuario generado por el backend (jamás debe ser el email o username legible).

---

## 🛡️ 2. Reglas Maestras de Auditoría

### 2.1. Delimitación Estricta del Dominio del Relying Party (`rpId`)
El `rpId` define el ámbito exacto de validez de una credencial. Un autenticador firma un hash SHA-256 del `rpId` verificado contra el origen del navegador.
- **Vulnerabilidad:** Configurar el `rpId` en un dominio padre registrable (`corp.example`) para compartir credenciales entre múltiples subdominios no relacionados.
- **Heurística de Auditoría:**
  1. El `rpId` debe coincidir con el sufijo de dominio válido del origen actual o ser el host exacto (`auth.example.com`).
  2. El servidor debe validar el hash `rpIdHash` del `authData` recibido contra el hash SHA-256 de su propio `rpId` configurado.
  3. El origen (`origin`) reportado en `clientDataJSON` debe validarse contra una lista blanca inmutable de orígenes permitidos (incluyendo esquema `https://`, host y puerto). Prohibido construir el origen esperado a partir de cabeceras HTTP no confiables (`Host` o `X-Forwarded-Host`).

### 2.2. Distinción Epistemológica entre Presencia (UP) y Verificación de Usuario (UV)
- **User Presence (UP):** Demuestra que una persona interactuó físicamente con el autenticador (e.g. tocó un botón capacitivo).
- **User Verification (UV):** Demuestra que el autenticador verificó localmente la identidad del usuario mediante biometría (huella dactilar, escaneo facial) o un PIN de dispositivo.
- **La Regla Inmutable:**  
  *Un Passkey no es automáticamente multi-factor (MFA).* Para satisfacer una política de autenticación de alta seguridad o MFA, el RP debe:
  1. Solicitar `userVerification: "required"` en las opciones de la ceremonia.
  2. Verificar explícitamente el bit de flag UV (bit 2 de `flags` en `authData`). Si el bit UV es `0`, la autenticación NO califica como MFA aunque el bit UP sea `1`.

### 2.3. Validación Server-Side de la Ceremonia WebAuthn
Toda verificación de registro y autenticación debe realizarse en el servidor utilizando una biblioteca mantenida (e.g. `@simplewebauthn/server`, `py_webauthn`).
- **Verificación de Desafío (Challenge):**
  - El challenge debe ser un nonce criptográfico de alta entropía ($\ge 32$ bytes aleatorios).
  - Debe asociarse a la sesión efímera del usuario y expirar rápidamente ($\le 120$ segundos).
  - Debe consumirse de forma atómica en un único intento (un challenge jamás puede reutilizarse).
- **Contador de Firmas (`signCount`):**
  - Para autenticadores con contador, el nuevo `signCount` debe ser estrictamente mayor que el último registrado.
  - Si el nuevo `signCount` es menor o igual al registrado previamente, emitir alerta de clonación de autenticador (*cloned authenticator detection*).
  - *Nota:* Los passkeys sincronizados en la nube pueden reportar `signCount = 0` constante; el backend debe soportar esta excepción sin desactivar la comprobación para credenciales de hardware.

### 2.4. Ciclo de Vida, Gestión de Credenciales y Rutas de Recuperación
- **Autenticación Reciente Previa a Cambios:** Agregar, renombrar o eliminar un Passkey debe exigir re-autenticación reciente o autenticación escalonada (*Step-Up Auth*).
- **Soporte de Múltiples Autenticadores:** El sistema debe fomentar el registro de al menos dos autenticadores (e.g. Passkey de plataforma + Llave de seguridad USB) para evitar que la pérdida de un dispositivo derive en mecanismos de recuperación débiles basados en correo electrónico o preguntas de seguridad.
- **Aislamiento de la Ruta de Recuperación:** Un proceso de recuperación de cuenta vulnerable (e.g. restablecimiento por SMS o enlace mágico débil) invalida completamente la resistencia al phishing proporcionada por WebAuthn.

---

## 🔍 Checklist Rápido de Auditoría SAST / Code Review

- [ ] ¿El backend valida que `clientDataJSON.type` corresponda exactamente a `webauthn.create` (registro) o `webauthn.get` (autenticación)?
- [ ] ¿El challenge recibido en `clientDataJSON` coincide exactamente con el challenge almacenado en la sesión del usuario?
- [ ] ¿El `rpIdHash` en `authData` coincide con el hash del dominio de la aplicación?
- [ ] ¿El origen en `clientDataJSON` está validado contra una lista de orígenes permitidos (`https://...`)?
- [ ] ¿Se verifica el flag `UP` en todas las operaciones y el flag `UV` cuando se requiere MFA?
- [ ] ¿El `userHandle` almacenado es un identificador aleatorio opaco que no expone PII ni nombres de usuario?
- [ ] ¿Se previene la reutilización de credenciales entre tenants en arquitecturas multi-inquilino?
