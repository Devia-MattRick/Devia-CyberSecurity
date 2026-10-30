# Catálogo de 9 Vectores de Account Takeover (ATO) y 7 Evasiones de MFA

> **ID de Vulnerabilidad:** `VULN-IAM-014` / `VULN-IAM-001`  
> **Taxonomía:** CWE-640 (*Weak Password Recovery Mechanism*) / CWE-305 (*Authentication Bypass by Primary Weakness*) / OWASP Top 10 A07:2021/2025  
> **Dimensión:** `IDENTITY_ACCESS_SESSION`  
> **Skill:** `identity-access-session`  

---

## 1. Las 9 Rutas Críticas de Secuestro de Cuentas (ATO)

| # | Vector de Ataque | Mecanismo de Explotación | Remediación Canónica |
|:---:|:---|:---|:---|
| **1** | **Password Reset Poisoning vía Host Header** | El backend genera el enlace de recuperación usando `req.headers.host` no validado. El atacante manipula la cabecera hacia `attacker.com`. | Usar variable de entorno fija (`process.env.APP_URL`) para el dominio del enlace de restablecimiento. |
| **2** | **Fuga de Reset Token vía Referer** | La página de cambio de contraseña carga recursos de terceros (analytics, fuentes, widgets) que registran la URL completa con el token en logs. | Aplicar cabecera `Referrer-Policy: no-referrer` en endpoints de autenticación sensible. |
| **3** | **Actualización de Email sin Re-autenticación** | Un atacante con acceso temporal (XSS o sesión abierta) cambia el email del usuario sin confirmar la contraseña actual ni enviar confirmación al email original. | Exigir contraseña actual y enviar correo de alerta con enlace de reversión al email anterior. |
| **4** | **Envenenamiento de Redirección OAuth (Open Redirect)** | El parámetro `redirect_uri` en el flujo OAuth permite subdominios no controlados o caracteres de escape, filtrando el código de autorización. | Whitelist exacta y estricta de URIs de callback registradas previamente. |
| **5** | **Fijación de Sesión Previa al Login (Session Fixation)** | El identificador de sesión asignado al usuario anónimo no se regenera tras una autenticación exitosa. | Invocar `req.session.regenerate()` obligatoriamente al autenticar. |
| **6** | **Fuga de Token en Historial del Navegador (Query Strings)** | El token de sesión o JWT se transmite en la barra de direcciones (`/dashboard?token=...`). | Transmitir tokens exclusivamente en cookies `HttpOnly; Secure; SameSite=Strict` o cabeceras `Authorization`. |
| **7** | **Agotamiento de Entropía en Reset Tokens** | Generación de tokens de recuperación mediante generadores pseudoaleatorios débiles (`Math.random()`, timestamps). | Usar `crypto.randomBytes(32).toString('hex')`. |
| **8** | **Inseguridad en Enlaces Mágicos (Magic Links)** | Enlaces mágicos sin expiración corta (válidos por días) o con uso ilimitado. | Expiración de 10 a 15 minutos y consumo estrictamente de un solo uso (*One-Time Token*). |
| **9** | **Cuentas Pre-Creadas (Account Pre-Hijacking)** | El atacante crea una cuenta con el email de la víctima antes de que esta se registre. Cuando la víctima se registra vía OAuth, el atacante mantiene acceso. | Forzar verificación de correo previa a la vinculación de identidades federadas. |

---

## 2. Los 7 Patrones de Evasión de MFA (Multi-Factor Authentication)

1. **Ausencia de Rate Limiting en Código OTP:** El endpoint `/api/mfa/verify` permite fuerza bruta sobre códigos de 6 dígitos (1 millón de combinaciones en menos de 10 minutos).  
   *Mitigación:* Bloqueo tras 5 intentos fallidos y expiración del challenge en 5 minutos.
2. **Reutilización de OTP (No-Invalidation After Use):** El código OTP sigue siendo válido después de una autenticación exitosa hasta que expira el reloj.  
   *Mitigación:* Eliminación inmediata del challenge en base de datos tras el primer uso verificado.
3. **Manipulación de Respuesta del Cliente (Client-Side Check):** El frontend solo verifica si la respuesta HTTP es `200 OK` o `{"success": true}` y el backend confía en que el cliente no avanzará si falla el MFA.  
   *Mitigación:* La sesión post-login solo adquiere alcance completo cuando el backend emite un token elevado tras validar el MFA.
4. **Bypass por Canal Alternativo (SMS Fallback Degradation):** La aplicación permite degradar una clave de seguridad FIDO2 a SMS y luego explota debilidades de SIM swapping.  
   *Mitigación:* Políticas estrictas de autenticación resistente a phishing.
5. **Condición de Carrera en Verificación de Challenge:** Múltiples solicitudes simultáneas con códigos distintos antes de que el contador de fallos se actualice en la base de datos.  
   *Mitigación:* Bloqueo transaccional o Redis atómico `INCR` con clave de challenge.
6. **Fuga de Códigos de Respaldo (Backup Codes en Texto Plano):** Códigos de respaldo almacenados sin hash en la base de datos.  
   *Mitigación:* Almacenar códigos de respaldo aplicando `bcrypt` o `argon2id`, igual que una contraseña.
7. **CSRF en Activación de MFA:** El endpoint de enrolamiento de MFA no valida CSRF, permitiendo a un atacante vincular su propia aplicación Authenticator a la cuenta de la víctima.  
   *Mitigación:* Exigir re-ingreso de contraseña y token CSRF estricto antes de confirmar el enrolamiento.
