# Autenticación Multifactor Resistente a Phishing, Detección de Fatiga (Prompt Bombing) y Modo Fail-Closed

Esta guía técnica establece el estándar de auditoría y evaluación de robustez para soluciones **MFA (Multi-Factor Authentication)**, políticas de autenticación adaptativa y mitigación de ataques de fatiga en **Devia-CyberSecurity**.

---

## 🏛️ 1. Taxonomía de Robustez de Factores de Autenticación (NIST SP 800-63B)

No todos los factores de segundo paso ofrecen el mismo nivel de garantía. Toda auditoría debe clasificar los factores según su nivel de aseguramiento de autenticación (AAL):

| Categoría de Factor | Métodos Específicos | Resistencia a Phishing (AitM) | Nivel AAL NIST | Evaluación en Auditoría |
| :--- | :--- | :--- | :--- | :--- |
| **Resistente a Phishing** | FIDO2 / WebAuthn, Passkeys, Hardware Tokens (YubiKey), Verified Push con coincidencia de número | **Alta** (Vinculado criptográficamente al origen de dominio) | AAL3 | **Obligatorio para roles privilegiados / admins** |
| **Convencional** | Push estándar en app (un solo toque "Aprobar"), TOTP (Google Authenticator) | **Media/Baja** (Vulnerable a proxies inversos AitM como Evilginx) | AAL2 | Aceptable para usuarios estándar con monitoreo de anomalías |
| **Débil / Obsoleto** | SMS OTP, llamada telefónica de voz | **Nula** (Vulnerable a SIM swapping, intercepción SS7 e ingeniería social) | AAL1 | **Prohibido para cuentas corporativas y acceso remoto** |

---

## 🚨 2. Detección de Ataques de Fatiga MFA (MFA Prompt Bombing)

Los atacantes que han obtenido contraseñas legítimas intentan forzar al usuario a aprobar la notificación push generando decenas de solicitudes consecutivas (a menudo durante la madrugada) o haciéndose pasar por el soporte técnico.

### Algoritmo de Detección Heurística:
1. **Ventana Temporal de Monitoreo:** Agrupar eventos de autenticación por `user_id` en ventanas deslizantes de 15 minutos.
2. **Umbral de Denegaciones:** Si un usuario acumula $\ge 5$ eventos con resultado `denied`, `timeout` o `fraud`:
   - Emitir alerta de severidad **CRITICAL**: *Posible ataque de fatiga MFA / Prompt Bombing*.
   - Desencadenar bloqueo temporal preventivo de la sesión del usuario.
   - Forzar re-autenticación obligatoria con factor FIDO2 / WebAuthn o verificación fuera de banda con el SOC.

---

## 🔒 3. El Antipatrón Crítico de Modo de Fallo Abierto (`failmode=safe`)

> [!CAUTION]
> En proxies de autenticación (como Duo Authentication Proxy), el parámetro `failmode` controla cómo responde el sistema si los servidores de la nube de MFA se vuelven inaccesibles.
> - Si `failmode = safe`: El proxy permite que los usuarios inicien sesión **sin segundo factor** (*Fail-Open Disaster*). Un atacante que cause DoS contra el DNS o la red de salida logrará bypass total de MFA.
> - Si `failmode = secure`: El proxy rechaza la autenticación cuando el servicio MFA no responde (*Fail-Closed*).

**Regla Canónica Inmutable (`VULN-IAM-014`):**  
Todo sistema o proxy de autenticación debe estar configurado estrictamente con `failmode = secure`. Queda terminantemente prohibido el modo `safe` en entornos corporativos de producción.
