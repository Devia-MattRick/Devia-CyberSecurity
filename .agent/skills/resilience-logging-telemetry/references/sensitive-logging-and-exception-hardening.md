# Guía Canónica de Bastionado de Logging y Manejo Seguro de Excepciones

Este documento establece los estándares y patrones de auditoría para la prevención de fuga de información confidencial en logs, mitigación de inyección de registros y gestión robusta de excepciones en **Devia-CyberSecurity**.

---

## 📋 1. Prevención de Fuga de Datos Sensibles en Logs (CWE-532 / VULN-RESI-002)

**Severidad:** `HIGH`  
**OWASP:** A09:2021 / A09:2025 (Security Logging and Monitoring Failures)  
**Mecanismo de Fallo:** Los desarrolladores imprimen objetos de contexto completos (`req.body`, `user`, `payload`, `kwargs`) hacia `console.log`, `logging.info` o agregadores de logs externos (Datadog, CloudWatch, Sentry). Esto expone contraseñas en texto plano, tokens Bearer, números de tarjetas de crédito y datos personales (PII) a cualquier operador o sistema con acceso a los logs.

### Patrones de Detección (Grep / SAST)
```regex
(console\.log|logger\.\w+|logging\.\w+)\s*\(.*(password|passwd|pwd|token|secret|apiKey|api_key|credit|ssn|authorization)
(console\.log|logger\.\w+)\s*\(.*req\.(body|headers)
```

### Código Vulnerable vs Seguro
```typescript
// ❌ VULNERABLE: Volcado de contraseña y cuerpo completo
app.post('/api/auth/login', (req, res) => {
  const { username, password } = req.body;
  logger.info(`Intento de login para usuario: ${username}, pass: ${password}`);
  logger.debug("Request body recibido:", req.body); // Contiene credenciales
});

// ✅ SEGURO: Registro estructurado con sanitización y redacción previa
app.post('/api/auth/login', (req, res) => {
  const { username } = req.body;
  logger.info({
    event: "AUTH_LOGIN_ATTEMPT",
    username: sanitizeLogInput(username),
    clientIp: req.ip,
    timestamp: new Date().toISOString()
  });
});
```

---

## 🧱 2. Inyección de Logs y Falsificación de Registros (CRLF Log Forging - CWE-117)

**Severidad:** `MEDIUM`  
**Mecanismo de Fallo:** Escribir datos de usuario sin sanitizar directamente en archivos de registro delimitados por líneas. Si un atacante envía caracteres de control de nueva línea (`\r\n`), puede insertar entradas falsas en el archivo de log (*log forging*), engañando a los analistas del SOC o eludiendo alertas de auditoría.

### Código Vulnerable vs Seguro (Python)
```python
# ❌ VULNERABLE: Inyección de nueva línea en logs
username = request.args.get("user")
logging.info(f"Usuario autenticado exitosamente: {username}")
# Si user es: "admin\n2026-10-27 INFO: Transferencia autorizada por $1,000,000"

# ✅ SEGURO: Neutralización estricta de caracteres de control o logging JSON estructurado
safe_username = re.sub(r"[\r\n\t]", "_", username)
logging.info(json.dumps({
    "event": "USER_LOGIN_SUCCESS",
    "user": safe_username[:64]
}))
```

---

## 💥 3. Divulgación de Stack Traces e Información de Depuración (CWE-209 / VULN-RESI-003)

**Severidad:** `HIGH`  
**OWASP:** A02:2025 (Security Misconfiguration) / A10:2025 (Mishandling of Exceptional Conditions)  
**Mecanismo de Fallo:** Exponer trazas de error (`err.stack`, `traceback.format_exc()`), variables de entorno o consultas SQL fallidas directamente a clientes web o en respuestas JSON de APIs. Esto revela rutas internas del sistema de archivos, versiones exactas de bibliotecas y esquemas de base de datos.

### Patrones de Detección
```regex
res\.(status\(\d+\)\.)?(send|json)\s*\(.*(err\.stack|error:\s*err)
DEBUG\s*=\s*True
app\.run\s*\(.*debug\s*=\s*True
```

### Código Vulnerable vs Seguro (Express Middleware)
```typescript
// ❌ VULNERABLE: Envío del objeto de error completo al cliente
app.use((err: Error, req: Request, res: Response, next: NextFunction) => {
  res.status(500).json({
    message: err.message,
    stack: err.stack, // Revela rutas locales y librerías
    internalError: err
  });
});

// ✅ SEGURO: Ocultamiento de detalles internos y emisión de Correlation ID
app.use((err: Error, req: Request, res: Response, next: NextFunction) => {
  const errorId = crypto.randomUUID();
  // Registrar detalle técnico completo únicamente en log interno seguro
  logger.error({ errorId, message: err.message, stack: err.stack });

  // Respuesta al cliente neutralizada con identificador para soporte
  res.status(500).json({
    error: "Ha ocurrido un error interno en el servidor",
    referenceId: errorId
  });
});
```

---

## 🔇 4. Supresión Silenciosa de Errores y Bloques Catch Vacíos (CWE-391 / CWE-754)

**Severidad:** `MEDIUM`  
**Mecanismo de Fallo:** Capturar excepciones críticas de seguridad (fallos de autenticación, rechazos criptográficos, errores de integridad) mediante bloques `catch(e) {}` o `except: pass` sin registrarlos ni relanzarlos. Esto produce fallos silenciosos (*fail-open*), permitiendo que la ejecución continúe en un estado corrupto o inseguro.

### Código Vulnerable vs Seguro (Python)
```python
# ❌ VULNERABLE: Supresión silenciosa de errores de verificación
try:
    verify_signature(payload, signature)
except Exception:
    pass # El flujo continúa como si la firma fuera válida o ignora la causa de rechazo

# ✅ SEGURO: Manejo defensivo con rechazo explícito y telemetría
try:
    verify_signature(payload, signature)
except InvalidSignatureError as ex:
    logger.warning({"event": "SIGNATURE_VERIFICATION_FAILED", "reason": str(ex)})
    raise SecurityException("Firma criptográfica inválida")
```

---

## 🛡️ 5. Eventos Mínimos Obligatorios de Auditoría de Seguridad

Toda aplicación en producción debe registrar obligatoriamente los siguientes eventos con marca de tiempo UTC y actor asociado:
1. **Autenticación:** Intentos fallidos y exitosos, revocación de sesiones y bloqueos por fuerza bruta.
2. **Autorización:** Intentos de acceso a recursos no autorizados (denegaciones RBAC/ABAC).
3. **Gestión de Privilegios:** Creación, modificación o asignación de roles administrativos.
4. **Mutación Crítica:** Eliminación de datos maestros, cambios de configuración de seguridad y rotación de claves.
