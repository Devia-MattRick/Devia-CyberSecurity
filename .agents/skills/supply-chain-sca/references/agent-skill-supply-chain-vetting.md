# Auditoría Estática de Seguridad en Habilidades y Extensiones Agénticas (Skill Supply Chain Vetting)

Este documento establece las directivas y heurísticas canónicas para auditar paquetes de habilidades (*skills*), extensiones y plugins de agentes autónomos antes de su importación, absorción o ejecución en el ecosistema **Devia-CyberSecurity**.

---

## 🦠 1. Firmas de Cargas Maliciosas Comunes en Ecosistemas de IA (Campaña ClawHavoc)

La campaña ClawHavoc demostró que los atacantes publican paquetes en registros de habilidades (e.g. ClawHub, npm, PyPI) que pretenden ofrecer utilidades a los agentes mientras instalan ladrones de información (*infostealers*).

### Patrones de Infección AMOS (Atomic macOS Stealer):
```typescript
export const AMOS_PATTERNS = [
  /osascript\s+-e\s+.*display\s+dialog/i,     // Diálogo fraudulento de contraseña
  /osascript\s+-e\s+.*System\s+Events/i,     // Automatización de eventos del sistema
  /\/tmp\/\..*\.sh/i,                         // Scripts ocultos en temporales
  /curl.*-o\s+\/tmp\//i,                      // Descarga de payloads secundarios
  /xattr\s+-d\s+com\.apple\.quarantine/i,    // Desactivación de cuarentena Gatekeeper
  /spctl\s+--master-disable/i,                // Desactivación de Gatekeeper
  /security\s+delete-certificate/i           // Manipulación del llavero del sistema
];
```

### Firmas de Reverse Shells en Código de Habilidades:
```typescript
export const REVERSE_SHELL_PATTERNS = [
  /\/dev\/tcp\//i,
  /\/dev\/udp\//i,
  /mkfifo\s+\/tmp\//i,
  /nc\s+-e\s+\/bin\/(ba)?sh/i,
  /ncat\s+.*-e/i,
  /python.*socket.*connect.*subprocess/i,
  /bash\s+-i\s+>&?\s+\/dev\/tcp/i,
  /socat\s+exec/i
];
```

---

## 🔑 2. Cosecha de Credenciales Agénticas (Credential Harvesting)

Los paquetes maliciosos buscan capturar tokens de sesión de agentes de IA y claves de proveedores de modelos:

```typescript
export const CREDENTIAL_HARVESTING_PATTERNS = [
  /readFileSync.*(?:credential|auth-profile|sessions\.json|gateway)/i,
  /process\.env\s*\[\s*['"](?:OPENCLAW_|ANTHROPIC_|OPENAI_|DEEPSEEK_)API_KEY/i,
  /fs\.(?:readFile|readFileSync).*(?:config.*token|\.env)/i,
  /keychain|keytar|node-keytar/i
];
```

---

## ⚡ 3. Combinaciones de Permisos de Alto Riesgo (*Dangerous Permission Combos*)

Al igual que en sistemas Android o extensiones de Chrome, el riesgo en un agente no reside únicamente en un permiso individual, sino en la **cadena de capacidades concurrentes**:

| Combinación Peligrosa | Vector de Riesgo | Clasificación |
| :--- | :--- | :--- |
| `exec` + `write` + `sessions_send` | **Cadena Completa de Compromiso:** Puede ejecutar binarios, escribir archivos de persistencia y comunicar resultados por canales externos. | **CRITICAL** |
| `exec` + `read` + `browser` | **Cadena de Exfiltración:** Puede ejecutar comandos para inspeccionar el sistema, leer archivos y exfiltrar a través de peticiones HTTP en el navegador. | **CRITICAL** |
| `exec` + `gateway` | **Toma de Control Administrativo:** Permite modificar la configuración del despachador del agente. | **CRITICAL** |
| `write` + `cron` | **Mecanismo de Persistencia:** Capacidad de escribir tareas programadas persistentes. | **HIGH** |

---

## 🏷️ 4. Detección de Typosquatting en Nombres de Habilidades

Reglas de similitud y patrones de suplantación dirigidos a herramientas y clientes oficiales:
1. Variantes con guión (`openclaw-cli` vs `openclaw`).
2. Errores tipográficos comunes (`opneclaw`, `openclaww`).
3. Sustituciones leet y cero (`opencl4w`, `0penclaw`).
4. Falsos paquetes de actualización automática (`*-update`, `*-auto`).
