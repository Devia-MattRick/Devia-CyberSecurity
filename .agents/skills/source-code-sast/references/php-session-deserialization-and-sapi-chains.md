# Cadenas de Deserialización Insegura, LFI y Corrupción de Memoria en PHP (Investigación PHP2Shell)

Este documento condensa los vectores de ataque, precondiciones, análisis estático (SAST) y contramedidas para las cadenas de explotación en entornos PHP basadas en la investigación **PHP2Shell**.

---

## 1. Taxonomía Multimarco y Mapeo Canónico

- **Dimensión Canónica:** `SOURCE_CODE_SAST`
- **Identificadores Devia:** `VULN-SAST-003` (Path Traversal / LFI), `VULN-SAST-004` (Insecure Deserialization), `VULN-RESI-001` (Resource Exhaustion / OOM).
- **CWEs Primarios:**
  - `CWE-98`: Improper Control of Generation of Code ('PHP Remote File Inclusion / LFI')
  - `CWE-502`: Deserialization of Untrusted Data
  - `CWE-416`: Use After Free (UAF)
  - `CWE-400`: Uncontrolled Resource Consumption ('OOM Exhaustion')
- **OWASP Top 10:** A03:2021-Injection / A08:2021-Software and Data Integrity Failures

---

## 2. Anatomía de las Cadenas de Ataque (PHP2Shell)

```
┌────────────────────────────────────────────────────────────────────────┐
│                      CADENAS DE ATAQUE PHP2SHELL                       │
├─────────┬──────────────────────────────────┬───────────────────────────┤
│ Cadena  │ Mecanismo Principal              │ Superficie / SAPI         │
├─────────┼──────────────────────────────────┼───────────────────────────┤
│ Chain A │ Upload Progress + LFI -> RCE     │ PHP-FPM / Apache mod_php  │
│ Chain B │ var_destroy UAF Deserialization  │ CLI / FPM (unserialize)   │
│ Chain C │ Session Handler Mismatch Desync  │ PHP-FPM con .user.ini     │
│ Chain D │ mod_php OOM longjmp stale EG()   │ Apache mod_php (0-day)    │
│ Chain E │ FPM Session OOM BG(unserialize)  │ PHP-FPM                   │
└─────────┴──────────────────────────────────┴───────────────────────────┘
```

---

### 2.1. Chain A: Inyección de Sesión vía Upload Progress + LFI $\to$ RCE

#### Precondiciones:
1. `session.upload_progress.enabled = On` (por defecto en PHP).
2. `session.upload_progress.cleanup = Off` (o ventana de carrera si está On).
3. `session.use_strict_mode = Off` (por defecto).
4. Endpoint vulnerable a LFI (`include($_GET['page'])` o similar).

#### Mecánica de Ataque:
1. El atacante fija el `PHPSESSID` arbitrario mediante parámetro multipart o cabecera `Cookie`.
2. Envía un formulario multipart con `PHP_SESSION_UPLOAD_PROGRESS=x` y un campo de archivo cuyo `filename` contiene código PHP ejecutable (`<?php system($_GET['c']); ?>`).
3. PHP escribe el `filename` crudo en el archivo de sesión `/tmp/sessions/sess_<SID>`.
4. Mediante el endpoint LFI, se incluye el archivo de sesión:
   ```http
   GET /vuln.php?page=/tmp/sessions/sess_ctfchainA000000000000000000&c=id HTTP/1.1
   ```

---

### 2.2. Chain C: Desincronización de Session Handler (`php_serialize` vs `php`)

#### Precondiciones:
1. Dos rutas o módulos con directivas `session.serialize_handler` distintas compartiendo `session.save_path`:
   - Endpoint A (Escritura): `session.serialize_handler = php_serialize` (no trata el carácter `|` como delimitador).
   - Endpoint B (Lectura): `session.serialize_handler = php` (interpreta `|` como separador estructural de claves).
2. Clases cargadas en la aplicación con métodos mágicos de destrucción (`__destruct`) o despertar (`__wakeup`).

#### Mecánica de Ataque:
1. **Escritura:** El atacante inyecta una cadena que contiene un pipe `|` seguido de un objeto serializado en el filename de upload progress:
   ```
   filename="x|O:8:\"AppGadget\":1:{s:4:\"cmd\";s:2:\"id\";}"
   ```
   El manejador `php_serialize` almacena el valor como una cadena literal válida.
2. **Lectura:** Al procesar la sesión en el endpoint con manejador `php`, el parser hace split en el primer `|`, interpreta la subsecuente carga como un objeto y lo instancia. Al terminar la petición o fallar la deserialización, se ejecuta el método `__destruct` del objeto arbitrario, disparando la ejecución de código (RCE).

---

### 2.3. Chain D: Falla de Memoria (OOM) en Apache mod_php $\to$ Stale `EG()` Globals $\to$ RCE

#### Precondiciones:
1. Uso exclusivo de **Apache con `mod_php`** (no ocurre en PHP-FPM porque los workers mueren ante OOM).
2. Límites de memoria configurados (`memory_limit = 32M` o superior).
3. Cero dependencias de la aplicación (vulnerabilidad pre-autenticación a nivel de SAPI).

#### Mecánica de Ataque:
1. El atacante envía una petición con miles de cabeceras HTTP masivas (`X-Custom-N: AAAA...`) para forzar un error de Out of Memory (`zend_mm OOM`) durante `php_request_startup`.
2. La rutina de manejo de OOM ejecuta un `longjmp()` que aborta la inicialización de la petición, pero **Apache mod_php no finaliza el proceso de trabajo**.
3. El proceso de Apache queda reutilizado para la siguiente petición con los punteros de `EG()` (*Executor Globals*) en un estado corrupto o sucio (*stale state*).
4. La siguiente petición procesada por ese worker hereda estructuras de datos liberadas en memoria (Heap Use-After-Free) que permiten sobrescribir punteros de función durante la fase de apagado (`shutdown`) y lograr RCE.

---

## 3. Patrones de Detección Estática (SAST)

### 3.1. Detección de Sumideros LFI Inseguros
```python
# Patrón AST para detectar inclusiones directas no saneadas
def detect_insecure_inclusion(node):
    if node.kind in ("INCLUDE", "INCLUDE_ONCE", "REQUIRE", "REQUIRE_ONCE"):
        arg = node.children[0]
        if arg.kind in ("VARIABLE", "CONCAT_EXPRESSION") and not is_sanitized(arg):
            report_vulnerability(
                vuln_id="VULN-SAST-003",
                node=node,
                cwe="CWE-98",
                message="Inclusión de archivo dependiente de variable no saneada (LFI vulnerable a PHP2Shell Chain A)"
            )
```

### 3.2. Detección de Discrepancias de Session Handler (.user.ini / php.ini)
```bash
# Búsqueda estática de configuraciones conflictivas en repositorios
grep -rn "session.serialize_handler" --include="*.ini" --include="*.conf" .
```

---

## 4. Guía de Remediación y Bastionado

### 4.1. Configuración Inmune en `php.ini`
```ini
; 1. Deshabilitar o forzar limpieza automática de progreso de subida
session.upload_progress.enabled = On
session.upload_progress.cleanup = On

; 2. Habilitar modo estricto de sesión (neutraliza session fixation)
session.use_strict_mode = 1
session.use_only_cookies = 1

; 3. Estandarizar el manejador de serialización en todo el proyecto
session.serialize_handler = php_serialize

; 4. Almacén seguro de sesiones con permisos restringidos
session.save_path = "/var/lib/php/sessions"
```

### 4.2. Desacoplamiento de Arquitectura
- **Eliminar Apache `mod_php`:** Migrar a **PHP-FPM** sobre FastCGI o FrankenPHP con contenedores sin privilegios (`runAsNonRoot: true`). En PHP-FPM, los workers que experimentan OOM son terminados inmediatamente por el master, neutralizando Chain D.
- **Validación de Rutas en Código:** Nunca concatenar entradas de usuario en `include` o `require`. Utilizar listas blancas de nombres canónicos:
```php
// SEGURO: Mapeo estricto con lista blanca
$allowed_pages = [
    'home' => 'views/home.php',
    'contact' => 'views/contact.php',
];
$page = $_GET['page'] ?? 'home';
if (!isset($allowed_pages[$page])) {
    http_response_code(404);
    die('Página no encontrada');
}
require $allowed_pages[$page];
```
