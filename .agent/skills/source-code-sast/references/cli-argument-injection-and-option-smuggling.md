# Inyección de Argumentos CLI y Option Smuggling en APIs de Subprocesos Tokenizadas

Este documento define la metodología SAST para identificar y auditar vulnerabilidades de inyección de opciones (*Option Smuggling*) y parámetros en llamadas a procesos nativos del sistema operativo dentro de **Devia-CyberSecurity**.

---

## 🔍 La Falacia del Subproceso Seguro (`VULN-SAST-008`)

Existe la creencia generalizada en ingeniería de software de que utilizar APIs de subprocesos basadas en arrays o tuplas (como `subprocess.run(["cmd", arg], shell=False)` en Python o `child_process.spawn("cmd", [arg])` en Node.js) erradica por completo las inyecciones de comandos (CWE-78).

Si bien estas APIs evitan que los metacaracteres de la shell (`;`, `&`, `|`, `` ` ``) dividan el comando en múltiples procesos, **NO evitan que el binario destinatario reinterprete el contenido de un argumento como una opción de configuración o flag de ejecución** (CWE-88).

---

## 💥 Primitivas de Explotación de Argumentos

### 1. Option Smuggling vía Prefijos (`--option` / `-o`)
Si una aplicación coloca un dato suministrado por el usuario en la posición de un operando:
```python
# Intención: pasar el nombre de archivo como operando a curl
subprocess.run(["curl", "-s", user_url], check=True)
```
Si el atacante suministra:
`user_url = "-o /etc/cron.hourly/malicious.sh"` o `--output=/var/www/html/shell.php`
El binario `curl` interpretará la entrada no como una URL sino como el flag `--output`, escribiendo el resultado de la petición subsiguiente en una ruta arbitraria del sistema de archivos.

### 2. Evasión de Delimitador y Ausencia de Fin de Opciones (`--`)
La mayoría de las herramientas estándar POSIX (`git`, `tar`, `grep`, `ssh`, `rm`, `find`) aceptan el delimitador especial `--` para indicar el fin de las opciones: cualquier argumento posterior es tratado estrictamente como un operando posicional.
- **Vulnerabilidad:** Si la aplicación omite `--`, cualquier entrada que empiece con `-` activará opciones inesperadas.
- **Ejemplo en Git:** `git checkout $user_branch` -> Si `user_branch = "--orphan=pwn"`, altera radicalmente el comportamiento del comando.

### 3. Inyección mediante Response Files / Argument Files (`@file`)
Muchas herramientas CLI (`gcc`, `curl`, `javac`, `tar`, `powershell`) implementan soporte para leer listas de argumentos desde archivos en disco si el argumento comienza con el prefijo `@` (`@/path/to/args`):
- Si el usuario suministra `@/etc/shadow`, el binario intentará parsear el archivo sensible como si fueran flags, exponiendo su contenido en mensajes de error o registros de depuración (Information Disclosure - CWE-200).

### 4. Transformaciones Unicode Best-Fit en Windows
En Windows, cuando una aplicación pasa cadenas Unicode a APIs ANSI del sistema (como `CreateProcessA`), el sistema realiza una conversión *Best-Fit*:
- Caracteres como el guión largo (*em-dash* `—` `\u2014` o *en-dash* `–` `\u2013`) pueden transformarse en un guión simple ASCII `-`.
- Si un filtro de seguridad valida que la entrada no empieza con `-`, pero la aplicación subsiguiente pasa la cadena por una conversión ANSI, la entrada `—output` se transforma en `-output`, eludiendo el control de seguridad.

---

## 🛡️ Patrones de Mitigación Defensiva

### 1. Interpolar Siempre el Delimitador de Fin de Opciones (`--`)
```python
# Seguro: forzar a que user_filename sea tratado como operando
subprocess.run(["tool", "-v", "--", user_filename], check=True)
```

### 2. Validación y Sanitización Sintáctica Previa
```python
import re

def validate_cli_operand(value: str) -> str:
    # Rechazar cualquier valor que comience con guión o prefijo de opción
    if value.startswith(("-", "/")):
        raise ValueError(f"Operando inválido: no puede comenzar con guión o barra: {value!r}")
    # Rechazar response files
    if value.startswith("@"):
        raise ValueError(f"Response files no permitidos: {value!r}")
    return value
```

---

## 📋 Checklist de Auditoría SAST (`VULN-SAST-008`)

- [ ] ¿Las llamadas a subprocesos interpolan variables de usuario sin el delimitador `--`?
- [ ] ¿Se auditan binarios conocidos por aceptar opciones de redirección o ejecución (`curl -o`, `tar -T`, `ssh -oProxyCommand`)?
- [ ] ¿La aplicación sanitiza o rechaza entradas que comienzan con `@` en herramientas que soportan response files?
- [ ] En entornos Windows, ¿se realiza la validación sobre cadenas Unicode normalizadas antes de invocar APIs del sistema?
