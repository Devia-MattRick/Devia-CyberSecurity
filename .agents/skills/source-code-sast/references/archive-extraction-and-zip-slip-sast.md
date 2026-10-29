# Mitigación y Auditoría SAST contra Zip Slip y Bypass de Prefijos en Descompresión

Este documento establece la guía técnica autoritativa para la identificación en código fuente (SAST) y remediación definitiva de vulnerabilidades de cruce de directorios en operaciones de descompresión de archivos comprimidos (**Zip Slip / Tar Slip - CWE-22 / VULN-SAST-001**).

---

## 🏛️ 1. La Naturaleza de la Vulnerabilidad Zip Slip (CWE-22)

Los formatos de compresión (ZIP, TAR, GZ, BZ2) almacenan los nombres de los archivos como cadenas de texto relativas arbitrarias dentro de la cabecera de cada miembro. Si una aplicación extrae estas entradas concatenando ingenuamente la ruta de destino sin verificar los límites canónicos, un atacante puede forjar un archivo con secuencias de escape:
```text
payload.zip
  └── ../../../../../../../etc/cron.d/malicious_job
```
Al descomprimirse, el archivo escapa del directorio temporal y sobrescribe archivos críticos del sistema anfitrión con los permisos del proceso.

---

## 🚨 2. Análisis Forense: La Falacia del Filtro por Prefijo (`startswith`)

Durante la auditoría forense de herramientas de escaneo (e.g. `detecting-malicious-npm-packages`), se identificó un antipatrón recurrente donde los desarrolladores asumen haber solucionado el problema mediante comprobaciones superficiales de prefijo:

### 2.1. El Antipatrón Vulnerable
```python
# CÓDIGO VULNERABLE ENCONTRADO EN EL OBJETIVO:
with tarfile.open(tgz, "r:gz") as tf:
    # Intento fallido de saneamiento:
    members = [m for m in tf.getmembers() if not m.name.startswith(("/", ".."))]
    tf.extractall(extract, members=members)  # VULNERABLE!
```

### 2.2. Demostración de Bypass
El filtro `not m.name.startswith(("/", ".."))` descarta únicamente cadenas que inicien con `/` o `..`.
Un atacante forja un paquete con la siguiente estructura:
```text
package/../../../../../../tmp/evil.sh
```
1. `name.startswith("/")` $\to$ `False` (comienza con `'p'`).
2. `name.startswith("..")` $\to$ `False` (comienza con `'p'`).
3. El filtro evalúa `True` y admite el miembro.
4. `extractall` resuelve la ruta relativa, atraviesa hacia la raíz y escribe en `/tmp/evil.sh`.

> [!CAUTION]
> Los filtros que inspeccionan prefijos de cadenas o subcadenas superficiales jamás deben aceptarse como controles de seguridad contra Zip Slip.

---

## 🛡️ 3. Patrón de Sanitización y Contención Canónica

Para neutralizar de forma absoluta e ineludible cualquier intento de Zip Slip o Tar Slip en todas las plataformas (Linux, macOS, Windows):

### 3.1. Implementación Segura en Python 3.11+
```python
import os
import tarfile
import zipfile
from pathlib import Path

def is_safe_path(base_dir: Path, target_path: Path) -> bool:
    """Verifica que target_path resuelva estrictamente dentro de base_dir sin symlink escapes."""
    try:
        resolved_base = base_dir.resolve(strict=True)
        resolved_target = target_path.resolve(strict=False)
        return resolved_target.is_relative_to(resolved_base)
    except (ValueError, RuntimeError):
        return False

def safe_extract_zip(zip_file_path: str, extract_to_dir: str) -> None:
    base_dir = Path(extract_to_dir).resolve()
    base_dir.mkdir(parents=True, exist_ok=True)

    with zipfile.ZipFile(zip_file_path, "r") as zf:
        for member in zf.infolist():
            # Construir ruta absoluta de destino
            target_file = (base_dir / member.filename).resolve()
            
            # Comprobar contención estricta
            if not target_file.is_relative_to(base_dir):
                raise SecurityError(f"Intento de Zip Slip detectado: {member.filename}")
            
            zf.extract(member, base_dir)
```

### 3.2. Implementación Segura en TypeScript / Node.js
```typescript
import path from "node:path";
import fs from "node:fs";

export function assertSafeExtractionPath(destinationRoot: string, entryName: string): string {
  const resolvedRoot = path.resolve(destinationRoot);
  const resolvedTarget = path.resolve(destinationRoot, entryName);

  if (!resolvedTarget.startsWith(resolvedRoot + path.sep)) {
    throw new Error(`Zip Slip path traversal attempt blocked: ${entryName}`);
  }
  return resolvedTarget;
}
```

---

## 🔍 4. Reglas de Detección SAST para Auditores y Motores

Un motor SAST debe marcar como **VULN-SAST-001 (CRITICAL)** cualquier coincidencia de:
1. `zipfile.ZipFile.extractall()` o `tarfile.TarFile.extractall()` donde el segundo argumento `members` esté ausente o no provenga de una función de contención basada en `resolve()`.
2. Sanitizaciones que dependan exclusivamente de `replace('/', '')`, `replace('\\', '')` o `startswith()`.
3. Extracción de archivos en bucles `for` que omitan la validación de prefijo canónico con `path.resolve` y `path.sep`.

---

## 🏛️ 5. Gobernanza Dimensional MECE

- Toda vulnerabilidad de descompresión o bypass de contención de rutas se clasifica exclusivamente en:
  **`SOURCE_CODE_SAST`**
- Vinculado al identificador canónico **`VULN-SAST-001`** en `docs/VULNERABILITIES.md`.
