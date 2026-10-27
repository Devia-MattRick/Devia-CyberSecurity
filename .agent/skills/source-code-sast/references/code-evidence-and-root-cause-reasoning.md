# Evidencia Estructurada de Código, Causa Raíz y Razonamiento Conectivo

Este documento define el estándar autoritativo para construir evidencias en código (`codeEvidence`) y articular la causa raíz (`rootCause`) en hallazgos SAST dentro de **Devia-CyberSecurity**.

---

## 🏛️ Directiva de Causa Raíz: Demostración Fuente a Fuente

> [!IMPORTANT]
> **Prohibición de Veredictos en Prosa Genérica:**  
> Un análisis de causa raíz **NO** es un párrafo declarativo ("la vulnerabilidad existe porque falta sanitización en la línea 40").  
> Debe ser un recorrido estructurado respaldado por fragmentos de código que demuestre:
> 1. Dónde se declara o decodifica el dato controlado por el atacante.
> 2. Cada llamada, transformación o cambio de estado intermedio.
> 3. El control ausente o eludido y el sumidero sensible que concreta el impacto.

---

## 🔬 La Taxonomía de 7 Roles Semánticos de Evidencia (`CodeEvidenceRole`)

Cada elemento en el arreglo `codeEvidence` debe asignar uno de los 7 roles canónicos:

| Rol Semántico (`role`) | Propósito Técnico en la Cadena de Taint | Ejemplo |
| :--- | :--- | :--- |
| **`user_input`** | Punto exacto de recepción de datos controlados por el usuario o cliente. | Decodificación JSON de argumentos RPC (`EnvironmentAddParams`). |
| **`entrypoint`** | Ruta HTTP, manejador de eventos o interface pública expuesta. | Método handler del controlador (`handleEnvironmentPost`). |
| **`propagation`** | Traspaso de parámetros, llamadas intermedias o mutaciones de estado. | Invocación de `manager.upsert_environment(id, url)`. |
| **`root_control`** | Punto exacto de fallo de validación o control faltante/deficiente. | Función que acepta la variable sin verificar listas de exclusión. |
| **`sink`** | Operación peligrosa donde se materializa la explotación. | `fs.writeFile`, `child_process.exec`, `db.query`. |
| **`outcome`** | Efecto secundario resultante del impacto. | Reemplazo de la configuración en memoria afectando llamadas posteriores. |
| **`expected_control`** | **Contraste de Invariante:** Fragmento seguro que demuestra el control esperado. | Bloque de código en la rutina de inicio que sí rechazaba el ID reservado. |

---

## 🔗 Protocolo de Razonamiento Conectivo (*Connective Reasoning*)

Cada entrada de evidencia debe redactar su campo `explanation` como **razonamiento conectivo**:
- Identificar cuál es el valor exacto controlado por el atacante en ese paso.
- Especificar qué componente, función o variable recibe el valor a continuación.
- Demostrar por qué las líneas expuestas violan el invariante de seguridad esperado.

### Ejemplo de Estructura de Evidencia en `SecurityFinding`:
```json
{
  "codeEvidence": [
    {
      "id": "param-input",
      "label": "Parámetro controlado por el usuario",
      "path": "src/controllers/extract.ts",
      "startLine": 12,
      "endLine": 16,
      "role": "user_input",
      "code": "const { targetArchive, destination } = req.body;",
      "explanation": "El cliente HTTP suministra la ruta del archivo comprimido sin sanitizar."
    },
    {
      "id": "sink-zip-slip",
      "label": "Extracción sin validación de contención de directorio",
      "path": "src/utils/zip.ts",
      "startLine": 41,
      "endLine": 45,
      "role": "sink",
      "code": "fs.writeFileSync(path.join(destination, entry.fileName), entry.getData());",
      "explanation": "El nombre de entrada ('../../etc/cron.d/job') se concatena directamente sin comprobar si escapa de destination."
    },
    {
      "id": "expected-containment-check",
      "label": "Control seguro de contención esperado",
      "path": "src/utils/safe_fs.ts",
      "startLine": 10,
      "endLine": 15,
      "role": "expected_control",
      "code": "const resolved = path.resolve(destination, entry.fileName);\nif (!resolved.startsWith(path.resolve(destination) + path.sep)) throw new Error('Path traversal');",
      "explanation": "Se debió resolver la ruta absoluta y exigir que sea descendiente del directorio raíz de extracción."
    }
  ],
  "rootCause": {
    "summary": "Extracción insegura de archivos comprimidos (Zip Slip) por concatenación directa de rutas sin verificación de contención absoluta.",
    "evidenceRefs": ["param-input", "sink-zip-slip", "expected-containment-check"]
  }
}
```

---

## 🎯 Política de Reglas Estables (`ruleId`)

Para evitar identificadores volátiles o dependientes de la herramienta de escaneo:
- Formato Canónico: `<categoría-primaria>.<familia-de-control>`
- Ejemplos autorizados:
  - `path-traversal.archive-extraction`
  - `command-injection.shell-argument`
  - `sql-injection.unparameterized-query`
  - `deserialization.untrusted-yaml-loader`
  - `authorization-bypass.sibling-guard-discrepancy`
