# Protocolo Forense de Evidencia, Cobertura y Cadena de Custodia

Este documento establece las directivas autoritativas para la recolección, registro, clasificación epistemológica y trazabilidad de evidencia durante auditorías de ingeniería inversa en **Devia-CyberSecurity**.

---

## 1. Identidad de la Investigación y Fronteras de Autoridad

Toda auditoría de ingeniería inversa debe fijar de manera inmutable la identidad del objetivo antes de emitir cualquier conclusión o plan de absorción:

1. **Rutas e Identidad Física:**
   - Registrar la ruta suministrada por el usuario y su resolución canónica absoluta (`target.resolve()`).
   - Registrar fecha y hora UTC (`timestamp ISO 8601`).
   - Registrar el entorno de ejecución (Sistema Operativo, versión de Python, versión de Node/pnpm).
2. **Identidad del Contenido (Snapshot):**
   - Si el objetivo posee control de versiones Git, obtener la identidad sin alterar el working tree:
     ```bash
     git -C "<TARGET>" rev-parse HEAD
     git --no-optional-locks -C "<TARGET>" status --porcelain=v1 --untracked-files=all
     ```
   - Si no existe `.git`, el objetivo es un *filesystem snapshot*; se debe calcular el hash de los manifiestos principales o archivos críticos de configuración. Nunca asumir que la falta de `.git` invalida el análisis.
3. **Frontera de Confianza y Regla de No-Ejecución:**
   - **El código auditado es considerado dato no confiable (*untrusted data*).**
   - Queda estrictamente prohibido ejecutar scripts de instalación (`npm install`, `setup.py`, `cargo build`), macros, migraciones de base de datos o tests del objetivo sin autorización explícita previa del operador.
   - El inventario, escaneo de AST y análisis estático se realizan exclusivamente mediante herramientas externas o helpers estáticos en memoria.

---

## 2. Los Cuatro Ledgers Deterministas de Auditoría

Para garantizar reproducibilidad absoluta, la auditoría genera y mantiene cuatro archivos estructurados en formato JSONL / JSON:

### 2.1. Ledger de Inventario (`inventory.jsonl` y `summary.json`)
Registra cada nodo físico del árbol de archivos sin leer su contenido ni ejecutar parsers de terceros:
- **Campos por registro (`inventory.jsonl`):**
  - `path`: Ruta relativa estandarizada con separadores `/`.
  - `kind`: `"file"` | `"directory"` | `"symlink"` | `"reparse_point"`.
  - `size_bytes`: Tamaño en bytes.
  - `extension`: Extensión normalizada en minúsculas.
  - `security_critical`: Booleano que señala si es un manifiesto, archivo de configuración, script de CI o secreto potencial.
- **Campos de resumen (`summary.json`):**
  - Conteo total de archivos y directorios.
  - Desglose por extensiones y lenguajes detectados.
  - Detección de enlaces simbólicos, junctions de Windows y subdirectorios excluidos.

### 2.2. Ledger de Cobertura (`coverage.jsonl`)
Registra el estado exacto de revisión de cada ruta identificada en el inventario, evitando falsas ilusiones de completitud:

```json
{
  "path": "src/auth/jwt.ts",
  "subsystem": "authentication",
  "inventory_kind": "file",
  "review": "read",
  "extent": { "kind": "whole-file" },
  "evidence_ids": ["SRC-001", "SRC-002"],
  "reason": null,
  "remaining": []
}
```

- **Estados de revisión canónicos (`review`):**
  - `inventoried`: Registrado en el árbol físico, pendiente de inspección semántica.
  - `read`: Inspeccionado estáticamente según el alcance declarado en `extent`.
  - `traced`: Seguido a lo largo de un flujo de taint o de control de ejecución de extremo a extremo.
  - `verified`: Contrastado empíricamente contra pruebas o ejecuciones controladas autorizadas.
  - `excluded`: Fuera del alcance por directiva explícita (e.g. `node_modules`, `.git`, binarios de prueba pesados). Requiere justificación en `reason`.
  - `blocked`: No analizable por falta de permisos, ofuscación impenetrable o corrupción de archivo.
  - `not-applicable`: Archivo decorativo o irrelevante para la dimensión de seguridad evaluada.
- **Alcance de la inspección (`extent`):**
  - `whole-file`: Archivo completo leído y analizado.
  - `line-range`: Intervalo específico de líneas analizado (`[start, end]`).
  - `symbols`: Inspección acotada a firmas de funciones o interfaces exportadas.
  - `metadata-only`: Solo se evaluaron metadatos o encabezados.

### 2.3. Ledger de Evidencia Forense (`evidence.jsonl`)
Almacena cada cita factual que sustenta un hallazgo, técnica o recomendación de absorción:

```json
{
  "id": "SRC-042",
  "authority": "SOURCE",
  "claim_class": "OBSERVED",
  "target_path": "lib/crypto/cipher.py",
  "lines": { "start": 14, "end": 28 },
  "symbol": "encrypt_token",
  "evidence_snippet": "cipher = AES.new(key, AES.MODE_ECB)",
  "digest_sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
  "context": "Uso de modo ECB vulnerable a ataques de repetición y filtración de patrones",
  "timestamp": "2026-10-27T03:15:00Z"
}
```

- **Prefijos estándar de ID:**
  - `SRC-XXX`: Código fuente estático.
  - `ART-XXX`: Binario, paquete empaquetado o artefacto compilado.
  - `CFG-XXX`: Configuración, Dockerfile, workflow de CI o variable de entorno.
  - `RUN-XXX`: Evidencia obtenida en tiempo de ejecución o sandbox autorizado.
  - `DEC-XXX`: Código descompilado o desensamblado.

### 2.4. Ledger de Incertidumbres y Brechas (`unknowns.jsonl`)
Registra con honestidad técnica todo elemento no resuelto, evitando asumir equivalencia por omisión:

```json
{
  "id": "UNK-007",
  "title": "Mecanismo de rotación de claves criptográficas",
  "affected_component": "lib/crypto/key_manager.py",
  "contradiction_or_gap": "Se declara compatibilidad con HSM en el README, pero el código fuente solo contiene un stub en memoria sin implementación de proveedor PKCS#11",
  "required_evidence": "Inspección de módulos nativos compilados o configuración de producción",
  "impact": "No se puede confirmar si las claves maestras persisten en memoria plana"
}
```

---

## 3. Jerarquía Epistemológica de Certeza

Todo juicio emitido en los reportes y planes de absorción debe clasificarse rigurosamente en una de las cuatro categorías:

| Nivel | Definición Operativa | Ejemplo |
| :--- | :--- | :--- |
| **OBSERVED** | Hecho comprobable directamente en el código fuente, manifest o ejecución controlada. | La línea 45 de `server.ts` invoca `eval(req.body.code)`. |
| **DERIVED** | Conclusión formal deducida de relaciones estructurales, tipos de TypeScript o grafo AST. | El parámetro `userId` viaja sin sanitizar desde el handler HTTP hasta la consulta SQL. |
| **INFERRED** | Hipótesis plausible basada en patrones, nombres de identificadores o convenciones. | La clase `TokenService` parece implementar refresco de tokens OAuth2, pero falta revisar el webhook. |
| **UNKNOWN** | Ausencia explícita de evidencia o contradicción no resuelta. | Se desconoce si la biblioteca externa valida certificados SSL en conexiones salientes. |

> [!CAUTION]
> **Prohibición de Asunciones Falsas:** Jamás transformar la ausencia de un hallazgo en prueba de seguridad ("No encontré vulnerabilidades, por ende es seguro"). La cobertura no completada se reporta explícitamente como brecha.

---

## 4. Trazabilidad Multidireccional de Flujos (*Bidirectional Flow Analysis*)

Para entender a fondo las prácticas y vulnerabilidades del objetivo, se aplican dos vectores de análisis complementarios:

```
[FORWARD TRACE - Entrada a Efecto]
Trigger / Input (API, CLI, Env)
       │
       ▼
Decodificación y Validación (Schemas, Regex, Types)
       │
       ▼
Despacho y Enrutamiento (Handlers, Middleware)
       │
       ▼
Lógica de Dominio y Algoritmos (Reglas de Negocio, Criptografía)
       │
       ▼
Efecto Secundario / Persistencia / Salida (BD, Archivo, Red, Respuesta)

[BACKWARD SLICING - Sumidero a Fuente]
Sink Crítico (eval, query SQL, fs.writeFile, exec)
       │
       ▲
Transformaciones y Sanitizaciones intermedias
       │
       ▲
Límites de Confianza cruzados (Trust Boundaries)
       │
       ▲
Fuente no confiable original (Taint Source)
```

Ambos vectores permiten extraer la verdadera arquitectura del sistema y determinar con precisión qué lecciones y utilidades deben ser absorbidas en Devia-CyberSecurity.
