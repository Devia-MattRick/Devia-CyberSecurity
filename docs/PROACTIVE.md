# Devia-CyberSecurity — Memoria Proactiva de Ingeniería y Heurísticas Operativas

Este documento constituye la **Memoria Proactiva de Lecciones Aprendidas** de **Devia-CyberSecurity**. Registra soluciones probadas, heurísticas deterministas, decisiones arquitectónicas y atajos de ingeniería para optimizar futuros flujos de trabajo, evitar el sobregasto de tokens en deliberaciones ya resueltas y maximizar la velocidad y precisión defensiva.

---

## 🏛️ 1. Arquitectura y Modelado Contract-First (Capa 2: TypeScript + Zod)

### 1.1. El Patrón del Paquete Sellado (*Sealed Scan Contract*)
- **La Lección:** Tratar los reportes Markdown (`report.md`) o exportaciones SARIF como el estado de verdad de una auditoría provoca pérdida de tipos, falsificación de cobertura y vulnerabilidades de manipulación de estado (`VULN-ARCH-004`).
- **La Regla Operativa:**  
  La auditoría se sella en un bundle inmutable compuesto exclusivamente por:
  1. `scan-manifest.json`: Recibo terminal criptográfico con hashes SHA-256 de los artefactos.
  2. `findings.json`: Hallazgos semánticos canónicos.
  3. `coverage.json`: Cobertura honesta y superficies evaluadas.
- **Proyecciones de Solo Lectura:** `report.md`, exports SARIF o HTML son proyecciones *downstream*. Ningún script ni agente debe parsear Markdown para obtener datos de auditoría.

### 1.2. Huellas Primarias Estables (*Fingerprints*) Desacopladas de Líneas
- **La Lección:** Si la identidad de un hallazgo depende de números de línea (`path:line`), cualquier refactorización, inserción de comentarios o commit rompe el seguimiento histórico y duplica incidencias.
- **La Solución:** Derivar la huella primaria a partir de 4 elementos semánticos estables:
  $$\text{Fingerprint} = \text{SHA-256}(\text{targetId} : \text{ruleId} : \text{anchor} : \text{instance})$$
  - `ruleId`: Familia de control estable (`<categoría>.<control>`, e.g. `path-traversal.archive-extraction`).
  - `anchor`: Ancla semántica del control raíz (e.g. `extract-entry-without-containment`).
  - `instance`: Diferenciador opcional para instancias hermanas.
  - Formato: `devia/v1:sha256:<64-hex>`.

### 1.3. Estructura de Evidencia de Código con 7 Roles Semánticos
- **La Lección:** Los veredictos en prosa genérica ("falta validación") son ambiguos y difíciles de verificar.
- **La Solución:** Todo hallazgo SAST debe estructurar su `codeEvidence` asignando a cada fragmento uno de los 7 roles canónicos:
  `user_input` $\to$ `entrypoint` $\to$ `propagation` $\to$ `root_control` $\to$ `sink` $\to$ `outcome`, complementado con `expected_control` para contrastar el invariante esperado.

---

## ⚡ 2. Rendimiento y Complejidad Algorítmica (Capa 3: Python Determinista)

### 2.1. Traversal y Cálculo Determinista en Python vs Bucles ReAct
- **La Lección:** Intentar listar directorios, parsear JSONs grandes o calcular hashes mediante bucles conversacionales de LLM o comandos bash encadenados gasta decenas de miles de tokens y es propenso a errores de timeout.
- **La Regla Operativa:**  
  Toda operación de cálculo de hashes, inventario de archivos o análisis de lockfiles debe delegarse a scripts Python deterministas en `src/scripts/` con soporte `--json`.
  - [`src/scripts/forensic_inventory.py`](file:///k:/Devia-CyberSecurity/src/scripts/forensic_inventory.py): Traversal determinista en memoria sin ejecutar código del objetivo.
  - [`src/scripts/target_snapshot.py`](file:///k:/Devia-CyberSecurity/src/scripts/target_snapshot.py): Hashing ordenado lexicográficamente $O(n \log n)$ y huellas primarias $O(1)$.

### 2.2. Manejo de Inodos de 64/128 bits en Windows para SQLite
- **La Lección:** En Windows con Python 3.12+, `os.stat()` puede reportar IDs de inodo de 128 bits o dispositivos de 64 bits sin signo. Si se almacenan directamente en columnas `INTEGER` de SQLite, se produce un error por desbordamiento del entero firmado de 64 bits ($> 2^{63}-1$).
- **La Solución:** Si el valor excede $[-(2^{63}), 2^{63}-1]$, serializar como cadena prefijada: `stat:<hex>`.

---

## 🛡️ 3. Heurísticas Defensivas y Detección de Falsos Negativos

### 3.1. Estándar de Divulgación de Secretos en Código Fuente
- **La Lección:** Analistas o LLMs frecuentemente descartan secretos diciendo: *"está en la carpeta tests"*, *"es un mock"*, o *"la función nunca es invocada en runtime"*.
- **La Regla Operativa:**  
  Un lector con acceso al código fuente que obtiene una credencial que otorga acceso a recursos externos es una ruta de divulgación válida e inmediata (`VULN-CRYP-001`). No se requiere que el código sea ejecutable en producción. Nunca desestimar un secreto únicamente por estar en rutas de test o ejemplos. Queda estrictamente prohibido probar las claves en servicios remotos para ver si están activas.

### 3.2. Discrepancia de Guardias en Operaciones Hermanas (*Sibling Operations*)
- **La Lección:** Los fallos más severos de autorización e IDOR no ocurren en la ruta principal de creación, sino en métodos secundarios de sincronización, actualización o mutación en runtime (`upsert`, `batch-update`, `add`).
- **Heurística de Detección:** Comparar siempre todos los endpoints que aceptan el mismo identificador de entidad y auditar si las rutas secundarias omiten los controles de inmutabilidad o permisos de la ruta principal.

### 3.3. Contención Estricta en Descompresión de Archivos (Zip Slip - CWE-22)
- **La Lección:** Comprobar únicamente si el nombre del archivo contiene `../` es eludible mediante enlaces simbólicos, codificaciones URL o caracteres especiales.
- **Heurística Segura:**
  ```typescript
  const resolvedPath = path.resolve(destinationRoot, entryName);
  if (!resolvedPath.startsWith(path.resolve(destinationRoot) + path.sep)) {
    throw new SecurityException("Zip Slip path traversal attempt");
  }
  ```

### 3.4. El Principio Epistemológico de Inconclusión en Auditorías Incompletas
- **La Lección:** Si una auditoría se detiene por timeout, excepción o cancelación (`failed`, `interrupted`, `canceled`), el agente tiende erróneamente a reportar: *"no se encontraron más vulnerabilidades"*.
- **La Regla Inmutable:**  
  La ausencia de hallazgos en un escaneo no completado es **estrictamente INCONCLUSA**. Queda prohibido emitir certificados de seguridad sobre auditorías parciales.

---

## 💻 4. Entornos de Ejecución Windows y Prevención de Hijacking

### 4.1. Secuestro de Ruta de Búsqueda en Scripts Batch (CWE-427 / CWE-428)
- **La Lección:** Invocar `node.exe` o `python.exe` en scripts `.cmd` sin ruta calificada o desde un directorio de trabajo no seguro permite a un atacante colocar un binario malicioso en esa carpeta y lograr RCE (`VULN-CONF-004`).
- **El Patrón de Bastionado:**
  1. Desvincular el working directory inmediatamente: `cd /d "%SystemRoot%"`.
  2. Resolver rutas autorizadas en orden de menor a mayor privilegio.
  3. Comprobar existencia física antes de llamar (`if exist ...`).
  4. Encapsular la invocación con comillas dobles estrictas: `"%TARGET_NODE%" "%SCRIPT_PATH%" %*`.

---

## 🗂️ 5. Cadena de Custodia en Auditorías Forenses (Los 4 Ledgers)

Toda auditoría de repositorio ejecutada con la Skill `security-reverse-engineering` debe generar y mantener 4 ledgers estructurados en `audits/<objetivo>/`:
1. `inventory/inventory.jsonl` y `summary.json`: Árbol físico determinista, conteo de extensiones y categorización.
2. `coverage.jsonl`: Disposición por archivo (`read`, `traced`, `verified`, `excluded`, `blocked`).
3. `evidence.jsonl`: Citas factuales con hashes SHA-256, líneas base 1 y nivel epistemológico (`OBSERVED`, `DERIVED`, `INFERRED`).
4. `unknowns.jsonl`: Brechas explícitas, contradicciones y dependencias remotas no resueltas.

---

## 🚀 6. Atajos y Comandos de Verificación Rápida

| Acción | Comando | Beneficio Operativo |
| :--- | :--- | :--- |
| **Calcular Snapshot Determinista** | `python src/scripts/target_snapshot.py snapshot <DIR> --json` | Obtiene el hash inmutable del workspace en $<1$ segundo. |
| **Derivar Fingerprint de Hallazgo** | `python src/scripts/target_snapshot.py fingerprint --target-id <ID> --rule-id <RULE> --anchor <ANCHOR> --json` | Genera huella primaria estable e independiente de líneas. |
| **Compilar Contratos TypeScript** | `pnpm build` | Verifica cero errores de tipos en esquemas Zod (`tsc`). |
| **Ejecutar Tests de Esquemas** | `pnpm test` | Ejecuta runner nativo `node --test "dist/**/*.test.js"`. |
| **Ejecutar Tests Unitarios Python** | `python -m unittest discover -s src/scripts -p "test_*.py"` | Valida suites de scripts de Capa 3 sin dependencias externas. |
