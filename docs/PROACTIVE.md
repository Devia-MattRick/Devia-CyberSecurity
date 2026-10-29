# Devia-CyberSecurity — Memoria Proactiva de Invariantes y Reglas Maestras

Este documento constituye el **Playbook Operativo de Invariantes de Ingeniería y Plataforma** de **Devia-CyberSecurity**. Registra soluciones probadas, heurísticas de rendimiento, trampas críticas de sistemas operativos y patrones arquitectónicos transversales para garantizar ejecuciones deterministas sin deriva técnica ni sobregasto de tokens.

> [!NOTE]
> **Descentralización de Heurísticas Específicas:**
> Las técnicas y análisis detallados de vulnerabilidades (e.g. CSWSH en WebSockets, AD CS ESC1, Prototype Pollution, PQC Migration, etc.) residen de forma modular en los **112 documentos técnicos de referencia** dentro de sus respectivas Skills operativas (`.agents/skills/*/references/*.md`). Este documento consolida exclusivamente los **invariantes transversales de ingeniería**.

---

## 🏛️ 1. Arquitectura y Modelado Contract-First (Capa 2: TypeScript + Zod)

### 1.1. El Patrón del Paquete Sellado (*Sealed Scan Contract*)
- **La Lección:** Tratar reportes Markdown (`report.md`) o exportaciones SARIF como el estado de verdad de una auditoría provoca pérdida de tipado, falsificación de cobertura y vulnerabilidades de manipulación de estado (`VULN-ARCH-004`).
- **La Regla Operativa:**  
  Toda auditoría se sella en un bundle inmutable compuesto exclusivamente por contratos JSON validados:
  1. `scan-manifest.json`: Recibo terminal criptográfico con hashes SHA-256 de los artefactos (`SealedScanManifestSchema`).
  2. `findings.json`: Hallazgos semánticos canónicos (`SecurityFindingSchema`).
  3. `coverage.json`: Cobertura honesta y superficies evaluadas (`CoverageSummarySchema`).
- **Proyecciones de Solo Lectura:** `report.md`, exports SARIF o dashboards HTML son proyecciones *downstream*. Ningún script ni agente debe parsear Markdown para obtener datos de auditoría.

### 1.2. Huellas Primarias Estables (*Fingerprints*) Desacopladas de Líneas
- **La Lección:** Si la identidad de un hallazgo depende de números de línea (`path:line`), cualquier refactorización, inserción de comentarios o commit rompe el seguimiento histórico y duplica incidencias.
- **La Solución:** Derivar la huella primaria a partir de 4 elementos semánticos estables:
  $$\text{Fingerprint} = \text{SHA-256}(\text{targetId} : \text{ruleId} : \text{anchor} : \text{instance})$$
  - `ruleId`: Familia de control estable (`<categoría>.<control>`, e.g. `path-traversal.archive-extraction`).
  - `anchor`: Ancla semántica del control raíz (e.g. `extract-entry-without-containment`).
  - `instance`: Diferenciador opcional para instancias hermanas.
  - Formato: `devia/v1:sha256:<64-hex>`.

### 1.3. Estructura de Evidencia de Código con 7 Roles Semánticos
- **La Lección:** Los veredictos en prosa genérica ("falta validación") son ambiguos y difíciles de verificar o automatizar.
- **La Solución:** Todo hallazgo SAST debe estructurar su `codeEvidence` asignando a cada fragmento uno de los 7 roles canónicos:
  `user_input` $\to$ `entrypoint` $\to$ `propagation` $\to$ `root_control` $\to$ `sink` $\to$ `outcome`, complementado con `expected_control` para contrastar el invariante esperado.

### 1.4. Contratos de Mapeo Multimarco (ATT&CK, NIST CSF, ASVS)
- **La Lección:** Consumir capas JSON de visualización táctica (MITRE ATT&CK Navigator v4.x) sin tipado estricto genera fallos silenciosos por discrepancias de versión y roturas de esquema.
- **La Solución:** Todo mapeo táctico valida contra `AttackNavigatorLayerSchema` y `CrossFrameworkMappingEntrySchema` en `src/schemas/framework-mapping.schema.ts`.

---

## ⚡ 2. Rendimiento y Complejidad Algorítmica (Capa 3: Python Determinista)

### 2.1. Traversal y Cómputo Determinista en Python vs Bucles ReAct
- **La Lección:** Intentar listar directorios, parsear JSONs grandes o calcular hashes mediante bucles conversacionales de LLM o comandos bash encadenados gasta decenas de miles de tokens y es propenso a errores de timeout.
- **La Regla Operativa:**  
  Toda operación de cálculo de hashes, inventario de archivos o análisis de lockfiles debe delegarse a scripts Python deterministas en `src/scripts/` con soporte `--json`.
  - [`src/scripts/forensic_inventory.py`](file:///k:/Devia-CyberSecurity/src/scripts/forensic_inventory.py): Traversal determinista en memoria sin ejecutar código del objetivo.
  - [`src/scripts/target_snapshot.py`](file:///k:/Devia-CyberSecurity/src/scripts/target_snapshot.py): Hashing ordenado lexicográficamente $O(n \log n)$ y huellas primarias $O(1)$.
  - [`src/scripts/hard_exclusions.py`](file:///k:/Devia-CyberSecurity/src/scripts/hard_exclusions.py): Filtrado determinista $O(1)$ de rutas fuera de alcance.

### 2.2. Manejo de Inodos de 64/128 bits en Windows para SQLite
- **La Lección:** En Windows con Python 3.12+, `os.stat()` puede reportar IDs de inodo de 128 bits o identificadores de dispositivo de 64 bits sin signo. Si se almacenan directamente en columnas `INTEGER` de SQLite, se produce un error por desbordamiento del entero firmado de 64 bits ($> 2^{63}-1$).
- **La Solución:** Tratar y almacenar siempre inodos e IDs de volumen como `TEXT` (cadenas de texto hexadecimales o decimales) o usar hashing truncado.

---

## 🛡️ 3. Invariantes Críticos Transversales de Seguridad

### 3.1. Axioma de Confianza Cero en Código Cliente (Frontend)
- **La Regla:** El código del navegador (JavaScript, WebAssembly, HTML, TypeScript en cliente) es territorio hostil bajo control absoluto del usuario.
- **Consecuencia de Auditoría:** Una verificación o sanitización realizada exclusivamente en el cliente **NO constituye un control de seguridad**. Todo hallazgo que dependa de protecciones frontend debe reportarse como vulnerable en el backend.

### 3.2. Confinamiento Estricto de Salida y Anti-Fuga de Datos
- **La Regla:** Ningún script de auditoría, motor MCP o herramienta debe escribir reportes, volcados o evidencias fuera de la ruta de salida explícitamente autorizada (`-o / --output-dir`).
- **Mitigación:** Validar que la ruta de destino resuelva dentro del directorio de trabajo o sandbox mediante `Path.resolve()` y comprobación de prefijo canónico (`os.path.commonpath`).

### 3.3. Confinamiento Anti-TOCTOU con Verificación de File Descriptors
- **La Regla:** En operaciones de lectura y modificación de archivos críticos, abrir primero el descriptor de archivo (`os.open` con flags `O_RDONLY | O_NOFOLLOW`) y verificar `fstat(fd)` contra la ruta antes de procesar el contenido, mitigando Time-of-Check to Time-of-Use (`TOCTOU`).

### 3.4. Sincronización Cuádruple Canónica Obligatoria
- **La Regla:** Para garantizar cero deriva técnica, cualquier nuevo vector, script o análisis debe mantener la coherencia perfecta de cuatro puntos:
  $$\text{Skill (Capa 1)} \longleftrightarrow \text{Referencias (references/)} \longleftrightarrow \text{Scripts (Capa 3)} \longleftrightarrow \text{Catálogo (docs/VULNERABILITIES.md)}$$

---

## 🪟 4. Entornos de Ejecución Windows y Prevención de Hijacking

### 4.1. Secuestro de Ruta de Búsqueda en Scripts Batch (`CWE-427` / `CWE-428`)
- **La Lección:** En Windows, el intérprete `cmd.exe` busca ejecutables en el directorio de trabajo actual (`.`) **antes** de consultar las rutas del sistema en `%PATH%`. Si un script batch invoca ejecutables sin extensión completa o sin comillas, un atacante local puede colocar un binario malicioso (`git.exe`, `node.exe`, `python.exe`) en el directorio y lograr ejecución de código.
- **La Regla Operativa:**  
  1. En scripts `.bat` o `.cmd`, calificar siempre la ruta absoluta o invocar explícitamente con extensión (e.g. `python.exe`, no `python`).
  2. En subprocesos Python, pasar listas tokenizadas sin `shell=True` (`subprocess.run(["python.exe", ...], shell=False)`).

### 4.2. Invocación Segura de Subprocesos y Paso de Prompts Vía Stdin
- **La Lección:** En Windows, la línea de comandos tiene un límite estricto de longitud (`ARG_MAX` = 8,191 caracteres para `cmd.exe` y 32,767 para `CreateProcessW`). Intentar pasar prompts grandes o contenidos de archivos mediante argumentos CLI falla catastróficamente.
- **La Regla Operativa:**  
  Pasar siempre datos grandes, prompts y contenidos de archivos a través de `sys.stdin` / `input=...` en el subproceso, nunca como argumentos posicionales de línea de comandos.

### 4.3. Separadores de Ruta Multiplataforma y Anti-Zip Slip en Windows
- **La Lección:** Las rutas en archivos zip o tar comprimidos en Windows pueden contener tanto barras diagonales directas (`/`) como invertidas (`\`). Si un parser solo reemplaza `/`, un archivo malicioso con `..\..\windows\system32` escapa del directorio de extracción (`VULN-SAST-003`).
- **La Regla Operativa:**  
  Normalizar siempre rutas con `os.path.normpath(entry.name.replace("\\", "/"))` y validar rigurosamente con `os.path.commonpath([target_dir, resolved_path]) == target_dir`.

---

## 📜 5. Cadena de Custodia Forense (Los 4 Ledgers)

Toda auditoría de ingeniería inversa y análisis forense exhaustivo debe producir y mantener los cuatro ledgers canónicos en `audits/<target>/`:

1. **`inventory.jsonl` / `summary.json`:** Metadatos del sistema de archivos, tamaños, tipos MIME y hashes SHA-256 (`src/scripts/forensic_inventory.py`).
2. **`coverage.jsonl`:** Disposición epistemológica por archivo (`inventoried`, `read`, `traced`, `verified`, `excluded`, `blocked`).
3. **`evidence.jsonl`:** Citas factuales estructuradas (`SRC-XXX`, `ART-XXX`, `RUN-XXX`) con nivel epistemológico (`OBSERVED`, `DERIVED`, `INFERRED`).
4. **`unknowns.jsonl`:** Incertidumbres explícitas, contradicciones y dependencias no verificadas.

---

## 🚀 6. Atajos y Comandos de Verificación Rápida

| Objetivo de Verificación | Comando Canónico | Criterio de Éxito |
| :--- | :--- | :--- |
| **Suite de Contratos Zod (Capa 2)** | `pnpm test` | Todos los tests pasan (`node --test "dist/**/*.test.js"`). |
| **Compilación y Tipado TypeScript** | `pnpm build` o `pnpm typecheck` | Cero errores de compilación (`tsc`). |
| **Suite Completa de Motores Python (Capa 3)** | `python -m unittest discover -s src/scripts -p "test_*.py"` | 134+ tests pasando en $< 0.5$s. |
| **Auditoría Forense de un Repositorio Externo** | `python src/scripts/forensic_inventory.py "<TARGET>" -o "<OUT>/inventory"` | Generación de `inventory.jsonl` y `summary.json`. |
| **Escaneo de Secretos por Entropía** | `python src/scripts/scan_secrets.py "<TARGET>" --json` | Detección determinista sin falsos positivos. |
| **Auditoría de Integridad de Lockfiles** | `python src/scripts/check_lockfiles.py "<TARGET>" --json` | Validación de hooks y dependencias. |
