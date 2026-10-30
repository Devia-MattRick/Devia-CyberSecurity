# Guía Operativa de Taint Analysis con CodeQL y Extensiones de Datos

> **Dimensión:** `SOURCE_CODE_SAST`  
> **Taxonomía:** CWE-89 / CWE-78 / CWE-22 / OWASP A03:2021  
> **Origen de Absorción:** `security-audit/static-analysis/skills/codeql/SKILL.md` (Acción `ABS-007`)  
> **Vulnerabilidad Asociada:** `VULN-SAST-001` (SQL / NoSQL Injection)  

---

## 🏛️ Principios Operativos Esenciales de CodeQL

CodeQL modela el código fuente como una base de datos relacional y realiza análisis de flujo de datos (*Data Flow*) y seguimiento de taint (*Taint Tracking*) interprocedural a través de múltiples archivos.

Para que los análisis SAST basados en CodeQL sean concluyentes y rigurosos, se deben respetar 5 leyes de calidad:

1. **La Calidad de la Base de Datos es No Negociable:** Una base de datos que compila sin errores no es necesariamente válida. Debe verificarse el recuento de archivos extraídos contra el total de archivos fuente reales. Un build en caché o un fallo en el extractor produce cero cobertura real.
2. **Las Extensiones de Datos (*Data Extensions*) Capturan lo que CodeQL Omite:** Las aplicaciones reales emplean wrappers propios alrededor de queries a base de datos, parsers de peticiones o llamadas al sistema. Sin extensiones de datos YAML que declaren estas funciones como fuentes (*sources*) o sumideros (*sinks*), CodeQL ignora los flujos de taint internos.
3. **Las Referencias Explícitas a Suites Evitan el Filtrado Silencioso:** Nunca pasar nombres de paquetes directamente a `codeql database analyze`; los archivos de suite por defecto pueden aplicar filtros ocultos. Siempre generar un archivo `.qls` explícito.
4. **Cero Hallazgos Requiere Investigación, No Celebración:** La ausencia total de resultados suele ser síntoma de fallos en el extractor, modelos faltantes o suites mal configuradas, y no prueba de seguridad.
5. **Detección de Arquitectura Apple Silicon:** En macOS con procesadores M1/M2/M3, el código de salida 137 suele deberse a discrepancias entre `arm64` y `arm64e`, resoluble mediante herramientas nativas o compilación Rosetta.

---

## 🛠️ Modelado de Sinks Propietarios mediante Data Extensions (YAML)

Cuando una aplicación utiliza un wrapper personalizado para ejecutar consultas SQL o comandos de sistema (e.g. `dbClient.rawExec(sql)` o `systemShim.run(cmd)`), se debe declarar la extensión de datos en formato YAML:

```yaml
extensions:
  - addsTo:
      pack: codeql/javascript-all
      extensible: sinkModel
    data:
      # [package, type, subtypes, name, signature, ext, input, kind]
      - ["@myorg/database", "DbClient", true, "rawExec", "(query)", "", "Argument[0]", "sql-injection"]
      - ["@myorg/system-utils", "SystemShim", true, "run", "(cmd)", "", "Argument[0]", "command-injection"]
```

---

## 📊 Ciclo de Ejecución de Taint Tracking

```
[Fuente No Confiable (Source)]
e.g. req.body.userInput, ipcEvent.payload, process.argv[2]
       │
       ▼
[Propagación / Taint Step]
Concatenación de strings, asignación de variables, retorno de funciones
       │
       ▼
[Sanitizador / Guard (Barrier)]
¿Existe Zod parse, parameterized query, o whitelist validation?
  ├── Sí ──> Taint Cortado (SEGURO)
  └── No ──> Continúa flujo no confiable
       │
       ▼
[Sumidero Crítico (Sink)]
db.query(untrusted), child_process.exec(untrusted), fs.writeFile(untrusted)
       │
       ▼
[VULNERABILIDAD SAST CONFIRMADA] (CWE-89, CWE-78, CWE-22)
```

---

## 💻 Flujo Operacional de Compilación y Análisis con CodeQL CLI

### 1. Creación Determinista de la Base de Datos
```bash
codeql database create codeql-db \
  --language=javascript-typescript \
  --source-root=. \
  --overwrite
```

### 2. Ejecución de la Suite con Exportación SARIF
```bash
codeql database analyze codeql-db \
  codeql/javascript-queries:codeql-suites/javascript-security-and-quality.qls \
  --format=sarif-latest \
  --output=codeql-findings.sarif \
  --threads=0 \
  --ram=8192
```

### 3. Normalización y Deduplicación en Devia-CyberSecurity
El archivo `codeql-findings.sarif` generado se procesa mediante el motor de Capa 3:
```bash
python src/scripts/sarif_toolkit.py codeql-findings.sarif --json -o audits/codeql-normalized.json
```
