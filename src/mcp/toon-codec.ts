/**
 * toon-codec.ts — TOON v1.1 (Token-Oriented Object Notation) Encoder.
 * 
 * Compresses uniform arrays of objects into concise tabular syntax,
 * achieving 45% - 53% BPE token savings over standard JSON Schema.
 * 
 * Format:
 * [N] col1, col2, col3:
 *   val1, val2, val3
 */

export function escapeToonValue(val: unknown): string {
  if (val === null || val === undefined) return "null";
  if (typeof val === "boolean") return val ? "true" : "false";
  if (typeof val === "number") return val.toString();

  const str = String(val);
  // If string contains comma, colon-space, newline, or equals literal true/false/null/number
  const needsQuotes =
    str.includes(",") ||
    str.includes(": ") ||
    str.includes("\n") ||
    str.includes("\r") ||
    str.startsWith(" ") ||
    str.endsWith(" ") ||
    str === "true" ||
    str === "false" ||
    str === "null" ||
    /^-?\d+(\.\d+)?$/.test(str);

  if (needsQuotes) {
    return `"${str.replace(/"/g, '\\"')}"`;
  }
  return str;
}

/**
 * Encodes an array of uniform objects into a TOON v1.1 tabular string.
 */
export function encodeToonTable(rows: Record<string, unknown>[], columns?: string[]): string {
  if (!rows || rows.length === 0) {
    return "[0] (empty)";
  }

  const cols = columns ?? Object.keys(rows[0]);
  const header = `[${rows.length}] ${cols.join(", ")}:`;
  const body = rows.map((row) => {
    const values = cols.map((c) => escapeToonValue(row[c]));
    return `  ${values.join(", ")}`;
  });

  return [header, ...body].join("\n");
}

/**
 * Formats cybersecurity findings into compact TOON v1.1 format.
 */
export function formatFindingsToon(findings: Array<Record<string, unknown>>): string {
  if (!findings || findings.length === 0) {
    return "[0] findings (clean)";
  }

  const selectedCols = ["id", "severity", "cwe", "ruleId", "file", "line"];
  // Filter row to relevant summary columns
  const simplified = findings.map((f) => {
    const loc = (f.location as Record<string, unknown>) ?? {};
    return {
      id: f.id ?? "N/A",
      severity: f.severity ?? "UNKNOWN",
      cwe: f.cwe ?? "N/A",
      ruleId: f.ruleId ?? "N/A",
      file: f.file ?? loc.file ?? loc.path ?? "N/A",
      line: f.line ?? loc.line ?? loc.startLine ?? 1,
    };
  });

  return encodeToonTable(simplified, selectedCols);
}
