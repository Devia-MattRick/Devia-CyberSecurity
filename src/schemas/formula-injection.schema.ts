import { z } from "zod";

/**
 * Caracteres canónicos que inician fórmulas o comandos DDE en Microsoft Excel,
 * LibreOffice Calc y Google Sheets (CWE-1236).
 */
export const DangerousFormulaPrefixSchema = z.enum([
  "=",
  "+",
  "-",
  "@",
  "\t",
  "\r",
  "|",
  "%"
]);

export type DangerousFormulaPrefix = z.infer<typeof DangerousFormulaPrefixSchema>;

/**
 * Tipos de exportadores de datos tabulares o formatos susceptibles a inyección.
 */
export const TabularExportFormatSchema = z.enum([
  "CSV",
  "TSV",
  "XLSX",
  "XLS",
  "ODS"
]);

export type TabularExportFormat = z.infer<typeof TabularExportFormatSchema>;

/**
 * Veredicto de sanitización para un sumidero o celda de exportación.
 */
export const FormulaSanitizationVerdictSchema = z.enum([
  "SAFE_SANITIZED",        // Neutralizado con prefijo de comilla simple (') y BOM UTF-8
  "PARTIALLY_SANITIZED",  // Neutraliza algunos caracteres pero omite pipes (|), porcentajes (%) o tabuladores (\t)
  "VULNERABLE_DIRECT_RAW", // Concatenación o mapeo crudo sin neutralización
  "MISSING_UTF8_BOM"       // Genera CSV sin \uFEFF exponiendo a corrupción de codificación en Excel
]);

export type FormulaSanitizationVerdict = z.infer<typeof FormulaSanitizationVerdictSchema>;

/**
 * Hallazgo individual de debilidad por inyección de fórmulas en exportadores o datos estáticos.
 */
export const FormulaInjectionFindingSchema = z.object({
  id: z.string().regex(/^FORMULA-[A-Z0-9_-]+$/, "El ID debe cumplir con el formato FORMULA-<ID>"),
  filePath: z.string().min(1),
  line: z.number().int().positive(),
  column: z.number().int().positive().optional(),
  format: TabularExportFormatSchema,
  verdict: FormulaSanitizationVerdictSchema,
  functionOrMethod: z.string().optional(),
  codeSnippet: z.string(),
  missingPrefixes: z.array(z.string()).default([]),
  bomEnforced: z.boolean().default(false),
  explanation: z.string().min(10),
  remediationSnippet: z.string().min(10)
});

export type FormulaInjectionFinding = z.infer<typeof FormulaInjectionFindingSchema>;

/**
 * Reporte consolidado de auditoría de inyección de fórmulas (CWE-1236).
 */
export const FormulaInjectionAuditReportSchema = z.object({
  targetPath: z.string(),
  scannedAt: z.string().datetime(),
  totalExportFunctionsAnalyzed: z.number().int().nonnegative(),
  vulnerableCount: z.number().int().nonnegative(),
  findings: z.array(FormulaInjectionFindingSchema),
  overallStatus: z.enum(["COMPLIANT", "NON_COMPLIANT"])
});

export type FormulaInjectionAuditReport = z.infer<typeof FormulaInjectionAuditReportSchema>;
