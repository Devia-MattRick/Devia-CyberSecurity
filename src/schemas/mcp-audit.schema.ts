import { z } from "zod";

/**
 * Flags heurísticas de envenenamiento y anomalías detectadas en herramientas MCP.
 */
export const McpPoisonFlagSchema = z.enum([
  "hidden_instruction",        // Instrucciones imperativas hacia el modelo (e.g. 'do not tell the user')
  "unicode_smuggling",        // Esteganografía con caracteres zero-width o secuencias bidi
  "oversized_description",    // Longitud excesiva de descripción (>1500 caracteres)
  "shadowing_trusted_tool",   // Suplantación o anulación de nombre de herramienta preexistente
  "prompt_injection_pattern", // Bloques <important>, <system>, [system] o reseteo de instrucciones
  "credential_access_pattern" // Búsqueda de .env, .ssh, id_rsa, /etc/passwd o tokens
]);

export type McpPoisonFlag = z.infer<typeof McpPoisonFlagSchema>;

/**
 * Esquema de definición de herramienta MCP individual.
 */
export const McpToolDefinitionSchema = z.object({
  name: z.string().min(1).max(128),
  description: z.string().optional(),
  inputSchema: z.record(z.string(), z.unknown()).optional(),
  outputSchema: z.record(z.string(), z.unknown()).optional(),
  annotations: z.record(z.string(), z.unknown()).optional()
});

export type McpToolDefinition = z.infer<typeof McpToolDefinitionSchema>;

/**
 * Veredicto de auditoría de una herramienta MCP individual.
 */
export const McpToolVerdictSchema = z.enum([
  "CLEAN",
  "SUSPICIOUS",
  "POISONED"
]);

export type McpToolVerdict = z.infer<typeof McpToolVerdictSchema>;

/**
 * Hallazgo de auditoría sobre una herramienta MCP.
 */
export const McpToolAuditFindingSchema = z.object({
  toolName: z.string(),
  verdict: McpToolVerdictSchema,
  flags: z.array(McpPoisonFlagSchema),
  schemaDigest: z.string().regex(/^sha256:[a-f0-9]{64}$/, "El digest debe ser sha256:<64-hex>"),
  descriptionLength: z.number().int().nonnegative(),
  snippet: z.string().optional(),
  rugPullDetected: z.boolean().default(false),
  pinnedDigest: z.string().optional()
});

export type McpToolAuditFinding = z.infer<typeof McpToolAuditFindingSchema>;

/**
 * Reporte consolidado de auditoría de un archivo de configuración o servidor MCP.
 */
export const McpConfigAuditReportSchema = z.object({
  timestamp: z.string().datetime(),
  targetConfig: z.string(),
  totalToolsScanned: z.number().int().nonnegative(),
  verdictCounts: z.object({
    clean: z.number().int().nonnegative(),
    suspicious: z.number().int().nonnegative(),
    poisoned: z.number().int().nonnegative()
  }),
  findings: z.array(McpToolAuditFindingSchema),
  pinnedToolsHashRegistry: z.record(z.string(), z.string()).optional()
});

export type McpConfigAuditReport = z.infer<typeof McpConfigAuditReportSchema>;
