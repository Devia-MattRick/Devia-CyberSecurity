import { z } from "zod";

/**
 * Frameworks web soportados por el extractor estático de rutas.
 */
export const HttpFrameworkSchema = z.enum([
  "flask",
  "fastapi",
  "django",
  "express",
  "spring",
  "go_router",
  "rails",
  "generic_http"
]);

export type HttpFramework = z.infer<typeof HttpFrameworkSchema>;

/**
 * Métodos HTTP canónicos soportados en la declaración de rutas.
 */
export const HttpMethodSchema = z.enum([
  "GET",
  "POST",
  "PUT",
  "DELETE",
  "PATCH",
  "HEAD",
  "OPTIONS",
  "ANY"
]);

export type HttpMethod = z.infer<typeof HttpMethodSchema>;

/**
 * Declaración de ruta HTTP extraída estáticamente del código fuente.
 */
export const RouteDeclarationSchema = z.object({
  method: HttpMethodSchema,
  path: z.string().min(1).describe("Ruta declarada en el código (e.g. /api/v1/users/:id)"),
  filePath: z.string().describe("Ruta relativa al código fuente donde se declara la ruta"),
  line: z.number().int().positive().describe("Línea base 1 del archivo"),
  framework: HttpFrameworkSchema,
  handlerName: z.string().optional().describe("Nombre de la función o controlador asociado")
});

export type RouteDeclaration = z.infer<typeof RouteDeclarationSchema>;

/**
 * Clases de sumideros vulnerables detectables en código fuente.
 */
export const VulnerabilitySinkClassSchema = z.enum([
  "rce",
  "cmdi",
  "sqli",
  "deserialization",
  "ssrf",
  "fileio",
  "template",
  "secrets",
  "auth",
  "redirect",
  "crypto"
]);

export type VulnerabilitySinkClass = z.infer<typeof VulnerabilitySinkClassSchema>;

/**
 * Sumidero vulnerable identificado estáticamente en el código fuente.
 */
export const VulnerabilitySinkSchema = z.object({
  sinkClass: VulnerabilitySinkClassSchema,
  filePath: z.string(),
  line: z.number().int().positive(),
  matchedSnippet: z.string().max(300),
  severity: z.enum(["CRITICAL", "HIGH", "MEDIUM", "LOW"])
});

export type VulnerabilitySink = z.infer<typeof VulnerabilitySinkSchema>;

/**
 * Lead correlacionado entre una ruta HTTP y uno o más sumideros co-ubicados.
 */
export const CorrelatedBridgeLeadSchema = z.object({
  leadId: z.string().regex(/^LEAD-[A-Z0-9_-]+$/, "Formato LEAD-XXX requerido"),
  route: RouteDeclarationSchema,
  associatedSinks: z.array(VulnerabilitySinkSchema).min(1),
  highestSeverity: z.enum(["CRITICAL", "HIGH", "MEDIUM", "LOW"]),
  confidenceScore: z.number().min(0.0).max(1.0),
  hypothesisOrigin: z.literal("source-to-runtime-bridge"),
  suggestedAction: z.string()
});

export type CorrelatedBridgeLead = z.infer<typeof CorrelatedBridgeLeadSchema>;

/**
 * Resultado completo del escaneo y puente bidireccional Source-to-Runtime.
 */
export const SourceToRuntimeBridgeScanResultSchema = z.object({
  scanId: z.string().uuid(),
  createdAt: z.string().datetime(),
  sourceRoot: z.string(),
  totalRoutesDiscovered: z.number().int().nonnegative(),
  totalSinksDiscovered: z.number().int().nonnegative(),
  correlatedLeads: z.array(CorrelatedBridgeLeadSchema),
  unmappedRoutes: z.array(RouteDeclarationSchema).optional(),
  isolatedSinks: z.array(VulnerabilitySinkSchema).optional()
});

export type SourceToRuntimeBridgeScanResult = z.infer<typeof SourceToRuntimeBridgeScanResultSchema>;
