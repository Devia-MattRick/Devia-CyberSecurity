import { z } from "zod";
import { SecurityDimensionSchema } from "./finding.schema.js";

/**
 * Identificadores canónicos de técnicas y sub-técnicas MITRE ATT&CK (e.g. T1059, T1059.001).
 */
export const MitreTechniqueIdSchema = z.string().regex(
  /^T\d{4}(\.\d{3})?$/,
  "El identificador de técnica MITRE ATT&CK debe seguir el formato T1XXX o T1XXX.XXX"
);

export type MitreTechniqueId = z.infer<typeof MitreTechniqueIdSchema>;

/**
 * Identificadores de tácticas de MITRE ATT&CK (e.g. TA0001 a TA0043).
 */
export const MitreTacticIdSchema = z.string().regex(
  /^TA\d{4}$/,
  "El identificador de táctica MITRE ATT&CK debe seguir el formato TA00XX"
);

export type MitreTacticId = z.infer<typeof MitreTacticIdSchema>;

/**
 * Las 6 Funciones Canónicas del ciclo de vida de riesgo en NIST Cybersecurity Framework (CSF 2.0).
 */
export const NistCsfFunctionSchema = z.enum([
  "GV", // Govern
  "ID", // Identify
  "PR", // Protect
  "DE", // Detect
  "RS", // Respond
  "RC"  // Recover
]);

export type NistCsfFunction = z.infer<typeof NistCsfFunctionSchema>;

/**
 * Categorías de control formalizadas en NIST CSF 2.0 (e.g. GV.OC, ID.AM, PR.AA, DE.CM).
 */
export const NistCsfCategorySchema = z.string().regex(
  /^(GV|ID|PR|DE|RS|RC)\.[A-Z]{2}$/,
  "La categoría NIST CSF 2.0 debe seguir el formato <Función>.<Categoría> (e.g. PR.AA, DE.CM)"
);

export type NistCsfCategory = z.infer<typeof NistCsfCategorySchema>;

/**
 * Categorías canónicas de riesgo crítico en aplicaciones web OWASP Top 10 (2025).
 */
export const OwaspTop10_2025Schema = z.enum([
  "A01:2025-Broken Access Control",
  "A02:2025-Cryptographic Failures",
  "A03:2025-Injection",
  "A04:2025-Insecure Design",
  "A05:2025-Security Misconfiguration",
  "A06:2025-Vulnerable and Outdated Components",
  "A07:2025-Identification and Authentication Failures",
  "A08:2025-Software and Data Integrity Failures",
  "A09:2025-Security Logging and Monitoring Failures",
  "A10:2025-Server-Side Request Forgery"
]);

export type OwaspTop10_2025 = z.infer<typeof OwaspTop10_2025Schema>;

/**
 * Metadatos asociados a una técnica dentro de una capa de MITRE ATT&CK Navigator.
 */
export const NavigatorMetadataItemSchema = z.object({
  name: z.string(),
  value: z.string()
});

export type NavigatorMetadataItem = z.infer<typeof NavigatorMetadataItemSchema>;

/**
 * Entrada de técnica dentro de una capa serializada para ATT&CK Navigator.
 */
export const NavigatorTechniqueEntrySchema = z.object({
  techniqueID: MitreTechniqueIdSchema,
  tactic: z.string().optional(),
  score: z.number().min(0).max(100).optional(),
  color: z.string().optional(),
  comment: z.string().optional(),
  enabled: z.boolean().default(true),
  metadata: z.array(NavigatorMetadataItemSchema).optional()
});

export type NavigatorTechniqueEntry = z.infer<typeof NavigatorTechniqueEntrySchema>;

/**
 * Esquema Autoritativo de Capa para MITRE ATT&CK Navigator (v4.5 / Navigator 4.9+).
 */
export const AttackNavigatorLayerSchema = z.object({
  name: z.string().min(1).max(200),
  versions: z.object({
    attack: z.string(),
    navigator: z.string(),
    layer: z.string()
  }),
  domain: z.enum(["enterprise-attack", "mobile-attack", "ics-attack"]).default("enterprise-attack"),
  description: z.string().optional(),
  filters: z.object({
    platforms: z.array(z.string()).optional()
  }).optional(),
  sorting: z.number().int().optional(),
  layout: z.record(z.string(), z.unknown()).optional(),
  hideDisabled: z.boolean().optional(),
  techniques: z.array(NavigatorTechniqueEntrySchema).min(1)
});

export type AttackNavigatorLayer = z.infer<typeof AttackNavigatorLayerSchema>;

/**
 * Contrato de Mapeo Multimarco que proyecta una Dimensión Canónica de Devia-CyberSecurity
 * contra los marcos rectores MITRE ATT&CK, NIST CSF 2.0 y OWASP Top 10 (2025).
 */
export const CrossFrameworkMappingEntrySchema = z.object({
  dimension: SecurityDimensionSchema,
  mitreTactics: z.array(MitreTacticIdSchema),
  mitreTechniquesSample: z.array(MitreTechniqueIdSchema),
  nistCsfFunctions: z.array(NistCsfFunctionSchema),
  nistCsfCategories: z.array(NistCsfCategorySchema),
  owasp2025Categories: z.array(OwaspTop10_2025Schema),
  cweCatalog: z.array(z.string().regex(/^CWE-\d+$/)),
  defensiveFocus: z.string().min(10)
});

export type CrossFrameworkMappingEntry = z.infer<typeof CrossFrameworkMappingEntrySchema>;
