import { z } from "zod";

/**
 * Las 8 Dimensiones Canónicas de Auditoría en Devia-CyberSecurity.
 */
export const SecurityDimensionSchema = z.enum([
  "THREAT_MODELING_ATTACK_SURFACE",
  "SOURCE_CODE_SAST",
  "SECRETS_CRYPTOGRAPHY",
  "IDENTITY_ACCESS_SESSION",
  "SUPPLY_CHAIN_SCA",
  "ARCHITECTURE_BOUNDARIES_ZERO_TRUST",
  "CONFIGURATION_HARDENING",
  "RESILIENCE_LOGGING_TELEMETRY"
]);

export type SecurityDimension = z.infer<typeof SecurityDimensionSchema>;

export const SeveritySchema = z.enum([
  "CRITICAL",
  "HIGH",
  "MEDIUM",
  "LOW",
  "INFORMATIONAL"
]);

export type Severity = z.infer<typeof SeveritySchema>;

export const ConfidenceSchema = z.enum([
  "CONFIRMED",
  "HIGH",
  "MEDIUM",
  "LOW"
]);

export type Confidence = z.infer<typeof ConfidenceSchema>;

export const CodeLocationSchema = z.object({
  path: z.string().describe("Ruta relativa del archivo dentro del repositorio auditado"),
  startLine: z.number().int().positive().describe("Línea inicial del hallazgo"),
  endLine: z.number().int().positive().optional().describe("Línea final del hallazgo"),
  startColumn: z.number().int().positive().optional().describe("Columna inicial"),
  endColumn: z.number().int().positive().optional().describe("Columna final"),
  symbol: z.string().optional().describe("Nombre de la función, clase o método involucrado")
});

export type CodeLocation = z.infer<typeof CodeLocationSchema>;

export const TaintTraceStepSchema = z.object({
  step: z.number().int().positive(),
  path: z.string(),
  line: z.number().int().positive(),
  description: z.string(),
  codeSnippet: z.string().optional()
});

export type TaintTraceStep = z.infer<typeof TaintTraceStepSchema>;

/**
 * Esquema Universal Canónico para Hallazgos de Vulnerabilidad.
 * Totalmente agnóstico de lenguaje, framework o infraestructura.
 */
export const SecurityFindingSchema = z.object({
  id: z.string().regex(/^SEC-[A-Z0-9_-]+$/, "El ID debe cumplir con el formato SEC-<ID>"),
  title: z.string().min(5).max(200).describe("Título conciso y técnico del hallazgo"),
  severity: SeveritySchema,
  confidence: ConfidenceSchema,
  dimension: SecurityDimensionSchema,
  cvss: z.object({
    score: z.number().min(0).max(10),
    vector: z.string().optional()
  }).optional(),
  cwe: z.array(z.string().regex(/^CWE-\d+$/)).min(1).describe("Identificadores CWE asociados"),
  owasp: z.array(z.string()).optional().describe("Categorías OWASP Top 10 o ASVS"),
  location: CodeLocationSchema,
  evidence: z.string().describe("Fragmento de código o configuración que evidencia el problema"),
  taintTrace: z.array(TaintTraceStepSchema).optional().describe("Traza de propagación de datos desde fuente no confiable hasta sumidero (sink)"),
  description: z.string().describe("Explicación exhaustiva del mecanismo de fallo y vector de explotación"),
  impact: z.string().describe("Impacto técnico específico (e.g., ejecución remota, fuga de secretos, bypass de autenticación)"),
  remediation: z.object({
    summary: z.string().describe("Recomendación de remediación concisa"),
    fixSnippet: z.string().optional().describe("Ejemplo de código seguro corregido"),
    steps: z.array(z.string()).min(1).describe("Pasos detallados para resolver el hallazgo")
  }),
  references: z.array(z.string().url()).optional().describe("Enlaces autoritativos de referencia (NIST, OWASP, MITRE)")
});

export type SecurityFinding = z.infer<typeof SecurityFindingSchema>;
