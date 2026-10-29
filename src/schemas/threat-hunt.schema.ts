import { z } from "zod";
import { SecurityDimensionSchema } from "./finding.schema.js";

/**
 * Severidad canónica para hallazgos de Threat Hunting.
 */
export const ThreatHuntSeveritySchema = z.enum([
  "CRITICAL",
  "HIGH",
  "MEDIUM",
  "LOW",
  "INFORMATIONAL"
]);

export type ThreatHuntSeverity = z.infer<typeof ThreatHuntSeveritySchema>;

/**
 * Métricas estadísticas deterministas de balizamiento C2 (Beaconing).
 */
export const C2BeaconMetricsSchema = z.object({
  totalConnections: z.number().int().positive(),
  avgIntervalSeconds: z.number().nonnegative(),
  intervalStdev: z.number().nonnegative(),
  coefficientOfVariation: z.number().nonnegative(),
  estimatedJitterPct: z.number().nonnegative(),
  dataSizeCv: z.number().nonnegative().optional(),
  destinationEntropy: z.number().nonnegative().optional()
});

export type C2BeaconMetrics = z.infer<typeof C2BeaconMetricsSchema>;

/**
 * Esquema autoritativo para un hallazgo individual de Threat Hunting.
 */
export const ThreatHuntFindingSchema = z.object({
  findingId: z.string().min(5),
  huntId: z.string().min(3),
  technique: z.string().regex(/^T\d{4}(\.\d{3})?$/, "Debe ser un identificador MITRE ATT&CK válido (e.g. T1071 o T1071.001)"),
  dimension: SecurityDimensionSchema,
  cwe: z.array(z.string().regex(/^CWE-\d+$/)).default([]),
  severity: ThreatHuntSeveritySchema,
  confidenceScore: z.number().min(0).max(10).describe("Puntuación de confianza del analista o motor (0.0 a 10.0)"),
  sourceEntity: z.string().min(1).describe("Entidad de origen (IP interna, hostname, cuenta de usuario)"),
  targetEntity: z.string().min(1).describe("Entidad destino (dominio C2, IP externa, proceso hijo, clave de registro)"),
  beaconMetrics: C2BeaconMetricsSchema.optional(),
  indicators: z.array(z.string()).min(1).describe("Lista de indicadores observables que motivaron la detección"),
  firstSeen: z.string().datetime(),
  lastSeen: z.string().datetime(),
  evidenceSnippet: z.string().optional()
});

export type ThreatHuntFinding = z.infer<typeof ThreatHuntFindingSchema>;

/**
 * Esquema del informe consolidado de campaña de Threat Hunting.
 */
export const ThreatHuntReportSchema = z.object({
  reportId: z.string().uuid(),
  generatedAt: z.string().datetime(),
  huntObjective: z.string().min(5),
  evaluatedDimensions: z.array(SecurityDimensionSchema).min(1),
  telemetrySources: z.array(z.string()).min(1).describe("Fuentes de telemetría analizadas (e.g. Zeek, Sysmon, EVTX)"),
  findings: z.array(ThreatHuntFindingSchema),
  metrics: z.object({
    totalFindings: z.number().int().nonnegative(),
    criticalFindings: z.number().int().nonnegative(),
    highFindings: z.number().int().nonnegative()
  })
});

export type ThreatHuntReport = z.infer<typeof ThreatHuntReportSchema>;
