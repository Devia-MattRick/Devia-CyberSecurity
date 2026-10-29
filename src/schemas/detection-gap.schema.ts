import { z } from "zod";

/**
 * Veredicto de detección sobre una actividad adversarial.
 */
export const DetectionVerdictSchema = z.enum([
  "DETECTED_ON_TIME",  // Detectado y alertado en tiempo útil (< SLA)
  "DETECTED_LATE",     // Detectado tras la ventana operativa de contención
  "MISSED_SILENT",     // Punto ciego total: ninguna alerta ni log útil generado
  "LOGGED_NOT_ALERTED" // El evento se registró en logs pero no disparó alerta en SIEM/EDR
]);

export type DetectionVerdict = z.infer<typeof DetectionVerdictSchema>;

/**
 * Registro de una actividad ofensiva ejecutada por el Red Team.
 */
export const RedTeamActivitySchema = z.object({
  activityId: z.string().regex(/^ACT-\d+$/, "El ID debe cumplir con el formato ACT-XXX"),
  name: z.string().min(3).max(150),
  techniqueId: z.string().regex(/^T\d+(\.\d+)?$/, "Debe cumplir formato MITRE ATT&CK (e.g. T1003.006)"),
  tactic: z.string().min(3),
  timestamp: z.string().datetime(),
  sourceHost: z.string().min(1),
  targetHost: z.string().min(1),
  toolOrMethod: z.string().min(1),
  executionEvidence: z.string().min(5),
  tags: z.array(z.string()).default([])
});

export type RedTeamActivity = z.infer<typeof RedTeamActivitySchema>;

/**
 * Telemetría defensiva (alerta o log) capturada por el Blue Team / SOC.
 */
export const DefendedTelemetrySchema = z.object({
  alertId: z.string().min(1),
  sourceSystem: z.string().min(1).describe("SIEM, EDR, Firewall, WAF, Windows Event Log"),
  alertName: z.string().min(3),
  timestamp: z.string().datetime(),
  severity: z.enum(["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL"]),
  ruleOrSignatureId: z.string().optional(),
  evidenceLogSnippet: z.string().optional()
});

export type DefendedTelemetry = z.infer<typeof DefendedTelemetrySchema>;

/**
 * Brecha de detección individual analizada.
 */
export const DetectionGapEntrySchema = z.object({
  gapId: z.string().regex(/^GAP-\d+$/, "El ID debe cumplir con el formato GAP-XXX"),
  activityId: z.string(),
  techniqueId: z.string(),
  verdict: DetectionVerdictSchema,
  detectionLagSeconds: z.number().nonnegative().optional(),
  telemetryEvidence: DefendedTelemetrySchema.optional(),
  rootCause: z.string().min(5).describe("Causa de la falta de detección (e.g. telemetría no recolectada, regla no afinada, umbral muy alto)"),
  remediationRecommendation: z.string().min(10)
});

export type DetectionGapEntry = z.infer<typeof DetectionGapEntrySchema>;

/**
 * Reporte formal de análisis de brechas de detección de campaña Red/Blue Team.
 */
export const DetectionGapReportSchema = z.object({
  engagementId: z.string().uuid(),
  campaignName: z.string().min(3).max(150),
  evaluatedPeriod: z.object({
    start: z.string().datetime(),
    end: z.string().datetime()
  }),
  totalActivities: z.number().int().nonnegative(),
  metrics: z.object({
    detectedCount: z.number().int().nonnegative(),
    missedCount: z.number().int().nonnegative(),
    loggedOnlyCount: z.number().int().nonnegative(),
    detectionRatePercent: z.number().min(0).max(100),
    meanDetectionLagSeconds: z.number().nonnegative().nullable()
  }),
  blindSpotTechniques: z.array(z.string()).describe("Lista de técnicas MITRE ATT&CK sin cobertura de detección alguna"),
  gaps: z.array(DetectionGapEntrySchema)
});

export type DetectionGapReport = z.infer<typeof DetectionGapReportSchema>;
