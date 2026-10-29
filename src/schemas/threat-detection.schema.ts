import { z } from "zod";
import { SecurityDimensionSchema } from "./finding.schema.js";

/**
 * Motores de telemetría y reglas de detección de amenazas admitidos.
 */
export const DetectionEngineTypeSchema = z.enum([
  "WINDOWS_SECURITY_EVENT",
  "SYSMON",
  "ZEEK",
  "FALCO",
  "CLOUDTRAIL",
  "GUARDDUTY",
  "AI_GUARDRAIL",
  "OT_ICS_PROTOCOL"
]);

export type DetectionEngineType = z.infer<typeof DetectionEngineTypeSchema>;

/**
 * Severidad canónica para alertas de detección de amenazas.
 */
export const DetectionSeveritySchema = z.enum([
  "CRITICAL",
  "HIGH",
  "MEDIUM",
  "LOW",
  "INFORMATIONAL"
]);

export type DetectionSeverity = z.infer<typeof DetectionSeveritySchema>;

/**
 * Configuración de ventana temporal para reglas de correlación multievento.
 */
export const CorrelationWindowSchema = z.object({
  windowSeconds: z.number().int().positive().describe("Ventana temporal máxima en segundos para correlacionar eventos"),
  minOccurrences: z.number().int().positive().default(1).describe("Número mínimo de ocurrencias para disparar la alerta"),
  groupBy: z.array(z.string()).min(1).describe("Campos por los que agrupar eventos (e.g. sourceIp, userAccount, host)")
});

export type CorrelationWindow = z.infer<typeof CorrelationWindowSchema>;

/**
 * Esquema de una regla de detección o correlación de amenazas.
 */
export const DetectionRuleSchema = z.object({
  ruleId: z.string().min(3).regex(/^[a-z0-9_.-]+$/i, "El ruleId debe contener sólo caracteres alfanuméricos, guiones o puntos"),
  title: z.string().min(5).max(200),
  engine: DetectionEngineTypeSchema,
  dimension: SecurityDimensionSchema,
  mitreTechnique: z.string().regex(/^T\d{4}(\.\d{3})?$/, "Debe ser un identificador MITRE ATT&CK válido (e.g. T1055 o T1558.001)"),
  cwe: z.array(z.string().regex(/^CWE-\d+$/)).default([]),
  severity: DetectionSeveritySchema,
  description: z.string().min(10),
  correlationWindow: CorrelationWindowSchema.optional(),
  detectionLogic: z.string().min(5).describe("Descripción o pseudocódigo formal de la condición de activación")
});

export type DetectionRule = z.infer<typeof DetectionRuleSchema>;

/**
 * Esquema de una alerta disparada por el motor de detección.
 */
export const DetectionAlertSchema = z.object({
  alertId: z.string().uuid(),
  timestamp: z.string().datetime(),
  ruleId: z.string(),
  engine: DetectionEngineTypeSchema,
  dimension: SecurityDimensionSchema,
  severity: DetectionSeveritySchema,
  confidenceScore: z.number().min(0).max(10).describe("Puntuación de confianza (0.0 a 10.0)"),
  sourceHost: z.string().optional(),
  targetHost: z.string().optional(),
  userAccount: z.string().optional(),
  processName: z.string().optional(),
  commandLine: z.string().optional(),
  evidenceSnippet: z.string().min(1).describe("Evidencia factual extraída del log o evento analizado"),
  correlatedEventCount: z.number().int().positive().default(1),
  correlationDetails: z.record(z.string(), z.unknown()).optional()
});

export type DetectionAlert = z.infer<typeof DetectionAlertSchema>;

/**
 * Esquema del reporte consolidado de evaluación y detección de amenazas.
 */
export const ThreatDetectionReportSchema = z.object({
  reportId: z.string().uuid(),
  generatedAt: z.string().datetime(),
  scanTarget: z.string().min(1),
  enginesEvaluated: z.array(DetectionEngineTypeSchema).min(1),
  evaluatedDimensions: z.array(SecurityDimensionSchema).min(1),
  totalEventsProcessed: z.number().int().nonnegative(),
  totalAlertsTriggered: z.number().int().nonnegative(),
  alertsBySeverity: z.record(DetectionSeveritySchema, z.number().int().nonnegative()),
  alertsByDimension: z.record(SecurityDimensionSchema, z.number().int().nonnegative()),
  alerts: z.array(DetectionAlertSchema)
});

export type ThreatDetectionReport = z.infer<typeof ThreatDetectionReportSchema>;
