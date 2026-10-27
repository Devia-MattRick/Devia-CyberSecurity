import { z } from "zod";
import { SeveritySchema } from "./finding.schema.js";

/**
 * Tipos canónicos de incidentes de seguridad catalogados.
 */
export const IncidentTypeSchema = z.enum([
  "malware",
  "ransomware",
  "phishing",
  "unauthorized_access",
  "data_exfiltration",
  "ddos",
  "insider_threat",
  "account_compromise",
  "web_attack",
  "privilege_escalation",
  "lateral_movement",
  "supply_chain"
]);

export type IncidentType = z.infer<typeof IncidentTypeSchema>;

/**
 * Escala de criticidad de los activos involucrados.
 */
export const AssetCriticalitySchema = z.enum([
  "critical",
  "high",
  "medium",
  "low"
]);

export type AssetCriticality = z.infer<typeof AssetCriticalitySchema>;

/**
 * Sensibilidad de la información comprometida o expuesta.
 */
export const DataSensitivitySchema = z.enum([
  "pii_phi",
  "pci",
  "confidential",
  "public"
]);

export type DataSensitivity = z.infer<typeof DataSensitivitySchema>;

/**
 * Estado y progreso de la amenaza observada.
 */
export const ThreatStatusSchema = z.enum([
  "active",
  "confirmed",
  "attempted",
  "recon"
]);

export type ThreatStatus = z.infer<typeof ThreatStatusSchema>;

/**
 * Alcance y dispersión del incidente en la infraestructura.
 */
export const IncidentScopeSchema = z.enum([
  "enterprise",
  "department",
  "single_system",
  "single_user"
]);

export type IncidentScope = z.infer<typeof IncidentScopeSchema>;

/**
 * Solicitud de evaluación cuantitativa de triaje para un incidente.
 */
export const IncidentTriageRequestSchema = z.object({
  incidentId: z.string().min(3).describe("Identificador único del incidente o notable event"),
  title: z.string().min(5).max(250),
  incidentType: IncidentTypeSchema,
  assetCriticality: AssetCriticalitySchema,
  dataSensitivity: DataSensitivitySchema,
  threatStatus: ThreatStatusSchema,
  scope: IncidentScopeSchema,
  affectedAssets: z.array(z.string()).min(1),
  indicatorsOfCompromise: z.array(z.string()).optional(),
  detectedAt: z.string().datetime().optional()
});

export type IncidentTriageRequest = z.infer<typeof IncidentTriageRequestSchema>;

/**
 * Resultado formal y determinista de triaje, severidad calculada y playbook asignado.
 */
export const IncidentTriageEvaluationSchema = z.object({
  incidentId: z.string().min(3),
  evaluatedAt: z.string().datetime(),
  severity: SeveritySchema,
  score: z.number().min(0).max(10).describe("Puntaje normalizado de 0.0 a 10.0"),
  assignedPlaybook: z.string().min(3).describe("Nombre del playbook de respuesta asignado"),
  assignedTeam: z.string().min(3).describe("Equipo primario de respuesta ante incidentes"),
  slaResponseHours: z.number().positive().describe("SLA máximo de primera respuesta en horas"),
  dimension: z.literal("RESILIENCE_LOGGING_TELEMETRY"),
  nistCsfCategory: z.enum(["RS.MA-01", "RS.MA-02", "RS.AN-03", "RC.RP-01", "DE.AE-02"]),
  sansPicerlPhase: z.literal("IDENTIFICATION_AND_TRIAGE"),
  escalationRequired: z.boolean(),
  containmentRecommendations: z.array(z.string()).min(1)
});

export type IncidentTriageEvaluation = z.infer<typeof IncidentTriageEvaluationSchema>;
