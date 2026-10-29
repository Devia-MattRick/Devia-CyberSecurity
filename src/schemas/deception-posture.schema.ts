import { z } from "zod";
import { SecurityDimensionSchema, SeveritySchema } from "./finding.schema.js";

/**
 * Tipos canónicos de artefactos y recursos de engaño defensivo (Deception Assets).
 */
export const DeceptionAssetTypeSchema = z.enum([
  "HONEYTOKEN",
  "CANARY_FILE",
  "DECOY_PRINCIPAL",
  "DECOY_BUCKET",
  "DECOY_SECRET",
  "DECOY_SPN",
  "SPA_GATEWAY"
]);

export type DeceptionAssetType = z.infer<typeof DeceptionAssetTypeSchema>;

/**
 * Estados de integridad para archivos canario y señuelos.
 */
export const CanaryFileStatusSchema = z.enum([
  "INTACT",
  "MODIFIED",
  "DELETED",
  "RENAMED",
  "ENCRYPTED"
]);

export type CanaryFileStatus = z.infer<typeof CanaryFileStatusSchema>;

/**
 * Alerta o anomalía detectada sobre un archivo canario.
 */
export const CanaryFileAlertSchema = z.object({
  type: z.enum([
    "RANSOMWARE_RENAME",
    "CANARY_MODIFIED",
    "CANARY_DELETED",
    "HIGH_ENTROPY_DETECTED",
    "RANSOM_NOTE_DETECTED",
    "SIGNIFICANT_SIZE_CHANGE"
  ]),
  severity: SeveritySchema,
  path: z.string(),
  renamedTo: z.string().optional(),
  entropy: z.number().min(0).max(8).optional(),
  detectedProcess: z.object({
    pid: z.number().int(),
    name: z.string(),
    cmdline: z.string().optional()
  }).optional(),
  timestamp: z.string().datetime()
});

export type CanaryFileAlert = z.infer<typeof CanaryFileAlertSchema>;

/**
 * Registro de inventario y postura de un artefacto señuelo.
 */
export const DeceptionAssetSchema = z.object({
  id: z.string().regex(/^DEC-\d+$/, "El ID debe cumplir con el formato DEC-XXX"),
  name: z.string().min(3),
  type: DeceptionAssetTypeSchema,
  environment: z.enum(["ON_PREM_AD", "CLOUD_AWS", "CLOUD_AZURE", "CLOUD_GCP", "ENDPOINT_FILE_SYSTEM", "NETWORK_PERIMETER"]),
  placement: z.string().describe("Ubicación exacta o contenedor donde reside el señuelo"),
  denyAllPolicyEnforced: z.boolean().describe("Garantiza que el señuelo no posee permisos reales (VULN-CONF-018)"),
  detectionWiring: z.object({
    telemetrySource: z.string().describe("e.g. CloudTrail, EventID 4769, Watchdog, Sentinel"),
    alertRule: z.string(),
    notificationSink: z.string(),
    playbookRef: z.string().optional()
  }),
  internalTagPresent: z.boolean().describe("Etiqueta interna oculta para evitar borrado accidental en mantenimiento"),
  lastValidatedAt: z.string().datetime().optional()
});

export type DeceptionAsset = z.infer<typeof DeceptionAssetSchema>;

/**
 * Verificación de paquete Single Packet Authorization (SPA) en pasarelas SDP.
 */
export const SpaPacketVerificationSchema = z.object({
  sourceIp: z.string().describe("Dirección IP origen del cliente SPA"),
  serviceRequested: z.string(),
  timestamp: z.number().positive(),
  nonce: z.string().min(8),
  hmacVerified: z.boolean(),
  ageSeconds: z.number(),
  replayDetected: z.boolean().describe("Detección de reutilización de nonce en la ventana de validez (VULN-ARCH-026)"),
  valid: z.boolean(),
  errors: z.array(z.string())
});

export type SpaPacketVerification = z.infer<typeof SpaPacketVerificationSchema>;

/**
 * Mapeo estratégico de operaciones de engaño según MITRE Engage.
 */
export const MitreEngageMappingSchema = z.object({
  operationName: z.string(),
  strategicGoal: z.enum(["PREPARE", "EXPOSE", "AFFECT", "ELICIT", "UNDERSTAND"]),
  targetActor: z.string().optional(),
  mappedAttackTechniques: z.array(z.string().regex(/^T\d+(\.\d+)?$/)),
  engageActivities: z.array(z.string()),
  coverageGaps: z.array(z.string()).optional()
});

export type MitreEngageMapping = z.infer<typeof MitreEngageMappingSchema>;

/**
 * Reporte Consolidado de Postura de Engaño y Detección Canaria.
 */
export const DeceptionPostureReportSchema = z.object({
  reportId: z.string().uuid(),
  generatedAt: z.string().datetime(),
  dimension: SecurityDimensionSchema.default("ARCHITECTURE_BOUNDARIES_ZERO_TRUST"),
  totalAssets: z.number().int().nonnegative(),
  postureScore: z.number().min(0).max(100),
  assets: z.array(DeceptionAssetSchema),
  canaryAlerts: z.array(CanaryFileAlertSchema),
  spaVerifications: z.array(SpaPacketVerificationSchema).optional(),
  engageMapping: MitreEngageMappingSchema.optional(),
  summary: z.object({
    compliantAssets: z.number().int().nonnegative(),
    nonCompliantAssets: z.number().int().nonnegative(),
    criticalAlertsCount: z.number().int().nonnegative(),
    replayAttacksBlocked: z.number().int().nonnegative()
  })
});

export type DeceptionPostureReport = z.infer<typeof DeceptionPostureReportSchema>;
