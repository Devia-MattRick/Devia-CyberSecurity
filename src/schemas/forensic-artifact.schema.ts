import { z } from "zod";
import { ConfidenceSchema } from "./finding.schema.js";
import { MitreTechniqueIdSchema } from "./framework-mapping.schema.js";

/**
 * Fuentes y orígenes de artefactos forenses de sistema, memoria y red.
 */
export const ForensicArtifactSourceSchema = z.enum([
  "WINDOWS_AMCACHE",
  "WINDOWS_PREFETCH",
  "WINDOWS_REGISTRY",
  "WINDOWS_SHIMCACHE",
  "WINDOWS_EVENT_LOG",
  "WINDOWS_LNK_JUMPLIST",
  "WINDOWS_MFT",
  "LINUX_AUDIT_LOG",
  "LINUX_SYSTEM_JOURNAL",
  "LINUX_KERNEL_MODULE",
  "MEMORY_PROCESS_LIST",
  "MEMORY_INJECTED_CODE",
  "NETWORK_PCAP_STREAM",
  "NETWORK_FLOW_RECORD",
  "C2_MALLEABLE_PROFILE",
  "ACTIVE_DIRECTORY_DACL"
]);

export type ForensicArtifactSource = z.infer<typeof ForensicArtifactSourceSchema>;

/**
 * Categorías forenses y tácticas de telemetría.
 */
export const ForensicArtifactCategorySchema = z.enum([
  "EXECUTION_HISTORY",
  "PERSISTENCE_MECHANISM",
  "PRIVILEGE_ESCALATION",
  "DEFENSE_EVASION",
  "CREDENTIAL_ACCESS",
  "COMMAND_AND_CONTROL",
  "EXFILTRATION",
  "LATERAL_MOVEMENT"
]);

export type ForensicArtifactCategory = z.infer<typeof ForensicArtifactCategorySchema>;

/**
 * Entrada estructurada individual de artefacto forense recolectado.
 */
export const ForensicArtifactEntrySchema = z.object({
  id: z.string().regex(/^ART-[A-Za-z0-9_.-]+$/, "El ID debe cumplir con el formato ART-<identificador>"),
  source: ForensicArtifactSourceSchema,
  category: ForensicArtifactCategorySchema,
  entityName: z.string().min(1).describe("Nombre del ejecutable, proceso, clave de registro o sesión"),
  observedTimestamp: z.string().datetime().describe("Marca de tiempo UTC del evento o artefacto"),
  systemPath: z.string().optional().describe("Ruta de archivo en el sistema de archivos analizado"),
  hashes: z.object({
    sha256: z.string().regex(/^[a-fA-F0-9]{64}$/).optional(),
    sha1: z.string().regex(/^[a-fA-F0-9]{40}$/).optional(),
    md5: z.string().regex(/^[a-fA-F0-9]{32}$/).optional()
  }).optional(),
  metadata: z.record(z.string(), z.union([z.string(), z.number(), z.boolean(), z.null()])).optional(),
  confidence: ConfidenceSchema.default("HIGH"),
  mitreTechniques: z.array(MitreTechniqueIdSchema).default([]),
  notes: z.string().optional()
});

export type ForensicArtifactEntry = z.infer<typeof ForensicArtifactEntrySchema>;

/**
 * Evento en la línea de tiempo forense normalizada.
 */
export const ForensicTimelineEventSchema = z.object({
  timestamp: z.string().datetime(),
  artifactId: z.string(),
  summary: z.string().min(5),
  isAnomaly: z.boolean().default(false)
});

export type ForensicTimelineEvent = z.infer<typeof ForensicTimelineEventSchema>;

/**
 * Reporte consolidado de investigación forense y telemetría de endpoint.
 */
export const ForensicInvestigationReportSchema = z.object({
  reportId: z.string().uuid(),
  generatedAt: z.string().datetime(),
  targetHostOrImage: z.string().min(1),
  artifacts: z.array(ForensicArtifactEntrySchema),
  timeline: z.array(ForensicTimelineEventSchema),
  metrics: z.object({
    totalArtifacts: z.number().int().nonnegative(),
    anomaliesCount: z.number().int().nonnegative(),
    sourceBreakdown: z.record(z.string(), z.number().int().nonnegative())
  })
});

export type ForensicInvestigationReport = z.infer<typeof ForensicInvestigationReportSchema>;
