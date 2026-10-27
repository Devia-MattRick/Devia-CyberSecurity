import { z } from "zod";

export const ThreatActorSchema = z.object({
  id: z.string(),
  name: z.string(),
  type: z.enum(["ANONYMOUS_REMOTE", "AUTHENTICATED_USER", "PRIVILEGED_INSIDER", "SUPPLY_CHAIN_DEPENDENCY", "LOCAL_PROCESS"]),
  capabilities: z.array(z.string()),
  motivation: z.string().optional()
});

export const TrustBoundarySchema = z.object({
  id: z.string(),
  name: z.string(),
  description: z.string(),
  componentsInside: z.array(z.string()),
  componentsOutside: z.array(z.string())
});

export const EntryPointSchema = z.object({
  id: z.string(),
  name: z.string(),
  type: z.enum(["HTTP_API", "CLI_ARGUMENT", "WEBSOCKET", "IPC_MESSAGE", "FILE_INPUT", "DATABASE_QUERY", "ENV_VARIABLE", "EXTERNAL_CALLBACK"]),
  location: z.string(),
  trustLevelRequired: z.string(),
  sanitizationPresent: z.boolean(),
  notes: z.string().optional()
});

export const ThreatScenarioSchema = z.object({
  id: z.string(),
  title: z.string(),
  threatCategory: z.enum(["SPOOFING", "TAMPERING", "REPUDIATION", "INFORMATION_DISCLOSURE", "DENIAL_OF_SERVICE", "ELEVATION_OF_PRIVILEGE"]),
  actorId: z.string(),
  affectedAsset: z.string(),
  description: z.string(),
  mitigationStatus: z.enum(["UNMITIGATED", "PARTIALLY_MITIGATED", "FULLY_MITIGATED"]),
  mitigationStrategy: z.string().optional()
});

export const ThreatModelSchema = z.object({
  targetName: z.string(),
  version: z.string().optional(),
  assessmentDate: z.string().datetime(),
  assets: z.array(z.object({
    id: z.string(),
    name: z.string(),
    sensitivity: z.enum(["PUBLIC", "INTERNAL", "CONFIDENTIAL", "RESTRICTED_CRITICAL"]),
    description: z.string()
  })),
  actors: z.array(ThreatActorSchema),
  trustBoundaries: z.array(TrustBoundarySchema),
  entryPoints: z.array(EntryPointSchema),
  threatScenarios: z.array(ThreatScenarioSchema)
});

export type ThreatModel = z.infer<typeof ThreatModelSchema>;
