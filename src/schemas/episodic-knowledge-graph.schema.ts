import { z } from "zod";

/**
 * Taxonomía Canónica de Etiquetas de Nodos para el Grafo de Conocimiento Episódico.
 * Modela todas las entidades descubiertas durante auditorías y penetration testing autónomo.
 */
export const EpisodicGraphNodeLabelSchema = z.enum([
  "Host",
  "Port",
  "Service",
  "WebApp",
  "Endpoint",
  "Account",
  "Vulnerability",
  "Misconfiguration",
  "Capability",
  "Credential",
  "ValidAccess",
  "PrivChange",
  "Tool",
  "ToolExecution",
  "Artifact",
  "Evidence",
  "Attempt",
  "AttackTechnique"
]);

export type EpisodicGraphNodeLabel = z.infer<typeof EpisodicGraphNodeLabelSchema>;

/**
 * Taxonomía Canónica de Tipos de Relaciones (Aristas) en el Grafo de Conocimiento Episódico.
 * Modela las conexiones de causa, descubrimiento y explotación entre entidades.
 */
export const EpisodicGraphEdgeTypeSchema = z.enum([
  "HAS_PORT",
  "RUNS_SERVICE",
  "HOSTS_APP",
  "HAS_ENDPOINT",
  "DETECTED_VULNERABILITY",  // Hallazgo preliminar no verificado
  "CONFIRMED_VULNERABILITY", // Hallazgo verificado empíricamente
  "HAS_VULNERABILITY",       // Explotación exitosa demostrada
  "HAS_MISCONFIGURATION",
  "AUTHENTICATES_TO",
  "YIELDED_ACCESS",
  "ESCALATED_VIA",
  "PIVOTED_TO",
  "ATTEMPTED_ON"
]);

export type EpisodicGraphEdgeType = z.infer<typeof EpisodicGraphEdgeTypeSchema>;

/**
 * Representación estructurada de un Nodo en el Grafo Episódico.
 */
export const EpisodicGraphNodeSchema = z.object({
  uuid: z.string().uuid("El identificador del nodo debe ser un UUID v4 válido"),
  label: EpisodicGraphNodeLabelSchema,
  name: z.string().min(1).describe("Nombre identificativo de la entidad (ej. IP, puerto, CVE)"),
  properties: z.record(z.string(), z.any()).default({}),
  discoveredAt: z.string().datetime(),
  sourceAgent: z.string().min(1).describe("Rol del agente que descubrió la entidad (ej. pentester, searcher)")
});

export type EpisodicGraphNode = z.infer<typeof EpisodicGraphNodeSchema>;

/**
 * Representación estructurada de una Arista (Relación) en el Grafo Episódico.
 */
export const EpisodicGraphEdgeSchema = z.object({
  uuid: z.string().uuid("El identificador de la arista debe ser un UUID v4 válido"),
  type: EpisodicGraphEdgeTypeSchema,
  sourceNodeUuid: z.string().uuid(),
  targetNodeUuid: z.string().uuid(),
  weight: z.number().min(0).max(1).default(1.0),
  properties: z.record(z.string(), z.any()).default({}),
  createdAt: z.string().datetime()
});

export type EpisodicGraphEdge = z.infer<typeof EpisodicGraphEdgeSchema>;

/**
 * Snapshot del Grafo de Conocimiento Episódico para un contexto de escaneo.
 */
export const EpisodicKnowledgeGraphSchema = z.object({
  scanContextId: z.string().min(1),
  generatedAt: z.string().datetime(),
  nodes: z.array(EpisodicGraphNodeSchema),
  edges: z.array(EpisodicGraphEdgeSchema),
  metrics: z.object({
    totalNodes: z.number().int().nonnegative(),
    totalEdges: z.number().int().nonnegative(),
    confirmedVulnerabilitiesCount: z.number().int().nonnegative()
  })
});

export type EpisodicKnowledgeGraph = z.infer<typeof EpisodicKnowledgeGraphSchema>;

/**
 * Parámetros de consulta estructurada hacia el Grafo de Conocimiento (Graphiti Query).
 */
export const EpisodicGraphQuerySchema = z.object({
  searchType: z.enum([
    "recent_context",
    "successful_tools",
    "episode_context",
    "entity_relationships",
    "diverse_results",
    "entity_by_label"
  ]),
  query: z.string().min(1),
  centerNodeUuid: z.string().uuid().optional(),
  nodeLabels: z.array(EpisodicGraphNodeLabelSchema).optional(),
  edgeTypes: z.array(EpisodicGraphEdgeTypeSchema).optional(),
  maxDepth: z.number().int().positive().max(5).default(2),
  recencyWindow: z.string().optional()
});

export type EpisodicGraphQuery = z.infer<typeof EpisodicGraphQuerySchema>;
