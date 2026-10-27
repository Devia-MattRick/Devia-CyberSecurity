export type {
  SecurityDimension,
  Severity,
  Confidence,
  CodeLocation,
  TaintTraceStep,
  CodeEvidenceRole,
  CodeEvidenceItem,
  FindingIdentity,
  FindingFingerprint,
  SecurityFinding
} from "../schemas/finding.schema.js";

export type {
  ThreatModel
} from "../schemas/threat-model.schema.js";

export type {
  AuditReport
} from "../schemas/report.schema.js";

export type {
  AbsorptionDestination,
  EvolutionaryIntent,
  TargetType,
  EpistemicTier,
  ExtractedKnowledgeItem,
  AbsorptionAction,
  AbsorptionPlan
} from "../schemas/absorption-plan.schema.js";

export type {
  SnapshotKind,
  ScanStatus,
  ArtifactReceipt,
  TargetSnapshot,
  ScanScope,
  SealedScanManifest,
  CoverageSurface,
  CoverageSummary
} from "../schemas/scan-contract.schema.js";

