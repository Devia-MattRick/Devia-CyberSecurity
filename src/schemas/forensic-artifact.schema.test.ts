import test from "node:test";
import assert from "node:assert/strict";
import {
  ForensicArtifactEntrySchema,
  ForensicInvestigationReportSchema
} from "./forensic-artifact.schema.js";

test("ForensicArtifactEntrySchema: validates a valid Windows Prefetch artifact entry", () => {
  const sampleEntry = {
    id: "ART-PREFETCH-CMD-001",
    source: "WINDOWS_PREFETCH",
    category: "EXECUTION_HISTORY",
    entityName: "CMD.EXE",
    observedTimestamp: "2026-10-28T14:15:00Z",
    systemPath: "C:\\Windows\\Prefetch\\CMD.EXE-A1B2C3D4.pf",
    hashes: {
      sha256: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    },
    metadata: {
      runCount: 42,
      lastRunTime: "2026-10-28T14:15:00Z"
    },
    confidence: "CONFIRMED",
    mitreTechniques: ["T1059.003"],
    notes: "Ejecución sospechosa invocada desde directorio temporal."
  };

  const parsed = ForensicArtifactEntrySchema.safeParse(sampleEntry);
  assert.equal(parsed.success, true);
  if (parsed.success) {
    assert.equal(parsed.data.entityName, "CMD.EXE");
    assert.equal(parsed.data.confidence, "CONFIRMED");
  }
});

test("ForensicInvestigationReportSchema: validates a full investigation report snapshot", () => {
  const sampleReport = {
    reportId: "a1b2c3d4-e5f6-47a8-b9c0-123456789abc",
    generatedAt: "2026-10-28T14:20:00Z",
    targetHostOrImage: "HOST-FINANCE-W11-04",
    artifacts: [
      {
        id: "ART-AMCACHE-MAL-001",
        source: "WINDOWS_AMCACHE",
        category: "EXECUTION_HISTORY",
        entityName: "payload.exe",
        observedTimestamp: "2026-10-28T13:45:00Z",
        systemPath: "C:\\Users\\Victim\\AppData\\Local\\Temp\\payload.exe",
        hashes: {
          sha1: "da39a3ee5e6b4b0d3255bfef95601890afd80709"
        },
        metadata: {
          fileDescription: "Cobalt Strike Beacon Stager"
        },
        confidence: "CONFIRMED",
        mitreTechniques: ["T1204.002", "T1071.001"]
      }
    ],
    timeline: [
      {
        timestamp: "2026-10-28T13:45:00Z",
        artifactId: "ART-AMCACHE-MAL-001",
        summary: "Ejecución inicial registrada en Amcache.hve",
        isAnomaly: true
      }
    ],
    metrics: {
      totalArtifacts: 1,
      anomaliesCount: 1,
      sourceBreakdown: {
        WINDOWS_AMCACHE: 1
      }
    }
  };

  const parsed = ForensicInvestigationReportSchema.safeParse(sampleReport);
  assert.equal(parsed.success, true);
  if (parsed.success) {
    assert.equal(parsed.data.metrics.totalArtifacts, 1);
    assert.equal(parsed.data.timeline[0].isAnomaly, true);
  }
});
