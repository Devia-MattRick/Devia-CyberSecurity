import test from "node:test";
import assert from "node:assert/strict";
import {
  SealedScanManifestSchema,
  CoverageSummarySchema
} from "./scan-contract.schema.js";

test("SealedScanManifestSchema validates a valid sealed manifest", () => {
  const sampleManifest = {
    documentType: "devia.scan-manifest",
    schemaVersion: "1.0",
    scan: {
      id: "scan_test_001",
      producer: {
        name: "devia-cybersecurity",
        version: "0.1.0"
      },
      status: "completed",
      startedAt: "2026-10-27T07:00:00Z",
      completedAt: "2026-10-27T07:05:00Z",
      sealedAt: "2026-10-27T07:05:00Z",
      target: {
        kind: "directory_snapshot",
        targetId: "target_test_id",
        snapshotDigest: "devia-snapshot/v1:sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
      },
      scope: {
        includePaths: ["."],
        excludePaths: ["node_modules"]
      },
      findingsRef: "findings.json",
      coverageRef: "coverage.json",
      artifacts: [
        {
          path: "findings.json",
          sha256: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
          mediaType: "application/json"
        },
        {
          path: "coverage.json",
          sha256: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
          mediaType: "application/json"
        }
      ]
    }
  };

  const parsed = SealedScanManifestSchema.parse(sampleManifest);
  assert.equal(parsed.scan.status, "completed");
  assert.equal(parsed.scan.artifacts.length, 2);
});

test("CoverageSummarySchema validates structured coverage", () => {
  const sampleCoverage = {
    documentType: "devia.coverage",
    schemaVersion: "1.0",
    scanId: "scan_test_001",
    mode: "repository",
    completeness: "complete",
    inventoryStrategy: "repository",
    includePaths: ["."],
    excludePaths: [],
    surfaces: [
      {
        id: "surface_auth",
        label: "Authentication & JWT",
        disposition: "reported",
        receiptRefs: ["REC-001"]
      }
    ],
    explicitExclusions: ["dist"],
    deferred: []
  };

  const parsed = CoverageSummarySchema.parse(sampleCoverage);
  assert.equal(parsed.completeness, "complete");
  assert.equal(parsed.surfaces[0].id, "surface_auth");
});
