import { test } from "node:test";
import assert from "node:assert/strict";
import {
  ArtifactKindSchema,
  ArtifactInputDigestSchema,
  ArtifactRefSchema,
  SastSourceLocationSchema,
  ReconciliationObservationSchema,
  ReconciliationTaskSchema
} from "./reconciliation.schema.js";

test("ReconciliationSchema: validates artifact kinds and input digests", () => {
  const validKind = ArtifactKindSchema.parse("producer-observations");
  assert.equal(validKind, "producer-observations");

  const digest = ArtifactInputDigestSchema.parse({
    artifactKind: "task-formation",
    sha256: "a".repeat(64)
  });
  assert.equal(digest.sha256, "a".repeat(64));

  assert.throws(() => {
    ArtifactInputDigestSchema.parse({
      artifactKind: "invalid-kind",
      sha256: "short-sha"
    });
  });
});

test("ReconciliationSchema: validates ArtifactRef with lineage inputs", () => {
  const artifactRef = ArtifactRefSchema.parse({
    path: "workspaces/run-1/tasks.json",
    artifactKind: "fixed-tasks",
    vulnerabilityClass: "injection",
    schemaVersion: 1,
    sha256: "b".repeat(64),
    inputs: [
      {
        artifactKind: "task-formation",
        sha256: "c".repeat(64)
      }
    ],
    counts: {
      candidates: 5,
      materialized: 3
    }
  });

  assert.equal(artifactRef.artifactKind, "fixed-tasks");
  assert.equal(artifactRef.inputs.length, 1);
});

test("ReconciliationSchema: validates SAST location and task reconciliation", () => {
  const observation = ReconciliationObservationSchema.parse({
    producerId: "capella-sast-01",
    scanSource: "sast",
    primaryPreference: "preferred",
    priority: "P1",
    title: "Raw SAST Observation",
    dimension: "SOURCE_CODE_SAST",
    cwe: "CWE-89"
  });
  assert.equal(observation.primaryPreference, "preferred");

  const location = SastSourceLocationSchema.parse({
    file: "src/auth/login.ts",
    line: 42,
    column: 15,
    ruleId: "CWE-89"
  });
  assert.equal(location.line, 42);

  const task = ReconciliationTaskSchema.parse({
    taskId: "TASK-INJ-001",
    producerId: "capella-sast-01",
    scanSource: "sast",
    priority: "P1",
    title: "SQL Injection in User Login Handler",
    dimension: "SOURCE_CODE_SAST",
    cwe: "CWE-89",
    sastSourceLocation: location,
    mergedObservations: [
      {
        producerId: "pentest-dynamic-02",
        scanSource: "vulnerability_analysis",
        priority: "P1",
        title: "Dynamic SQLi Confirmed on /api/login",
        dimension: "SOURCE_CODE_SAST",
        cwe: "CWE-89",
        dynamicEvidence: {
          endpoint: "/api/login",
          payload: "' OR '1'='1",
          status: 200
        }
      }
    ]
  });

  assert.equal(task.taskId, "TASK-INJ-001");
  assert.equal(task.mergedObservations?.length, 1);
  assert.equal(task.mergedObservations[0].dynamicEvidence?.status, 200);
});
