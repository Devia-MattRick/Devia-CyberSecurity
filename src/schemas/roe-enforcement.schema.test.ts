import test from "node:test";
import assert from "node:assert/strict";
import {
  MachineEnforcementSchema,
  DecisionSchema,
  AuditChainRecordSchema
} from "./roe-enforcement.schema.js";

test("MachineEnforcementSchema validates default and populated configurations", () => {
  const minimal = {};
  const parsedMin = MachineEnforcementSchema.safeParse(minimal);
  assert.equal(parsedMin.success, true);
  if (parsedMin.success) {
    assert.equal(parsedMin.data.allow_cloud_metadata, false);
    assert.equal(parsedMin.data.allow_sensitive_tlds, false);
    assert.ok(parsedMin.data.forbidden_destinations.includes("169.254.169.254"));
    assert.ok(parsedMin.data.forbidden_destinations.includes("fd00:ec2::254"));
  }

  const populated = {
    configured: true,
    in_scope: [
      { pattern: "192.168.1.0/24", kind: "cidr" },
      { pattern: "*.acme.internal", kind: "domain-glob" }
    ],
    out_of_scope: [
      { pattern: "192.168.1.1", kind: "ip" }
    ],
    forbidden_command_patterns: [
      "\\brm\\s+-rf\\b",
      "\\bhydra\\s.*-t\\s*[5-9]\\d+"
    ],
    allow_cloud_metadata: false,
    allow_sensitive_tlds: false,
    min_inter_request_delay_ms: 100,
    authorized_windows: [
      { start: "2026-10-27T08:00:00Z", end: "2026-10-27T18:00:00Z" }
    ]
  };

  const parsedPop = MachineEnforcementSchema.safeParse(populated);
  assert.equal(parsedPop.success, true);
});

test("DecisionSchema validates pass and refuse verdicts", () => {
  const allowDecision = {
    allow: true,
    reason_code: "IN_SCOPE",
    reason_detail: "Target matches authorized in-scope CIDR",
    risk: "low",
    matched_targets: ["192.168.1.0/24"]
  };
  const parsedAllow = DecisionSchema.safeParse(allowDecision);
  assert.equal(parsedAllow.success, true);

  const refuseDecision = {
    allow: false,
    reason_code: "SENSITIVE_TLD",
    reason_detail: "'fbi.gov' is on protected institutional TLD",
    risk: "high",
    matched_targets: [".gov"]
  };
  const parsedRefuse = DecisionSchema.safeParse(refuseDecision);
  assert.equal(parsedRefuse.success, true);
});

test("AuditChainRecordSchema validates cryptographically chained audit events", () => {
  const record = {
    seq: 42,
    ts: "2026-10-27T14:30:00Z",
    prev_hash: "a".repeat(64),
    hash: "b".repeat(64),
    hmac: "c".repeat(64),
    tool: "bash",
    command: "curl -s http://192.168.1.50/api",
    decision: {
      allow: true,
      reason_code: "IN_SCOPE",
      reason_detail: "Matches 192.168.1.0/24",
      risk: "low",
      matched_targets: ["192.168.1.0/24"]
    }
  };

  const parsed = AuditChainRecordSchema.safeParse(record);
  assert.equal(parsed.success, true);
});
