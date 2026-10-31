import { test, describe } from "node:test";
import * as assert from "node:assert/strict";
import { createDeviaMcpServer } from "../server.js";

describe("Devia MCP Server Core", () => {
  test("creates server instance with valid tool pinning digest", () => {
    const { server, context, toolPinDigest } = createDeviaMcpServer();

    assert.ok(server !== null, "Server instance should be created");
    assert.ok(context !== null, "Context should be initialized");
    assert.equal(toolPinDigest.length, 64, "Tool pin digest must be a 64-char SHA-256 hex string");
  });

  test("tool pinning digest is deterministic", () => {
    const inst1 = createDeviaMcpServer();
    const inst2 = createDeviaMcpServer();

    assert.equal(inst1.toolPinDigest, inst2.toolPinDigest, "Tool pin digest must be strictly deterministic");
  });

  test("CCR interceptor handles sub-threshold and over-threshold payloads", () => {
    const { context } = createDeviaMcpServer();

    // Small payload under threshold
    const smallPayload = JSON.stringify({ status: "OK", count: 2 });
    const res1 = context.ccr.processOutput(smallPayload, "test_tool");
    assert.equal(res1.isCcrStored, false);
    assert.equal(res1.content, smallPayload);

    // Large payload over threshold
    const largePayload = JSON.stringify({
      findings: Array.from({ length: 200 }, (_, i) => ({
        id: `VULN-${i}`,
        severity: "HIGH",
        cwe: "CWE-89",
        ruleId: "sqli",
        file: `src/file_${i}.ts`,
        line: i + 1,
      })),
    });

    const res2 = context.ccr.processOutput(largePayload, "test_tool");
    assert.equal(res2.isCcrStored, true);
    assert.ok(res2.handle !== undefined);
    assert.ok(res2.content.includes("Audit Handle:"));
    assert.ok(res2.content.includes("Distilled TOON Summary"));

    // Verify retrieval
    const retrieved = context.ccr.retrieve(res2.handle!);
    assert.equal(retrieved, largePayload);
  });
});
