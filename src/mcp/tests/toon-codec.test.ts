import { test, describe } from "node:test";
import * as assert from "node:assert/strict";
import { escapeToonValue, encodeToonTable, formatFindingsToon } from "../toon-codec.js";

describe("TOON v1.1 Tabular Codec", () => {
  test("escapes values with commas, colons, or booleans", () => {
    assert.equal(escapeToonValue("clean"), "clean");
    assert.equal(escapeToonValue("with,comma"), '"with,comma"');
    assert.equal(escapeToonValue("key: val"), '"key: val"');
    assert.equal(escapeToonValue(true), "true");
    assert.equal(escapeToonValue(null), "null");
    assert.equal(escapeToonValue(123), "123");
  });

  test("encodes arrays of uniform objects into compact tabular syntax", () => {
    const data = [
      { id: "usr_1", role: "admin", active: true },
      { id: "usr_2", role: "viewer", active: false },
    ];
    const encoded = encodeToonTable(data);
    assert.ok(encoded.startsWith("[2] id, role, active:"));
    assert.ok(encoded.includes("usr_1, admin, true"));
    assert.ok(encoded.includes("usr_2, viewer, false"));
  });

  test("formats cybersecurity findings into compact TOON table", () => {
    const findings = [
      {
        id: "VULN-CRYP-001",
        severity: "CRITICAL",
        cwe: "CWE-798",
        ruleId: "hardcoded-secret",
        file: "src/db.ts",
        line: 14,
      },
      {
        id: "VULN-SAST-001",
        severity: "HIGH",
        cwe: "CWE-89",
        ruleId: "sqli-sink",
        file: "src/query.ts",
        line: 88,
      },
    ];

    const toon = formatFindingsToon(findings);
    assert.ok(toon.startsWith("[2] id, severity, cwe, ruleId, file, line:"));
    assert.ok(toon.includes("VULN-CRYP-001, CRITICAL, CWE-798, hardcoded-secret, src/db.ts, 14"));
    assert.ok(toon.includes("VULN-SAST-001, HIGH, CWE-89, sqli-sink, src/query.ts, 88"));
  });

  test("handles empty findings gracefully", () => {
    const empty = formatFindingsToon([]);
    assert.equal(empty, "[0] findings (clean)");
  });
});
