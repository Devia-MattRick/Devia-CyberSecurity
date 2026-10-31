import { test, describe } from "node:test";
import * as assert from "node:assert/strict";
import * as path from "node:path";
import { runPythonScript, getPythonExecutable } from "../process-runner.js";

describe("Process Runner (12 mcptoon Axioms for Windows & Linux)", () => {
  test("resolves a valid python executable", () => {
    const py = getPythonExecutable();
    assert.ok(py.length > 0, "Python executable should be defined");
  });

  test("runs check_lockfiles.py --json on repository cleanly", async () => {
    const scriptPath = path.resolve(process.cwd(), "src", "scripts", "check_lockfiles.py");
    const result = await runPythonScript({
      scriptPath,
      args: ["--json", process.cwd()],
      timeoutMs: 15_000,
    });

    assert.equal(result.exitCode, 0, "Script should exit with code 0");
    assert.equal(result.success, true);
    assert.ok(result.stdout.length > 0, "Should have JSON stdout");

    const parsed = JSON.parse(result.stdout);
    assert.ok(parsed !== null, "Output must be valid JSON");
  });

  test("returns failure and preserves error for non-existent script", async () => {
    const fakeScript = path.resolve(process.cwd(), "src", "scripts", "non_existent_fake.py");
    const result = await runPythonScript({
      scriptPath: fakeScript,
      args: [],
    });

    assert.equal(result.success, false);
    assert.equal(result.exitCode, 127);
    assert.ok(result.error?.includes("Script not found"));
  });
});
