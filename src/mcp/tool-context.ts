import * as path from "node:path";
import { runPythonScript, ProcessRunResult } from "./process-runner.js";
import { sanitizeUntrustedText } from "./sanitizer.js";
import { CcrInterceptor } from "./ccr-interceptor.js";

export interface ToolContext {
  baseDir: string;
  scriptsDir: string;
  ccr: CcrInterceptor;
}

export function createToolContext(baseDir: string = process.cwd()): ToolContext {
  const scriptsDir = path.join(baseDir, "src", "scripts");
  const ccr = new CcrInterceptor(baseDir);
  return {
    baseDir,
    scriptsDir,
    ccr,
  };
}

export interface ExecuteScriptOptions {
  scriptName: string;
  args: string[];
  toolName: string;
  cwd?: string;
  timeoutMs?: number;
}

export interface McpToolResponse {
  [x: string]: unknown;
  content: Array<{ type: "text"; text: string }>;
  isError?: boolean;
}

/**
 * Standard execution wrapper for Capa 3 Python scripts.
 * Guarantees stdio resilience (no unhandled throws), ZWSP defanging,
 * and double-budget paging via CCR interceptor.
 */
export async function executePythonTool(
  ctx: ToolContext,
  options: ExecuteScriptOptions
): Promise<McpToolResponse> {
  const scriptPath = path.join(ctx.scriptsDir, options.scriptName);

  try {
    const result: ProcessRunResult = await runPythonScript({
      scriptPath,
      args: options.args,
      cwd: options.cwd ?? ctx.baseDir,
      timeoutMs: options.timeoutMs ?? 60_000,
    });

    const trimmedStdout = result.stdout.trim();
    const hasJsonStdout = (() => {
      if (!trimmedStdout.startsWith("{") && !trimmedStdout.startsWith("[")) return false;
      try {
        JSON.parse(trimmedStdout);
        return true;
      } catch {
        return false;
      }
    })();

    // Security linters/scanners return exit code 1 or 2 to signal detected findings.
    // As long as valid JSON is returned and no fatal timeout or missing file occurred,
    // the scan succeeded.
    const isSuccessfulScan = result.success || (hasJsonStdout && !result.timedOut && result.exitCode !== 127);

    if (!isSuccessfulScan) {
      const errorMsg = [
        `❌ Error executing ${options.toolName} (${options.scriptName})`,
        `Exit Code: ${result.exitCode}${result.timedOut ? " (TIMEOUT)" : ""}`,
        result.error ? `Error: ${result.error}` : "",
        result.tailStderr ? `Stderr Traceback:\n${result.tailStderr}` : "",
      ].filter(Boolean).join("\n");

      return {
        isError: true,
        content: [{ type: "text", text: sanitizeUntrustedText(errorMsg) }],
      };
    }

    const rawOutput = trimmedStdout || result.stderr.trim() || "{}";
    const intercepted = ctx.ccr.processOutput(rawOutput, options.toolName);
    const sanitizedText = sanitizeUntrustedText(intercepted.content);

    return {
      content: [{ type: "text", text: sanitizedText }],
    };
  } catch (err: unknown) {
    const errMsg = err instanceof Error ? err.message : String(err);
    return {
      isError: true,
      content: [{ type: "text", text: `Internal Tool Error: ${errMsg}` }],
    };
  }
}
