import { spawn, execFile } from "node:child_process";
import * as path from "node:path";
import * as fs from "node:fs";

export interface ProcessRunOptions {
  args: string[];
  scriptPath: string;
  cwd?: string;
  timeoutMs?: number;
  env?: NodeJS.ProcessEnv;
  maxBufferBytes?: number;
}

export interface ProcessRunResult {
  success: boolean;
  stdout: string;
  stderr: string;
  exitCode: number;
  tailStderr?: string;
  timedOut?: boolean;
  error?: string;
}

const CHUNK_SIZE = 4096;
const DEFAULT_TIMEOUT_MS = 60_000;
const DEFAULT_MAX_BUFFER = 10 * 1024 * 1024; // 10 MiB limit

/**
 * Resolves the Python executable deterministically.
 * Prefers active virtualenv, python3, or python in PATH.
 */
export function getPythonExecutable(): string {
  if (process.env.VIRTUAL_ENV) {
    const venvPy = process.platform === "win32"
      ? path.join(process.env.VIRTUAL_ENV, "Scripts", "python.exe")
      : path.join(process.env.VIRTUAL_ENV, "bin", "python");
    if (fs.existsSync(venvPy)) {
      return venvPy;
    }
  }
  return process.platform === "win32" ? "python" : "python3";
}

/**
 * Executes a Python script conforming to the 12 mcptoon Axioms:
 * 1. Asynchronous chunk-based stdout/stderr draining (prevents 4KB Windows / 64KB Linux pipe buffer deadlocks).
 * 2. Tail-first diagnostic preservation (captures last 4096 bytes of stderr upon failures).
 * 3. Finite deadlines with process tree termination on Windows (taskkill /PID /T /F).
 * 4. Zero shell invocation (executes python directly to prevent command injection).
 */
export async function runPythonScript(options: ProcessRunOptions): Promise<ProcessRunResult> {
  const pythonBin = getPythonExecutable();
  const scriptAbsPath = path.resolve(options.scriptPath);
  const timeoutMs = options.timeoutMs ?? DEFAULT_TIMEOUT_MS;
  const maxBuffer = options.maxBufferBytes ?? DEFAULT_MAX_BUFFER;

  if (!fs.existsSync(scriptAbsPath)) {
    return {
      success: false,
      stdout: "",
      stderr: `Script not found: ${scriptAbsPath}`,
      exitCode: 127,
      error: `Script not found: ${scriptAbsPath}`,
    };
  }

  const execArgs = [scriptAbsPath, ...options.args];

  return new Promise<ProcessRunResult>((resolve) => {
    let timedOut = false;
    let timer: NodeJS.Timeout | null = null;
    const stdoutChunks: Buffer[] = [];
    const stderrChunks: Buffer[] = [];
    let stdoutBytes = 0;
    let stderrBytes = 0;

    const child = spawn(pythonBin, execArgs, {
      cwd: options.cwd ?? process.cwd(),
      env: {
        ...process.env,
        PYTHONIOENCODING: "utf-8",
        PYTHONUNBUFFERED: "1",
        ...(options.env ?? {}),
      },
      stdio: ["pipe", "pipe", "pipe"],
      windowsHide: true,
    });

    const killProcessTree = () => {
      if (!child.pid) return;
      if (process.platform === "win32") {
        execFile("taskkill", ["/PID", child.pid.toString(), "/T", "/F"], () => {});
      } else {
        child.kill("SIGKILL");
      }
    };

    if (timeoutMs > 0) {
      timer = setTimeout(() => {
        timedOut = true;
        killProcessTree();
      }, timeoutMs);
    }

    if (child.stdout) {
      child.stdout.on("data", (chunk: Buffer) => {
        if (stdoutBytes < maxBuffer) {
          stdoutChunks.push(chunk);
          stdoutBytes += chunk.length;
        }
      });
    }

    if (child.stderr) {
      child.stderr.on("data", (chunk: Buffer) => {
        if (stderrBytes < maxBuffer) {
          stderrChunks.push(chunk);
          stderrBytes += chunk.length;
        }
      });
    }

    child.on("error", (err) => {
      if (timer) clearTimeout(timer);
      resolve({
        success: false,
        stdout: Buffer.concat(stdoutChunks).toString("utf-8"),
        stderr: err.message,
        exitCode: 1,
        error: err.message,
      });
    });

    child.on("close", (code) => {
      if (timer) clearTimeout(timer);

      const stdoutStr = Buffer.concat(stdoutChunks).toString("utf-8");
      const stderrBuf = Buffer.concat(stderrChunks);
      const stderrStr = stderrBuf.toString("utf-8");

      // Extract last 4096 bytes of stderr for diagnostic preservation
      const tailStderr = stderrBuf.length > CHUNK_SIZE
        ? stderrBuf.subarray(stderrBuf.length - CHUNK_SIZE).toString("utf-8")
        : stderrStr;

      const exitCode = timedOut ? 124 : (code ?? 0);
      const success = exitCode === 0 && !timedOut;

      resolve({
        success,
        stdout: stdoutStr,
        stderr: stderrStr,
        exitCode,
        tailStderr: tailStderr.trim(),
        timedOut,
        error: timedOut ? `Execution timed out after ${timeoutMs}ms` : undefined,
      });
    });
  });
}
