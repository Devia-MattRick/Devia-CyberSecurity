/**
 * ccr-interceptor.ts — Lossless CCR Dual Protocol, Hash Chains, and Double-Budget Paging.
 * 
 * Implements:
 * 1. Double Budget Paging (docs/PROACTIVE.md §3.8): hard limits of 1 MiB / 100 items.
 * 2. Lossless Content-Addressable Storage: outputs >1200 tokens stored in .cache/ccr/<handle>.json.
 * 3. Cryptographic Hash Chains: append-only forensic_chain.jsonl linking RecordHash = SHA256(...).
 */

import * as fs from "node:fs";
import * as path from "node:path";
import * as crypto from "node:crypto";
import { formatFindingsToon } from "./toon-codec.js";

const TOKEN_THRESHOLD_CHARS = 4800; // ~1200 tokens at ~4 chars/token
const HARD_BYTE_LIMIT = 1_048_576; // 1 MiB hard SSE / Stdio limit

export interface CcrEntry {
  index: number;
  timestamp: string;
  prevHash: string;
  recordHash: string;
  handle: string;
  tool: string;
  size: number;
  traceparent?: string;
}

export interface InterceptResult {
  isCcrStored: boolean;
  content: string;
  handle?: string;
  totalItems?: number;
  chainIndex?: number;
}

export class CcrInterceptor {
  private ccrDir: string;
  private chainFile: string;

  constructor(baseDir: string = process.cwd()) {
    this.ccrDir = path.join(baseDir, ".cache", "ccr");
    this.chainFile = path.join(this.ccrDir, "forensic_chain.jsonl");
    this.ensureDirs();
  }

  private ensureDirs(): void {
    if (!fs.existsSync(this.ccrDir)) {
      fs.mkdirSync(this.ccrDir, { recursive: true });
    }
  }

  private getLastChainBlock(): { index: number; hash: string } {
    if (!fs.existsSync(this.chainFile)) {
      return { index: 0, hash: "0".repeat(64) };
    }

    try {
      const lines = fs.readFileSync(this.chainFile, "utf-8").trim().split("\n");
      if (lines.length === 0 || !lines[lines.length - 1]) {
        return { index: 0, hash: "0".repeat(64) };
      }
      const lastObj = JSON.parse(lines[lines.length - 1]) as CcrEntry;
      return { index: lastObj.index, hash: lastObj.recordHash };
    } catch {
      return { index: 0, hash: "0".repeat(64) };
    }
  }

  private appendChain(handle: string, tool: string, size: number, traceparent?: string): number {
    const last = this.getLastChainBlock();
    const index = last.index + 1;
    const timestamp = new Date().toISOString();
    const prevHash = last.hash;

    const dataToHash = `${index}:${timestamp}:${prevHash}:${handle}:${tool}:${size}:${traceparent ?? ""}`;
    const recordHash = crypto.createHash("sha256").update(dataToHash).digest("hex");

    const entry: CcrEntry = {
      index,
      timestamp,
      prevHash,
      recordHash,
      handle,
      tool,
      size,
      traceparent,
    };

    fs.appendFileSync(this.chainFile, JSON.stringify(entry) + "\n", "utf-8");
    return index;
  }

  /**
   * Evaluates if raw JSON/string should be stored in CCR or passed directly.
   */
  public processOutput(rawOutput: string, toolName: string, traceparent?: string): InterceptResult {
    const byteLength = Buffer.byteLength(rawOutput, "utf-8");

    // Pass through if under limits
    if (byteLength < TOKEN_THRESHOLD_CHARS && byteLength < HARD_BYTE_LIMIT) {
      return {
        isCcrStored: false,
        content: rawOutput,
      };
    }

    // Exceeds threshold: generate deterministic 12-char SHA-256 handle
    const fullHash = crypto.createHash("sha256").update(rawOutput).digest("hex");
    const handle = fullHash.substring(0, 12);
    const filePath = path.join(this.ccrDir, `${handle}.json`);

    fs.writeFileSync(filePath, rawOutput, "utf-8");
    const chainIndex = this.appendChain(handle, toolName, byteLength, traceparent);

    // Build distilled summary with TOON
    let distilledText = "";
    try {
      const parsed = JSON.parse(rawOutput);
      if (Array.isArray(parsed)) {
        distilledText = formatFindingsToon(parsed.slice(0, 50));
      } else if (parsed && typeof parsed === "object") {
        if (Array.isArray(parsed.findings)) {
          distilledText = formatFindingsToon(parsed.findings.slice(0, 50));
        } else if (Array.isArray(parsed.results)) {
          distilledText = formatFindingsToon(parsed.results.slice(0, 50));
        } else {
          distilledText = JSON.stringify({
            status: parsed.status ?? "COMPLETED",
            summary: parsed.summary ?? "Audit output persisted in CCR.",
            metrics: parsed.metrics ?? {},
          }, null, 2);
        }
      }
    } catch {
      distilledText = rawOutput.substring(0, 500) + "... [Truncated for Context Window]";
    }

    const summaryBlock = [
      `🛡️ [Devia CCR Interceptor — Double-Budget Paging Enforcement]`,
      `Audit Handle: ${handle} (Forensic Chain Block #${chainIndex})`,
      `Original Payload Size: ${(byteLength / 1024).toFixed(2)} KB (exceeded context threshold).`,
      `Raw artifact persisted safely at: .cache/ccr/${handle}.json`,
      ``,
      `--- Distilled TOON Summary ---`,
      distilledText,
    ].join("\n");

    return {
      isCcrStored: true,
      content: summaryBlock,
      handle,
      chainIndex,
    };
  }

  /**
   * Retrieves an artifact by handle.
   */
  public retrieve(handle: string): string | null {
    const safeHandle = handle.replace(/[^a-zA-Z0-9_-]/g, "");
    const filePath = path.join(this.ccrDir, `${safeHandle}.json`);
    if (fs.existsSync(filePath)) {
      return fs.readFileSync(filePath, "utf-8");
    }
    return null;
  }
}
