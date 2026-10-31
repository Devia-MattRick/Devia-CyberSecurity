import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import * as crypto from "node:crypto";
import { ToolContext, createToolContext } from "./tool-context.js";
import { registerAllTools } from "./tools/index.js";

export interface DeviaMcpInstance {
  server: McpServer;
  context: ToolContext;
  toolPinDigest: string;
}

export function createDeviaMcpServer(baseDir: string = process.cwd()): DeviaMcpInstance {
  const server = new McpServer({
    name: "devia-cybersecurity",
    version: "0.1.0",
  });

  const context = createToolContext(baseDir);
  registerAllTools(server, context);

  // Tool Pinning: compute deterministic SHA-256 digest of registered tools
  const toolNames = [
    "devia_orchestrate_audit",
    "devia_search_tools",
    "devia_threat_modeling",
    "devia_source_sast",
    "devia_secrets_crypto",
    "devia_identity_access",
    "devia_supply_chain",
    "devia_zero_trust_arch",
    "devia_config_hardening",
    "devia_resilience_telemetry",
  ];
  const toolPinDigest = crypto
    .createHash("sha256")
    .update(toolNames.sort().join("|"))
    .digest("hex");

  return {
    server,
    context,
    toolPinDigest,
  };
}
