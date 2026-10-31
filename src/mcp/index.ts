#!/usr/bin/env node
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { createDeviaMcpServer } from "./server.js";

async function main(): Promise<void> {
  const { server, toolPinDigest } = createDeviaMcpServer();
  const transport = new StdioServerTransport();

  // Log to stderr only — stdout is exclusively for JSON-RPC 2.0 messages
  process.stderr.write(`[Devia-CyberSecurity MCP] Starting Server v0.1.0\n`);
  process.stderr.write(`[Devia-CyberSecurity MCP] Tool Pinning Digest: ${toolPinDigest}\n`);

  process.on("SIGINT", async () => {
    process.stderr.write(`[Devia-CyberSecurity MCP] Shutting down cleanly (SIGINT)...\n`);
    await server.close();
    process.exit(0);
  });

  process.on("SIGTERM", async () => {
    process.stderr.write(`[Devia-CyberSecurity MCP] Shutting down cleanly (SIGTERM)...\n`);
    await server.close();
    process.exit(0);
  });

  await server.connect(transport);
  process.stderr.write(`[Devia-CyberSecurity MCP] Connected via Stdio Transport. Ready.\n`);
}

main().catch((err) => {
  process.stderr.write(`[Devia-CyberSecurity MCP] Fatal startup error: ${err.message}\n`);
  process.exit(1);
});
