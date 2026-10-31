import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { ToolContext } from "../tool-context.js";
import { registerOrchestratorTool } from "./orchestrator.tool.js";
import { registerSearchTool } from "./search.tool.js";
import { registerThreatModelingTool } from "./threat-modeling.tool.js";
import { registerSourceSastTool } from "./source-sast.tool.js";
import { registerSecretsCryptoTool } from "./secrets-crypto.tool.js";
import { registerIdentityAccessTool } from "./identity-access.tool.js";
import { registerSupplyChainTool } from "./supply-chain.tool.js";
import { registerZeroTrustArchTool } from "./zero-trust-arch.tool.js";
import { registerConfigHardeningTool } from "./config-hardening.tool.js";
import { registerResilienceTelemetryTool } from "./resilience-telemetry.tool.js";

export function registerAllTools(server: McpServer, ctx: ToolContext): void {
  registerOrchestratorTool(server, ctx);
  registerSearchTool(server, ctx);
  registerThreatModelingTool(server, ctx);
  registerSourceSastTool(server, ctx);
  registerSecretsCryptoTool(server, ctx);
  registerIdentityAccessTool(server, ctx);
  registerSupplyChainTool(server, ctx);
  registerZeroTrustArchTool(server, ctx);
  registerConfigHardeningTool(server, ctx);
  registerResilienceTelemetryTool(server, ctx);
}
