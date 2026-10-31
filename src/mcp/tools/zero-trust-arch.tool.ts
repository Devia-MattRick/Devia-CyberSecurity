import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import * as path from "node:path";
import { ToolContext, executePythonTool } from "../tool-context.js";

export function registerZeroTrustArchTool(server: McpServer, ctx: ToolContext): void {
  server.tool(
    "devia_zero_trust_arch",
    "Dimensión 6: Arquitectura Zero Trust, auditoría de esquemas Model Context Protocol (MCP) anti-Tool Poisoning, validación anti-SSRF y detección C2.",
    {
      targetPath: z.string().describe("Ruta al archivo de configuración MCP, log de red o archivo de señuelos"),
      action: z
        .enum(["MCP_POISONING", "URL_VALIDATOR", "C2_BEACONING"])
        .default("MCP_POISONING")
        .describe("Acción Zero Trust: MCP_POISONING (auditoría de esquemas MCP), URL_VALIDATOR (control anti-SSRF de endpoints), C2_BEACONING (detección estadística de balizamiento)"),
      url: z.string().optional().describe("URL para validar con URL_VALIDATOR"),
    },
    async ({ targetPath, action, url }) => {
      const resolvedTarget = path.resolve(targetPath);

      if (action === "MCP_POISONING") {
        return executePythonTool(ctx, {
          scriptName: "mcp_tool_poisoning_scanner.py",
          args: ["scan", resolvedTarget, "--json"],
          toolName: "devia_zero_trust_arch:MCP_POISONING",
        });
      }

      if (action === "URL_VALIDATOR") {
        const targetUrl = url ?? targetPath;
        return executePythonTool(ctx, {
          scriptName: "url_validator.py",
          args: [targetUrl, "--json"],
          toolName: "devia_zero_trust_arch:URL_VALIDATOR",
        });
      }

      // C2_BEACONING
      return executePythonTool(ctx, {
        scriptName: "c2_beaconing_detector.py",
        args: [resolvedTarget, "--json"],
        toolName: "devia_zero_trust_arch:C2_BEACONING",
      });
    }
  );
}
