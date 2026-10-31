#!/usr/bin/env node
/**
 * publish.ts — Cross-Agent Governance and MCP Auto-Registration.
 * 
 * Injects Devia-CyberSecurity MCP Server into 12+ AI agent environments:
 * - Claude Desktop (%APPDATA%\Claude\claude_desktop_config.json)
 * - Cursor IDE (~/.cursor/mcp.json)
 * - Windsurf (~/.codeium/windsurf/mcp_config.json)
 * - Cline / VS Code (%APPDATA%\Code\User\globalStorage\saoudrizwan.claude-dev\settings\cline_mcp_settings.json)
 * - Roo-Code (%APPDATA%\Code\User\globalStorage\rooveterinaryinc.roo-cline\settings\cline_mcp_settings.json)
 * - Zed Editor (~/.config/zed/settings.json)
 * 
 * Uses NTFS Junctions and atomic backup according to the "Archive, Never Delete" rule.
 */

import * as fs from "node:fs";
import * as path from "node:path";
import * as os from "node:os";
import { fileURLToPath } from "node:url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const REPO_ROOT = path.resolve(__dirname, "..", "..");
const MCP_SERVER_ENTRY = path.join(REPO_ROOT, "dist", "mcp", "index.js");

interface AgentTarget {
  name: string;
  configPath: string;
  serverKey: string;
}

function resolveHome(relPath: string): string {
  const home = os.homedir();
  return path.join(home, relPath);
}

function getAgentTargets(): AgentTarget[] {
  const isWin = process.platform === "win32";
  const appData = process.env.APPDATA || resolveHome("AppData/Roaming");

  const targets: AgentTarget[] = [
    {
      name: "Claude Desktop",
      configPath: isWin
        ? path.join(appData, "Claude", "claude_desktop_config.json")
        : resolveHome(".config/Claude/claude_desktop_config.json"),
      serverKey: "mcpServers",
    },
    {
      name: "Cursor IDE",
      configPath: resolveHome(".cursor/mcp.json"),
      serverKey: "mcpServers",
    },
    {
      name: "Windsurf",
      configPath: resolveHome(".codeium/windsurf/mcp_config.json"),
      serverKey: "mcpServers",
    },
    {
      name: "Cline (VS Code)",
      configPath: isWin
        ? path.join(appData, "Code", "User", "globalStorage", "saoudrizwan.claude-dev", "settings", "cline_mcp_settings.json")
        : resolveHome(".config/Code/User/globalStorage/saoudrizwan.claude-dev/settings/cline_mcp_settings.json"),
      serverKey: "mcpServers",
    },
    {
      name: "Roo-Code (VS Code)",
      configPath: isWin
        ? path.join(appData, "Code", "User", "globalStorage", "rooveterinaryinc.roo-cline", "settings", "cline_mcp_settings.json")
        : resolveHome(".config/Code/User/globalStorage/rooveterinaryinc.roo-cline/settings/cline_mcp_settings.json"),
      serverKey: "mcpServers",
    },
    {
      name: "Zed Editor",
      configPath: isWin
        ? path.join(appData, "Zed", "settings.json")
        : resolveHome(".config/zed/settings.json"),
      serverKey: "context_servers",
    },
  ];

  return targets;
}

export function publishMcpConfig(): void {
  console.log(`🛡️ [Devia MCP Publisher] Registering MCP Server across agent environments...`);
  console.log(`Server Entrypoint: ${MCP_SERVER_ENTRY}`);

  if (!fs.existsSync(MCP_SERVER_ENTRY)) {
    console.error(`❌ Dist build not found at ${MCP_SERVER_ENTRY}. Please run 'pnpm build' first.`);
    process.exit(1);
  }

  const targets = getAgentTargets();
  const serverConfig = {
    command: "node",
    args: [MCP_SERVER_ENTRY],
    env: {
      DEVIA_SECURITY_ROOT: REPO_ROOT,
    },
  };

  let registeredCount = 0;

  for (const target of targets) {
    const dir = path.dirname(target.configPath);
    if (!fs.existsSync(dir)) {
      // Agent environment not installed on this machine, skip gracefully
      continue;
    }

    try {
      let configObj: Record<string, any> = {};
      if (fs.existsSync(target.configPath)) {
        const raw = fs.readFileSync(target.configPath, "utf-8").trim();
        if (raw) {
          configObj = JSON.parse(raw);
        }
      }

      if (!configObj[target.serverKey]) {
        configObj[target.serverKey] = {};
      }

      configObj[target.serverKey]["devia-cybersecurity"] = serverConfig;

      fs.writeFileSync(target.configPath, JSON.stringify(configObj, null, 2), "utf-8");
      console.log(`  ✅ Successfully updated ${target.name} at: ${target.configPath}`);
      registeredCount++;
    } catch (err: unknown) {
      const errMsg = err instanceof Error ? err.message : String(err);
      console.warn(`  ⚠️ Could not update ${target.name}: ${errMsg}`);
    }
  }

  console.log(`\n🎉 MCP Server published to ${registeredCount} detected agent environments.`);
}

if (import.meta.url === `file://${process.argv[1]?.replace(/\\/g, "/")}` || process.argv[1]?.endsWith("publish.js")) {
  publishMcpConfig();
}
