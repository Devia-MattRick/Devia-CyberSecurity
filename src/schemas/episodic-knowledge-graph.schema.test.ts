import test from "node:test";
import assert from "node:assert/strict";
import {
  EpisodicGraphNodeLabelSchema,
  EpisodicGraphEdgeTypeSchema,
  EpisodicGraphNodeSchema,
  EpisodicGraphEdgeSchema,
  EpisodicKnowledgeGraphSchema,
  EpisodicGraphQuerySchema
} from "./episodic-knowledge-graph.schema.js";

test("EpisodicGraphNodeLabelSchema validates canonical node labels", () => {
  assert.equal(EpisodicGraphNodeLabelSchema.parse("Host"), "Host");
  assert.equal(EpisodicGraphNodeLabelSchema.parse("Vulnerability"), "Vulnerability");
  assert.equal(EpisodicGraphNodeLabelSchema.parse("Credential"), "Credential");
  assert.throws(() => EpisodicGraphNodeLabelSchema.parse("InvalidEntityLabel"));
});

test("EpisodicGraphEdgeTypeSchema validates canonical edge types", () => {
  assert.equal(EpisodicGraphEdgeTypeSchema.parse("HAS_PORT"), "HAS_PORT");
  assert.equal(EpisodicGraphEdgeTypeSchema.parse("CONFIRMED_VULNERABILITY"), "CONFIRMED_VULNERABILITY");
  assert.equal(EpisodicGraphEdgeTypeSchema.parse("PIVOTED_TO"), "PIVOTED_TO");
  assert.throws(() => EpisodicGraphEdgeTypeSchema.parse("INVALID_RELATION"));
});

test("EpisodicKnowledgeGraphSchema validates a full snapshot", () => {
  const node1Uuid = "a1b2c3d4-e5f6-4a1b-8c2d-3e4f5a6b7c8d";
  const node2Uuid = "b2c3d4e5-f6a1-4b2c-9d3e-4f5a6b7c8d9e";
  const edgeUuid = "c3d4e5f6-a1b2-4c3d-8e4f-5a6b7c8d9e0f";

  const rawNode = {
    uuid: node1Uuid,
    label: "Host",
    name: "192.168.1.150",
    properties: { os: "Linux Ubuntu 22.04" },
    discoveredAt: "2026-10-27T17:20:00Z",
    sourceAgent: "searcher"
  };
  const parsedNode = EpisodicGraphNodeSchema.parse(rawNode);
  assert.equal(parsedNode.name, "192.168.1.150");

  const rawEdge = {
    uuid: edgeUuid,
    type: "CONFIRMED_VULNERABILITY",
    sourceNodeUuid: node1Uuid,
    targetNodeUuid: node2Uuid,
    weight: 1.0,
    properties: { proof: "sshd banner leak verified" },
    createdAt: "2026-10-27T17:26:00Z"
  };
  const parsedEdge = EpisodicGraphEdgeSchema.parse(rawEdge);
  assert.equal(parsedEdge.type, "CONFIRMED_VULNERABILITY");

  const validGraph = {
    scanContextId: "flow-101",
    generatedAt: "2026-10-27T17:30:00Z",
    nodes: [
      parsedNode,
      {
        uuid: node2Uuid,
        label: "Vulnerability",
        name: "CVE-2024-6387",
        properties: { severity: "CRITICAL", cvss: 9.8 },
        discoveredAt: "2026-10-27T17:25:00Z",
        sourceAgent: "pentester"
      }
    ],
    edges: [
      parsedEdge
    ],
    metrics: {
      totalNodes: 2,
      totalEdges: 1,
      confirmedVulnerabilitiesCount: 1
    }
  };

  const parsed = EpisodicKnowledgeGraphSchema.parse(validGraph);
  assert.equal(parsed.nodes.length, 2);
  assert.equal(parsed.edges[0].type, "CONFIRMED_VULNERABILITY");
});

test("EpisodicGraphQuerySchema validates structured query filters", () => {
  const query = {
    searchType: "recent_context",
    query: "nmap results for 192.168.1.150",
    nodeLabels: ["Host", "Port"],
    edgeTypes: ["HAS_PORT"],
    maxDepth: 2,
    recencyWindow: "6h"
  };

  const parsed = EpisodicGraphQuerySchema.parse(query);
  assert.equal(parsed.searchType, "recent_context");
  assert.equal(parsed.maxDepth, 2);
});
