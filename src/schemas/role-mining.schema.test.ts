import { describe, it } from "node:test";
import assert from "node:assert/strict";
import {
  EntitlementAssignmentSchema,
  MinedRoleSchema,
  RoleMiningAnalysisSchema
} from "./role-mining.schema.js";

describe("RoleMiningSchema Contract Test", () => {
  it("valida una asignación individual válida", () => {
    const assignment = {
      user: "alice@corp.local",
      system: "aws-iam",
      entitlement: "S3ReadOnlyAccess",
      grantedAt: "2026-10-29T10:00:00Z"
    };

    const parsed = EntitlementAssignmentSchema.parse(assignment);
    assert.equal(parsed.user, "alice@corp.local");
    assert.equal(parsed.entitlement, "S3ReadOnlyAccess");
  });

  it("valida un rol minado correctamente", () => {
    const role = {
      roleId: "ROLE-001",
      name: "Security Auditor ReadOnly",
      permissions: ["aws-iam:S3ReadOnlyAccess", "azure-rbac:Reader"],
      assignedUsers: ["alice@corp.local", "bob@corp.local"],
      userCount: 2,
      algorithm: "BOTTOM_UP_EXACT" as const
    };

    const parsed = MinedRoleSchema.parse(role);
    assert.equal(parsed.roleId, "ROLE-001");
    assert.equal(parsed.userCount, 2);
  });

  it("valida un análisis completo de minería de roles", () => {
    const analysis = {
      analysisId: "c2a9a4b8-8e6d-4b82-9a3d-3df372861e6f",
      analyzedAt: "2026-10-29T12:00:00Z",
      targetSystem: "ActiveDirectory & AWS Entra",
      minUsersThreshold: 2,
      similarityThreshold: 0.8,
      minedRoles: [
        {
          roleId: "ROLE-001",
          name: "Standard Cloud Developer",
          permissions: ["aws:EC2Describe", "aws:S3ListBucket"],
          assignedUsers: ["dev1", "dev2", "dev3"],
          userCount: 3,
          algorithm: "TOP_DOWN_JACCARD" as const,
          jaccardSimilarity: 0.85
        }
      ],
      residualDirectPermissions: [
        {
          user: "admin_breakglass",
          permissions: ["aws:AdministratorAccess"]
        }
      ],
      metrics: {
        totalUsers: 4,
        totalUniquePermissions: 3,
        totalOriginalAssignments: 7,
        minedRolesCount: 1,
        roleExplosionRatio: 0.5,
        assignmentReductionPercent: 42.8
      }
    };

    const parsed = RoleMiningAnalysisSchema.parse(analysis);
    assert.equal(parsed.metrics.totalUsers, 4);
    assert.equal(parsed.minedRoles[0].roleId, "ROLE-001");
  });

  it("rechaza roles con formato inválido de ID", () => {
    const invalidRole = {
      roleId: "INVALID_ID",
      name: "Bad Role",
      permissions: ["sys:perm"],
      assignedUsers: ["user1"],
      userCount: 1,
      algorithm: "BOTTOM_UP_EXACT" as const
    };

    assert.throws(() => MinedRoleSchema.parse(invalidRole));
  });
});
