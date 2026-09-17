#!/usr/bin/env node
'use strict';

const { Client } = require('pg');

const fail = (message) => {
  console.error(`QA VA binding preflight failed: ${message}`);
  process.exitCode = 78;
};

const workspaceSchemaName = (workspaceId) => {
  const hex = workspaceId.replaceAll('-', '');

  return `workspace_${BigInt(`0x${hex}`).toString(36)}`;
};

const verifyQaVaBinding = async ({ client, environment = process.env }) => {
  const workspaceId = environment.QA_VA_WORKSPACE_ID;
  const workspaceMemberId = environment.QA_VA_WORKSPACE_MEMBER_ID;
  const userWorkspaceId = environment.QA_VA_USER_WORKSPACE_ID;
  const userId = environment.QA_VA_USER_ID;
  const userEmail = environment.QA_VA_USER_EMAIL;

  const binding = await client.query(
    `SELECT uw.id, u."canImpersonate", u."canAccessFullAdminPanel"
       FROM core."userWorkspace" uw
       JOIN core."user" u ON u.id = uw."userId"
       JOIN core.workspace w ON w.id = uw."workspaceId"
      WHERE uw.id = $1
        AND uw."userId" = $2
        AND uw."workspaceId" = $3
        AND uw."deletedAt" IS NULL
        AND u.email = $4
        AND u."deletedAt" IS NULL
        AND COALESCE(u.disabled, false) = false
        AND COALESCE(u."canImpersonate", false) = false
        AND COALESCE(u."canAccessFullAdminPanel", false) = false
        AND w."deletedAt" IS NULL`,
    [userWorkspaceId, userId, workspaceId, userEmail],
  );

  if (binding.rowCount !== 1) {
    throw new Error(
      'configured user/workspace/email tuple is not active and unprivileged',
    );
  }

  const memberships = await client.query(
    `SELECT COUNT(*)::int AS count
       FROM core."userWorkspace"
      WHERE "userId" = $1 AND "deletedAt" IS NULL`,
    [userId],
  );

  if (memberships.rows[0]?.count !== 1) {
    throw new Error('configured user must have exactly one active workspace');
  }

  const workspaces = await client.query(
    `SELECT COUNT(*)::int AS count
       FROM core.workspace
      WHERE "deletedAt" IS NULL`,
  );

  if (workspaces.rows[0]?.count !== 1) {
    throw new Error('QA instance must contain exactly one active workspace');
  }

  const schemaName = workspaceSchemaName(workspaceId);
  const workspaceMember = await client.query(
    `SELECT id
       FROM "${schemaName}"."workspaceMember"
      WHERE id = $1
        AND "userId" = $2
        AND "userEmail" = $3
        AND "deletedAt" IS NULL`,
    [workspaceMemberId, userId, userEmail],
  );

  if (workspaceMember.rowCount !== 1) {
    throw new Error('configured workspace member does not match the user tuple');
  }

  const role = await client.query(
    `SELECT r."canAccessAllTools", r."canUpdateAllSettings"
       FROM core."roleTarget" rt
       JOIN core.role r ON r.id = rt."roleId"
      WHERE rt."userWorkspaceId" = $1
        AND rt."workspaceId" = $2`,
    [userWorkspaceId, workspaceId],
  );

  if (
    role.rowCount !== 1 ||
    role.rows[0].canAccessAllTools !== false ||
    role.rows[0].canUpdateAllSettings !== false
  ) {
    throw new Error('QA role must deny all tools and settings');
  }
};

const main = async () => {
  const client = new Client({ connectionString: process.env.PG_DATABASE_URL });

  try {
    await client.connect();
    await verifyQaVaBinding({ client });
    console.log('QA VA binding preflight passed');
  } catch (error) {
    fail(error instanceof Error ? error.message : 'unknown error');
  } finally {
    await client.end().catch(() => {});
  }
};

if (require.main === module) {
  void main();
}

module.exports = { verifyQaVaBinding, workspaceSchemaName };
