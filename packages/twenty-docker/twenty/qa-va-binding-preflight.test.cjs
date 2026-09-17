'use strict';

const assert = require('node:assert/strict');
const { test } = require('node:test');

const {
  verifyQaVaBinding,
  workspaceSchemaName,
} = require('./qa-va-binding-preflight.cjs');

const environment = {
  QA_VA_WORKSPACE_ID: '11111111-1111-4111-8111-111111111111',
  QA_VA_WORKSPACE_MEMBER_ID: '22222222-2222-4222-8222-222222222222',
  QA_VA_USER_WORKSPACE_ID: '33333333-3333-4333-8333-333333333333',
  QA_VA_USER_ID: '44444444-4444-4444-8444-444444444444',
  QA_VA_USER_EMAIL: 'qa-va@example.com',
};

const createClient = (overrides = {}) => ({
  query: async (sql) => {
    if (sql.includes('JOIN core."user"')) {
      return {
        rowCount:
          overrides.bindingRows ??
          (overrides.canImpersonate || overrides.canAccessFullAdminPanel
            ? 0
            : 1),
        rows: [
          {
            canImpersonate: overrides.canImpersonate ?? false,
            canAccessFullAdminPanel:
              overrides.canAccessFullAdminPanel ?? false,
          },
        ],
      };
    }

    if (sql.includes('FROM core."userWorkspace"')) {
      return { rowCount: 1, rows: [{ count: overrides.memberships ?? 1 }] };
    }

    if (sql.includes('FROM core.workspace')) {
      return { rowCount: 1, rows: [{ count: overrides.workspaces ?? 1 }] };
    }

    if (sql.includes('."workspaceMember"')) {
      return { rowCount: overrides.workspaceMemberRows ?? 1, rows: [{}] };
    }

    if (sql.includes('FROM core."roleTarget"')) {
      return {
        rowCount: overrides.roleRows ?? 1,
        rows: [
          {
            canAccessAllTools: overrides.canAccessAllTools ?? false,
            canUpdateAllSettings: overrides.canUpdateAllSettings ?? false,
          },
        ],
      };
    }

    throw new Error(`unexpected query: ${sql}`);
  },
});

test('accepts one exact identity tuple in one locked workspace', async () => {
  await assert.doesNotReject(
    verifyQaVaBinding({ client: createClient(), environment }),
  );
});

test('rejects a stale identity tuple', async () => {
  await assert.rejects(
    verifyQaVaBinding({
      client: createClient({ bindingRows: 0 }),
      environment,
    }),
    /tuple is not active and unprivileged/,
  );
});

test('the binding query requires an active workspace and unprivileged user', async () => {
  const client = createClient();
  const originalQuery = client.query;

  client.query = async (sql, values) => {
    if (sql.includes('JOIN core."user"')) {
      assert.match(sql, /JOIN core\.workspace w/);
      assert.match(sql, /u\."canImpersonate"/);
      assert.match(sql, /u\."canAccessFullAdminPanel"/);
      assert.match(sql, /w\."deletedAt" IS NULL/);
    }

    return originalQuery(sql, values);
  };

  await assert.doesNotReject(verifyQaVaBinding({ client, environment }));
  await assert.rejects(
    verifyQaVaBinding({
      client: createClient({ canImpersonate: true }),
      environment,
    }),
    /unprivileged/,
  );
  await assert.rejects(
    verifyQaVaBinding({
      client: createClient({ canAccessFullAdminPanel: true }),
      environment,
    }),
    /unprivileged/,
  );
});

test('rejects another workspace membership or workspace', async () => {
  await assert.rejects(
    verifyQaVaBinding({
      client: createClient({ memberships: 2 }),
      environment,
    }),
    /exactly one active workspace/,
  );
  await assert.rejects(
    verifyQaVaBinding({
      client: createClient({ workspaces: 2 }),
      environment,
    }),
    /exactly one active workspace/,
  );
});

test('rejects a role that exposes tools or settings', async () => {
  await assert.rejects(
    verifyQaVaBinding({
      client: createClient({ canAccessAllTools: true }),
      environment,
    }),
    /deny all tools and settings/,
  );
});

test('derives a safe deterministic workspace schema name', () => {
  assert.match(workspaceSchemaName(environment.QA_VA_WORKSPACE_ID), /^workspace_[0-9a-z]+$/);
});
