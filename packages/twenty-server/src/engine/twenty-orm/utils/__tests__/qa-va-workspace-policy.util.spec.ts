import { type WorkspaceAuthContext } from 'src/engine/core-modules/auth/types/workspace-auth-context.type';
import {
  isQaVaToolContext,
  isQaVaUserWorkspaceBinding,
  validateQaVaWorkspaceOperationOrThrow,
} from 'src/engine/twenty-orm/utils/qa-va-workspace-policy.util';

jest.mock(
  'src/engine/metadata-modules/permissions/permissions.exception',
  () => ({
    PermissionsException: class PermissionsException extends Error {},
    PermissionsExceptionCode: { PERMISSION_DENIED: 'PERMISSION_DENIED' },
    PermissionsExceptionMessage: { PERMISSION_DENIED: 'Permission denied' },
  }),
);

const WORKSPACE_ID = '11111111-1111-4111-8111-111111111111';
const MEMBER_ID = '22222222-2222-4222-8222-222222222222';
const USER_ID = '33333333-3333-4333-8333-333333333333';
const USER_WORKSPACE_ID = '88888888-8888-4888-8888-888888888888';
const RECORD_ID = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
const PARENT_ID = 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb';
const PERSON_ID = 'cccccccc-cccc-4ccc-8ccc-cccccccccccc';

const qaAuthContext = {
  type: 'user',
  workspace: { id: WORKSPACE_ID },
  workspaceMemberId: MEMBER_ID,
  userWorkspaceId: USER_WORKSPACE_ID,
  user: { id: USER_ID },
} as WorkspaceAuthContext;

describe('validateQaVaWorkspaceOperationOrThrow', () => {
  const previousEnv = process.env;

  beforeEach(() => {
    process.env = {
      ...previousEnv,
      QA_VA_POLICY_REQUIRED: 'true',
      QA_VA_WORKSPACE_ID: WORKSPACE_ID,
      QA_VA_WORKSPACE_MEMBER_ID: MEMBER_ID,
      QA_VA_USER_WORKSPACE_ID: USER_WORKSPACE_ID,
      QA_VA_USER_ID: USER_ID,
      QA_VA_USER_EMAIL: 'qa-va@example.com',
      QA_VA_PERSON_UPDATE_FIELDS: 'qaDisposition',
    };
  });

  afterAll(() => {
    process.env = previousEnv;
  });

  it('allows reads and the narrow workflow writes in the QA workspace', () => {
    expect(() =>
      validateQaVaWorkspaceOperationOrThrow({
        authContext: qaAuthContext,
        entityName: 'company',
        operationType: 'select',
      }),
    ).not.toThrow();

    for (const allowedUpdate of [
      { entityName: 'note', updatedColumns: ['title', 'bodyV2'] },
      {
        entityName: 'task',
        updatedColumns: ['title', 'bodyV2', 'dueAt', 'status'],
      },
    ]) {
      expect(() =>
        validateQaVaWorkspaceOperationOrThrow({
          authContext: qaAuthContext,
          operationType: 'update',
          ...allowedUpdate,
        }),
      ).not.toThrow();
    }

    expect(() =>
      validateQaVaWorkspaceOperationOrThrow({
        authContext: qaAuthContext,
        entityName: 'person',
        operationType: 'update',
        updatedColumns: ['qaDisposition'],
      }),
    ).not.toThrow();

    const allowedInserts = [
      { entityName: 'note', value: { id: RECORD_ID } },
      {
        entityName: 'noteTarget',
        value: {
          id: RECORD_ID,
          noteId: PARENT_ID,
          targetPersonId: PERSON_ID,
        },
      },
      {
        entityName: 'task',
        value: { id: RECORD_ID, assigneeId: MEMBER_ID },
      },
      {
        entityName: 'task',
        value: { id: RECORD_ID, assigneeId: null },
      },
      {
        entityName: 'taskTarget',
        value: {
          id: RECORD_ID,
          taskId: PARENT_ID,
          targetPersonId: PERSON_ID,
        },
      },
    ];

    for (const { entityName, value } of allowedInserts) {
      expect(() =>
        validateQaVaWorkspaceOperationOrThrow({
          authContext: qaAuthContext,
          entityName,
          operationType: 'insert',
          insertValues: [value],
        }),
      ).not.toThrow();
    }
  });

  it('denies the same user in another workspace or member binding', () => {
    expect(() =>
      validateQaVaWorkspaceOperationOrThrow({
        authContext: {
          ...qaAuthContext,
          workspace: { id: '44444444-4444-4444-8444-444444444444' },
          workspaceMemberId: '55555555-5555-4555-8555-555555555555',
        } as WorkspaceAuthContext,
        entityName: 'person',
        operationType: 'select',
      }),
    ).toThrow();
  });

  it('denies broad writes, destructive actions, and unapproved person fields', () => {
    const deniedCases = [
      { entityName: 'company', operationType: 'insert' as const },
      { entityName: 'person', operationType: 'delete' as const },
      {
        entityName: 'note',
        operationType: 'update' as const,
        updatedColumns: ['createdBy'],
      },
      {
        entityName: 'task',
        operationType: 'update' as const,
        updatedColumns: ['assigneeId'],
      },
      { entityName: 'task', operationType: 'soft-delete' as const },
      { entityName: 'workspaceMember', operationType: 'relation' as const },
    ];

    for (const deniedCase of deniedCases) {
      expect(() =>
        validateQaVaWorkspaceOperationOrThrow({
          authContext: qaAuthContext,
          ...deniedCase,
        }),
      ).toThrow();
    }

    expect(() =>
      validateQaVaWorkspaceOperationOrThrow({
        authContext: qaAuthContext,
        entityName: 'person',
        operationType: 'update',
        updatedColumns: ['name'],
      }),
    ).toThrow();
  });

  it('denies upserts, unbound targets, missing idempotency IDs, and task reassignment', () => {
    const deniedInserts = [
      { entityName: 'note', insertValues: [] },
      {
        entityName: 'note',
        insertValues: [{ id: RECORD_ID }],
        isUpsert: true,
      },
      {
        entityName: 'noteTarget',
        insertValues: [{ id: RECORD_ID, noteId: PARENT_ID }],
      },
      {
        entityName: 'noteTarget',
        insertValues: [
          {
            id: RECORD_ID,
            noteId: PARENT_ID,
            targetPersonId: PERSON_ID,
            targetCompanyId: PERSON_ID,
          },
        ],
      },
      {
        entityName: 'task',
        insertValues: [{ id: RECORD_ID, assigneeId: PERSON_ID }],
      },
      {
        entityName: 'taskTarget',
        insertValues: [
          { id: RECORD_ID, taskId: PARENT_ID, targetOpportunityId: PERSON_ID },
        ],
      },
    ];

    for (const deniedInsert of deniedInserts) {
      expect(() =>
        validateQaVaWorkspaceOperationOrThrow({
          authContext: qaAuthContext,
          operationType: 'insert',
          ...deniedInsert,
        }),
      ).toThrow();
    }
  });

  it('rejects a broadened or misspelled disposition field configuration', () => {
    for (const invalidFields of ['name', 'qaDisposition,name', '']) {
      process.env.QA_VA_PERSON_UPDATE_FIELDS = invalidFields;

      expect(() =>
        validateQaVaWorkspaceOperationOrThrow({
          authContext: qaAuthContext,
          entityName: 'person',
          operationType: 'select',
        }),
      ).toThrow();
    }
  });

  it('fails closed when any policy configuration is missing or malformed', () => {
    delete process.env.QA_VA_WORKSPACE_ID;

    expect(() =>
      validateQaVaWorkspaceOperationOrThrow({
        authContext: qaAuthContext,
        entityName: 'person',
        operationType: 'select',
      }),
    ).toThrow();
  });

  it('strips settings and tool permissions only for the exact user-workspace binding', () => {
    expect(
      isQaVaUserWorkspaceBinding({
        userWorkspaceId: USER_WORKSPACE_ID,
        workspaceId: WORKSPACE_ID,
      }),
    ).toBe(true);

    expect(
      isQaVaUserWorkspaceBinding({
        userWorkspaceId: '99999999-9999-4999-8999-999999999999',
        workspaceId: WORKSPACE_ID,
      }),
    ).toBe(false);

    expect(() =>
      isQaVaUserWorkspaceBinding({
        userWorkspaceId: USER_WORKSPACE_ID,
        workspaceId: '44444444-4444-4444-8444-444444444444',
      }),
    ).toThrow();

    expect(
      isQaVaToolContext({
        userWorkspaceId: USER_WORKSPACE_ID,
      }),
    ).toBe(true);
    expect(
      isQaVaToolContext({
        userWorkspaceId: '99999999-9999-4999-8999-999999999999',
        userId: USER_ID,
      }),
    ).toBe(true);
  });

  it('does not alter other users or trusted system operations', () => {
    expect(() =>
      validateQaVaWorkspaceOperationOrThrow({
        authContext: {
          ...qaAuthContext,
          user: { id: '66666666-6666-4666-8666-666666666666' },
          workspaceMemberId: '77777777-7777-4777-8777-777777777777',
        } as WorkspaceAuthContext,
        entityName: 'person',
        operationType: 'delete',
      }),
    ).not.toThrow();

    expect(() =>
      validateQaVaWorkspaceOperationOrThrow({
        authContext: {
          type: 'system',
          workspace: { id: WORKSPACE_ID },
        } as WorkspaceAuthContext,
        entityName: 'person',
        operationType: 'delete',
      }),
    ).not.toThrow();
  });

  it('is inactive only when the image does not require the policy and all bindings are absent', () => {
    delete process.env.QA_VA_POLICY_REQUIRED;
    delete process.env.QA_VA_WORKSPACE_ID;
    delete process.env.QA_VA_WORKSPACE_MEMBER_ID;
    delete process.env.QA_VA_USER_WORKSPACE_ID;
    delete process.env.QA_VA_USER_ID;
    delete process.env.QA_VA_USER_EMAIL;
    delete process.env.QA_VA_PERSON_UPDATE_FIELDS;

    expect(() =>
      validateQaVaWorkspaceOperationOrThrow({
        authContext: qaAuthContext,
        entityName: 'person',
        operationType: 'delete',
      }),
    ).not.toThrow();
  });

  it('fails closed when the required policy loses its entire environment block', () => {
    delete process.env.QA_VA_WORKSPACE_ID;
    delete process.env.QA_VA_WORKSPACE_MEMBER_ID;
    delete process.env.QA_VA_USER_WORKSPACE_ID;
    delete process.env.QA_VA_USER_ID;
    delete process.env.QA_VA_USER_EMAIL;
    delete process.env.QA_VA_PERSON_UPDATE_FIELDS;

    expect(() =>
      validateQaVaWorkspaceOperationOrThrow({
        authContext: qaAuthContext,
        entityName: 'person',
        operationType: 'select',
      }),
    ).toThrow();
  });
});
