import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';

import { validateQueryIsPermittedOrThrow } from 'src/engine/twenty-orm/repository/permissions.utils';

const readServerSource = (relativePath: string) =>
  readFileSync(resolve(__dirname, '../../../..', relativePath), 'utf8');

describe('QA VA policy wiring', () => {
  const qaPolicyEnvironment = {
    QA_VA_POLICY_REQUIRED: 'true',
    QA_VA_WORKSPACE_ID: '11111111-1111-4111-8111-111111111111',
    QA_VA_WORKSPACE_MEMBER_ID: '22222222-2222-4222-8222-222222222222',
    QA_VA_USER_WORKSPACE_ID: '33333333-3333-4333-8333-333333333333',
    QA_VA_USER_ID: '44444444-4444-4444-8444-444444444444',
    QA_VA_USER_EMAIL: 'qa-va@example.com',
    QA_VA_PERSON_UPDATE_FIELDS: 'qaDisposition',
  } as const;
  const originalQaPolicyEnvironment = Object.fromEntries(
    Object.keys(qaPolicyEnvironment).map((key) => [key, process.env[key]]),
  );

  afterEach(() => {
    for (const [key, value] of Object.entries(originalQaPolicyEnvironment)) {
      if (value === undefined) {
        delete process.env[key];
      } else {
        process.env[key] = value;
      }
    }
  });

  it('enforces the policy behavior before a query-builder bypass returns', () => {
    Object.assign(process.env, qaPolicyEnvironment);

    const authContext = {
      type: 'user',
      user: { id: qaPolicyEnvironment.QA_VA_USER_ID },
      workspace: { id: qaPolicyEnvironment.QA_VA_WORKSPACE_ID },
      workspaceMemberId: qaPolicyEnvironment.QA_VA_WORKSPACE_MEMBER_ID,
      userWorkspaceId: qaPolicyEnvironment.QA_VA_USER_WORKSPACE_ID,
    } as any;
    const args = {
      authContext,
      objectsPermissions: {},
      flatObjectMetadataMaps: {},
      flatFieldMetadataMaps: {},
      objectIdByNameSingular: {},
      shouldBypassPermissionChecks: true,
    } as const;
    const expressionMap = (queryType: string, entityName: string) =>
      ({
        aliases: [{ metadata: { name: entityName } }],
        joinAttributes: [],
        onUpdate: undefined,
        queryType,
        selects: [],
        valuesSet: {},
      }) as any;

    expect(() =>
      validateQueryIsPermittedOrThrow({
        ...args,
        expressionMap: expressionMap('select', 'person'),
      }),
    ).not.toThrow();
    expect(() =>
      validateQueryIsPermittedOrThrow({
        ...args,
        expressionMap: expressionMap('delete', 'person'),
      }),
    ).toThrow();

    const activityUpdate = expressionMap('update', 'note');

    activityUpdate.valuesSet = { bodyV2: { blocknote: 'QA note' } };
    expect(() =>
      validateQueryIsPermittedOrThrow({
        ...args,
        expressionMap: activityUpdate,
      }),
    ).not.toThrow();

    const attributedPersonUpdate = expressionMap('update', 'person');

    attributedPersonUpdate.valuesSet = {
      qaDisposition: 'booked',
      updatedBySource: 'MANUAL',
      updatedByWorkspaceMemberId: qaPolicyEnvironment.QA_VA_WORKSPACE_MEMBER_ID,
      updatedByName: 'QA VA',
      updatedByContext: {},
    };
    expect(() =>
      validateQueryIsPermittedOrThrow({
        ...args,
        expressionMap: attributedPersonUpdate,
      }),
    ).not.toThrow();

    attributedPersonUpdate.valuesSet = {
      ...attributedPersonUpdate.valuesSet,
      updatedByWorkspaceMemberId: '55555555-5555-4555-8555-555555555555',
    };
    expect(() =>
      validateQueryIsPermittedOrThrow({
        ...args,
        expressionMap: attributedPersonUpdate,
      }),
    ).toThrow();

    const upsert = expressionMap('insert', 'note');

    upsert.valuesSet = [{ id: 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa' }];
    upsert.onUpdate = ['title'];
    expect(() =>
      validateQueryIsPermittedOrThrow({
        ...args,
        expressionMap: upsert,
      }),
    ).toThrow();
  });

  it('runs the policy before ordinary permission bypasses', () => {
    const permissionsSource = readServerSource(
      'engine/twenty-orm/repository/permissions.utils.ts',
    );
    const policyCall = permissionsSource.indexOf(
      'validateQaVaWorkspaceOperationOrThrow({',
      permissionsSource.indexOf('validateQueryIsPermittedOrThrow'),
    );
    const bypassReturn = permissionsSource.indexOf(
      'if (shouldBypassPermissionChecks)',
      permissionsSource.indexOf('validateQueryIsPermittedOrThrow'),
    );

    expect(policyCall).toBeGreaterThan(-1);
    expect(bypassReturn).toBeGreaterThan(policyCall);
  });

  it.each([
    'workspace-select-query-builder.ts',
    'workspace-insert-query-builder.ts',
    'workspace-update-query-builder.ts',
    'workspace-delete-query-builder.ts',
    'workspace-soft-delete-query-builder.ts',
  ])('passes authenticated context through %s', (filename) => {
    const source = readServerSource(`engine/twenty-orm/repository/${filename}`);

    expect(source).toContain('authContext: this.authContext');
  });

  it('protects entity-manager persistence even when normal checks are bypassed', () => {
    const source = readServerSource(
      'engine/twenty-orm/entity-manager/workspace-entity-manager.ts',
    );
    const validationMethod = source.slice(
      source.indexOf('  validatePermissions<Entity extends ObjectLiteral>'),
      source.indexOf('private extractTargetNameSingularFromEntityTarget'),
    );
    const policyCall = validationMethod.indexOf(
      'validateQaVaWorkspaceOperationOrThrow({',
    );
    const bypassReturn = validationMethod.indexOf('return;', policyCall);

    expect(policyCall).toBeGreaterThan(-1);
    expect(bypassReturn).toBeGreaterThan(policyCall);
    expect(validationMethod).toContain('authContext: this.authContext');
  });

  it('denies a second workspace before the QA user reaches workspace creation', () => {
    const authResolverSource = readServerSource(
      'engine/core-modules/auth/auth.resolver.ts',
    );
    const methodStart = authResolverSource.indexOf(
      'async signUpInNewWorkspace(',
    );
    const policyCall = authResolverSource.indexOf(
      'isQaVaToolContext({ userId: currentUser.id })',
      methodStart,
    );
    const workspaceCreation = authResolverSource.indexOf(
      'signUpOnNewWorkspace(',
      methodStart,
    );

    expect(methodStart).toBeGreaterThan(-1);
    expect(policyCall).toBeGreaterThan(methodStart);
    expect(workspaceCreation).toBeGreaterThan(policyCall);
  });
});
