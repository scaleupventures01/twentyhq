import { ToolCategory } from 'twenty-shared/ai';

import { ToolExecutorService } from 'src/engine/core-modules/tool-provider/services/tool-executor.service';
import { ToolRegistryService } from 'src/engine/core-modules/tool-provider/services/tool-registry.service';

const QA_ENVIRONMENT = {
  QA_VA_POLICY_REQUIRED: 'true',
  QA_VA_WORKSPACE_ID: '11111111-1111-4111-8111-111111111111',
  QA_VA_WORKSPACE_MEMBER_ID: '22222222-2222-4222-8222-222222222222',
  QA_VA_USER_WORKSPACE_ID: '33333333-3333-4333-8333-333333333333',
  QA_VA_USER_ID: '44444444-4444-4444-8444-444444444444',
  QA_VA_USER_EMAIL: 'qa-va@example.com',
  QA_VA_PERSON_UPDATE_FIELDS: 'qaDisposition',
} as const;

describe('QA VA tool policy', () => {
  const previousEnvironment = process.env;

  beforeEach(() => {
    process.env = { ...previousEnvironment, ...QA_ENVIRONMENT };
  });

  afterAll(() => {
    process.env = previousEnvironment;
  });

  it('returns an empty catalog for the QA membership and immutable user', async () => {
    const provider = {
      category: ToolCategory.ACTION,
      isAvailable: jest.fn().mockResolvedValue(true),
      generateDescriptors: jest.fn().mockResolvedValue([
        {
          name: 'send_email',
          category: ToolCategory.ACTION,
          description: 'send email',
          icon: 'IconMail',
          executionRef: { kind: 'static', toolId: 'send_email' },
        },
      ]),
    };
    const service = new ToolRegistryService([provider] as any, {} as any);
    const baseContext = {
      workspaceId: QA_ENVIRONMENT.QA_VA_WORKSPACE_ID,
      roleId: 'role-id',
      rolePermissionConfig: { unionOf: ['role-id'] },
    } as any;

    await expect(
      service.getCatalog({
        ...baseContext,
        userWorkspaceId: QA_ENVIRONMENT.QA_VA_USER_WORKSPACE_ID,
      }),
    ).resolves.toEqual([]);
    await expect(
      service.getCatalog({
        ...baseContext,
        userWorkspaceId: '55555555-5555-4555-8555-555555555555',
        userId: QA_ENVIRONMENT.QA_VA_USER_ID,
      }),
    ).resolves.toEqual([]);
    expect(provider.generateDescriptors).not.toHaveBeenCalled();
  });

  it('denies dispatch even when a descriptor bypasses catalog discovery', async () => {
    const service = Object.create(
      ToolExecutorService.prototype,
    ) as ToolExecutorService;

    await expect(
      service.dispatch(
        {
          name: 'send_email',
          category: ToolCategory.ACTION,
          description: 'send email',
          icon: 'IconMail',
          executionRef: { kind: 'static', toolId: 'send_email' },
        },
        {},
        {
          workspaceId: QA_ENVIRONMENT.QA_VA_WORKSPACE_ID,
          roleId: 'role-id',
          rolePermissionConfig: { unionOf: ['role-id'] },
          userId: QA_ENVIRONMENT.QA_VA_USER_ID,
        },
      ),
    ).resolves.toMatchObject({ success: false });
  });
});
