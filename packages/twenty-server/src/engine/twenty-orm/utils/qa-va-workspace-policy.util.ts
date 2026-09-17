import { Logger } from '@nestjs/common';

import { type WorkspaceAuthContext } from 'src/engine/core-modules/auth/types/workspace-auth-context.type';
import {
  PermissionsException,
  PermissionsExceptionCode,
  PermissionsExceptionMessage,
} from 'src/engine/metadata-modules/permissions/permissions.exception';

export type QaVaOperationType =
  | 'select'
  | 'insert'
  | 'update'
  | 'delete'
  | 'restore'
  | 'soft-delete'
  | 'relation';

type QaVaWorkspacePolicyConfig = {
  workspaceId: string;
  workspaceMemberId: string;
  userWorkspaceId: string;
  userId: string;
  userEmail: string;
  personUpdateFields: Set<string>;
};

const QA_VA_CONFIG_KEYS = [
  'QA_VA_WORKSPACE_ID',
  'QA_VA_WORKSPACE_MEMBER_ID',
  'QA_VA_USER_WORKSPACE_ID',
  'QA_VA_USER_ID',
  'QA_VA_USER_EMAIL',
  'QA_VA_PERSON_UPDATE_FIELDS',
] as const;

const UUID_PATTERN =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const QA_DISPOSITION_FIELD = 'qaDisposition';
const NOTE_UPDATE_FIELDS = new Set(['bodyV2', 'title']);
const TASK_UPDATE_FIELDS = new Set(['bodyV2', 'dueAt', 'status', 'title']);
const UPDATED_BY_FIELDS = new Set([
  'updatedBySource',
  'updatedByWorkspaceMemberId',
  'updatedByName',
  'updatedByContext',
]);
const qaVaPolicyLogger = new Logger('QaVaWorkspacePolicy');

const WRITE_POLICY: Readonly<Record<string, ReadonlySet<QaVaOperationType>>> = {
  note: new Set(['insert', 'update']),
  noteTarget: new Set(['insert']),
  person: new Set(['update']),
  task: new Set(['insert', 'update']),
  taskTarget: new Set(['insert']),
};

const deny = (
  reason = 'unspecified',
  context: Record<string, unknown> = {},
): never => {
  if (process.env.QA_VA_POLICY_LOG_DENIALS?.trim() === 'true') {
    qaVaPolicyLogger.warn(
      JSON.stringify({
        event: 'qa_va_policy_denied',
        reason,
        ...context,
      }),
    );
  }

  throw new PermissionsException(
    PermissionsExceptionMessage.PERMISSION_DENIED,
    PermissionsExceptionCode.PERMISSION_DENIED,
  );
};

const readConfig = (): QaVaWorkspacePolicyConfig | null => {
  const values = Object.fromEntries(
    QA_VA_CONFIG_KEYS.map((key) => [key, process.env[key]?.trim() ?? '']),
  ) as Record<(typeof QA_VA_CONFIG_KEYS)[number], string>;

  const isRequired = process.env.QA_VA_POLICY_REQUIRED?.trim() === 'true';
  const hasAnyBinding = QA_VA_CONFIG_KEYS.some((key) => values[key] !== '');

  if (!isRequired && !hasAnyBinding) {
    return null;
  }

  if (!isRequired) {
    deny('partial_binding_without_required_mode');
  }

  const ids = [
    values.QA_VA_WORKSPACE_ID,
    values.QA_VA_WORKSPACE_MEMBER_ID,
    values.QA_VA_USER_WORKSPACE_ID,
    values.QA_VA_USER_ID,
  ];
  const personUpdateFields = new Set(
    values.QA_VA_PERSON_UPDATE_FIELDS.split(',')
      .map((field) => field.trim())
      .filter(Boolean),
  );

  if (
    ids.some((id) => !UUID_PATTERN.test(id)) ||
    !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(values.QA_VA_USER_EMAIL) ||
    values.QA_VA_USER_EMAIL !== values.QA_VA_USER_EMAIL.toLowerCase() ||
    personUpdateFields.size !== 1 ||
    !personUpdateFields.has(QA_DISPOSITION_FIELD)
  ) {
    deny('invalid_binding_configuration');
  }

  return {
    workspaceId: values.QA_VA_WORKSPACE_ID,
    workspaceMemberId: values.QA_VA_WORKSPACE_MEMBER_ID,
    userWorkspaceId: values.QA_VA_USER_WORKSPACE_ID,
    userId: values.QA_VA_USER_ID,
    userEmail: values.QA_VA_USER_EMAIL,
    personUpdateFields,
  };
};

export const isQaVaUserWorkspaceBinding = ({
  userWorkspaceId,
  workspaceId,
}: {
  userWorkspaceId: string;
  workspaceId: string;
}) => {
  const config = readConfig();

  if (config === null || userWorkspaceId !== config.userWorkspaceId) {
    return false;
  }

  if (workspaceId !== config.workspaceId) {
    deny('workspace_binding_mismatch');
  }

  return true;
};

export const isQaVaToolContext = ({
  userWorkspaceId,
  userId,
}: {
  userWorkspaceId?: string;
  userId?: string;
}) => {
  const config = readConfig();

  if (config === null) {
    return false;
  }

  return userWorkspaceId === config.userWorkspaceId || userId === config.userId;
};

export const validateQaVaWorkspaceOperationOrThrow = ({
  authContext,
  entityName,
  operationType,
  updatedColumns = [],
  updateValues = [],
  insertValues = [],
  isUpsert = false,
}: {
  authContext: WorkspaceAuthContext;
  entityName: string;
  operationType: QaVaOperationType;
  updatedColumns?: string[];
  updateValues?: Record<string, unknown>[];
  insertValues?: Record<string, unknown>[];
  isUpsert?: boolean;
}) => {
  const config = readConfig();

  if (config === null || authContext.type !== 'user') {
    return;
  }

  const isQaVaIdentity =
    authContext.user.id === config.userId ||
    authContext.workspaceMemberId === config.workspaceMemberId;

  if (!isQaVaIdentity) {
    return;
  }

  if (
    authContext.user.id !== config.userId ||
    authContext.workspace.id !== config.workspaceId ||
    authContext.workspaceMemberId !== config.workspaceMemberId ||
    authContext.userWorkspaceId !== config.userWorkspaceId
  ) {
    deny('identity_binding_mismatch');
  }

  // The dedicated QA workspace contains synthetic cohort records only. Reads
  // remain available so the normal Twenty UI can resolve its metadata and
  // relations, while every mutation is denied unless explicitly listed here.
  if (operationType === 'select') {
    return;
  }

  if (!WRITE_POLICY[entityName]?.has(operationType)) {
    deny('operation_not_allowlisted', { entityName, operationType });
  }

  if (isUpsert) {
    deny('upsert_not_allowed', { entityName });
  }

  const activityUpdateFields =
    entityName === 'note'
      ? NOTE_UPDATE_FIELDS
      : entityName === 'task'
        ? TASK_UPDATE_FIELDS
        : null;

  if (operationType === 'update') {
    const businessUpdateFields =
      entityName === 'person'
        ? config.personUpdateFields
        : activityUpdateFields;

    if (
      businessUpdateFields !== null &&
      (updatedColumns.length === 0 ||
        updatedColumns.some(
          (column) =>
            !businessUpdateFields.has(column) && !UPDATED_BY_FIELDS.has(column),
        ))
    ) {
      deny('update_fields_not_allowlisted', {
        entityName,
        updatedColumns,
      });
    }

    const updatedByColumns = updatedColumns.filter((column) =>
      UPDATED_BY_FIELDS.has(column),
    );

    if (updatedByColumns.length > 0) {
      const hasCompleteUpdatedByActor =
        updatedByColumns.length === UPDATED_BY_FIELDS.size &&
        updateValues.length > 0 &&
        updateValues.every((value) => {
          const context = value.updatedByContext;

          return (
            value.updatedBySource === 'MANUAL' &&
            value.updatedByWorkspaceMemberId === config.workspaceMemberId &&
            typeof value.updatedByName === 'string' &&
            value.updatedByName.trim() !== '' &&
            typeof context === 'object' &&
            context !== null &&
            !Array.isArray(context) &&
            Object.keys(context).length === 0
          );
        });

      if (!hasCompleteUpdatedByActor) {
        deny('updated_by_actor_not_trusted', {
          entityName,
          updatedByColumns,
        });
      }
    }
  }

  if (operationType !== 'insert') {
    return;
  }

  if (
    insertValues.length === 0 ||
    insertValues.some((value) => !UUID_PATTERN.test(String(value.id ?? '')))
  ) {
    deny('insert_requires_client_uuid', { entityName });
  }

  if (
    entityName === 'task' &&
    insertValues.some(
      (value) =>
        value.assigneeId != null &&
        value.assigneeId !== config.workspaceMemberId,
    )
  ) {
    deny('task_assignee_not_qa_member');
  }

  if (entityName === 'noteTarget' || entityName === 'taskTarget') {
    const parentIdField = entityName === 'noteTarget' ? 'noteId' : 'taskId';
    const allowedKeys = new Set(['id', parentIdField, 'targetPersonId']);

    if (
      insertValues.some(
        (value) =>
          !UUID_PATTERN.test(String(value[parentIdField] ?? '')) ||
          !UUID_PATTERN.test(String(value.targetPersonId ?? '')) ||
          Object.keys(value).some((key) => !allowedKeys.has(key)),
      )
    ) {
      deny('activity_target_not_person_only', {
        entityName,
        payloadKeys: insertValues.map((value) => Object.keys(value).sort()),
      });
    }
  }
};
