#!/bin/sh
set -eu

if [ "${QA_VA_POLICY_REQUIRED:-}" != "true" ]; then
  echo "QA VA image refuses to start without QA_VA_POLICY_REQUIRED=true" >&2
  exit 64
fi

: "${QA_VA_WORKSPACE_ID:?QA_VA_WORKSPACE_ID is required}"
: "${QA_VA_WORKSPACE_MEMBER_ID:?QA_VA_WORKSPACE_MEMBER_ID is required}"
: "${QA_VA_USER_WORKSPACE_ID:?QA_VA_USER_WORKSPACE_ID is required}"
: "${QA_VA_USER_ID:?QA_VA_USER_ID is required}"
: "${QA_VA_USER_EMAIL:?QA_VA_USER_EMAIL is required}"
: "${QA_VA_PERSON_UPDATE_FIELDS:?QA_VA_PERSON_UPDATE_FIELDS is required}"
: "${IS_MULTIWORKSPACE_ENABLED:?IS_MULTIWORKSPACE_ENABLED must be explicitly false}"

is_uuid() {
  printf '%s\n' "$1" | grep -Eq \
    '^[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[1-8][0-9A-Fa-f]{3}-[89ABab][0-9A-Fa-f]{3}-[0-9A-Fa-f]{12}$'
}

for qa_va_id in \
  "$QA_VA_WORKSPACE_ID" \
  "$QA_VA_WORKSPACE_MEMBER_ID" \
  "$QA_VA_USER_WORKSPACE_ID" \
  "$QA_VA_USER_ID"
do
  if ! is_uuid "$qa_va_id"; then
    echo "QA VA image refuses to start with a malformed identity binding" >&2
    exit 64
  fi
done

if [ "$QA_VA_PERSON_UPDATE_FIELDS" != "qaDisposition" ]; then
  echo "QA VA image permits only QA_VA_PERSON_UPDATE_FIELDS=qaDisposition" >&2
  exit 64
fi

if [ "$IS_MULTIWORKSPACE_ENABLED" != "false" ]; then
  echo "QA VA image requires IS_MULTIWORKSPACE_ENABLED=false" >&2
  exit 64
fi

if ! printf '%s\n' "$QA_VA_USER_EMAIL" | grep -Eq '^[^[:space:]@]+@[^[:space:]@]+\.[^[:space:]@]+$' \
  || [ "$QA_VA_USER_EMAIL" != "$(printf '%s' "$QA_VA_USER_EMAIL" | tr '[:upper:]' '[:lower:]')" ]; then
  echo "QA VA image requires a normalized lower-case QA_VA_USER_EMAIL" >&2
  exit 64
fi

node /app/qa-va-binding-preflight.cjs

exec /app/upstream-entrypoint.sh "$@"
