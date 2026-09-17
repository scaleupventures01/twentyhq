# ScaleUp QA VA overlay

This overlay pins the official Twenty v2.8.3 amd64 image and replaces only the compiled outputs of the AGPL source files changed by the QA policy. It does not rebuild or replace Enterprise-marked modules.

The image is intentionally unusable as a general Twenty image. Before either the server or worker starts, it requires:

- single-workspace mode explicitly disabled (`IS_MULTIWORKSPACE_ENABLED=false`);
- one exact QA user/workspace/user-workspace/workspace-member/email binding;
- one active workspace and one active membership for that user;
- an assigned role with tool and settings access disabled; and
- a reachable PostgreSQL database containing that already-provisioned tuple.

The intended deployment sequence is therefore: initialize a new empty database with the stock v2.8.3 image on a localhost-only port, provision the isolated workspace and identities, disable the QA role's tools/settings, stop the stock server, then start this overlay against the same dedicated QA volumes. Do not point it at a production database.

Build after compiling `twenty-server` with the repository's required Node version:

```sh
docker build \
  -f packages/twenty-docker/twenty/Dockerfile.qa-va-overlay \
  --build-arg SOURCE_REVISION=<public-40-character-commit> \
  -t scaleup-twenty-qa:<public-commit> .
```

Focused verification:

```sh
node --test packages/twenty-docker/twenty/qa-va-binding-preflight.test.cjs
```

The policy allows tenant-local reads, one configured Person disposition update, stock UI Note/Task skeleton creation and narrow editor updates, and person-only NoteTarget/TaskTarget creation. It denies destructive and unrelated writes, upserts, settings, tool catalogs, and tool dispatch for the bound identity. The separate QA database must contain synthetic assigned records only.
