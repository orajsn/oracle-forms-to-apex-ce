# Recover an incomplete first mapping

This is one controlled retry, not a general retry button or a conversion pass.
The original attempt, source files and model result remain available.

## User flow

1. Open the current source version and its **Action needed** prototype run.
2. Choose **Check recovery options**. This reads retained proof only.
3. If eligible, review why the first mapping was incomplete. The retry uses
   smaller requests without dropping any original object or selected code body.
4. Review the processing destination and the original code-unit selection. If
   the analysis workflow changed, confirm that change and the three processing
   consents again.
5. Choose **Retry mapping in smaller steps** once. A distinct child attempt is
   created in the same project and source version. Both attempts remain in history.

An existing child is returned, not dispatched again. If the response is uncertain,
check the current run rather than resubmitting. Ordinary generation still refuses
duplicate source-version runs. Reviewer rejection, unknown model results, partial
imports, later-stage failures and retries of a retry require operator review.

## What is verified

Recovery reconstructs the original source snapshot and first focus, verifies its
sealed mapper result, and checks that no later production operation started.
The retry must retain the exact original selected whole code units, current owner,
source version and approved destination. A workflow-role change requires fresh
consent; changing region, database, authentication or other destination metadata
is not an implicit retry option.

Schema-1 snapshots retain their original 250-object focus policy. Schema 2 binds
32-object partitions and rechecks complete coverage. This changes request sizing,
not business scope. The deterministic child identity makes a repeated request
observable without creating another paid execution.

## Storage and operator boundary

The application performs a transactional migration of the known SQLite `runs`
schema to remove only `UNIQUE(project,source_hash)`. It preserves all eight columns,
row IDs, data and foreign-key relationships, validates copied rows and restores
the caller's foreign-key setting. Unexpected custom schema, triggers or indexes
stop migration; failed checks roll back. Back up and use the guarded deployment
procedure. Do not run old application binaries against a migrated live store.

The verifier can classify only the exact proven terminal empty-first-mapper case
as having no active executable work. It never marks that run verified, creates an
application, grants retry permission or ignores unknown files. Operator diagnostics
must remain separate from production checkpoints, with their evidence preserved.

V3/V4 prompt resources are additive and inactive until an operator configures them.
Their registration and passing synthetic tests do not establish model quality.
A retained real-source diagnostic initially received `CHANGES_REQUIRED` for a
module-only partition. An explicitly approved, single reviewer-only retest using
the partition-aware V4 reviewer returned `APPROVED` with zero findings on the
unchanged saved candidate. Generation was not repeated; no application was
imported. This is one partition, not complete-application proof. The complete
live journey must still pass before describing the converter as ready.

APEX generated, technically verified and business behavior accepted are separate.
