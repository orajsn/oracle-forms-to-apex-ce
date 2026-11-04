# Recovery of a stopped verification precheck

Source/component work, 4 November 2026. **Not a deployed live recovery command.**

## Why a separate outcome exists

A missing environment prerequisite can stop verification before QA starts.
That is not a completed QA failure, and must not be represented with fabricated
allocation, import, browser or passing-proof receipts. An unfinished read-only
check intent is not a successful check and must remain in the original journal.

The precheck recovery family records a failed/unfinished pre-QA attempt while
preserving the original generated output, run, queue, claim and evidence. It
never marks the application VERIFIED/ACCEPTED and grants no automatic retry.

## Implemented source

- `qa/operator/precheck_reconciliation.py` classifies one retained claimed
  attempt with completed claim/prepare records and an unfinished clean-check
  intent. It validates the exact seven-file journal, binding/hash chain,
  stopped verifier, no observed active SQLcl process, missing QA dependency,
  original queue/run/package/source linkage and independent release/code pins.
  Extra or mutating phases, completed clean-check/QA state, live execution,
  changed bytes, partial records and mismatched claims are rejected. Captured
  JSON and the classifier result are not host attestation or closure authority.
- The already measured `fox.verification_recovery` module owns a separate
  `verification_precheck_failures` append-only table and strict UPDATE/DELETE
  fences. Creating that ledger requires explicit initialization; reads never
  repair missing fences or unknown schemas.
- `close_precheck_failure` requires an exact reviewed assessment hash, explicit
  apply and a protected fresh-observation callback. It rechecks the real
  retained-package/source gate, current queue/claim, acceptance/proof absence
  and original outcome records inside the reserved SQLite transaction. It
  inserts only the new failure record; lost replies have immutable readback
  rather than replay. Old run/queue/source bytes are not rewritten.
- Readers validate that record, its fences and the original retained job.
  A valid closed precheck can release admission for other/new work, but never
  grants retry authority for the old attempt. Conflicting failed-QA/retry
  history, corrupt metadata and changed retained sources remain blocking.
- The owner-checked public status and read-only UI presentation explain
  "Verification precheck failed", retain generated output and direct the user
  to the FOX operator. No passing check, active executor, acceptance or retry
  control is inferred.

## Required live integration boundary

The schema/store API is not an installed host adapter. Before a live append,
the operator integration must validate the exact installation, resource scope,
containers, reviewed code, source/queue binding and retained journal; acquire
the original operator's actual OS exclusion lock; and preserve a protected
database/history export. Its observer must obtain fresh actual stopped-producer
evidence under that lock, not return a cached capture or caller JSON.

Only after that observation and all guards may it append the failure. It must
reconcile a lost reply by reading the ledger and authoritative process state,
not re-run a conversion/import or delete intents. No old journal is sealed as
a successful session. Old runtimes may still refuse to admit work; a new
source-measured reader and controlled paired rollout must consume the history.
This does not waive target-version checks, install missing modules, provide
customer-tenancy authority or certify the generated package for a new target.

## Verification performed so far

Synthetic classifier and ledger tests cover changed/mixed evidence, mandatory
observation, create-only recording, immutable readback, original-row preservation,
fence tampering, source changes and conflict with completed-QA recovery. The
retained-package gate is real in the ledger tests; external producer observation
is explicitly injected. The existing recovery/queue/runtime/worker regressions
remain separate evidence, not Oracle runtime proof.

A network-disabled, read-only-root container on the existing lab VM rehearsed
the new reader against a protected copy of the actual retained synthetic
project's run/queue, package, source, release, download and target cache. It used
the deployed FOX image and a measured recovery candidate compiled only in that
isolated process. Original copied rows/files remained unchanged and the copy
received one failure record, with no technical success, acceptance or retry.
The observer in that rehearsal was simulated. It is not a live closure or a
test of the not-yet-installed fresh-observation transport.

## Remaining work

Implement/prove the lock-held fresh observer and protected export/write/readback
route, perform the separately guarded live append, then rebind the actual target
version and roll out a coherent measured release. Re-run the installed native
conversion/import/export proof. The broader FOX product goal remains active;
this recovery component alone does not finish it.
