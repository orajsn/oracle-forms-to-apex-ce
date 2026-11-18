# Private OCI response receipts

Status: the component remains opt-in. Version 0.29.3 integrates it only behind
a specific, explicitly acknowledged one-extra-attempt operator action and its
remaining calls. No implicit processing permission, structured-output generation
or automatic retry is added. Historical jobs and OPAF records retain their
existing behavior. Source release, private activation and live acceptance differ.

## Purpose

A received model response should remain available even if its JSON, finish reason,
model identity or content is invalid. Store the client request identity before
submission and the bounded SDK response data before parsing model text. Validation
still decides whether that response can become a usable mapping or review.

This is not an exactly-once guarantee. If the transport outcome is unknown and
no response was captured, stop and reconcile; do not submit again automatically.

## Explicit API

The trusted caller provisions a dedicated private receipt directory outside the
sealed job tree and supplies it explicitly:

```python
store = LocalProviderReceiptStore(receipt_directory, sealed_job_root=job_directory)
output, invocation, environment, timing = client.invoke_prepared(
    role, request, identity,
    role_name=role_name,
    target_profile=target_profile,
    before_invoke=persist_existing_job_intent,
    receipt_store=store,
)
```

Without `receipt_store`, existing call behavior remains unchanged. Do not derive
storage paths from an uploaded filename or a browser-supplied directory. The
store parent must exist; use a local filesystem supporting atomic hard links.

For a captured response, an explicit read/parse operation is available:

```python
# First recheck current owner/source permission and acquire job ownership.
# Open existing storage without mkdir, fsync or write capability.
store = LocalProviderReceiptStore.read_only(receipt_directory, sealed_job_root=job_directory)
output, invocation, environment = client.recover_prepared(
    role, request, identity,
    role_name=role_name,
    target_profile=target_profile,
    receipt_store=store,
)
# Then apply the normal source/reference/design checks before adoption.
```

Recovery does not initialize instance-principal authentication, call the provider,
invent timestamps, change the response, seal a pipeline checkpoint, or alter job
status. It returns the original invocation/environment data only after the same
response checks pass. A captured malformed response remains invalid.

## Evidence and privacy

Intent and response records are create-only and bound to the exact job, source,
request, wire request, target, role, model and prompt. Receipt hashes detect
corruption; they are not signatures or proof against a writer controlling storage.
The component retains SDK response data, not a raw HTTP-wire transcript.

Only necessary invocation metadata is retained. Authorization headers, cookies,
SDK credentials and request bodies are not part of the receipt metadata. Model
response text is preserved privately without source redaction or semantic repair.
Bodies are bounded; an oversized/unserializable body cannot be recovered as valid.

For a recognized SDK `ServiceError`, only its bounded HTTP status, error code and
OCI request ID are captured, alongside the already retained client request ID.
The exception message and other headers are excluded. This is failure metadata,
not a generated model reply and not proof that the external operation never ran.
It cannot be adopted as a valid mapping and does not authorize automatic retry,
including for rate-limit or server errors. Untyped transport exceptions remain
unknown. Earlier calls without receipts cannot be reconstructed retroactively.

POSIX owner/mode checks are enforced. Windows operators must provision restrictive
ACLs; `chmod` alone cannot establish that confidentiality boundary. Paths must be
unlinked; corrupt, missing, incomplete or changed records fail closed. Temporary
unpublished files left by a crash are not receipts and must not authorize a retry.

On supported POSIX local filesystems, the root parent, receipt files and receipt
directory are flushed before the corresponding operation returns. This still
depends on the filesystem/storage honoring those operations. Windows verification
covers process interruption only, not namespace persistence across OS/power failure.
Do not enable automatic live recovery on Windows based on these component tests.

## Integration boundary

The current `prototype_pipeline._role` still stops on an existing uncertain
intent. This component does not bypass that gate. A future integrated continuation
must recheck current authority, require an exclusively owned inactive job, read
the matching receipt, and append a new outcome only after ordinary validators
pass. Never rewrite an old intent or fabricate a missing response.

Schema-constrained model output and backend-owned administrative bindings are
separate architecture increments. They must be versioned and capability-tested;
do not change an already-approved request/profile silently.

An opt-in synthetic pipeline test injects the receipt-enabled client through the
existing provider seam and reaches a generated package using an authored validator.
That is not actual model or SQLcl execution. Its invalid-response case confirms
the existing pending-intent gate remains in force and no provider call is repeated.

## Bounded operator integration

The authenticated `provider-reexecution` inspection returns a plan hash for the
exact inactive fourth-mapper intent and three already approved sections. Execution
requires both explicit acknowledgements: prior outcome unknown, possible extra
charge. The consumed latch uses exclusive creation and its own committed event
before POST. The actual SDK binding is checked against the reviewed plan before
receipt intent creation/submission. One allowance cannot be restored by deleting
receipt storage. Duplicate requests return retained status without queueing work.

Successful adoption creates the previously absent mapper checkpoint with a
`provider_reexecution` marker, private receipt hashes and a separate durable
adoption event. The old intent and all prefix files remain unchanged. Later new
calls are captured, and package proof includes the new-attempt lineage. No
original response is reconstructed or fabricated. Partial/crashed adoption is
an operator reconciliation task; it is not a second automatic inference attempt.
