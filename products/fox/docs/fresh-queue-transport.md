# Fresh installation queue adapter

Status: locally implemented container-side adapter, not a running verifier,
admission authority or released connected installer.

`qa.operator.fresh_queue` builds a command from the concrete selected C3/R4/F
provider and emits a fixed-path container program. Packet construction rechecks
the protected source/configuration and exact selected release. It does not
execute a container, read ADMIN, claim work or write installation records.

The container adapter uses the existing verification queue and completion
dispatcher. It does not introduce a second queue or workflow engine. The shared
dispatcher's default validator still accepts only the legacy R1/R2/R3 releases;
the fresh path supplies its separate exact R4 wire validator explicitly. Merely
passing a v4 manifest to the old dispatcher or ProductVerifier remains refused.
R4 now includes `fresh_queue.py` in its required measured operator code closure.
Existing frozen releases must not be edited to add it.

Before a queue operation, the fresh adapter checks:

- The exact release and context fields, types, target and source maps.
- Independent provider, projection, backend and release hashes in the actual
  container environment, plus its declared effective user.
- The existing `FreshStartupFence` against actual mounted public records and
  coherent read-only SQLite state. Missing A leaves the queue fenced.
- The same installation identity as the selected provider.

The generated program uses fixed `/data`, `/run/fox-installation` and profile
paths. It checks mounted profile bytes and all declared FOX module hashes before
compiling those bytes through the measured import finder. Application package
initializers and unbound FOX modules are not imported. Dependency/base-image
contents remain a separate release gate.

The existing queue owns claims, attention, completion proof checks and returned
field filtering. Only a claim result carries a private token. Status and other
results do not expose it. The startup fence is checked again after an operation;
a failed postcheck is an uncertain outcome, never permission to retry. No schema
initialization, claim recovery, bootstrap restart or human acceptance is added.

## What is not enabled

There is no fresh host executor/admission lease integration here. General fresh
execution and ADMIN retrieval still refuse; the R4 supervisor branch is still
disabled. Remaining clean-install, QA, collection and promotion transports must
all use the same fresh binding before this program can be launched by a genuine
authority. A public JSON ready flag or a synthetic A record cannot replace that
authority. No OCI, Oracle, model or live-service operation is part of this step.

## Verification scope

`qa/operator/tests/test_fresh_queue.py` uses real new S0/F/SQLite stores under a
nonroot Linux account. It executes the exact serialized helper functions with
actual queue/startup modules, testing two configurations, pre-admission refusal,
claim exclusion, private-token filtering, fabricated-proof refusal and removal
of A after activity. Normal-state cases explicitly use a synthetic A record;
they are not live admission or actual container-mount evidence. The fixture
also retains the existing explicitly unexecuted future-authority
placeholder; it is not an installable source release or proof of `fresh_connected`.
The production
container wrapper is compiled, and malformed wire is tested in a real isolated
child. Its complete happy-path mount/import wrapper still needs runtime proof.

Use the selected isolated test interpreter and installed pinned test dependencies.
The fixture can copy defusedxml0.7.1 from that test environment; no private venv,
download, Oracle binary or installed dependency tree is part of public source.
