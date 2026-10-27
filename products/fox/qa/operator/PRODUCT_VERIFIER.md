# Protected product verifier

This is a bounded workstation operator process, not a privileged service, Windows
autostart, general customer installer, or public FOX administration endpoint.
Recovery image `3a091103…b1f1e46` activated with operator F release `57e15ef2…`
on the existing JSN VM at 2026-10-18 04:33:30 UTC. The genuine historical
failure reader passed; old C is retained stopped. Use the current F artifact,
not the frozen root C CLI, for the next distinct verification. [Activation
evidence](../../outputs/beta/recovery-runtime-activated-20261018f.json).
The retained H image is deliberately ineligible. The
protected pump is not an installed/autostart service; its first real automatic
job proof remains incomplete: the first actual pump completed clean installation and stopped at terminal browser QA attention. Eleven cases passed, two were N/A, and a read-readiness timeout preceded concurrent saves. Its evidence is retained; do not replay the pump or use proof-only reconciliation to erase that failure. No live action is authorized by this document alone.

## Boundary

The server owns enqueue and safe status. It derives job/source/package hashes,
uses `FOX_VERIFICATION_ENABLED=0` by default, and requires an operator-installed
`FOX_VERIFIER_RELEASE_SHA256` when enabled. The public app has no SSH, DPAPI or
ADMIN execution capability. UI contact recency is not a promise of availability.

The protected workstation process uses existing OCI/SSH/DPAPI transports. It
claims one job, creates a fresh immutable clean plan, runs the existing four
clean phases, stages/runs/collects the existing per-package native QA, invokes
the existing technical promotion gate, and completes the queue by rechecking its
retained proof. It does not run the product UI-regression journey per job. Current
per-package proof requirements are not weakened. Human acceptance is never called.

## Reviewed release prerequisite

`product_verifier.py manifest` is local-only and disabled by default. Its digest
binds actual adapter/bridge/queue/runtime/gate/policy bytes, the existing clean
bundle, native-QA source bundle, promotion wrapper, exact JSN target and actual
declared FOX/converter image pins, plus the actual native profile bytes. The
existing read-only `/run/fox-native/profile.json` bind remains sourced from the
approved H release profile path; no arbitrary replacement mount is accepted.
Workstation pins must match the underlying
guarded tools. Each protected action rechecks those bytes before dispatch.

The reviewed queue-aware FOX release is required. Its installed module hashes
and runtime environment must match the manifest; the bridge checks these inside
the exact pinned image before a claim or queue mutation. Neither a Boolean in a
JSON file nor a changed digest makes H queue-aware. The new module must reach the
existing FOX service through a separately approved release, not a live source patch.

The non-secret operator configuration is a closed document:

```json
{
  "schema_version": 1,
  "scope": "fox-product-verifier-operator-config-v1",
  "enabled": false,
  "images": {
    "fox": "sha256:<actual-reviewed-FOX-image>",
    "converter": "sha256:<actual-reviewed-converter-image>"
  }
}
```

These placeholders are not runnable pins. No credential, command, URL, customer
target or arbitrary path belongs in that document. Build/inspect the approved
image first, update reviewed tool pins consistently, obtain the actual enabled
manifest, then use that digest in the server's deployment-controlled environment.
The runtime release digest is configured when starting the container, not baked
into the image, avoiding an image/digest cycle.

## Explicit finite startup

After the reviewed deployment and private operator storage are ready:

```text
python -B qa/operator/product_verifier.py manifest --release-config <CONFIG>
python -B qa/operator/product_verifier.py run-once --release-config <CONFIG> --release-sha256 <REVIEWED_SHA> --apply
python -B qa/operator/product_verifier.py pump --release-config <CONFIG> --release-sha256 <REVIEWED_SHA> --apply --max-jobs 5 --max-polls 60 --max-seconds 3600 --poll-seconds 15
```

`--apply` authorizes that bounded user-session startup, not an installed scheduler
or future starts. A stopped process must be started explicitly again. The bounds
stop new polls/jobs; an in-flight protected job is not forcibly interrupted by the
wall-clock polling budget. Its existing finite transport/SQL/QA timeouts remain.
Heartbeats are sent at polling and phase boundaries, never as a privileged public
API. No password or claim token is accepted through command-line arguments.

The reused promotion guard requires the conversion queue to be idle. Managed
server admission reserves one conversion through `QA_REQUIRED`; reaching
`VERIFIED` releases the slot without waiting for human acceptance. This retains
the existing promotion guard. Unexpected conflicting work still stops the
attempt for attention rather than bypassing its prerequisites.

## Journals, uncertain outcomes and reconnect

Private journals live under `work/private/clean-install/product-verifier/`, keyed
by the first 16 release-digest characters and a random session. `release.json`
retains the full digest; a prefix collision fails closed without replacement.
The longest current-workspace phase path is 216 characters, with a 240-character
portable guard; no Windows long-path registry setting is needed.
Owner-only files, an OS lock, exclusive creation,
fsync, intent/result bindings and terminal hash seals preserve the record. The
claim token is retained only privately; public results omit it and provider text.

An unanswered claim or phase stops the session. Reconnecting cannot prepare a
replacement plan, rerun an import, rebuild a failed stage or reset QA dispatch.
An unfinished session blocks a new pump for that release. Existing remote clean
phase journals and allocation-keyed browser journals remain authoritative too.
Changing a release is not a retry mechanism for an old job: queue rebinding is
forbidden and historical plans/evidence remain unchanged.

A separately authorized reconciliation can only recheck an already retained
technical proof and close the same queue/session record:

```text
python -B qa/operator/product_verifier.py reconcile --release-config <CONFIG> --release-sha256 <REVIEWED_SHA> --session <EXACT_PRIVATE_SESSION> --apply
```

It cannot allocate, import, run QA, promote, or create human acceptance. A lost
claim response or missing completed technical proof remains blocked for operator
adjudication. Never delete a journal, fabricate a receipt or use a fresh namespace
to clear it. Known failed QA is collected read-only, then stops before promotion.
If this explicit proof-only reconciliation itself loses its reply, a later
explicit invocation may reuse only its byte-identical bound intent. It rechecks
the existing proof and preserves any identical completion/seal bytes. It never
re-enters clean, QA or promotion phases; altered intent/result bytes fail closed.

## Offline verification

```text
fox/.venv/Scripts/python.exe -B -m unittest qa.operator.tests.test_product_queue_transport qa.operator.tests.test_product_verifier -q
```

Tests use fake transports/phases and temporary SQLite/files. Positive proof-reader
results are explicit synthetic mocks; the real reader rejects fabricated evidence.
These tests are not a deployed queue, actual browser run, installation certificate,
customer authorization, or acceptance of Jason's retained packages.
