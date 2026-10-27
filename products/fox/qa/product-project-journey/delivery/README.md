# Isolated delivery proof for a genuine FOX project

This harness tests the **same built FOX application image** with copied,
already-verified project output and a separate synthetic login. It does not
convert a form, invoke OPAF, connect to an Oracle database, promote a copied run,
or record acceptance in the public FOX instance. A successful result is an
isolated delivery/API/UI proof, not Jason's or a customer's business approval.

No live run is authorized merely by these files. Root must review the harness,
pin the actual deployment and select an approved labelled-synthetic job first.

## Inputs and retained identities

The external binding has exactly these keys:

```json
{
  "job_id": "fox-<20 lowercase hex>",
  "project_id": "<32 lowercase hex>",
  "source_hash": "<exact source manifest SHA256>",
  "package_sha256": "<exact unchanged ZIP SHA256>",
  "proof_sha256": "<raw retained project verification.json SHA256>",
  "fox_image": "sha256:<actual built FOX image>",
  "release_sha256": "<actual hosted operator release R>"
}
```

These are declaration examples, not usable hashes. In particular, a valid
receipt format does not establish that its observations were gathered live.
The invoking operator must bind a real, authorized deployment and genuine job.

`contract.export_readonly(Path('/data'), binding)` runs inside the independently
guarded live FOX image. It uses a query-only SQLite connection and the real
`technical_release.checked_release` reader. It requires the exact `VERIFIED`
project with no acceptance, copies its original project/run/technical rows and
the following exact file closure, then performs a fresh independent read and
file-hash recheck. It never opens a login session or changes the live database.

- `source-snapshot.json`, `release-evidence.json`, `apex-package.zip`
- `native-project-pipeline/download.json`
- `native-project-pipeline/target-profile.json`
- `project-technical-verification/verification.json`
- `project-technical-verification/verification-profile.json`
- `project-technical-verification/allocation-receipt.json`
- `project-technical-verification/attempt.json`
- `project-technical-verification/clean-install.json`
- `project-technical-verification/qa-result.json`
- `project-technical-verification/qa-target.json`
- `project-technical-verification/qa-profile.json`

The result is canonical UTF-8 JSON with one trailing newline, scope
`fox-genuine-project-delivery-input-v1`. Files are represented by exact byte
count, SHA-256 and base64. Pin the complete export SHA independently and keep
the export owner-private. Do not display the full source payload in logs.
The export observes two consistent snapshots; it is not a lock preventing a
real owner from subsequently reviewing the live project.

## Isolated runtime

`runtime.py` is mounted separately from the unchanged FOX image. It calls that
image's actual `create_app(..., enable_worker=False)` and normal login/review
endpoints. It clears integration settings before importing the app, sets the
new private data directory before import-time storage initialization, and
disables managed verification. It requires the actual `/app/fox` package and
hashes the actual `/app/dist` assets.

The only configured login is `synthetic-project-delivery`. A newly generated
random password reaches the backend and browser through stdin, never source,
command arguments, logs or output files. No real FOX, OPAF, APEX or database
credential is mounted. The isolated database owner/customer/description and
OS-relative artifact spelling are the only adapted record fields. Preserve
the original project ID **and name**, every producer file, source approvals,
timestamps, run ID, package and technical-proof row. New source-history row IDs
are confined to the copied database; their selected content hash must match.

Stdin packets are bounded before a child is launched: 4,096 bytes for the
backend and 262,144 bytes for the browser. The host writes to a fresh raw POSIX
pipe using nonblocking writes and a ten-second absolute deadline. Partial
delivery, timeout or a broken pipe records an unconfirmed result and raises
into owned-container cleanup. The descriptor's original mode is restored;
backend stdin stays open, and browser EOF is sent only after complete delivery.

Before serving and after review, the actual retained-project reader must pass.
The post-review audit requires exactly one synthetic acceptance/event and exact
unchanged producer bytes. The original hosted run remains unaccepted.

## Host runner

The host runner is intended for the existing approved JSN VM under `opc` and
must be reviewed before execution. It consumes a separately SHA-pinned plan:

```text
python3.11 -I -B host.py run --plan /private/plan.json --plan-sha256 <SHA> --apply
python3.11 -I -B host.py inspect --plan /private/plan.json --plan-sha256 <SHA>
```

The plan pins the export, external binding, real D deployment envelope and
all four harness files. Runtime records stay under a new private
`/home/opc/.local/state/fox-project-delivery/<attempt>` directory. No application
data, wallet, signing key, ADMIN file or production service mount is reused.

The exact host plan fields are:

```text
schema_version: 1
scope: fox-isolated-project-delivery-plan-v1
attempt_id: delivery-<24 lowercase hex; fresh for each attempt>
input: {path: <private absolute export path>, sha256: <whole export SHA>}
binding: <the seven-key binding above>
deployment: {path: <private absolute D path>, sha256: <canonical D SHA>}
harness:
  directory: <private absolute staged harness directory>
  files: {contract.py: <SHA>, runtime.py: <SHA>, browser.mjs: <SHA>, host.py: <SHA>}
```

Serialize the complete plan as sorted compact UTF-8 JSON with one trailing
newline and pin its SHA externally. The plan, D and export files must be
owner-private `0600` files in `0700` directories. Stage the reviewed harness in
a separate private directory, not inside the attempt's eventual output root.

The backend uses `--network=none` with no published port. The browser joins only
that exact test container's network/user namespace and uses the cached approved
Playwright image. Its request policy additionally permits only the isolated
loopback origin, selected project, hashed assets and exact armed login/review
requests. Model, upload, process, source-selection and external navigation
requests are prohibited. Test containers/logs are retained; cleanup stops only
the exact owned test container identities. An unknown outcome is inspected,
not rerun or converted into a passing result.

## What the browser proves

The runner uses the current project workbench, not the old single-form tabs:

1. Normal synthetic login and actual image asset-byte checks.
2. The run reports every form generated/technically verified, with no human acceptance.
3. Download blocked before review and incomplete acceptance rejected.
4. Normal review controls create one explicitly labelled synthetic acceptance.
5. Downloaded ZIP byte count and SHA match the original unchanged package.
6. Duplicate acceptance is rejected; API technical proof is unchanged.

The runtime performs the independent raw-file/proof-row audit afterwards.
The browser does not open the genuine APEX preview: original APEX runtime QA is
separate evidence, already required for the copied `VERIFIED` result.

## Test scope

`tests/test_contract.py` uses the real project producer and retained/API readers
with **authored synthetic Oracle/QA observations**, not a live database or model.
It covers immutable export/copy, rejected tampering, independent WAL acceptance
recheck, normal synthetic login/acceptance/download, and a fresh process importing
the frozen B reader without importing storage-initializing `fox.app`.

`test-browser.mjs` exercises contract/request-policy behavior; it does not claim
Chromium execution. Host tests isolate external Podman/IMDS operations. A real
run of the exact images, normal login and browser still requires root's reviewed
execution against a newly generated genuine multi-form project.

Recorded development checks: the retained-copy/API suite passed 22 tests. The
updated host suite passed 41 Windows tests with 15 POSIX-only skips and all 56
tests on POSIX. Its real owned-pipe tests cover a non-reading child, partial
writes, EOF, broken readers and descriptor-mode restoration; external Podman
and IMDS outcomes remain substituted in controller tests. Browser contract and
request-policy tests passed 23 cases. API tests emit two existing
FastAPI/Starlette deprecation warnings, not proof failures. These counts do not
claim a real container, Chromium, Oracle or model run.
