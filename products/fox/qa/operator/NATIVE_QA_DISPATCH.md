# Parent-dispatched native QA v2

This helper stages and launches the current native QA runner on the existing pinned JSN VM only. It does not allocate targets, import applications, provision accounts, restart services, install dependencies, pull images, or grant human acceptance. Existing clean-operator modules and historical QA tags/stages remain unchanged.

## Separate actions

From the workspace root, first inspect the local-only source manifest:

```text
python qa/operator/native_qa_dispatch.py manifest
```

Use the returned `qa_source_sha256` and the exact immutable clean plan. The following are **separate parent-authorized commands**, not an automatic sequence:

```text
python qa/operator/native_qa_dispatch.py stage --plan <ABS_CLEAN_PLAN_JSON> --plan-sha256 <EXACT_CLEAN_PLAN_SHA256> --source-sha256 <EXACT_QA_SOURCE_SHA256> --apply
python qa/operator/native_qa_dispatch.py run --plan <ABS_CLEAN_PLAN_JSON> --plan-sha256 <EXACT_CLEAN_PLAN_SHA256> --source-sha256 <EXACT_QA_SOURCE_SHA256> --apply
python qa/operator/native_qa_dispatch.py collect --plan <ABS_CLEAN_PLAN_JSON> --plan-sha256 <EXACT_CLEAN_PLAN_SHA256> --source-sha256 <EXACT_QA_SOURCE_SHA256>
```

`stage` and `run` each reuse the clean operator's guarded read-only check and require its actual `QA_READY` handoff. After runtime writes, that target is no longer initially empty, so a new `run` must not be inferred safe. `collect` instead reads historical retained evidence without a fresh emptiness check or a write-authorization flag.

The initial helper checkpoint is source SHA-256 `1eed6500f2838a3d0560ce32c4b75197436d7ea05edf510645d0a60a29413f1d`; re-run `manifest` after any source change and have the new digest reviewed. Do not silently substitute a new hash in an approved command.

## What is preserved and checked

- Exact JSN OCI identities, VM metadata, non-root `opc`, rootless Podman, pinned running FOX/converter images, converter environment and jobs bind mount.
- Historical installed QA image `e3f7b9648271a741cf320b7ad928a17e0e1591ba66835e7420864905524eb571`, official Playwright base digest and exact package/package-lock bytes. A small unique-tag overlay copies code only, with `--pull=never --network=none`; no npm command or dependency installation runs.
- The host wrapper is Python 3.6-compatible. Canonical clean-plan/allocation/profile validation executes inside the already-installed converter Python 3.11.
- Only six exact operator handoff files are read: package, native spec, raw allocation, operator verification profile, passed clean-import receipt and the two-runtime-account credential file. The schema credential, ADMIN secret and wallet are never copied.
- Handoff copies live in new `0700` directories with exclusive `0600` files. The original converter data is never relabeled for QA. Only private copies are mounted into the new container.
- The staged runner wrapper differs from the frozen `run-jsn-qa.sh` only in its image selection, which becomes the resolved immutable image ID. Existing isolation, timeout, read-only input mounts and rootless resource-limit qualifications remain.

Stages use `/home/opc/.config/fox-qa/v2-stages/<clean-plan-sha>/<qa-source-sha>`. They are create-only; no partial stage is automatically overwritten. A separate fixed allocation-keyed `launch-v2/<allocation-sha>.json` is created and fsynced before browser dispatch. The runner itself owns `dispatch-v2/<allocation-sha>.json`, immediately before its first possible business write. Never delete either journal to reset a run. A timeout/failure means inspect and reconcile, not retry.

## Non-secret evidence collection

`collect` reads raw bytes of the original package/spec, allocation, operator profile, clean-import receipt, derived QA profile, target receipt, QA result, stage receipt and launch intent. It includes the launch completion receipt when present. The runtime dispatch receipt is required for attempted writes and included when present; a preflight-blocked result correctly has no such receipt.

The remote process scans the selected bytes against both runtime-account credential values before returning them. It returns only the selected artifacts plus SHA-256 hashes, never credential files or logs. Screenshots remain in the protected remote result directory for separately authorized inspection.

The local destination is create-only and private:

```text
<clean-plan-directory>/qa-<first-16-characters-of-qa-source-sha>/
```

`collection-manifest.json` retains the full 64-character source SHA-256, inspected artifact hashes and exact remote report path. The short directory name avoids Windows path-length failure; an existing prefix collision still fails closed without overwriting. These are the raw inputs for the independent v2 technical/release verifier; successful collection is not itself technical promotion or human acceptance.

## Local checks

```text
python -m unittest qa.operator.tests.test_native_qa_dispatch -v
```

The focused tests mock all process, remote, browser and private-write boundaries. They cover exact input/source binding, allocation bytes, two-account shape, offline image preparation, immutable staged runner selection, tamper rejection, allocation-keyed no-replay and non-secret/preflight evidence collection. They do not prove the actual remote stage or browser journey.
