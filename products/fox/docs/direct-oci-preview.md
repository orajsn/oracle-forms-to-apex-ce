# Direct OCI Generative AI preview

FOX0.26.0 adds a direct provider for the existing focused prototype flow. The
UI, SQLite queue, Oracle Forms extraction, source approval, deterministic APEX
renderer and SQLcl/runtime gates remain in FOX. OPAF remains an optional provider.
The direct route needs neither an OPAF repository nor an embedding service.

## Operator configuration

This preview is restricted to the existing JSN Ashburn synthetic lab target.
It does not authorize another target, public cutover, infrastructure creation or
customer data processing. Oracle Forms, Java, SQLcl, the saved target connection
and an authenticated runtime browser are separately installed prerequisites.
Oracle binaries are not distributed in the package.

Use `deployment/target-profile.jsn-project-2616-oci-genai.json` as the direct
profile. Its `design_provider.roles` select independent mapper and reviewer
invocations. Both initially use `xai.grok-4.3`; model IDs are configurable, while
prompt versions are bound to the installed source. Revalidate availability in
Ashburn before an approved run. Do not silently substitute a model or region.
Calls use the OCI Python SDK and instance-principal authentication. Raw Forms
binaries are not model input; only the selected approved redacted source is.

`FOX_PROTOTYPE_PROFILE_FILE` selects a JSON envelope containing `target_profile`
and its canonical `target_profile_sha256`. The converter uses the raw profile
through `F2A_TARGET_PROFILE_PATH`. Set `FOX_RUN_ADAPTER=oci-genai` and
`FOX_CONVERSION_PROFILE=native-project-v1`. Set `FOX_CONVERTER_CREDENTIAL_FILE`
to a protected JSON object containing only `converter_token`; direct mode does
not read an OPAF login. Preserve the normal converter token and source authority
checks. `FOX_DIRECT_LOOPBACK_AUTHORITY=1` explicitly permits the preview's exact
127.0.0.1 HTTP authority origin; it does not allow remote plaintext origins.

`deployment/run_direct_preview.py --config <private-json>` starts loopback API,
converter, native extraction and runtime polling processes. The private JSON
selects an existing `instance_root`, packaged `product_root`, distinct `api_port`
and `converter_port`, `oracle_home`, `java_home`, `credentials_file` and an
`environment` object holding the provider/target/runtime settings above.
The launcher keeps Python and SQLcl scratch under the private instance `tmp`
directory so an operator-provided SQLcl container wrapper can see the same paths.
A SQLcl wrapper must also expose the matching installed compiler metadata under
its adjacent `lib/apexlang-compiler.jar`; these Oracle prerequisites remain outside
the public package.

The credentials file contains `username`, scrypt `password_hash` and
`converter_token`. Use new private data, jobs, forms-queue, forms-tmp,
runtime-staging, qa and logs directories under the instance root. A single
launcher lock prevents duplicate preview supervisors. Preserve the instance
folder across restarts; interrupted or claimed operations require reconciliation.

The runtime worker uses the explicit protected configuration documented in
`qa/operator/direct_preview_runtime.py`. Its synthetic account and target must
already exist. It checks credential hashes, current FOX source authority,
target identity and account availability before starting the real browser.
It does not create or reset an account. A running listener is not runtime proof.

## Clean distribution

Build the frontend with the checked-in package lock. Prepare a target-platform
wheelhouse from `deployment/requirements-direct-lock.txt`, copied into the
wheelhouse as `requirements.txt`. These are the exact dependency versions from
the verified isolated Python 3.11 environment, including the application,
converter and OCI SDK. Then run:

```text
python deployment/package_direct_preview.py --wheelhouse <wheelhouse> --output <new-archive.tar.gz>
```

The archive contains built UI assets, Python source, QA runtime code, dependency
wheels and a file-hash manifest. It excludes source-control metadata, local
histories, instance data and Oracle binaries. In a new directory, verify every
manifest hash, create a new Python environment and install offline:

```text
python3.11 -m venv venv
venv/bin/python -m pip install --no-index --find-links wheelhouse -r wheelhouse/requirements.txt
venv/bin/python -m pip check
```

Configure the existing external prerequisites explicitly. Do not copy a previous
installation's jobs, database, runtime receipts or recovery wrappers into a clean
installation. The package builder does not itself prove that installation or a
conversion succeeds.

## Evidence and limitations

Direct invocations retain versioned provider, model, SDK, prompt, request and
response hashes plus the actual OCI request ID. They contain no invented OPAF
workflow, room or conversation. Old OPAF records retain their original checks.
Saved completed calls are reused only with their exact source and target binding.
An uncertain invocation or import is not automatically repeated.

A generated package, technical runtime proof and human business acceptance are
separate results. Partial scope must list omitted behavior and synthetic data.
The export still needs its own exact-downloaded-byte fresh-ID import test;
successful generation is not evidence of that test or of customer compatibility.

## Continuing a retained run

A structural conflict caused by omitting a source-proven Form container can be
corrected through **Review corrected structure**. The original mapping and review
stay saved; one new independent review must approve the derived structure. This
adds no business behavior and does not bypass the merge checks.

After the operator fixes the validation environment, **Recheck saved draft**
permits one explicit second attempt for a definitively failed, unchanged
connectionless validation. The original failure remains immutable. Uncertain
attempts and any run with downstream effects are ineligible. No model call is
repeated. If validation passes, the originally approved synthetic schema, import,
runtime and export steps continue with fresh target checks.
