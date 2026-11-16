# Export-only APEX packages

FOX0.27 adds an explicit package-delivery mode. The business-user outcome is a
native APEXlang ZIP with format-validation evidence and enough information for
the user to choose a compatible APEX environment and import it separately.

## User flow

1. Upload/prepare related Forms in one project using the existing supported
   Oracle extraction path. Review missing inputs and choose the approved scope.
2. Choose **Generate APEX package**. The selected provider designs and reviews
   the supported mapping; FOX renders native APEXlang deterministically.
3. SQLcl validates the generated application with `/nolog`. Invalid output is
   not published. No target database, schema creation or app import is invoked.
4. Open the generated output, read the target/MMD information, prerequisites and
   omissions, then choose **Download APEX package**.

The ZIP retains the native application files and `.apex/apexlang.json`. Extra
handoff files are under `fox-package/`: metadata, remediation, source hashes,
source-to-page mapping, supporting synthetic schema SQL and import instructions.
Supporting SQL is supplied, not executed. No conventional database-derived
`fNNN.sql` export is claimed by this route.

**Generated and format-validated** is not **import-tested**, **runtime-tested**
or **business accepted**. Declared target versions are configuration; the actual
generated MMD and observed SQLcl version are reported separately. Unsupported
business behavior remains explicit, and synthetic keys/storage are not claims
about a customer's authoritative schema.

## Existing saved designs

For an eligible inactive legacy prototype, **Check saved APEX output** can
prepare a separate format-only delivery from its reviewed deterministic candidate.
It repeats neither AI design nor target operations. A fresh offline format check
may run. Previous job files, source snapshot, status and failure records remain
unchanged; the new package does not turn an old runtime failure into a pass.

Readiness and preparation bind the current owner, source version, candidate and
profile. Unknown preparation responses are checked through GET; the UI does not
automatically repeat a POST. Preparation is idempotent for the same successful
binding. Missing review, changed source or candidate, active work, invalid format
or damaged compiler evidence blocks the shortcut with a concrete error.

Saved deliveries use `dataRoot/package-deliveries/<run>/apexlang-v1/`, outside the
original job tree. The original legacy output routes retain their old validators.

## Operator prerequisites

- Keep supported Oracle Forms tooling for binary extraction. This increment does
  not install or redistribute Oracle binaries or replace that extraction route.
- Configure the selected design provider and approved source-processing policy.
  Direct OCI mode does not need OPAF, its repository or an embedding service.
- Configure Java and SQLcl on the worker. `FOX_EXPORT_SQLCL_PATH` takes precedence
  over `F2A_SQLCL_PATH`, then PATH discovery. An ordinary SQLcl executable or a
  compatible isolated wrapper may be used.
- Set a private `TMPDIR` for compiler input/script staging. The wrapper must
  support version queries and batch `-nohistory -S /nolog @script`. Logs are
  retained privately under their hashes; their contents are not returned in
  public API metadata. No saved database connection or wallet is needed by the
  format-only validator.
- The current configuration loader reuses the prototype provider/compatibility
  profile. It may contain legacy declared target metadata; that metadata is not
  permission to execute against a database and no such connection is made by
  package delivery. A fully minimal fresh-customer profile/installer remains a
  separate packaging task.

The new route does not construct the legacy converter/database gateway and does
not need `FOX_CONVERTER_URL` or its token. Existing raw-extraction configuration
and unrelated legacy services are not automatically changed or stopped.

Package readiness is reported separately from legacy execution readiness.
Being configured for package generation does not authorize the legacy `/runs`
operation. Project sessions default to package readiness. Operators retaining an
older full-runtime configuration can explicitly set `FOX_DEFAULT_DELIVERY_MODE=legacy`
to report that configuration; it is not an automatic fallback when package
prerequisites are missing. The additive `deployment/run_export_preview.py` starts only the API
and optional configured Forms worker, with private UI credentials and temporary
storage. It shares the existing preview lock; do not run two supervisors on the
same data. The legacy `run_direct_preview.py` remains available for optional lab
operations. Preview activation and public routing remain explicit operator steps.

## API contract

New creation uses the existing prototype-run endpoint with the immutable field
`delivery_mode: "apexlang_package"`. Omitting the field preserves legacy behavior;
continuations cannot silently change an old job's mode.

The existing `/output` and `/download` routes serve the new mode with output scope
`fox-apexlang-package-output-v1`, `package_format: "apexlang_zip"` and
`format_validated: true`. Import, runtime, reimport, technical-verification and
business-acceptance flags remain false. Source/owner/profile and package integrity
checks still precede download.

Legacy saved-format delivery is separate:

```text
GET  /api/projects/{project}/prototype-runs/{run}/saved-package/readiness
POST /api/projects/{project}/prototype-runs/{run}/saved-package
GET  /api/projects/{project}/prototype-runs/{run}/saved-package/output
GET  /api/projects/{project}/prototype-runs/{run}/saved-package/download
```

POST requires the returned `preparation_binding_sha256` and explicit
`approved_format_only_delivery: true`. Its output scope is
`fox-saved-apexlang-package-output-v1`; `legacy_run_state` remains unchanged.

## Timing and speed boundaries

The package progress route shows mapping, rendering, format validation and
packaging, not a wait for optional runtime tests. Timing sidecars live under
`dataRoot/telemetry/<run>/`, outside job/authority trees. They contain bounded
numeric durations/counts and job/source/role identifiers, never prompts, source
text, headers or credentials. Missing or damaged telemetry does not block output.

Recorded request time includes network/provider processing; it is not isolated
model inference, time-to-first-token or whole-job elapsed time. Existing model
checkpoints remain reusable, and uncertain requests are not automatically retried.
Independent-focus concurrency and model changes are not enabled by this release.

## Manual import

Use a compatible APEX instance matching the declared profile. Review and install
the supporting synthetic schema where required, then use App Builder's import
wizard for the APEXlang ZIP or the corresponding SQLcl import command. Choose a
new application ID and review authentication, authorization and behavior before
using real data. FOX does not perform these steps in export-only mode.

Oracle documents APEXlang ZIP import for APEX26.1, including parsing-schema REST
enablement when requested by the wizard, and connectionless SQLcl validation:
[App Builder import](https://docs.oracle.com/en/database/oracle/apex/26.1/apxdc/importing-apexlang-app-builder.html),
[SQLcl validation](https://docs.oracle.com/en/database/oracle/apex/26.1/apxdc/using-sqlcl-apexlang.html).
