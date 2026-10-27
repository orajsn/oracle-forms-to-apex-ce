# FOX project proof harness

These are developer-only tests for the existing JSN deployment. They are not
part of the business-user UI or the conversion runtime.

- The live journey uses normal FOX login, creates one labelled synthetic project,
  uploads both Forms XML modules and their DDL, and starts the normal conversion.
  It finishes only when the complete project is technically verified and the
  workbench displays its generated APEX application. It never accepts or downloads
  a live project.
- The [isolated delivery harness](delivery/README.md) uses the exact built FOX
  image and copied genuine output with a new synthetic login. It tests review and
  exact ZIP download without changing Jason's project or its acceptance state.

No tool here provisions infrastructure, repairs permissions on existing data,
resets a run, replaces an application or retries an uncertain write.

## Live prerequisites

Use the installed Windows Python and Node runtimes, plus an existing Playwright
installation and Edge. The tested UI observer uses Playwright 1.62.1; it is
separate from the APEX runtime QA container's pinned Playwright 1.64.0. Nothing
is downloaded or installed by this harness. Node and the Playwright entrypoint
are hash-bound; this is not a full operating-system or dependency attestation.

Supply the actual frozen source bundle B, canonical provider configuration C,
operator release R and installed deployment envelope D, with independently
reviewed SHA-256 values. The Python preparer runs the packaged production
validators against these inputs without selecting or starting a runtime.
Stopped candidates are not sufficient: the live preflight requires the exact
containers and protected verification service to be running.

Only the bundled `fixtures/ordinary-two-form.json` or a directory containing its
four exact original files is accepted. The JSON stores source text without an
added terminal newline; decoded/uploaded bytes retain the original SHA-256 values.
This is synthetic XML/DDL, not evidence of Forms binary extraction.

## Prepare and inspect

From the development workspace, set the variables below to the actual reviewed
files and hashes. Use a fresh short output directory. No credentials belong in
these declarations.

```powershell
& .\fox\.venv\Scripts\python.exe -I -B .\qa\product-project-journey\cli.py prepare `
  --provider $FoxProviderFile --provider-sha256 $FoxProviderSha `
  --release $FoxReleaseFile --release-sha256 $FoxReleaseSha `
  --admission $FoxAdmissionFile --admission-sha256 $FoxAdmissionSha `
  --bundle-root $FoxBundleRoot --bundle-sha256 $FoxBundleSha `
  --inventory $FoxSourceInventory `
  --sources .\qa\product-project-journey\fixtures\ordinary-two-form.json `
  --node $FoxNodeExe --playwright-module $FoxPlaywrightModule `
  --browser-channel msedge --output .\work\journey-plan-01
```

The result is `PREPARED_NOT_PREFLIGHTED`. Review its plan and retain the returned
plan SHA. Preparation creates no cloud request, login, project or conversion.

Read-only installed preflight:

```powershell
& .\fox\.venv\Scripts\python.exe -I -B .\qa\product-project-journey\cli.py inspect `
  --plan .\work\journey-plan-01\plan.json --plan-sha256 $FoxJourneyPlanSha `
  --ssh-key $FoxExistingPocSshKey
```

It checks the exact JSN VM/ADB through instance principal, actual D container
identities, frozen source/UI, selected project profile, real service process
identity, installed configuration and read-only queue eligibility. The public
origin is fixed to the existing JSN FOX URL. No login password or database secret
is needed for this inspection.

## Run once

Use the existing protected secret tooling to supply an owner-private JSON file
with exactly `username` and `password` for the normal FOX account. Keep it outside
the repository. Do not pass its contents as arguments, environment variables or
chat messages. The SSH reference must identify the existing dedicated POC key,
not the OCI signing key.

On Windows, prefer the existing user-scoped DPAPI password reference to avoid
creating a plaintext credential file. Use `--credentials-dpapi <private-file>`
and `--username <normal-FOX-user>` instead of `--credentials`. The reader checks
the owner-only ACL, decrypts in a hidden bounded child, passes the value only
through protected pipes, and never prints or saves the password. It does not
rotate credentials or repair existing permissions. JSON and DPAPI modes are
mutually exclusive.

```powershell
& .\fox\.venv\Scripts\python.exe -I -B .\qa\product-project-journey\cli.py run `
  --plan .\work\journey-plan-01\plan.json --plan-sha256 $FoxJourneyPlanSha `
  --ssh-key $FoxExistingPocSshKey --credentials $FoxPrivateLoginFile `
  --output .\work\journey-run-01 --apply
```

`run` always obtains a fresh preflight; it does not reuse a saved readiness flag.
It attaches Node to an owned Windows job before delivering protected stdin.
Pipe delivery and the browser lifetime are bounded. Cleanup targets only that
owned process tree. Terminating the observer does not cancel a remote conversion
and never proves that its HTTP request failed.

Create, upload and process each have a create-only intent before forwarding their
HTTP request. The plan itself is also claimed once, so another output directory
cannot replay the same attempt. A new rehearsal needs a new prepared plan and a
new project; it must not be used to bypass an unresolved previous attempt.

`LIVE_VERIFIED_NO_ACCEPTANCE` means the normal hosted route reported the complete
project technically verified, the exact built UI rendered the result, and review
and download stayed locked. It does not mean business acceptance or a public
download occurred. Actual per-form database/runtime evidence remains in the
managed verifier's immutable records.

If the saved run remains `QA_REQUIRED` but its owner-checked verification status
reports `attention`, the observer stops with
`CONVERSION_REQUIRES_OPERATOR_ATTENTION`. It preserves the generated artifact
and the original one-shot requests; it does not wait out the whole timer or
generate a replacement job. This is a failed/unfinished observation, never a
technical pass. A separately authorized recovery and read-only follow-up must
establish the later outcome without relabeling this original trial.

## Inspect uncertainty

Do not rerun a dispatched plan, delete its markers or select a different output
directory to get past an error.

```powershell
# Local retained records and current native process identity, no cloud request:
& .\fox\.venv\Scripts\python.exe -I -B .\qa\product-project-journey\cli.py inspect `
  --plan .\work\journey-plan-01\plan.json --plan-sha256 $FoxJourneyPlanSha `
  --attempt-output .\work\journey-run-01

# Additionally read the exact saved synthetic project/run through guarded SSH:
& .\fox\.venv\Scripts\python.exe -I -B .\qa\product-project-journey\cli.py inspect `
  --plan .\work\journey-plan-01\plan.json --plan-sha256 $FoxJourneyPlanSha `
  --attempt-output .\work\journey-run-01 --remote --ssh-key $FoxExistingPocSshKey
```

The process read compares PID, native creation identity and executable. Missing
or terminated processes do not authorize HTTP replay. Remote inspection can run
while the saved conversion is active; it does not claim a queue job or read a
database password. Ambiguous matching projects, changed deployment bindings or
unverified output stop the check.

## Current coverage

The first live scenario is a fresh project containing the ordinary-source
`ALPHA` and `BETA` forms. Independent new plans exercise additional projects
without per-job source edits. Changed-source conversion, blocked-input live
journeys and richer/shared-table fixtures are separate scenarios, not implied
by this first one.

Development tests cover pure contracts, actual Windows private ACLs and process
ownership, bounded non-reading-child pipes, packaged B/C/R validation, Python/Node
input parity, and the actual frozen UI with a simulated HTTP backend. They are
not a live Oracle/model result. Review the exact deployment and plan, then run the
read-only installed check before either the live journey or the isolated test.
