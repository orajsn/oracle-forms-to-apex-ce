# FOX: Form to APEX

FOX is a development preview for Oracle Forms modernization. One project groups
related Forms modules, with one native APEX application/export as the intended output.
The web UI manages multiple projects, source versions, conversion runs, findings
and result review. Business users do not need Codex, prompts or QA commands.

See [What changed](CHANGELOG.md) for versioned FOX increments and the
[release policy](docs/release-policy.md) for source, verification and deployment
boundaries. FOX tags use `fox-v…`; the root CE repository has separate versions.

## Export-only preview — 17 November 2026

Patch 0.27.3 reduces repeated saved-output proof reconstruction for initial-direct
runs. On the same OCI host and retained input, two alternating samples per version
measured a median **14.88 seconds before / 2.53 seconds after** (82.99% reduction).
This measures one saved-candidate step, not complete UI loading, model inference
or total conversion. Proof outputs and original files were identical. Reuse ends
with the read operation; owner/source checks and offline validation still run.

Patch 0.27.2 keeps the download action near the package summary and collapses long
omission lists by default, without removing any report content. An isolated
hosted 0.27.1 check has now prepared and downloaded a real retained Forms-derived
package through the UI. The exact whole downloaded ZIP passed connectionless
SQLcl validation; its native files and original run evidence were unchanged.
This is format-only acceptance, not public cutover or business acceptance.
The isolated 0.27.2 desktop/mobile check also passed, with all 366 report entries
available and the exact same package bytes downloaded without another preparation.

Patch0.27.1 gives saved-output GET checks a bounded90-second allowance after an
actual valid readiness request took28.9seconds and the30-second UI budget proved
too tight under concurrent work. This corrects premature UI aborts; it is not a
claim that backend computation became faster. Preparation remains bounded at
180seconds and unknown outcomes are checked through GET, not repeated POSTs.

FOX0.27.0 makes the default new UI conversion a downloadable **APEXlang ZIP**:
reviewed design -> deterministic native rendering -> SQLcl `/nolog` format
validation -> package. No target database connection, schema creation, app import,
browser test or reimport is required by that delivery path.

The package includes declared compatibility, the generated MMD version, observed
SQLcl version, synthetic supporting SQL, import instructions and explicit gaps.
Format validation is separate from target import, runtime testing and human
business acceptance. The ordinary source-owner and AI-review checks remain.

For eligible older inactive runs, **Check saved APEX output** can prepare a new
format-only delivery from the retained approved design. It does not repeat model
calls, change the original run status or erase earlier failures.

Recorded AI-request timings are visible when available. Prepared OPAF calls avoid
two duplicated setup requests and can reuse one pinned TLS connection per role.
Direct OCI already reuses its SDK client; no cloud model-latency gain is claimed.

Local API/browser scenarios and real connectionless compiler checks have passed;
the isolated hosted saved-design download path has also passed. Fresh new-mode
hosted generation and customer installation remain separate acceptance scopes.
Existing public routing is unchanged. Oracle Forms, Java and SQLcl are external
prerequisites, and the current operator setup still supplies provider/compatibility
profile metadata. A fresh customer installation is not yet established by these
checks. See [export-only packages](docs/export-only-packages.md).

## Historical direct OCI preview — 16 November 2026

FOX0.26.0 adds direct OCI Generative AI design and independent review to the
existing prototype flow. OPAF remains optional. See the [direct preview guide](docs/direct-oci-preview.md)
for configuration, external prerequisites and offline packaging.

This was an isolated-preview implementation. It did not resume the cleared
OPAF deployment work or authorize public cutover. The first hosted real-FMB
acceptance run was in progress at that checkpoint. Its import/runtime work is
now optional; it does not gate0.27 format-only delivery.

The package has passed a clean offline dependency installation and API startup
smoke check without old operational history. That check is not a completed
Oracle conversion or a fresh customer-target installation.

## Historical OPAF checkpoint — 16 November 2026

The following records the preceding OPAF line. Its active-work statements are
historical and do not govern the isolated direct OCI preview.


**Development preview, not a ready end-to-end migration product.**

In plain terms: one approved real Forms module has produced a native APEX
prototype and server-side SQL export, with explicit omissions and synthetic data.
The user-facing finish is still incomplete: successful FOX UI download and a
fresh application import of those exact downloaded bytes are not yet proven.
The converter/deployment goal is **active**. Source 0.25.0 added an explicit,
source-backed check option. Patch 0.25.1 corrects a startup dependency-list defect
found before activation; deployment and live acceptance remain separate.

| Item | Last verified state |
| --- | --- |
| Current software source | 0.25.1 startup dependency correction, retaining the 0.25.0 source-check feature and preceding download fixes. Source publication does not imply activation. |
| Hosted lab | 0.24.0 remains online. Preparation and runtime workers are held for the guarded upgrade; the strict-output verifier is stopped. The download defect below prevents declaring the full user journey ready. |
| Real hosted conversion | The original real-FMB run continued through the UI with explicit query omissions. Mapping/review, SQLcl validation, synthetic schema, new application import, authenticated runtime checks and SQL/APEXlang export completed. Business acceptance remains separate. |
| New source increment | Discover one supported check from the exact source button, approve its limited scope and generate a separate native APEX check. Original actions remain explicit remediation. Existing runs cannot be silently upgraded. |
| Deployment checkpoint | Both 0.25.0 images and stopped replacements are preserved, but that bundle must not be activated because its exact startup-loader path fails locally. A corrected 0.25.1 bundle is prepared offline for the existing registered APEX 26.1.6 profile. Cloud images, installation and cutover remain pending; hosted FOX still serves 0.24.0. |
| Known download defect | FOX expects a boolean where the required-input runtime contract returns a typed status string. The unchanged retained package passes the locally tested correction, but the hosted UI download remains blocked until a coherent patch is deployed. |
| Local verification | The corrected release passes 327 targeted clean-source startup/preservation/package tests, with two existing skips; all six new closed-startup cases run. Earlier source-check API/browser and connectionless SQLcl evidence applies to unchanged conversion code. None proves this release's live Oracle runtime or cutover. |
| Source-derived behavior | Earlier native create/edit and required-input rejection were observed with synthetic data. The new saved-row check is implemented and locally compiled, but actual Oracle fixture/runtime proof remains pending. Human acceptance and full legacy parity are separate. |
| Full real-module acceptance | Still pending: hosted UI download, fresh-ID import/runtime verification of the exact downloaded SQL bytes, and the source-derived business-action proof above. Three-run repeatability follows separately. |
| Development work | Active, explicitly resumed. The next checkpoint is the connected hosted flow and its exact downloadable SQL, not a test-count milestone. |

### What the recent versions actually changed

Categories added retrospectively on 15 November 2026; existing commits and tags
are unchanged. These labels describe the change, not its deployment status.

| Version | Category / scope | Practical change | Available in the hosted lab? |
| --- | --- | --- | --- |
| 0.24.0 | `[feature]` conversion flow | Continue the same run after explicitly accepting the supported query omissions. | Yes; not proof of complete business conversion. |
| 0.24.1 | `[fix]` output + operations | Correct the draft-download check and preserve completed results during upgrade. | No; included in the pending 0.24.3 package. |
| 0.24.2 | `[fix]` operations | Accept the two valid stored JSON formats without altering original evidence. | No; included in the pending 0.24.3 package. |
| 0.24.3 | `[maintenance]` operations | Increase the bounded backup allowance so retained history can be preserved. | Prepared, not activated. No new converter capability or measured speedup. |
| 0.25.0 | `[feature]` conversion + UI | Select a source-supported check and generate it as a separate native APEX action, with explicit partial scope. | Not yet. Local implementation/compilation is separate from live acceptance. |
| 0.25.1 | `[fix]` startup | Include the new renderer dependencies in the strict startup checker that preserves earlier prototypes. | No; corrected source and offline lab-target bundle are prepared. |

The active delivery priorities are: make the real run's
**Download APEX** path work in hosted FOX; prove those exact SQL bytes import and
run as a separate application on the declared target; then close the remaining
source-derived action gap. Testing supports each change. UI refinements and
measured performance work follow concrete user-flow bottlenecks, not test counts.

### Optional source check in 0.25.0

When creating a new prototype, choose **Find source checks**. FOX shows the source
file, module, block and button for a recognized check. Select one and approve its
partial scope, or explicitly continue without it. A refreshed or failed lookup
cannot silently remove your intended check and start conversion.

The first supported pattern checks saved synthetic detail rows for missing or
zero numeric values. The generated APEX button performs that check only. It does
not approve a record or reproduce the remaining original action. Negative nonzero
values, an empty grouping value and no matching rows pass this isolated predicate;
unsaved Forms data and later rules remain outside its scope. FOX requires the
new profile's passing and rejected runtime cases before releasing its export.
This source capability is not yet a hosted availability or business-equivalence claim.

Version 0.23.0 addresses the normal schema-index file rejected by the earlier
startup collector and the global admission rule that held up new projects behind
unrelated stopped runs. The new route preserves old failures and asks the converter
for a fresh read-only protocol observation. It does not restart old imports or
change their status to make a new project pass. Actual hosted acceptance of the
new route has reached real hosted raw intake and mapping on 0.23.2, not a completed export.

Version 0.23.1 corrects the startup observer's attribution of the two normal
service launchers. It does not exempt the Forms worker or bypass idle checks.
Version 0.23.2 registers a reader missing from the protected startup manifest
and tests that exact loader path. Neither fix is proof of a completed conversion.
The separately versioned [deployment tools](deployment/CHANGELOG.md) now allow
bounded HTTPS warm-up without changing the frozen 0.23.2 application bundle.

Version 0.24.0 offers **Continue with query omissions** when a saved mapping
incorrectly asserted a redacted filter and ordering as proven facts. It keeps the
same run and original response, states what is not implemented, requires explicit
approval, and sends the derived partial design to an independent reviewer. It
does not guess masked values, bypass technical checks or represent a complete
business conversion. See [query omission continuation](docs/query-omission-continuation.md).

The lab reference target is **APEX 26.1.6 with SQLcl 26.1.2.0**. This is not a
compatibility guarantee for another database, APEX patch or customer tenancy.
The exported package must still prove import on its declared target.

Use the [current user guide](docs/fox-user-guide.md) for implemented routes and
the [roadmap](docs/product-roadmap.md) for intended outcomes. The historical
milestones below are dated implementation context, not the current deployment.

```text
Project → Upload/prepare → Resolve gaps → Process → Native APEX output
                                              → Technical checks
                                              → Human business review
```

Generated output, technical verification and human business acceptance are
separate. Complete source evidence does not guarantee equivalent business
behavior. Missing definitions and unsupported constructs are explicit findings;
FOX must not invent keys, omit selected forms silently or guess human meaning.

For an early demo, **Partial draft / demo** previews the supported subset and
requires explicit acceptance of omitted behavior. It saves a separate source
version, retaining the originals. The ordinary technical checks still apply.
After they pass, **Download development draft** lets users continue in native
APEX without recording business acceptance. Read [partial drafts and their
limits](docs/partial-drafts.md); a source release is not a hosted demo-readiness claim.

The [product and UI roadmap](docs/product-roadmap.md) defines the feature goals,
user journey and acceptance criteria. These are targets, not released features.

## Development status

Start with the [current user flow](docs/fox-user-guide.md),
[server-side FMB preparation](docs/server-side-fmb-preparation.md),
[generated prototype output](docs/generated-prototype-output.md), and
[saved-review correction](docs/review-scope-correction.md). These describe the
implemented routes and their boundaries, not a guarantee that every deployment
or Forms application has passed them. See the changelog for each source version.

### Historical implementation milestones

Source **0.8.0 adds prepared redacted Forms intake and prototype workflow UI**.
One approved real module passed local authenticated upload/assessment with its
exact source hash and all 71 code units retained. In Upload, choose **Open prepared
prototype intake**, then provide redacted XML and matching redaction receipts.
Uploading does not invoke AI. Technical identifiers remain visible; receipts do
not establish complete anonymization or permission to process customer code.

Prototype processing is separately configured and is not activated automatically.
At the 0.8.0 milestone, hosted deployment and full-flow acceptance were pending.
For today's distinction between source, lab deployment and remaining acceptance,
use the checkpoint above. See [prepared prototype intake](docs/prepared-prototype-intake.md).

Source **0.7.0 introduced an inactive conversion-engine preview**, not a completed
hosted conversion release. It adds source-bound OPAF design/review contracts,
effective-property derivation, conservative redaction, and native multi-block
prototype rendering. These helpers do not enable a new end-to-end UI route.
See the [checkpoint, verification and remaining work](docs/conversion-engine-checkpoint.md).

Source 0.6.0 introduced [broad local Forms assessment](docs/broad-local-assessment.md):
FMB/XML with multiple blocks and ordinary business SQL can receive a complete
local object inventory without starting generation or AI submission. The UI
keeps observed facts separate from OPAF understanding. The broader OPAF design
and native generator remain in development; the narrow generation profile below
still applies to that older path.

This is experimental source, not an Oracle product, Support commitment or
production migration factory. The multi-form implementation and local tests
are ahead of the deployed lab release. A new host's fully connected installer,
runtime admission and shipped end-to-end acceptance remain unfinished. A
passing local test is not a validated customer conversion.

The local Windows route provides preparation and assessment, not connected
APEX generation. Connected development currently uses the explicitly guarded
JSN lab adapter. Non-secret target identifiers/guards in that adapter are
reference scope, not portable customer defaults or credentials. Do not change
them to bypass a failed gate or point a demo at production.

## Linux setup preview

Run `bash scripts/install-fox.sh` from this product folder as a nonroot
operator. It checks/prepares a private pinned Python runtime with download
consent, then opens the loopback setup wizard. It prepares storage and protected
access/OPAF inputs for the registered JSN test target, not connected services or
customer onboarding. Read the [managed setup runtime guide](docs/managed-setup-runtime.md)
before use. `--inspect` checks that runtime without downloads or file changes.

## Supported conversion profile

The initial native profile supports a narrow synthetic prototype: reviewed
table-backed forms, explicit supplied keys, deterministic report/form pages,
search and insert/update behavior. It composes selected modules into one app
and records source/page/storage traceability. Unsupported libraries, triggers,
LOVs, reports, external calls and web/Forms behavior need evidence and an
explicit remediation decision. It is not a universal Forms transpiler.

Only redacted readable source is sent for approved AI processing. Oracle Forms
tools remain necessary to authoritatively convert raw FMB/MMB/OLB/PLL modules.
No Oracle installer, wallet, private key, customer source or production record
is part of this source distribution.

## Components

The [dependency-guidance source/UI slice](docs/dependency-guidance.md) explains
the current object-level call path, missing-package-part actions and declaration
checks. It includes the tested boundaries and remaining conversion/deployment
work; source presence must not be confused with translated business behavior.

The [precheck recovery component](docs/precheck-recovery.md) distinguishes a
stopped pre-QA attempt from successful verification. Its source and isolated
rehearsal do not constitute an installed live recovery command or release.

- `fox/`: React/TypeScript UI and Python API, preparation and persistent jobs.
- `converter/`: internal MCP tools, deterministic native generation, validation
  and guarded import/export.
- `qa/`: developer-only operator, clean-import, runtime and integrity checks.
- `scripts/`, `tools/`, `deployment/`: setup/build checks and guarded development
  adapters. A source helper is not an activation command.
- `fox/skills/fox-install/`: optional Codex installation assistance, not a runtime
  dependency or authority to deploy a customer environment.

Start with [installation](docs/fox-installation-v1.md),
[user flow](docs/fox-user-guide.md), [architecture](docs/architecture.md) and
[operations/support boundaries](docs/operations.md). The root CE skill's
`install.py` does not install these components.

Developer checks are documented in [verification](docs/verification.md).
Development model selection, thinking effort and handoffs are documented in
[developer orchestration](docs/development-orchestration.md). Those models assist
development; they are not FOX's embedded OPAF runtime models.
Read the [lab-adapter boundary](docs/lab-adapter.md) before considering any
connected deployment/operator code. Third-party distribution limits are in
[THIRD_PARTY.md](THIRD_PARTY.md).

## Source and safety

The original CE repository content and public history are preserved. FOX source
is maintained here without importing the former private Git history. Credentials,
live private state, run outputs and historical deployment attestations are not
source prerequisites and must not be committed to make a test pass.

Use inferred stubs and synthetic records only for the POC; do not connect to a
legacy production database. APEX output is importable only against its declared
compatible target after the required validation/import checks. Human review
remains responsible for business acceptance.

Repository license and trademark terms remain in the root `LICENSE.txt` and
README. Oracle tools and third-party dependencies retain their separate terms.

## Following updates

Every pushed FOX update must have a changelog entry, including documentation-only
changes. Software changes use versioned entries and immutable `fox-v…` tags;
documentation-only entries do not relabel the application or deployed images.
See [historical source updates](docs/historical-changelog.md) for retrospective
entries added on 14 November 2026 using the original Git-recorded dates.
