# FOX: Form to APEX

FOX is a development preview for Oracle Forms modernization. One project groups
related Forms modules, with one native APEX application/export as the intended output.
The web UI manages multiple projects, source versions, conversion runs, findings
and result review. Business users do not need Codex, prompts or QA commands.

See [What changed](CHANGELOG.md) for versioned FOX increments and the
[release policy](docs/release-policy.md) for source, verification and deployment
boundaries. FOX tags use `fox-v…`; the root CE repository has separate versions.

**Have one .fmb?** On a hosted installation with Forms preparation enabled,
choose **New project**, give it a name, then select the file and click
**Prepare FMB**. FOX checks extraction status on the server. Review the result
and choose **Next**. FOX saves the prepared source to the project for you.
Check the single local-processing and partial-output confirmation, then choose
**Generate APEX package**. No redaction-mode selection is needed in the hosted
export workflow. A blocked preparation explains why you cannot continue.
Open **APEX output** for the ZIP and a list of what was not converted. The ZIP
is a format-validated APEXlang project, not a conventional APEX SQL export.

**Saved exports (0.38.2 source):** downloading a completed XML-mapping package
checks its original source, ZIPs and compiler evidence without re-running today's
Forms parser on that saved run. New conversions still use the current parser.
This is a local artifact-reader change, not a change to conversion coverage or
a hosted rollout. See [export recovery and the proposed OCI storage design](docs/export-durability.md).

## Parent-child context and assignment encoding - 19 November 2026

Private preview 0.34.0 is verified through a fresh browser generation/download
round. It reports two read-only relation views and two unwired assignment rules
without inflating converted code-unit counts. Public deployment is unchanged.

Version 0.34.0 adds [source-linked record context](docs/record-context-mapping.md):
manual filtered detail pages derived from explicit Forms relations, preserving
existing calculations and validation links. It also emits source-bound before-
insert/update value-copy procedures as review code, without claiming event wiring.
The website reports these separately from converted code units. See the changelog
for actual deployment and acceptance status.

## More business mappings and specific gap explanations - 19 November 2026

At the earlier 0.33.0 checkpoint, its browser run reported four
generated/adapted units and 49 explained gaps, while the previous download remains
unchanged. Public deployment is unchanged.

Version 0.33.0 adds [local comparison function/formula mapping](docs/business-comparison-mapping.md),
including concatenation and explicit control-session inputs. Helper bodies are
counted once only when a supported caller is generated. The package and website
explain each unconverted unit as an engine mapping/context gap, a positively
identified missing definition, or a review need. Historical completed packages
retain their original source/catalog/compiler proof across library upgrades.

The retained-source candidate increases from two to four generated/adapted code
units. Other business workflows remain unfinished; generated and format validated
are still distinct from target execution and business acceptance. See the changelog
for actual deployment and acceptance status.

## Earlier private web checkpoint: 0.32.1 - 19 November 2026

At the earlier 0.32.1 checkpoint, an authenticated browser started one reusable
mapping run from retained original XML, restored it after reload and downloaded
the exact SQLcl-format-validated package. Desktop/mobile output checks passed.
The reporting patch preserved that same package and did not rerun conversion.
Public deployment remains unchanged. This verifies the website integration;
unsupported business behavior and target runtime testing remain separate.

## Reusable mappings in the project website - 19 November 2026

Version 0.32.0 connects the [XML mapping engine](docs/xml-mapping-engine.md) to
Convert and APEX output in the project website. Review the complete selected XML
source set and explicit partial/synthetic scope, confirm local processing, then
start a durable run. FOX reports generated and unsupported code-unit counts and
enables the source-bound package download after fresh SQLcl format validation.
This route makes no AI request and imports no database application. Existing
AI-assisted conversion remains separate. See the changelog for actual delivery
and acceptance status; source publication alone does not establish deployment.

## Reusable XML mapping engine - 19 November 2026

Version 0.31.0 adds a [direct XML-to-APEXlang engine](docs/xml-mapping-engine.md).
It uses installed, versioned mappings to produce native synthetic reports/control
pages and supported business behavior from fresh XML, without a prior AI job or
package. Multiple XML modules can share one generated application. A bounded
numeric expression parser expands formulas beyond the original CEIL pattern.

The operator CLI exposes the mapping catalog and produces complete source/object
and code-unit coverage. Unknown relationships, actions and dependencies remain
explicit. Database blocks default to read-only reports; no customer schema or
transaction behavior is inferred. Normal hosted web integration, deployment and
APEX runtime/business acceptance remain separate. Two public synthetic example
modules demonstrate reuse across different names and formulas.

## Source-linked business-rule generation - 18 November 2026

Version 0.30.0 adds an [operator CLI and library](docs/source-behavior-generation.md)
for two complete source patterns: a numeric CEIL report calculation and a numeric
nonzero guard with minimum validation and focus movement. It generates native
APEX components from original XML and an exact matching parent package, preserves
source evidence and records every unsupported unit. A derivative package passed
fresh local SQLcl format validation; target execution remains unverified.

This first slice is available through the operator tool. It is not yet connected
to the normal web generation action or deployed to the existing preview. The
validation page does not save changes, and the complete form remains unfinished.

## Verified private checkpoint — 18 November 2026

A retained preserved-source run completed Oracle XML intake, AI mapping/review,
native APEX generation, whole-package SQLcl format validation and authenticated
desktop/mobile package download. The private preview is verified on 0.29.6; the
public deployment remains unchanged. Original source and review evidence were
preserved, and the final compiler/UI steps made no new model calls.

This is a downloadable synthetic-storage prototype, not a claim that legacy
business code has been implemented. Review the package remediation before a
separately authorized target import and runtime/business testing. Saved-output
verification still takes several minutes; the longer UI wait is not a speedup.

## Saved-output verification wait — 18 November 2026

Patch 0.29.6 keeps the read-only output check open while retained evidence is
verified, with a bounded ten-minute wait and a clear status message. It reuses
the existing generated package. It does not restart conversion or change backend
validation, and it does not claim faster verification.

## Exact compiler completion — 18 November 2026

Patch 0.29.5 adds a bounded operator continuation for a fully reviewed design
whose items omit a screen link already fixed by their own source block. It
completes only those redundant links, preserves every original AI response and
review, and records a separate compiler derivation before the unchanged package
validators. No new AI call or business-behavior approval is introduced.

## Lossless proposal representation — 18 November 2026

Patch 0.29.4 preserves bounded long behavior proposals as ordered text segments
within the existing schema. Every character and UTF-8 byte is retained. The raw
response and source remain unchanged, and a new independent reviewer checks the
derived mapping. A bounded continuation reuses a captured fifth mapper while
preserving four approved sections and the prior provider-attempt proof. It does
not repeat completed calls or grant permission for an unknown-outcome retry.
See the changelog for verification and delivery status.

## Explicit one-attempt provider reconciliation — 18 November 2026

Version 0.29.3 adds a bounded operator action for one uncertain fourth-mapper
outcome. It requires explicit acknowledgement that the earlier call may have
completed or been charged. Approved sections and the original intent stay intact;
no automatic retry is introduced. The new attempt and remaining calls retain
private SDK response receipts before parsing, and download proof identifies the
new attempt separately. Failed or partial actions require reconciliation.
See the changelog for candidate, Linux, private and live acceptance status.

## Earlier opt-in provider component — 18 November 2026

An optional [private response receipt component](docs/provider-response-receipts.md)
retains bounded OCI replies before model-content parsing and provides explicit
read-only recovery. It also records safe SDK failure metadata without repeating
the call. Existing behavior is unchanged unless the caller supplies the store.
Local synthetic checks and independent review passed; production pipeline wiring,
Linux persistence and real-SDK verification remain separate. This is not enabled
on the active conversion or public service and does not recover earlier missing
responses. Schema-constrained generation is not introduced by this checkpoint.

## Combined reference compatibility — 18 November 2026

Patch 0.29.2 also handles an exact duplicate source-binding echo accompanying
selected chunk references. It preserves the original response and code, and
requires independent review of the derived candidate. A bounded follow-up keeps
the first two approved sections under their original V1 proofs while enabling V2
for the saved third mapping and remaining work. No completed call is repeated.
Unknown or mismatched bindings and semantic defects still stop processing.

## Exact source-reference compatibility — 18 November 2026

Patch 0.29.1 handles a mapper response that cites a selected code chunk instead
of its exact source unit. The correspondence must be proven from original bytes
and the same source owner; code and claim text stay unchanged. Independent review
still checks the resulting proposal. A bounded continuation preserves a completed
first mapper rather than starting the application conversion again. Other or
combined defects remain explicit reconciliation needs. See the changelog for
source, private acceptance and public deployment status.

## Development-source APEX generation — 17 November 2026

Version 0.29.0 connects preserved development XML to **Generate APEX package**.
Upload an FMB for Oracle extraction, add its reviewed XML to the project, review
the prototype scope, select the code units and approve processing without
redaction through the configured AI provider. Mapping and independent design
review feed the native renderer and offline SQLcl validation before download.

The new approval is bound to the exact source, preparation mode, selected code
and destination. It does not relabel old masked-source approvals or restart old
jobs. Original code and business literals remain unchanged. Existing uncertain
provider outcomes require reconciliation, never an automatic repeat.

The generated package remains a synthetic-storage development prototype. General
PL/SQL behavior, missing APIs/libraries and unsupported features stay visible as
remediation; AI analysis is not a claim of executable business equivalence. Source
release and private acceptance are distinct from public deployment. Public FOX
remains 0.27.4. The private preview serves 0.29.0; fresh real-input provider
acceptance for this mode is still pending. See the changelog for verified checks.

## Development-source preparation — 17 November 2026

Version 0.28.0 adds an explicit **Preserve development source** preparation mode.
Oracle Forms-to-XML remains inside the hosted preparation flow. Original native
XML is retained, and normal business literals are preserved. Possible credentials
produce review locations and private XML downloads; correct the original source
and upload a new request before adoption. Zero findings still requires review.

Clean development XML can be added to project history for analysis. At the 0.28.0 milestone, AI conversion
for this mode was not enabled; 0.29.0 above adds a separate explicit processing contract. Existing masked preparation and historical jobs keep their original meaning.
See [hosted preparation](docs/server-side-fmb-preparation.md) for the modes and
boundaries. Actual private-preview upload/extraction, XML downloads and analysis
adoption passed on 0.28.0, retaining all 56 original non-empty code fields. No
provider submission or database operation ran. Source publication does not promote
the public service, which remains 0.27.4. The 0.27.5 checkpoint below describes its
earlier verified output behavior.

## Export-only preview — 17 November 2026

Patch 0.27.5 adds grouped, searchable findings with the supplied next actions and
qualified source references, preserving every original record and package byte.
It also reuses identical source parsing within the existing initial-direct saved
read scope. A same-host/input comparison against published 0.27.4, three samples
each, measured saved-candidate median **2.38 seconds before / 1.14 seconds after**
(51.99% reduction). This is a component result, not total UI or model time.
The private-preview browser check passed with all 366 findings and identical
package bytes. Observed readiness was 17.19 to 2.39 seconds, output visible 23.96
to 4.64 seconds, and download 4.88 to 2.26 seconds. These individual UI observations
also include the inherited 0.27.4 export-mode guard removing an unnecessary legacy
validation request; they are not an isolated cache or model-inference benchmark.
The public service remains 0.27.4. No source-intake policy, provider submission,
target import or public rollout was changed by this increment.


Patch 0.27.4 supports an explicitly configured HTTPS public origin behind an
existing reverse proxy, without exposing a new listener or inheriting database
credentials. Export-only sessions hide unavailable legacy runtime recovery
actions; existing history and saved package output remain visible. Promotion
requires a preserved public store, unchanged owner credentials, queue migration
and separate live acceptance. A source release alone does not switch a public site.
The authorized existing-instance promotion has now passed real HTTPS login and
desktop/mobile checks. Its original login, 15 projects, 28 sources, 12 runs and
prepared upload queue were retained. No new conversion was run during promotion;
the separate private-preview demo project was not merged into the public store.

Patch 0.27.3 reduces repeated saved-output proof reconstruction for initial-direct
runs. On the same OCI host and retained input, two alternating samples per version
measured a median **14.88 seconds before / 2.53 seconds after** (82.99% reduction).
This measures one saved-candidate step, not complete UI loading, model inference
or total conversion. Proof outputs and original files were identical. Reuse ends
with the read operation; owner/source checks and offline validation still run.
The final private-preview UI check passed with the same downloaded package.
Observed readiness was about 18.0 seconds versus 45.5 seconds on the prior build;
download was 4.9 versus 30.2 seconds. These individual runs are not guaranteed
response times. At that 0.27.3 checkpoint the public service had not been switched;
the subsequent 0.27.4 promotion is recorded above.

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
The 0.27.4 promotion reuses the existing public address and reverse proxy.
Oracle Forms, Java and SQLcl are external
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
