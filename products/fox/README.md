# FOX: Form to APEX

FOX is a development preview for Oracle Forms modernization. One project groups
related Forms modules, with one native APEX application/export as the intended output.
The web UI manages multiple projects, source versions, conversion runs, findings
and result review. Business users do not need Codex, prompts or QA commands.

See [What changed](CHANGELOG.md) for versioned FOX increments and the
[release policy](docs/release-policy.md) for source, verification and deployment
boundaries. FOX tags use `fox-v…`; the root CE repository has separate versions.

## Current checkpoint — 15 November 2026

**Development preview, not a ready end-to-end migration product.**

| Item | Last verified state |
| --- | --- |
| Current software source | 0.23.2; see the versioned changelog. Publication does not imply activation. |
| Hosted lab | 0.22.8. This documentation update does not poll or change the running service. |
| Hosted candidate state | The 0.23.1 attempt stopped at a protected startup check. The 0.23.2 source-registration fix needs a new coherent deployment. |
| Local verification | Fresh-admission, converter-isolation and startup/metadata suites passed with the limitations recorded in the changelog. This is not live conversion acceptance. |
| Full real-module acceptance | Still pending: authenticated runtime behavior, conventional APEX SQL download, exact-byte fresh-ID reimport, and three repeatable recorded runs. |
| Development work | Active, focused on one real FMB reaching a proven SQL download and fresh-ID reimport. Broader repeatability/polish follows separately. |

Version 0.23.0 addresses the normal schema-index file rejected by the earlier
startup collector and the global admission rule that held up new projects behind
unrelated stopped runs. The new route preserves old failures and asks the converter
for a fresh read-only protocol observation. It does not restart old imports or
change their status to make a new project pass. Actual hosted acceptance of the
new route is still pending; the last verified hosted version remains 0.22.8.

Version 0.23.1 corrects the startup observer's attribution of the two normal
service launchers. It does not exempt the Forms worker or bypass idle checks.
Version 0.23.2 registers a reader missing from the protected startup manifest
and tests that exact loader path. Neither fix is proof of a completed conversion.

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
