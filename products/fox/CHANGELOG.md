# FOX changelog

FOX software versions use `fox-v<major>.<minor>.<patch>` Git tags, separate from
the CE repository's tags. A source release is not proof of deployment or a
successful conversion. See [release policy](docs/release-policy.md).

Independently pinned deployment-only corrections have a separate
[deployment-tool changelog](deployment/CHANGELOG.md); they do not change the
application version or relabel existing images.

## [0.22.0] - 2026-11-12

### Preserve required inputs in native APEX forms

- New prototype runs opt into a source-bound input policy: an explicit Forms
  Required property becomes native APEX value-required validation on supported
  editable database fields. Existing NOT NULL checks remain effective; synthetic
  database nullability is unchanged. Noneditable and unsupported items remain
  remediation work rather than silently becoming mandatory fields.
- Preserve the original renderer and all existing saved-run contracts. Old runs,
  retries and continuations do not silently adopt the new policy. Reject unknown,
  malformed or mismatched policies and renderer profiles.
- Carry the selected profile through package checks, recovery, runtime evidence,
  export and the paired application payload. New-run UI submission opts in while
  retaining the existing explicit consent and independent review gates.
- Add a developer-only runtime probe for missing required input. Its browser
  check exercises client-side rejection; it does not establish server-side
  rejected-write behavior or Forms transaction equivalence.

Verification: the source planner suite passed 285 tests; renderer integration
passed 677, with a further 62 browser-adapter tests and 10 Node tests. Packaging
and package checks passed 118 with 10 skips; isolated payload checks passed 4;
recovery/context checks passed 28. All 13 local UI browser scenarios passed with
mocked APIs. Suites overlap and are not a count of unique end-to-end scenarios.
Historical fixture failures and an initial malformed-package regression were
retained; the regression was fixed and retested. Independent source review cleared
this bounded change.

A developer-authored structural candidate from one real, Oracle-extracted Forms
module contains three native form blocks and six source-required inputs. Its
exact APEXlang ZIP passed SQLcl 26.1.2 validation without a database connection.
This is not an OPAF-reviewed mapping, hosted conversion, import/runtime proof,
clean-package reimport, complete business-logic translation or human acceptance.
Publication does not activate the feature on an existing installation.

## [0.21.6] - 2026-11-12

### Read standard radio-button and required-field metadata

- Recognize Oracle Forms RadioButton objects rather than rejecting an otherwise
  readable module during local redaction. Keep scoped names, IDs and locations.
- Preserve explicit boolean Required properties for subsequent conversion work.
  RadioButtonValue remains masked; no private option value is inferred.
- Keep existing XML namespace, inherited/default-property, DSC identity and
  source-permission boundaries unchanged. Oracle ALL output remains provenance
  evidence, not a substitute for the normal OVERRIDDEN source export.

Verification:900 relevant tests passed,12 were skipped, and9 subtests passed.
The39 new cases had35 failures before the fix and all passed afterward. Two
real Oracle-validated OVERRIDDEN exports passed the updated local redaction,
facts and source-packet path; one contained9 radio buttons. One code unit in
that larger module was withheld by redaction rather than reconstructed.

These are local intake results, not hosted extraction, generated APEX, native
radio/Required validation behavior, import/export or business acceptance.

## [0.21.5] - 2026-11-11

### Back up larger retained development histories

- Increase the bounded upgrade snapshot capacity from 20,000 to 25,000 entries
  and from 128 MiB to 160 MiB. This accommodates retained development history
  without deleting previous evidence or adding infrastructure.
- Keep the 64 MiB member limit and 8 MiB manifest limit unchanged, together with
  archive integrity, unsafe-path, link, SQLite and isolated-restore checks.
- Continue to reject snapshots above the new limits. Every deployment still
  requires its own fresh capacity measurement and successful backup/restore.

Verification: all 33 snapshot tests passed on Linux. Across normal and isolated
rootless Linux runs, 57 of 60 hosted-snapshot scenarios passed; three opt-in
Podman launcher scenarios were not run. Coverage includes exact-capacity and
overflow rejection, streaming archive membership, private ownership, links,
SQLite/WAL preservation, and actual synthetic capture/isolated restore. Windows
checks passed with POSIX-only skips. An initial wrong-checkout namespace run was
preserved and excluded; the corrected run verified the exact source path/hash.

These are local tests, not proof of a successful live upgrade, APEX conversion,
downloaded-package import or business acceptance. Existing frozen releases and
historical evidence remain unchanged.

## [0.21.4] - 2026-11-11

### Preserve stopped validation history during upgrades

- Add a distinct maintenance-only check for a stopped validation request whose
  claim is retained but whose validation has not completed. Preserve original
  continuation/event/attempt, request, snapshot and generated ZIP bindings.
- Use paired read-only collection and actual retained transition provenance
  during upgrade and startup. The existing unclaimed path remains separate.
- Keep ordinary admission blocked and retry unavailable for unresolved work.
  Preservation is not model execution, validation, import or business acceptance.

Verification: all 16 focused Linux tests passed, including the complete synthetic
claimed-history path, rejection matrix, real SQLite selection/consent changes,
record/attempt mutations and final paired-tree preservation. Startup provenance
uses modeled external observations. All five measured code/test files retained
their exact hashes; one new synthetic import-time database was accounted for.

The separate Windows fast batch had 212 passes, three failures caused by absent
legacy profile fixtures and one skip; it is not claimed as an entirely passing
suite. Windows historical-fixture diagnostics ended in a native interpreter
failure, so the complete focused proof was performed on Linux. Original failed
evidence remains retained. No installed upgrade, live validation, import/export
or business acceptance is claimed, and no consumed attempt may be replayed.

## [0.21.3] - 2026-11-11

### Retain export files in writable storage

- Create private export attempts under the existing persistent jobs directory,
  rather than requiring its protected parent to be writable.
- Keep failed or uncertain export files for inspection. No cleanup, automatic
  replay, permission change or unverified package publication is introduced.
- Preserve the existing application/runtime identity, SQLcl validation and
  exact-byte checks. Export scratch is not a dispatchable job and remains
  included in backup inventory.

Verification: 125 relevant local tests passed, including six focused export
cases that failed against the old path and passed after the fix. Tests exercised
real persistent directories and snapshot/queue readers with modelled SQLcl and
browser responses. This is not live Oracle export, clean-install or business
acceptance proof. The stopped real validation claim still requires separately
verified preservation and recovery; this source release does not authorize retry.

## [0.21.2] - 2026-11-11

### Prepare validation files and reuse saved checks

- Use a private system temporary directory for APEX validation. A writable jobs
  directory no longer requires its parent to be writable too. Keep the exact
  retained ZIP, extracted-tree checks, validation log and receipt requirements.
- Keep overlapping read-only epoch, review and model-proof checks inside the
  existing operation-local proof scope during converter-phase reconstruction.
- Preserve exact source-file entry/exit checks and fresh owner, selection,
  target and consent checks. Reuse ends before external execution.
- No persistent cache, cached processing permission, new model call or
  automatic retry is introduced.

Verification: 54 existing FOX regressions, 128 converter tests and the focused
fresh historical-checkpoint test passed. The scratch-path regression failed
before the fix and passed after it. In the synthetic checkpoint comparison,
container-proof computations fell from 21 to 2 and derivations from 12 to 1;
the typed phase, retained files and model-call count were unchanged. Source
mutation and changed owner, consent and target were rejected. The measured
phase took 49.29s before and 9.81s after, excluding fixture preparation; this is
not a live conversion speed guarantee. Existing dependency warnings and a
JUnit property-format warning remain.

These are source-level checks, not proof of deployment or a successful real-file
APEX import/export. Existing consumed validation attempts remain preserved and
still require explicit reconciliation; this release does not authorize replay.

## [0.21.1] - 2026-11-09

### Correct existing-host upgrade admission

- Match the existing hosted container roles: the FOX root filesystem is
  read-only; the converter uses its approved writable root filesystem.
- Require the converter's exact existing jobs bind mount instead of an
  unrelated parent directory. No container setting or mount is changed.
- Retain identity, image, process, unchanged-configuration and paired-job
  preservation checks. This correction grants no conversion retry or import.

39 focused tests and 165 relevant regressions passed; 12 POSIX-only checks were
skipped on Windows. The broader historical suite could not pass without its
private legacy fixtures and is not included in those pass counts.
Local modeled checks cover both approved role configurations and reject changed
paths, mount types, access modes, identities and post-read evidence. These tests
are not proof of a successful hosted upgrade or conversion. The failed 0.21.0
upgrade and its original evidence remain retained; deployment and the real-file
validation/import/export path require separate live verification.

## [0.21.0] - 2026-11-09

### Continue validation of a saved draft

- Offer **Continue validation** when a reviewed draft is retained and the
  converter proves that validation has not started. Reuse the same run and its
  exact approved model outputs; require fresh owner confirmations.
- Keep the original intent and failed handoff. Bind the new continuation to the
  saved source, target, draft, reviews and converter state, then make one exclusive
  first validation claim. Unknown responses never trigger an automatic repeat.
- Show clear recorded/pending states and operator guidance when reconciliation
  is required. Reject stale project/source responses and hide unrelated XML
  intake controls while reviewing this saved-draft action.
- Cache only bounded pure reconstruction work within a single read scope.
  Current owner, source and target permissions remain freshly checked.
- Align trusted validation waits with SQLcl and authorization budgets. These
  are socket waits, not a guarantee of total completion time.
- Use the existing prototype source-snapshot reader consistently, fixing a
  later 2 MB checkpoint limit that rejected already-admitted larger sources.
- Preserve recognized stopped pre-validation history during upgrades only after
  independently checking both retained job trees and current runtime identities.
  Maintenance preservation grants no retry or processing permission.

Local verification covers same-run continuation, exact ZIP download, missing or
changed proof, concurrent submissions, unknown responses, source/project switches
and legacy compatibility. Provider, database and browser outcomes in backend
integration fixtures are simulated. A passing local test or source release does
not prove the hosted application has completed conversion.

SQLcl validation, unique import, authenticated runtime checks and exact export
remain required. A recorded continuation in ATTENTION still needs operator
reconciliation. Business acceptance, clean-schema portability and customer-target
compatibility are separate outcomes.

## [0.20.1] - 2026-11-09

### Reduce repeated checks when resuming

- Reconstruct the exact already-reviewed prefix together when continuing a
  saved mapping. Its validated continuation record, frontier and proof hashes
  determine the boundary; file presence alone is not enough.
- Keep every source and review check. Missing, negative or changed evidence
  stops processing instead of falling back to another model call.
- Close the bounded read-only scope before new work. Fresh owner, consent,
  source and target checks remain in the existing execution path; no persistent
  cache or cached processing permission is introduced.

111 targeted tests passed. A read-only synthetic benchmark reconstructed all
14 authorized retained views in 4.99 seconds with unchanged proofs/files and
no provider or database operations. This is not a live latency guarantee.
Source publication does not change an already-running conversion or prove
deployment, APEX output, or business acceptance.

## [0.20.0] - 2026-11-09

### Review corrected mapping format and continue

- Add a source-bound format policy for an exact repeated binding field and two
  Item metadata kind aliases. Values, evidence, statuses and business behavior
  are unchanged; mismatched or unsupported facts still stop processing.
- Preserve successful legacy owner/context handling. Original model responses
  remain immutable, with separate normalization evidence and fresh independent
  review of the resulting candidate.
- Offer **Review corrected format and continue** for an eligible saved mapping.
  Show reviewed sections, the saved mapping and unstarted work; lock the original
  selection and require three fresh processing confirmations. Duplicate and
  uncertain requests do not automatically queue another attempt.
- Materialize only deterministically derived review artifacts under a separate
  same-run continuation authorization. Do not reset consumed repair records,
  create another mapping epoch or regenerate completed mapping calls.
- Separate protected maintenance preservation of recognized, closed provider
  history from ordinary conversion admission. Preservation grants no review,
  retry, processing, import or business-acceptance authority. Unknown work and
  Oracle-stage artifacts remain blocking.

The format policy does not repair missing business logic or invent source facts.
APEX validation, unique import, runtime verification and exact export gates remain
required. Source publication, deployment, completed conversion and human business
acceptance are separate outcomes.

Local checks cover source-bound normalization, retained-result authority,
duplicate/invalid requests, and an exact ZIP downloaded through FOX using authored
model, SQLcl and browser replies. The UI suite passed 22 checks and TypeScript
checking passed. A read-only check against the retained real job confirms the
continuation plan without adopting it or calling a model/database operation.
These checks are not proof of a completed live conversion.

## [0.19.1] - 2026-11-08

### Preserve completed review failures during upgrades

- Recognize the bounded, sealed post-correction negative-review state as stopped
  work that can be preserved during a software upgrade. Earlier terminal
  classifications retain their existing rules.
- Recheck original history, correction authorization and event, contiguous
  completed independent reviews, and the final result/history/publication.
  Historical reads do not replace or rewrite the physical current result.
- Keep active repairs, pending or orphan calls, unexpected files and Oracle-stage
  artifacts blocking. The retirement reader independently checks the terminal
  classification rather than trusting its label.
- Grant no retry, review approval, application import, conversion success or
  business acceptance through this classification.

This patch changes upgrade preservation, not the generated APEX format or the
conversion's required independent-review and deterministic-validation gates.
Source publication does not establish deployment or a completed real conversion.

## [0.19.0] - 2026-11-08

### Recognize saved Forms column names and continue

- Read direct `DSCName` metadata from the exact saved source when older facts
  omitted a DataSourceColumn name. Preserve historical source and object IDs;
  reject ambiguous, conflicting or unsupported identity metadata.
- Offer **Review recognized names and continue** for the bounded eligible
  retained stop. Project only missing-name explanations, not dispositions,
  business behavior or SQL. Each changed candidate requires a fresh independent
  review; completed mapping calls and original negative results remain intact.
- Show unchanged reviewed sections, mappings needing fresh review and sections
  not started. Require the displayed processing confirmations and reconcile
  recorded or uncertain submissions rather than automatically repeating them.
- Bind supplemental model input to the source and immutable task policy.
  Preserve legacy requests and reconstruct modern historical input separately;
  unexpected metadata sidecars do not establish processing provenance.
- Keep deterministic APEX validation, current authority, unique import, runtime
  verification and exact export checks on the connected path. Name recognition
  is not business-logic conversion or human acceptance.
- Clarify the user recovery path and the separate FOX/converter image roles.

Local connected HTTP tests exercise fresh review through output download using
authored model, SQLcl and browser replies. The combined local UI suite passed
21 tests with no skips. These are not live Oracle or real-file conversion proof.
Publication, deployment and the retained real run require separate verification.

## [0.18.1] - 2026-11-08

### Show the saved run's actual next step

- Replace the premature saved-output banner with waiting, processing, attention
  or generated-prototype wording based on the recorded run.
- Open the existing relevant progress/output surface without starting another
  conversion. Keep current-source readiness ahead of older run history.
- Suppress the banner for invalid history, source bindings or unknown outcomes.
- Keep generated output, technical verification and human acceptance separate.
- Align the readable-upload regression with existing server-side FMB guidance;
  retain its disabled-upload and zero-upload assertions.

The complete local workbench suite passed 97 tests, including both isolated
browser scenarios, with no skips. These use synthetic local fixtures, not a
live conversion. This source release does not prove deployment or APEX output.

## [0.18.0] - 2026-11-08

### Review an invalid response without regenerating the mapping

- Add one source-bound review-correction attempt beneath the saved continuation
  when a structurally invalid AI response attributes context-only objects to the
  current section. Preserve the original response and mapping; a fresh independent
  approval is still required. Genuine semantic rejection remains blocking.
- Supply explicit owned-object, context-object and inherited-screen information
  to the corrected review and new later reviews. Historical requests are unchanged.
- Offer **Review saved mapping again**, with fresh processing confirmations next
  to the action and the original locked code-unit list available on expansion.
  Recorded or uncertain submissions cannot be automatically repeated.
- Preserve the existing supported role-graph-update recovery route. Clear stale
  plans after failed refreshes instead of leaving an old action enabled.
- Reuse immutable technical calculations only within bounded read-only operations.
  Current ownership, source selection, consent, events and target checks remain
  fresh; model, package-transfer and execution boundaries remain enforced.
- Use a 30-second socket-operation timeout for current-authority calls and a
  30-second total UI budget for output readiness. The socket setting is not a
  promise of a 30-second total callback duration. This accommodates measured
  validation tail latency without skipping checks; an unavailable authority
  response grants no permission and no operation is automatically replayed.
  Other request budgets are unchanged.
- Recognize the exact sealed invalid-review stop for upgrade preservation without
  granting retry, import, download or business-acceptance authority.
- Clarify hosted FMB preparation, generated-output requirements and the product
  delivery order in the user guide and roadmap.

Local connected tests cover review correction through output download, current
authority checks and measured request budgets. UI tests cover the action and
uncertain-result handling. These tests use authored provider/Oracle/browser
outcomes, not live Oracle acceptance; protected
read-only planning checks do not constitute a new model review or APEX conversion.
See [review-scope correction](docs/review-scope-correction.md).

## [0.17.0] - 2026-11-08

### Review saved mapping without repeated generation

- Remove an exact duplicate screen declaration only when a previously reviewed
  source Block owns it and the current Item/Trigger references belong to that
  same Block. Conflicts, uncertain ownership and behavioral changes still stop.
- Preserve the raw mapping and every non-screen field. Record the derived
  candidate and source-bound projection evidence; neither is an AI approval.
- Add a bounded sixth continuation for the recognized pre-review stop. Reuse
  the saved mapping, run its independent review first, and start the next mapping
  only after approval. Earlier completed calls are not repeated.
- Apply the same checked projection to eligible later mappings in this
  continuation, with independent review still required for every candidate.
- Show **Review saved mapping and continue**, separating reviewed sections,
  a saved mapping awaiting review and sections not started. Original selections,
  three fresh confirmations and uncertain-submission locks remain in place.
- Preserve the missing fifth result publication as an absence, not a fabricated
  result. Historical bytes, approval events, current authority and exact export
  checks stay bound to the corresponding continuation.
- Recognize only the complete, sealed pre-review stop for upgrade admission.
  Evidence references for source links and dependencies use their canonical
  occurrence IDs; admission grants neither approval nor retry permission.

The projection and continuation have local source/API/browser tests using
authored external responses. Separate read-only checks on retained real evidence
confirmed the screen-only change and unchanged original files. These are not a
completed real-file conversion, deployed release or human business acceptance.
SQLcl validation, a unique import, runtime verification and the exact download
still require their own evidence. See
[saved mapping review](docs/saved-mapping-review.md).

## [0.16.1] - 2026-11-08

### Faster checked continuation requests

- Reuse the same exact historical review view within one read-only planning
  operation. Keep its record identity in the cache key, separate from current
  results, previews and live model execution.
- Close the read-only scope before adoption writes. File-integrity checks still
  run at its boundaries; ownership and approval events are not cached permission.
- Give only continuation-plan reads and continuation submissions a bounded
  45-second wait. Other prototype requests retain their 15-second budget.
- Explain when a read-only plan check times out without suggesting that
  conversion started. An uncertain submission still requires checking the
  existing run and cannot be automatically submitted again.

This patch addresses a measured timing mismatch between a valid retained-plan
response and the browser's earlier request budget. It changes neither the saved
candidate nor the independent approval, and does not bypass APEX validation,
import, runtime checks or human business review. Source publication, deployment
and completed real-file conversion remain separately verified milestones.

## [0.16.0] - 2026-11-08

### Continue remaining sections

- Give the independent reviewer losslessly deduplicated source, mapping and
  shared-screen context. Retain the full audit context separately; do not
  truncate selected code or change the candidate to obtain approval.
- Present previous findings as historical allegations to reassess, rather than
  embedding a response-shaped verdict. Explain shared-screen references for
  items and subordinate triggers while keeping substantive checks mandatory.
- Reuse an exact approved saved review through a bounded fifth continuation.
  Preserve all previous results and failures. Completed sections are not
  regenerated or reviewed again; unfinished sections use the compact context.
- Show **Continue remaining sections**, the retained reviewed count and remaining
  work. Lock the original source selection and require fresh confirmations.
  Uncertain submissions cannot trigger a second processing request.
- Keep historical-result validation separate from the current continuation.
  Check current authority before processing and after reading an export package.
- Recognize only the fully sealed pre-database review stop for upgrade admission;
  that classification grants neither processing permission nor success.

Verification covers lossless context reconstruction, tampered-proof rejection,
local API/worker/HTTP/download behavior with authored external responses, desktop
and mobile UI states, and the isolated upgrade-reader contract. A bounded actual
OPAF review approved the unchanged saved candidate, and read-only checks against
its retained hosted proof preserved the original job. This is not yet evidence
of a complete real-file conversion or a deployed release.

Remaining analysis, SQLcl validation, unique import, authenticated runtime and
downloadable export still require live acceptance. Business acceptance remains
human. See [retained review continuation](docs/retained-review-continuation.md).

## [0.15.0] - 2026-11-08

### Continue with reviewed structure

- Check the source-bound mapping prefix for omitted-parent conflicts, related
  screen references and selected trigger coverage before further AI work.
- Represent an eligible nonvisual container correction as a new, independently
  reviewed proposal. Preserve the original response and reuse only its exact
  approved replacement; do not infer missing business behavior.
- Offer **Continue with corrected structure** for the recognized stopped run.
  Reuse completed root/clause work and the next section's saved mapping. Review
  that section with checked screen context before continuing unfinished work.
- Append a fourth same-run continuation record with exact proof, source, target,
  predecessor and fresh confirmation bindings. Preserve earlier failures and
  byte-bound result history; interrupted publication cannot trigger a replay.
- Recheck current approval events and historical proof before output metadata or
  download, and again after the private package read.
- Reuse technical proof reads only within one bounded operation, with filesystem
  checks at entry and exit. No permission cache crosses requests, model calls or
  package transfers.
- Recognize the fully recorded pre-database rejection through the measured
  upgrade checker, without new runtime dependencies, retry authority or success
  claims.

Verification includes source/context and tamper tests, local API/worker/authority
checks, actual local HTTP route/gateway/ZIP checks with authored external
responses, lost-response and desktop/mobile UI checks, generated upgrade-reader
tests and independent reviews. A bounded real-source container proposal passed
independent OPAF review; read-only checks against its retained OCI evidence
preserved all existing job files. These are separate from deployment acceptance.

Real-file remaining analysis, SQLcl validation, unique import, authenticated
runtime verification and exact downloadable export still require live evidence.
No business acceptance is implied. See
[reviewed structure continuation](docs/reviewed-structure-continuation.md).

## [0.14.0] - 2026-11-08

### Continue with reviewed results

- Add a bounded OPAF contract for interpreting supplied Forms WhereClause and
  OrderByClause text, with source-bound limitations instead of invented facts.
- Reconstruct an explicitly derived candidate from retained analysis, verify
  the exact independent review, and preserve both original responses and history.
- Offer **Continue with reviewed result** for the recognized stopped repair.
  Reuse the completed clause analysis and review; review the next saved section's
  projection once, then continue unfinished sections using the original target.
- Append a third same-run continuation record with exact predecessor, source,
  target and saved-proof bindings plus fresh processing confirmations. Unknown
  outcomes, missing proof and later database work remain blocking.
- Transfer only the required JSON evidence to the converter. Evidence code is
  never executed or transferred, and SQLcl/import/runtime/export gates remain.
- Recognize the narrowly proven sealed repair failure for upgrade admission
  without granting retry, proof adoption, conversion success or business acceptance.

Verification includes retained-proof reconstruction and tamper tests, actual local
API/worker/authority/transport tests with authored external responses, repeated
and concurrent submission checks, modelled browser tests and independent reviews.
A bounded real-source OPAF clause analysis and independent review passed; read-only
checks on the retained OCI job confirmed the saved-proof continuation plan and
preserved its existing files. Separate Linux test copies verified permission and
link rejection without changing the original job.

These checks do not establish a deployed release or a complete real FMB-to-APEX
conversion. Remaining analysis, SQLcl validation, unique import, authenticated
runtime verification and downloadable export acceptance are still required.
See [reviewed-result continuation](docs/reviewed-result-continuation.md).

## [0.13.0] - 2026-11-07

### Source-checked repair and append-only continuation

- Check source-fact claims against the existing exact whitelist and evidence
  rules before new review. AI approval cannot override a failed source check.
- Add a bounded targeted repair and new independent review for an eligible
  saved section. Preserve original responses and prior approvals as history;
  only newly validated proof can become active for export.
- Project only proven repeated context declarations and exact property aliases.
  Preserve excluded records and rationales in versioned evidence and include
  that evidence in the independently bound reviewer request.
- Append source-, target- and checkpoint-bound continuation records with exact
  predecessor hashes, fresh consent and same-run identity. Do not replace the
  earlier continuation record or restart completed model requests.
- Show AI-reviewed and source-checked counts separately. Continue remaining
  sections only after the corrective phase passes; no automatic repair loop.

Verification includes pure source-fact/repair tests, local epoch API and worker
scenarios, interrupted-operation and staged-path guards, and an integrated local
authority/staging/export test with authored external responses. Modelled UI
regressions and independent reviews passed. Read-only checks against the retained
real job confirmed the bounded repair plan and preserved all 69 child-run files
in both container and host-reader checks; those checks invoked no model or import.

Publication and deployment are separate from live repair success. The corrected
candidate, remaining analysis, SQLcl validation, import, runtime checks and export
must still pass. See [source-fact repair](docs/source-fact-repair.md).

## [0.12.0] - 2026-11-07

### Source-reference resolution and saved-progress continuation

- Resolve a claim's code-unit ID to its exact owning Forms object using the
  authoritative request. Reject unknown, conflicting or out-of-scope references;
  do not infer missing business behavior or alter the original AI response.
- Retain a separate source-bound resolution record. Independent review, merge
  and export proof must use and verify the same resolved candidate.
- Add an explicit same-run continuation path for a proven stopped mapping step.
  Reuse completed model checkpoints; preserve the source snapshot, original
  responses, run identity and previously approved sections.
- Require current ownership, source selection, unchanged target, exact checkpoint
  evidence and three fresh processing confirmations. Unknown outcomes and
  database-stage failures do not become eligible for automatic retry.
- Show saved progress and the continuation choice in the prototype conversion UI.

Verification includes local ownership-resolution, same-run API, lost-record,
transaction-orphan, conditional authority-transfer and retained-proof tests;
modelled continuation/retry browser checks; and independent review. Read-only
checks against a real saved job found five reusable reviews and twelve exact
reference resolutions, preserving every original checkpoint in both container
and host-reader contexts. No new model or database operation ran in those checks.

This source change is not proof of a completed live conversion. Deployment,
remaining model work, SQLcl validation, import, runtime checks and exact export
must succeed before the application can be presented as generated. See
[checkpoint continuation](docs/checkpoint-continuation.md).

## [0.11.0] - 2026-11-07

### Explicit first-mapping recovery

- Parse a single model JSON object with an optional single JSON/plain Markdown
  fence. Reject prose, multiple values, duplicate keys and nonfinite values;
  retain the untouched API-response hash. No model content is synthesized.
- Add a read-only recovery check and an explicitly approved, deterministic child
  attempt for a proven incomplete first mapper. Preserve the original source,
  selected code units and failed attempt. Unknown, later-stage, reviewer-rejected
  and chained attempts are not automatically retried.
- Bind new request partitions to schema 2 with at most 32 owned objects each;
  preserve schema-1/250 historical reconstruction. Every source object and whole
  selected code unit remains covered; smaller requests are not omitted Forms.
- Permit only a freshly approved role-profile update with the same destination,
  model and processing boundary. Show the changed-workflow notice in the UI.
- Migrate only the legacy SQLite run-source uniqueness constraint, preserving
  run IDs/rows, primary/foreign keys and transaction rollback. Normal generation
  retains serialized duplicate guards. History accepts only the validated
  deterministic parent/child pair and shows two linked runs, not duplicate data.
- Recognize an exact, sealed, empty first-mapper failure as terminal before any
  executable work. This grants neither success nor retry authority. Generic
  attention, missing proof, later work and unknown operations remain blocking.
- Add separate v3 analysis/review prompt resources that distinguish non-executing
  analysis from source safety flags. Existing workflow resources are preserved.
- Add a partition-aware v4 reviewer that accepts supported module-level analysis
  without demanding screens from a partition that owns no Blocks. Known Block
  and Item mapping, ownership and behavior-evidence requirements remain intact.
  Registration permits only the new reviewer and preserves the existing mapper.

Verification: scoped local API/SQLite/history/rollback and parser regressions;
simulated desktop/mobile recovery UI; independent review; and read-only tests
of the terminal-failure classifier on actual retained proof in both rootless UID
contexts. Legacy fixture cases were tested in an isolated source copy.

**Not a live conversion-readiness claim.** The real-source diagnostic returned
structured behavior analysis. One explicitly approved reviewer-only retest of
that unchanged saved module-level candidate returned `APPROVED`, zero findings;
generation was not repeated and no import occurred. This verifies one partition,
not the whole application. Guarded deployment, a complete real-file
import/runtime/export and human business review remain separate. See
[mapping recovery](docs/prototype-mapping-recovery.md).

## [0.10.0] - 2026-11-07

### Generated prototype output and connected verification adapters

- Add current-project authority checks for every protected prototype stage;
  owner, selected source, consent, retained review and target must still match.
- Connect opt-in converter startup and private host browser verification through
  bounded, expiring requests. Claims and uncertain outcomes are retained without
  automatic model/import/browser replay. No public QA endpoint or Podman socket.
- Add a separate generated-prototype output view and exact package download.
  Stale sources, changed targets or incomplete evidence block download without
  promoting the run to human accepted or strict clean-install verified.
- Include the pure package validator in the app payload. Historical stage proof
  is verified locally; downloading does not reauthorize or replay earlier stages.
- Bind focused OPAF metadata, HTTPS authority and measured worker source into the
  explicit upgrade plan, retaining the existing target and private Forms queue.
- Handle bare/prefixed Podman image IDs, expired queue entries and the measured
  rootless-cgroups-v1 diagnostic. CPU/memory/pids limits are not claimed enforced
  on cgroups v1; the container lifetime remains independently bounded.
- Permit the two standard APEX script endpoints only for the exact application,
  preserving foreign-app, password-change and expired-request rejection.

Verification includes isolated source/package tests, authenticated local API and
simulated UI checks, actual installed-dependency server startup, OCI namespace
handoff/container-lifetime checks, and a separate existing-app login prerequisite.
These do **not** establish a deployed end-to-end real-FMB conversion. A successful
prototype remains synthetic/partial, with explicit remediation; clean reimport,
customer compatibility and business acceptance are separate. See
[prototype output and operator wiring](docs/generated-prototype-output.md).

## [0.9.1] - 2026-11-07

- Add an explicit private-queue option to the guarded upgrade plan. Candidate
  creation and activation must agree on the exact setting; existing deployments
  without the option keep their previous behavior.
- Bind the opted-in candidate plan into the transition's checked references.
  Reject queue paths outside the dedicated private preparation namespace.
- Reuse the existing app data mount and compatible native host. No extra public
  port, mount, SSH credential, database credential or OCI resource is introduced.
- Raise the finite backup entry limit from 10,000 to 20,000 to retain accumulated
  audit history. The 128 MiB total-data, 64 MiB member and 8 MiB manifest limits
  remain in place; backups still fail closed if any limit is exceeded.

The option is deployment configuration, not proof of extraction or conversion.
The actual installed UI/native-worker journey and downstream OPAF/APEX stages
require separate acceptance evidence.

## [0.9.0] - 2026-11-07

### Server-side FMB preparation

- Add a Linux Oracle Forms adapter with headless JDAPI initialization, private
  byte-identical input copies and explicit OVERRIDDEN/ALL exports.
- Compose native extraction, effective metadata and redaction into a retained,
  hash-bound preparation result. Raw files and unredacted outputs stay private;
  source code is not executed or sent to a model by preparation.
- Add a private host queue and authenticated project upload/status/adoption
  routes. Each request binds the owner and selected source version. Unconfirmed
  submissions keep their identity; claimed jobs are never automatically replayed.
- Add raw-FMB controls to the project upload screen, with clear queued, uncertain,
  blocked and prepared states. Adding the result is explicit and does not approve
  AI processing, import an application or accept business behavior.
- Keep the secondary prepared-XML route and existing source history. A previously
  adopted result cannot falsely report that it was added to an older selection.

Verification includes local queue/native-policy regression tests, authenticated
API tests, a canonical local browser journey with a labelled synthetic native
exporter, and an actual OCI real-FMB container-to-host preparation/result check.
That real check preserved the original and independently validated the redacted
result. The source release does not establish deployed browser upload, OPAF
generation, APEX import or a downloadable converted real application.

The browser check exposed and verified a repair for strict-renderer assessment
blocking the project page after redacted-source adoption. Such sources remain
readable for prototype review; the strict generation gate remains unchanged.

Initial hosted scope is **one FMB per request, up to 20 MiB**. MMB/OLB/PLL and
linked dependency preparation are not silently included in that claim. Oracle
tools are separately installed, licensed prerequisites, not redistributed here.
See [operator setup](docs/server-side-fmb-preparation.md).

## [0.8.1] - 2026-11-06

- Package the exact native renderer, source contracts, XML dependency and
  template files into the FOX app image. An isolated projected-app check renders
  a real two-block native candidate without borrowing checkout/site packages.
- Add an operator-only protected closure for retained pre-business QA failures,
  preserving an original-state export before the append-only failed disposition.
  Pipe reads/writes and the reserved-transaction observer have explicit deadlines.
- Preserve failed outcomes and prohibit automatic retry. Closure does not claim
  technical success, human acceptance or a successful Forms conversion.

Local packaging/recovery tests and controlled Linux timeout/permission checks
passed. Installed-version and full-conversion claims still require their own
live verification; the version number alone is not deployment evidence.

## [0.8.0] - 2026-11-06

### Prepared Forms intake and prototype workflow

- Added prepared redacted XML/receipt upload without relaxing the ordinary
  data-loading filter. Exact immutable provenance is revalidated on history
  reads. Comments and processing instructions cannot hide unmasked payloads.

- Added an explicit project prototype assessment/submission path and worker
  branch, preserving the existing strict native-project route. Source versions,
  selected code units, owner permission and processing destination are bound to
  the saved job; uncertain operations are not automatically repeated.
- Added a separate native-prototype UI with readable code-unit labels, explicit
  synthetic-storage scope, refreshed consent after selection changes, and
  actionable configuration/rejection states.
- Added converter authority transport, authenticated stage routes and guarded
  runtime/export adapters. Runtime requires a real authenticated browser runner;
  missing adapters do not produce verification claims.
- Separated generated/exported output from package reimport, clean installation
  and human business acceptance. Export alone cannot mark a package verified.

Local verification includes actual authenticated upload/assessment of one approved
redacted real Forms module, unchanged source hash and all 71 code units retained;
59 prepared-source/API tests; 103 existing history/project regressions; and actual
desktop/mobile browser interaction checks with synthetic API responses. A focused
independent review confirmed the hidden-XML-content repair.

Hosted activation and a complete real-file conversion are **not yet proven**.
The processing profile, trusted converter authorization, production browser
callback and complete-package reimport remain integration work. This release
does not enable them automatically or claim a ready downloadable real application.

## [0.7.0] - 2026-11-05

### Inactive conversion-engine preview

This source checkpoint preserves verified engine work at the user's request.
It is an explicit checkpoint exception to the usual connected-feature release
rhythm: no new end-to-end UI route, hosted activation or successful real Forms
conversion is claimed. See [checkpoint limits](docs/conversion-engine-checkpoint.md).

### Added

- Paired Oracle XML effective-metadata derivation with exact identities,
  default/override provenance and original/code preservation; inherited behavior
  is not silently declared resolved.
- Conservative local redaction with exact whitespace-escape normalization,
  body-free hash receipts and fail-closed credential-command handling.
- Source-bound evidence packets, bounded linked analysis sections, full-object
  blueprint merging and separate independent-review receipt validation.
- Versioned tool-free OPAF understanding/review definitions and additive,
  guarded one-operation registration without replacing existing workflows.
- Native multi-block synthetic prototype planning/rendering, including large
  forms, source-free control display items and read-only report handling.
  Interactive-grid editing falls back explicitly to a read-only report.
- Labelled synthetic benchmark fixtures and scoring that separates valid
  structure, proposed mappings and actual business behavior.

### Verification and limits

- Real local Oracle extraction/effective-metadata checks retained all 9 blocks,
  222 items and 662 recognized objects in the primary acceptance file.
- An authored engineering candidate planned 216 fields and explicitly retained
  six unsupported buttons. Its complete APEXlang project passed actual offline
  SQLcl validation. This was not an OPAF-produced, imported or browser-proven app.
- The initial synthetic OPAF comparison recorded both model and reviewer calls;
  it exposed over-refusal, unnecessary questions and a reviewer false approval
  which deterministic validation rejected. Neither result proves universal quality.
- Original customer source, model-response bodies, credentials and lab journals
  are excluded from this release. Helper checks do not grant transfer or execution
  permission, certify complete PII detection, or record human acceptance.
- Real-file OPAF completion, connected FOX UI, unique import, runtime verification
  and exact native export/download remain pending. Unrelated recovery/transport
  work is deliberately excluded rather than published without integration proof.

## [0.6.0] - 2026-11-05

### Added

- Explicit localhost **Extract and assess locally** action for FMB and Forms
  XML. Broad, non-executing facts include all modules/blocks/items, source-bound
  identities/locations, code hashes, lexical reference candidates and findings.
  Normal quoted/numeric SQL in business code is not a blanket assessment refusal.
- Authenticated assessment jobs use the existing loopback/owner/file controls
  and single-extraction reservation. Original selections, readable output,
  assessment and original-input sidecar hashes are retained and rechecked.
  Assessment creates no ready/upload manifest and cannot authorize model calls,
  generation, import, business acceptance or legacy source handoff.
- Responsive all-block/item view, source identity and explicit **Application
  understanding: Not run**. Source tampering revokes facts; unconfirmed POST
  results are not automatically replayed. The new action requires an explicit
  server capability; older preparation remains available separately.
- Offline synthetic blueprint-evaluation fixtures/checks for future model
  comparisons. No model winner or live benchmark is claimed by these fixtures.

### Fixed

- Hosted pages no longer offer a local preparation action that cannot run there;
  both exact localhost origin and explicit server capability are required.
- Presentation accepts the exact safe wildcard locations emitted for unknown
  XML wrappers, retaining known blocks/items and their uninterpreted finding.
- Saved-history browser fixtures resolve Windows' lazy platform metadata before
  their unchanged external-action guard. Readiness now checks HTTP health/child
  exit, so a failed fixture cannot masquerade as an application login timeout.

### Verification and limits

- Actual installed Oracle extraction and the authenticated local API assessed
  two privately retained real FMBs: 9 blocks/222 items/54 triggers and 51 blocks/
  414 items/95 triggers. Originals were unchanged; only metadata was returned.
- Source/unit, API/race/tamper and canonical local browser checks use labelled
  synthetic fixtures. Browser fake-native evidence is separate from actual
  Oracle extraction proof. Desktop/mobile screenshots are retained locally.
- This is G1 of the OPAF-first goal, not complete conversion. OPAF understanding,
  model A/B inference, broader native generation and the real-file APEX export
  acceptance case remain unfinished. No customer source or credentials are
  included here. Existing hosted intake/generation gates remain unchanged.
- No model switch, cloud/database mutation, deployment or human acceptance is
  established by this source increment. Preserve earlier failed evidence and
  the retained verifier fault; do not replay it to obtain a green result.

## [0.5.0] - 2026-11-05

### Added

- Complete-conversion / partial-demo scope selection. A read-only preview lists
  included forms, omitted forms, skipped behavior and corrective actions. An
  explicit confirmation creates a separate derived source version; originals
  and their blocking findings remain available.
- Partial drafts recompose only proven table-backed fields and supplied DDL.
  Known code/library/report/control-item omissions are recorded, not executed
  or presented as translated. Missing keys, conflicting definitions, restricted
  operations and uncertain field mappings do not become invented working forms.
- Draft scope remains visible on saved project/run views, has an owner-scoped
  report download and is included as comments in packaged source evidence.
  Draft source branches are frozen: return to the original version to correct
  dependencies. Lost creation responses reconcile against the exact saved
  scope without replaying the operation.
- A separate development-draft download rechecks the existing complete native
  technical proof and returns the unchanged package bytes. It records no human
  acceptance. The accepted-package download and its human gate are unchanged.
- Contextual next actions, responsive scope cards, a configuration/service
  readiness view and APEX handoff instructions using recorded test versions.

### Fixed

- Derived draft sources fail closed if their saved scope receipt is missing,
  corrupt or belongs to a different owner. Assessment, queueing, acceptance and
  development download cannot silently reinterpret such a branch as complete.
- Clean-checkout browser regressions build the current UI in memory instead of
  depending on ignored build assets. Legacy consent checks require the actual
  stronger source-revision/current-consent and busy guards.

### Verification and limits

- Local API/storage, source-planning, normal queue-submission, exact-byte native
  release and UI regression scenarios are covered. The canonical browser path
  uses a real isolated local API and SQLite with synthetic sources and no worker.
- These checks do not establish a live OPAF conversion, real FMB/PLL extraction,
  SQLcl/Oracle execution or business acceptance. Hosted deployment and its
  retained verifier failure remain separate work; this is a source increment.
- Omitted actions are absent, not newly implemented disabled-placeholder APEX
  components. Wider native component mapping and fresh-host installation remain
  tracked in the product roadmap. No new OCI resources or dependencies added.

## [0.4.2] - 2026-11-05

### Fixed

- Native-project runtime QA now reads the unique username entry emitted by the
  generated APEX Navigation Bar, instead of requiring an account-button class
  that this template does not render.
- Account comparison remains mandatory and case-insensitive. Missing, wrong,
  empty or duplicate labels still fail; no arbitrary page text is accepted.

### Verification and limits

- 168 focused browser-adapter/project-runtime/input/profile checks passed using
  synthetic models. The real read-only APEX26.1.6 DOM observation confirmed one
  matching username entry and zero matches for the old selector, without CRUD,
  conversion or import. This is not a full runtime-QA pass.
- TypeScript/Vite, three release-API checks and release consistency passed;
  two dependency deprecation warnings remain.
- Source patch only. Earlier failed attempts are retained and unverified; no
  promotion, acceptance, replay or automatic retry is authorized by this fix.
- A fresh measured deployment and a safe failed-attempt disposition are still
  required before the corrected runtime checks can run normally.

## [0.4.1] - 2026-11-05

### Fixed

- Version-two hosted recovery plans include exact, hash-pinned admission and
  source-inventory files when they sit outside normal protected directories.
  Their parent directories are not implicitly added to the capture.
- Version-two current-pair transitions can use an explicitly pinned recovery
  helper from the new measured bundle without modifying the older installed
  source or replacing its normal module namespace. Version-one plans retain
  their original reader and field contract.
- Pure transition path contracts now remain POSIX-shaped during Windows checks.
  Offline rollback tests no longer depend on ignored private operator history.

### Limits

- This is deployment-tooling support, not a completed backup or permission to
  switch a running release. A real held operator lock, exact installation,
  stopped-writer checks, capture and isolated restore proof are still required.
- No replay, conversion, import, human-review or download gate changes. A new
  measured build is required; older images are never relabelled.
- See [recovery plan versioning](docs/deployment-recovery.md).

### Verification

- Windows deployment contracts: 64 passed, 36 platform/namespace skips;
  release API: three passed. Two dependency deprecation warnings remain.
- Linux contracts, pinned import, adapter and lease checks: 106 passed, with
  17 namespace checks separately exercised under rootless Podman: all 17 passed.
  Exact-file capture/isolated restore excludes an unapproved neighboring file.
- Frontend regression: 301 passed, including real local API/browser source and
  saved-history flows. TypeScript/Vite and release consistency checks passed.
- Local namespace fixtures do not establish a live JSN backup, database import,
  model invocation or human acceptance.

## [0.4.0] - 2026-11-05

### Added

- Saved progress and per-form responses on every project output, available after
  reopening the project. Original form/source labels are derived from each
  validated retained run, never borrowed from a newer source version.
- Read-only status checking on normal saved-run views as well as attention
  states. Viewing history does not replay conversion, import or human review.
- Explicit unavailable original-label and malformed-detail handling. Saved
  checkpoints are not presented as proof of a live process.
- Real local API/browser coverage of reopening an output and renaming its source
  without changing retained work or granting acceptance/download.

### Limits

- No new behavioral translation or import/verification/review permissions.
  Generated per-form output remains separate from complete-project technical
  checks and genuine human acceptance.
- Source release only. Local tests use synthetic Oracle/OPAF transports, not a
  live database import or runtime proof. See [saved history](docs/saved-run-history.md).

### Verification

- Clean-source Windows backend: 331 passed, two explicit POSIX-only skips.
  Native Linux retained-history/package-reader checks: 138 passed.
- Frontend: 301 checks passed, including a real local API/SQLite browser flow
  that reopens output, renames selected source and preserves the original run.
- TypeScript/Vite build and release consistency passed. Desktop/mobile renders
  were inspected. Two dependency deprecation warnings remain.
- External Oracle/OPAF transports in package fixtures are synthetic. No live
  import, model invocation, runtime APEX proof or human acceptance is claimed.

## [0.3.0] - 2026-11-05

### Added

- Grouped source requests across Forms, retaining every assessed caller and
  keeping schema-qualified objects separate.
- Specific missing package-part and unconfirmed-routine actions, copyable
  owner/DBA requests and a source-version-bound request download.
- A same-project add-source path with reassessment. Source availability is
  explicitly distinct from translated behavior and conversion readiness.
- Desktop/mobile coverage of real local API upload and reassessment, with
  stale request exports rejected after a source change.

### Limits

- No expansion of behavioral translation or relaxation of conversion, import,
  technical-verification or human-review gates. Raw binaries still require
  supported Oracle preparation. See [source requests](docs/source-requests.md).
- Request grouping summarizes assessed dependencies; it does not guarantee that
  every runtime dependency is discoverable. Incomplete/oversized lists retain
  detailed findings rather than reporting confirmed zero requests.
- Source release only; this entry is not an installed release or Oracle
  conversion claim. Verification receipts are recorded with the increment.

### Verification

- Clean-source backend regression: 195 tests passed. Focused Linux assessment
  and request checks: 32 passed. Two dependency deprecation warnings remain.
- Frontend presentation, source-history and request checks: 293 passed,
  including a real local API/SQLite upload and reassessment browser scenario.
- TypeScript/Vite build and release consistency checks passed. Desktop/mobile
  screenshots were visually inspected; no Oracle/model call or human business
  acceptance was performed. The source-history test harness now includes the
  release panel added in 0.2.0.

## [0.2.0] - 2026-11-05

### Added

- A version and **What changed** panel in both workspace layouts.
- A public, read-only software identity endpoint shared with health reporting.
- Clear UI/server mismatch and unavailable-status messages, with a read-only retry.
- A canonical software release manifest and consistency checks for package and
  changelog versions. No extra runtime service or dependency is required.

### Limits

- Experimental source preview. This increment does not expand conversion coverage
  or certify a target database, native runtime flow or customer installation.
- Generated APEX, technical verification and human business acceptance remain
  distinct; no import, verification or download gate is relaxed.
- UI notes identify the loaded UI release. A different/unconfirmed server is
  explicitly labelled; publishing this version does not update a running host.

### Verification

- Clean-source API, submission gates, health and packaging: 102 tests passed;
  two explicit skips and two dependency deprecation warnings remain.
- Release presentation: four focused checks passed. TypeScript/Vite build passed.
- Headless desktop/mobile product-flow scenario passed with synthetic API only;
  release-note screenshots were visually inspected. No live conversion, Oracle
  connection or human business acceptance was performed by these checks.

An optional skip is not a pass or an installed-flow claim. Cloud activation and
installed native-output evidence are separate from this software increment.

## Earlier experimental source

Packages previously reported `0.1.0` without a FOX release changelog. Existing
history is preserved; this file does not retroactively call those commits
versioned, deployed or technically verified releases.
