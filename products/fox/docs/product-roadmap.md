# FOX product and UI roadmap

Updated 4 November 2026. Implementation of the broader product/UI goals has been explicitly started. The goal definitions below refine the existing one-project/multiple-Forms/one-native-APEX contract. Implementation evidence and deployment status are tracked separately; a started goal is not a completed feature, deployed release or availability claim.

## Product outcome

A business user manages multiple projects. Each project contains the Forms modules and supporting sources for one application. FOX helps the user complete that source set, explains what can and cannot be converted, runs embedded conversion and review, and produces a native APEX export with explicit target requirements and technical evidence. The user does not need to operate OPAF, write prompts or run Forms2XML/SQLcl/QA commands.

"APEX generated", "technically verified" and "business behavior accepted" remain separate facts. The outcome is a declared supported conversion, not universal behavioral equivalence or an import guarantee for unspecified targets.

## Business-user UI journey

```text
Projects
  Project workspace
    Overview       Status, forms, unresolved actions and the next useful button
    Forms & files  Add/prepare sources; identify modules and link supporting files
    To resolve     Explain missing inputs, unsupported behavior and human decisions
    Conversion     Review mapping; process; inspect per-form progress and recovery
    APEX output    Native export, target version, evidence and final human review
```

The project title, selected source version and current run remain visible across these views. Technical identifiers, hashes and logs go under expandable evidence. Do not make users navigate a separate OPAF UI to finish normal conversion.

## Feature goals and acceptance

### G1 — A clear project workspace

**UI:** searchable project dashboard, project creation, form/file counts, current stage and a single context-appropriate next action. Use plain labels such as "Needs 2 files", "Needs a decision", "Ready to convert", "Converting" and "APEX generated"; do not expose a bare BLOCKED code as the explanation.

**Done when:** two independent projects can be revisited without mixing sources, findings, runs or outputs. A user can identify what to do next without developer help. Desktop and narrow-screen layouts are readable, keyboard usable and have clear loading/empty/error states. Counts are computed from the selected source version, not invented progress percentages.

### G2 — Guided source intake and preparation

**UI:** select Forms files and supporting material, see recognized types and extraction progress, and receive specific per-file failures. Required Oracle-tool preparation happens behind the same UX on a configured supported host/worker; it is not a business-user script step. If extraction is not configured, say exactly what an administrator must configure and retain the selected job safely.

**Done when:** genuine FMB/MMB/OLB/PLL cases use supported Oracle extraction; raw and prepared files are not confused; originals and hashes remain preserved; prepared XML/text can be reviewed before any approved model transfer. Malformed inputs do not lose good files or silently enter generation. Presence of tooling is not represented as successful extraction or complete conversion. Retain the existing raw-local/data-boundary contract unless an approved extraction-worker design explicitly changes it. Installer/media distribution is a separate prerequisite, not a promised bundled Oracle runtime.

### G3 — Understand the application and its dependencies

**UI:** form inventory and source-linked relationships, with an expandable path such as form → block/item/button → trigger/program unit → called object/routine. Display the actual known path; mark unproven locations instead of guessing a button label or a source line.

**Done when:** the resolver distinguishes version-appropriate Oracle built-ins, module-local code, supplied custom sources and unresolved external dependencies. Package specification, body and referenced routine availability are separate observations. Same-name or conflicting definitions require an explicit authoritative choice. Static/dynamic references are labelled by evidence strength. "Source present" never means "behavior converted". Cross-form/module/library/table links are scoped to the correct project and form.

### G4 — Explain gaps and help the user resolve them

**UI:** each finding states what was found, where, what is missing/unsupported, why it matters, what to provide/do, who can help and the next action. Distinguish missing input, implementation limitation and business decision. Avoid asking for nonexistent filenames: a missing database package may require a readable export rather than a literal file already on disk.

**Example:** "Order Entry → Approve button calls ORDER_API.APPROVE_ORDER. The package body is missing. Ask the application owner/DBA for its package specification and body (.pks/.pkb or readable SQL). Until supplied and mapped, approval behavior is not converted." Show only the source-location details actually established by the evidence.

**Done when:** upload of a previously missing body updates the same project's assessment; resolved findings are cleared and unrelated findings remain. If the required routine is still absent or unsupported, show that specific remaining action instead of saying ready. Adding a file does not imply approval, behavioral translation or a model request. Inaccessible or unparsed code is "not assessed", not falsely "missing".

### G5 — Predictable conversion and safe continuation

**UI:** review the supported mapping before processing; show per-form and whole-project stages; retain progress across refresh/reopen. Give specific recovery actions such as "Add files", "Resolve mapping", "Check existing run" or "Retry this safe step". Explain operator-only faults without making users manipulate services.

**Done when:** recognized layout metadata (including Coordinate) does not block conversion. Meaningful code/dependency gaps remain explicit; no selected form or required behavior disappears to force an output. Clear source changes invalidate affected results/approvals and create a newly bound run, preserving older history. Completed model calls/imports are not replayed as a retry. Unknown import outcomes are reconciled read-only; transient failures and real missing-input/human-decision states are not conflated. A whole-application conversion is not labelled complete after only some selected forms succeed.

### G6 — A native APEX output workspace

**UI:** show what was generated for each form, supported pages/actions, remediation, export file, source version, stated APEX target and technical results. Keep "Generated", "Verification pending/failed/passed" and "Business review pending/accepted" separately visible. A technical failure must not erase an already generated artifact or turn it into a success claim.

**Done when:** the exact exported package passes deterministic SQLcl validation, a new non-overwriting import into the declared compatible test target and applicable native runtime checks. Show the import requirements, package manifest, source-to-page mapping, validation and smoke evidence. Native APEX SQL is the manual-import deliverable; APEXlang is included where actually supported and proven. Existing acceptance/download gates remain enforced and explained. A reviewer can record a genuine business-flow decision separately; software never impersonates that acceptance. No "100% success on any database" wording.

### G7 — Installation and operation as a product

**Administrator UI:** a separate setup/readiness area for the extraction backend, OPAF/model roles, APEX/SQLcl target, persistent storage and protected connections. Show configured, tested and available as different states. Expose no passwords, signing keys or wallets through business-user pages or diagnostics.

**Done when:** one documented supported installation route, a clear prerequisites/version report, durable background processing independent of Codex, and tested start/stop/resume/backup/restore/upgrade behavior preserve projects and artifacts. A new administrator can set up the declared supported profile without editing application code. Business users receive one URL; developer QA remains outside their controls. Customer tenancy, shared SaaS isolation and infrastructure changes require their own approved scope.

### G8 — Ship and demonstrate the complete journey

**Done when:** the actual released UI, API, converter, OPAF, target and verifier are exercised together—not merely mocked independently. The same coherent version must be published, deployed and identifiable in the app. Perform:

1. One genuine valid binary roundtrip with explicit DDL through native APEX export and runtime proof.
2. A synthetic missing-package-body scenario: show the exact finding, add the body, reassess, distinguish source resolution from supported behavioral mapping, then continue only when both are proven. If package-call translation is not yet implemented, report that limitation rather than relabel presence as conversion.
3. One project with multiple forms into one APEX application, plus an independent project.
4. Refresh/reopen, source revision, malformed input, transient failure, unknown outcome and safe recovery scenarios.
5. An unchanged manual-import package installed into the declared test version, with no app replacement, false verification or automated user acceptance.

The existing hosted verifier fault, APEX target-version rebinding and controlled paired rollout are engineering prerequisites here. The published Coordinate fix is source/test proof, not proof the live site has it. Preserve the retained failed trial and all existing resources; do not replay it to manufacture a green demo.

## Delivery order

1. **Make the lab baseline demonstrable:** reconcile the existing verifier/target issues and release binding, preserving all previous outcomes. This is not new infrastructure or permission for blind recovery.
2. **Build one connected vertical slice:** G1–G5 for one form, an evidence-backed dependency and a clear missing-input correction. Implement resolver tests and UI presentation together; do not polish screens disconnected from real backend facts.
3. **Finish the output slice:** G6 plus the supported behavior mapping required by that example, then extend to multiple forms/projects.
4. **Package and release:** G7–G8, complete UI/accessibility/error-state QA and concise end-user/admin guides.

A feature is source-complete, tested, published and deployed only when each corresponding fact has evidence. Report these dimensions separately in the workboard. Do not mark G1–G8 complete because a roadmap, mockup, component test or a single successful model call exists.

## Later product scope

Direct customer-database deployment, organization accounts/SSO, multi-tenant hosting, broad master/detail/LOV/trigger/library/report support and large-scale concurrency remain separately prioritized extensions. V1 is a usable bounded native converter with manual export/import, not a general SaaS migration factory. Keep cost/workload sizing minimal and do not provision extra infrastructure merely to support roadmap items.
