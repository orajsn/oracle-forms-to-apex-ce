# FOX developer orchestration

Updated 15 November 2026. This is a development working agreement, not a FOX
runtime dependency, a model-access entitlement or an end-to-end readiness claim.
The lead selects the model and thinking effort for each actual assignment.
Do not run every model on every task or use maximum effort by default.

## Model pool and task routing

| Model | Suitable work | Normal effort | Escalation / boundary |
| --- | --- | --- | --- |
| `gpt-6-astra` | Lead decisions, difficult architecture, independent high-risk or release review | High for FOX's risk-bearing work; Low/Medium for bounded triage | Extra High only for a specific unresolved decision; Max/Ultra are exceptional, not the default. |
| `gpt-6.1-sol` | Backend/conversion implementation, API integration and regression diagnosis | High for implementation; Medium for QA; Low for mechanical work | Increase only when concrete failures or ambiguity justify it. |
| `gpt-6.1-terra` | Business-user UI, visual inspection, interaction and clear user-facing copy | Medium | High for complex interaction/state or accessibility work; not the sole approval for database/permission logic. |
| `gpt-6-luna` | Bounded inventories, extraction, changelog/tag comparisons and routine checks | Low/Medium | Use only when deterministic checks can verify the result; not the sole decision-maker for conversion semantics or risky releases. |
| `gpt-6-sol` | Compatibility fallback or an explicitly useful comparison with an older model | Medium; High for nontrivial implementation | Prefer Sol 6.1 when available. Do not add a fallback agent merely to use every model. |

This covers the explicit model-override pool exposed to the current development
session, not every fixed model behind other installed specialist roles. Recheck
availability before dispatch; do not silently substitute or claim an unavailable
model ran. Official guidance supports per-agent model and reasoning selection;
the table is FOX's task-specific policy, not a universal model benchmark.
See [subagents](https://learn.chatgpt.com/docs/agent-configuration/subagents) and
[model selection](https://learn.chatgpt.com/docs/models).

## Configured role defaults

The existing workspace-local roles are:

- Lead/default: Astra High.
- `fox_backend`: Sol 6.1 High.
- `fox_ui`: Terra 6.1 Medium.
- `fox_qa`: Sol 6.1 Medium.
- `fox_reviewer`: Astra High, read-only independent review.

These are configured defaults, not proof that a running chat changed its model.
Named roles may fix their model/effort. If a different effort is appropriate and
the current tool supports it, use an explicit model/effort dispatch with the same
role instructions and report that override. Do not claim the named role switched
when it did not. Workstation-specific `.codex` files, trust settings and credentials
are not published by this document, and other installations must configure their
own supported roles. Global defaults and permissions are not changed here.

## Required handoff for every subagent

Before dispatch, record a short brief in the task's local evidence:

```text
Task / outcome:
Role and selected model ID:
Selected effort and why:
Owned files; other owners / shared contracts:
Acceptance checks and evidence location:
Allowed actions and stop condition:
```

Use a concise fresh brief, not the entire chat. Tell workers they are not alone.
Keep at most two workers active, with no nested delegation. Only the lead may
integrate, commit, push, deploy, use credentials or operate cloud/Oracle resources.
Workers return exact results and artifact pointers; a chosen model or a green
unit test is not proof of a completed conversion.

After the task, record the actual dispatched role/model/effort, result, checks and
any fallback. If runtime model identity cannot be independently observed, say
"requested/configured" rather than inventing confirmation. Keep private paths,
customer source and operational evidence out of public changelogs.

## Work and pause discipline

- Begin with the user-visible change to deliver, not a test-count target. Name
  its commit category and the UI/conversion acceptance scenario before assigning work.
- Lead with the first failing real user-flow step. Reuse deterministic code and
  existing procedures before adding orchestration or new model calls.
- Keep implementation and its targeted tests in one bounded slice. Separate
  `[testing]` and `[maintenance]` work honestly from product improvements; neither
  is a new converter capability by itself. Use `[performance]` only with comparable
  measured before/after results. Follow the [release labels and format](release-policy.md#make-the-change-visible-in-git).
- Reuse passing evidence for unchanged code/inputs/environment. Repeat checks when
  a changed risk, freshness requirement or uncertain outcome requires it, not merely
  to produce another verification update. Never bypass required safety gates.
- Delegate only independent work that saves time or adds a useful independent
  check. Small dependent tasks stay with the lead.
- A pause stops goal execution and its implementation workers. A separately
  requested documentation update does not resume conversion or deployment.
- Publish one reviewed slice with its changelog; keep local tests, publication,
  staged source, active deployment, technical verification and human acceptance
  separate. Preserve unrelated unfinished work.
- Report what the user can do now, where it is available, and the remaining gap.
  If a slice is operations-only, say so and identify the user-flow blocker it removes.

These developer models are distinct from the configured OCI/OPAF mapper,
reviewer and embedding model. Updating this policy does not change those runtime
models, send Forms code to a provider, or grant permission for a paid call.
