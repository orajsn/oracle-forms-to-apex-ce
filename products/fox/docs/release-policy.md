# FOX incremental releases

Each completed product increment has a semantic version, changelog entry,
reviewed source commit, relevant verification and a `fox-vX.Y.Z` Git tag.
Existing CE versions/tags are independent and must not be replaced.

## Make the change visible in Git

Every new FOX commit subject and changelog change heading starts with one primary
category. These are readable commit labels, not replacements for Git version tags.

| Label | Meaning | What the entry must explain |
| --- | --- | --- |
| `[feature]` | A new user capability | What the user can now do. |
| `[improvement]` | A better existing workflow or conversion result | What becomes clearer, easier or more complete. |
| `[fix]` | A specific defect corrected | The failing case and corrected behavior. |
| `[performance]` | A measured speed or resource improvement | Comparable before/after measurements, workload and environment. |
| `[testing]` | Tests or QA tooling only | The coverage added; explicitly state that no product capability was added. |
| `[maintenance]` | Deployment, dependencies, backup or operational work | The operational blocker addressed, not a claimed converter feature. |
| `[docs]` | Documentation or working conventions | What was clarified; no implied runtime change. |

Use `[category] scope: observable change`, for example:

```text
[improvement] fox-ui: explain missing dependencies and the next action
[fix] fox-output: allow downloads after a passed required-field check
[testing] fox-converter: cover malformed Forms packages
```

These are format examples, not additional shipped features. Keep existing commit
subjects, dates and version tags unchanged. Older changelog entries may receive
clearly dated retrospective category labels without rewriting Git history.

## Deliver a user outcome, then show the evidence

- Start an increment with one observable UI/conversion outcome or a specific bug.
  Finish that slice before opening unrelated improvements or operational tooling.
- Tests normally accompany the feature/fix commit. A passing test count is evidence,
  not a feature, conversion result, deployment or performance gain.
- Maintenance is justified when it blocks that outcome. Name the blocker and the
  user-facing step it enables; do not present it as new conversion functionality.
- Reuse valid existing evidence when source, inputs and environment are unchanged.
  Run targeted regression for changed risks; investigate expired or uncertain
  outcomes rather than automatically replaying work. Required safety gates remain.
- Use `[performance]` only with measured results. Raising a capacity limit,
  selecting a different model or adding tests does not itself prove a speedup.

Each changelog item leads with these fields; detailed logs remain linked evidence:

```text
### [category] Short outcome
Impact: What changes for the user, or "Operations only; no new converter feature."
Change: The specific behavior or implementation changed.
Delivery: Source published / prepared / deployed, with the actual served version.
Verification: Focused checks and their scope; measured before/after for performance.
Remaining: Any unproven behavior or limitation.
```

Release updates to the user follow the same order: **what changed → where it is
available → what remains**. Verification details support that summary, not replace it.

## Versioning

- **Minor (0.x.0):** a visible workflow or supported conversion capability.
- **Patch (0.x.y):** a compatible fix or smaller quality-of-life improvement.
- **Major:** an intentionally incompatible product contract; explain migration.

While FOX is experimental, version numbers are not a production/support promise.
Native schema, template and target-profile IDs remain separate compatibility
contracts; do not rename them merely to bump the product version. The internal
converter distribution retains its component version unless that component is
intentionally released separately.

## Per-increment checklist

1. State the user problem, primary change category and concrete UI/conversion acceptance scenario.
2. Implement the smallest connected vertical slice. Preserve old projects,
   source versions, jobs and proof; do not bypass unknown outcomes or acceptance.
3. Update `fox/fox/release.json`, the frontend package/lock versions and
   `CHANGELOG.md`. Run `python -B tools/check_product_release.py`.
4. Test the changed backend/UI and packaging paths. Record actual results and
   limitations; use installed end-to-end proof for installed-flow claims.
5. Commit only reviewed sanitized task files, push to the agreed repository,
   create/push the unique `fox-vX.Y.Z` tag, then verify the remote commit/tag.
   Never force or move a published version. Fix it in the next increment.
6. Report the user-visible change, version, source link, actual deployment status
   and remaining gap, followed by concise verification. Keep private operational
   details and credentials private.

## Every pushed update has a changelog

For each FOX-scoped commit intended for publication, include a matching entry in
the product or applicable component changelog. A push containing several commits
must leave every shipped change covered; do not rely on a commit subject alone.
An entry may group related changes, but must identify what changed and its actual
verification/deployment status. Update the README when the current checkpoint,
user flow, setup or compatibility changes; it is not a duplicate per-commit log.

Documentation-only changes go under dated **Documentation updates** in the
product changelog. They do not bump `release.json`, package versions or software
tags. Do not rebuild/relabel a runtime merely to publish documentation.

When backfilling history, record both the original Git-recorded date and the date
the retrospective note was added. Link the original commit and describe only
what its evidence supports. Commit date is not a verified push, deployment or
acceptance date. Never amend/rebase old commits, change their timestamps, force
push, move tags or invent old test results to make the chronology look complete.
The [historical changelog](historical-changelog.md) follows this convention.

Publishing, preparing an image, activating it and verifying a conversion are
different facts. Do not edit a frozen image/manifest to relabel it. A deployment
must use a newly measured coherent build with preserved state and its actual
software identity. The UI compares its bundled version with the read-only server
release, without treating that comparison as technical or business acceptance.

## Next product increments

### Independently pinned deployment tools

Deployment-only corrections outside the measured application bundle may use
`deployment/RELEASE.json`, `deployment/CHANGELOG.md` and `fox-deploy-vX.Y.Z` tags.
Record the exact controller hash and the tested FOX version/bundle. This narrow
category does not apply to bundled backend, converter, frontend or runtime
configuration changes, which still require the full product release checklist.

Keep the existing application version, images, installation, frozen source and
handoff unchanged. Bind the new published tool bytes explicitly in a fresh tool
directory and transition plan; obtain a fresh successful inspection and all
normal backup/restore/activation evidence. An old handoff or failed inspection
cannot attest a corrected controller. Never move an existing application tag or
claim a deployment-tool test proves a completed conversion.

Developer-only QA tooling can be released independently. The project observer
uses `qa/product-project-journey/RELEASE.json`, its own changelog and
`fox-qa-vX.Y.Z` tags. Such a release must report the tested runtime separately
and must not bump/relabel the hosted FOX version or imply a live conversion
pass. Product/runtime changes still use the full product checklist above.

Prioritize guided intake/file requirements; actionable form/button/routine
dependencies and same-project reassessment; safe progress/recovery; and clear
native APEX output/target requirements. Validate each with positive, missing-input
and failed/uncertain-operation paths. Publishing documentation or a version alone
does not finish the conversion product goal.
