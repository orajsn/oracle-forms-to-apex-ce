# FOX incremental releases

Each completed product increment has a semantic version, changelog entry,
reviewed source commit, relevant verification and a `fox-vX.Y.Z` Git tag.
Existing CE versions/tags are independent and must not be replaced.

- **Minor (0.x.0):** a visible workflow or supported conversion capability.
- **Patch (0.x.y):** a compatible fix or smaller quality-of-life improvement.
- **Major:** an intentionally incompatible product contract; explain migration.

While FOX is experimental, version numbers are not a production/support promise.
Native schema, template and target-profile IDs remain separate compatibility
contracts; do not rename them merely to bump the product version. The internal
converter distribution retains its component version unless that component is
intentionally released separately.

## Per-increment checklist

1. State the user problem and a concrete UI/conversion acceptance scenario.
2. Implement the smallest connected vertical slice. Preserve old projects,
   source versions, jobs and proof; do not bypass unknown outcomes or acceptance.
3. Update `fox/fox/release.json`, the frontend package/lock versions and
   `CHANGELOG.md`. Run `python -B tools/check_product_release.py`.
4. Test the changed backend/UI and packaging paths. Record actual results and
   limitations; use installed end-to-end proof for installed-flow claims.
5. Commit only reviewed sanitized task files, push to the agreed repository,
   create/push the unique `fox-vX.Y.Z` tag, then verify the remote commit/tag.
   Never force or move a published version. Fix it in the next increment.
6. Report version, user-visible changes, verification, source link and actual
   deployment status. Keep private operational details and credentials private.

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
