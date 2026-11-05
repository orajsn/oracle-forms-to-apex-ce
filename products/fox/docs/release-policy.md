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

Publishing, preparing an image, activating it and verifying a conversion are
different facts. Do not edit a frozen image/manifest to relabel it. A deployment
must use a newly measured coherent build with preserved state and its actual
software identity. The UI compares its bundled version with the read-only server
release, without treating that comparison as technical or business acceptance.

## Next product increments

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
