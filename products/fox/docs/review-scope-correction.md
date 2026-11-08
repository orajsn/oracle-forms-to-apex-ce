# Review a saved mapping again

Sometimes an AI review refers to an object from another section as though it
belongs to the section being reviewed. FOX treats that response as invalid;
it does not mean the original Forms file is missing that object.

For the supported saved-review case, FOX can request one corrected independent
review without regenerating the mapping or restarting the whole conversion.
This is not an option to override a genuine business or mapping defect.

## In the project

1. Open the affected conversion and select **Check repair plan**.
2. If eligible, FOX explains: **Review response referred to an object outside
   this section. Your saved mapping is preserved.**
3. Review the prototype scope. The original code-unit selection is locked;
   confirm the three processing statements beside the review action. Expand
   **View locked code units** to inspect the selection without changing it.
4. Select **Review saved mapping again** once.
5. Check the existing run. A valid approval lets the remaining work continue;
   a valid rejection still needs resolution. Another invalid or uncertain
   response stops instead of starting an automatic retry loop.

If the request was already recorded, or the browser lost its response, check
the existing run status. Do not submit another request to work around a timeout.
If the source or target changed, refresh and follow the applicable recovery path.

## What FOX preserves and checks

- Original source, completed mappings, previous approvals and the invalid review.
- A separate correction request linked to that exact source, candidate, target
  and previous response. It cannot replace the original response.
- Explicit ownership information: objects in the current section, context-only
  objects, and screens inherited from earlier reviewed sections.
- One distinct reviewer invocation; the saved mapper is not invoked again.
- Duplicate-request protection and fresh source, ownership and consent checks.

The same clearer ownership information accompanies new later reviews after the
correction is authorized. Historical requests are not rewritten. A reported
defect about an owned object or an application-level issue is not silently
converted into this technical correction route.

## What this does not prove

A corrected review is not an APEX export or business acceptance. Generation,
SQLcl validation, a non-overwriting import, runtime checks and export still have
to finish. Follow the output package's stated requirements; exact-package
reimport and clean-schema installation are separate evidence.

## Operator boundary

The correction is a child attempt beneath the retained mapping epoch, not a new
full conversion. Its authorization and model records are append-only. Changed
bindings, incomplete calls, unexpected files or later work block admission.
Only deterministic proof derivation may be reused within an existing read-only
operation; live ownership, selected source, consent and target checks stay fresh.
No cache crosses a model operation or package HTTP request.

Current-authority network operations use a 30-second socket timeout, not a hard
total callback deadline. The output-readiness UI aborts after 30 seconds. A timeout
is not approval and does not restart a conversion or import. The package download
uses its separate existing transport budget; downloading does not imply that
the package has been independently reimported.

Developer tests distinguish local API/browser/ZIP checks with authored external
responses from an actual OPAF/Oracle conversion. Installation and health checks
alone do not establish that a real source has passed this path.
