# Continue remaining sections

FOX can reuse a saved independent approval for an unchanged section and continue
unfinished work. This bounded route addresses a recorded shared-screen review
failure; it is not a general retry button or a promise that every form converts.

## What the user sees

An eligible stopped run offers **Continue remaining sections**. It shows how many
sections have retained approvals and how many remain. The original sources stay
locked. The user confirms the displayed processing scope before continuing.
Earlier failed reviews remain visible as history rather than being relabelled.

Checking a large saved run can take time. Continuation-plan checks and submission
wait up to 45 seconds for the verified response. A timed-out plan check has not
started conversion. A timed-out submission is different: check the existing run
before taking another action, because the server may already have recorded it.

If the submission outcome is uncertain, inspect the existing run. Do not create
a second run or repeat completed work to force progress. Missing or inconsistent
proof requires operator attention, not a business user's manual file editing.

## What FOX checks

- The original source, selected code, owner, target and previous continuation
  still match the recorded job and its approval events.
- The retained review approved the exact unchanged candidate. Its request,
  invocation, response and source-bound context must all match.
- Compact context round-trips to the full checked context. Deduplication does
  not remove code, source objects, mappings or substantive review requirements.
- The old failure and every predecessor file remain intact. Only the controlled
  latest-result pointer changes, with its previous bytes archived.
- Completed sections cannot issue new model calls. Remaining sections still
  require generation, independent review and deterministic checks.

The operator stages only the exact JSON proof package in the private data area.
Staging alone does not authorize processing. Browser requests cannot select
evidence paths, execute archived code or turn arbitrary saved output into proof.
Unknown model outcomes and partially recorded operations remain blocking.

## APEX is still the finish line

A section's approval does not mean an APEX application exists. FOX must finish
the application design, validate the generated package, import a new application
without replacing an existing one, and complete the applicable runtime checks.
The download remains tied to the exact checked package and current authority.

Generated, technically verified and business behavior accepted are separate
states. Human acceptance is never inferred from a model verdict or a test pass.
Source publication, deployment and an actual completed conversion are also
reported separately.
