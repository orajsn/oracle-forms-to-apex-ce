# Continue a stopped mapping from saved progress

Some AI responses use a code-unit reference where FOX expects the Forms object
that owns that code. FOX can resolve that reference only when the supplied
source records one exact owner in the same section. It cannot invent an owner,
repair missing customer logic or treat a context-only object as owned.

The original AI response stays unchanged. A separate resolution record binds
the original request and response to the resolved candidate. The independent
reviewer must review that candidate, and later validation must reconstruct the
same evidence before any APEX import.

## Business-user flow

1. Open the current project's stopped prototype run and choose **Check saved
   progress**. This only inspects retained evidence.
2. Review how many sections already passed review and how many source references
   can be resolved. The existing source and selected code units are preserved.
3. Review the prototype scope and confirm the three processing permissions.
4. Choose **Continue from saved progress**. FOX continues the same run; it does
   not create another application attempt or repeat completed model calls.

Continuation still has work to do: review the resolved section, analyze and
review remaining sections, validate the generated APEX source, then import and
test only if all required gates pass. It is not a conversion success or business
acceptance decision.

## When continuation is unavailable

- A model request has an uncertain or incomplete outcome.
- The reviewer already rejected the failed section.
- Source, ownership, target or retained checkpoints changed.
- The reference cannot be resolved uniquely from the supplied source.
- Database work or a later execution stage already started.

An interrupted continuation request must be reconciled against its saved record.
Do not reset the run, delete the record or repeatedly press a processing button.
An existing recorded continuation is returned without dispatching it again.

The older **Retry mapping in smaller steps** path creates a distinct child for a
different, proven first-mapper failure. It is separate from this same-run action.
