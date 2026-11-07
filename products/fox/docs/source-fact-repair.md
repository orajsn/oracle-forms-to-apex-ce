# Repair a source mismatch without restarting the file

An AI reviewer can approve a statement that still fails an exact source check.
FOX keeps those facts separate. A failed source check cannot be turned into a
pass by changing an approval flag or silently dropping the affected behavior.

## What the repair does

For a proven, supported stopped checkpoint, FOX can make one new targeted model
request using the original source, saved candidate and precise diagnostics. This
is a distinct repair operation, not a replay of the original request. Its result
must preserve unrelated mappings and pass source checks and a new independent
review. The original response and its historical review remain available.

Some failures are structural rather than behavioral. A section may repeat a
background Block already reviewed in its owning section, or use a noncanonical
property name for an exact source value. FOX can project these only when the
mapping, ownership and evidence agree. Excluded records and rationales are
retained and presented to the reviewer, not silently discarded.

## User flow

1. Choose **Check repair plan** on the current stopped prototype run.
2. Read the separate AI-review and source-check counts, corrective operations
   and remaining-work summary. Checking the plan does not call a model.
3. Review the original source selection and confirm the three processing
   permissions again.
4. Choose **Repair and continue**. FOX appends a new continuation record and
   continues the same run only after the corrective checks pass.

Every continuation binds its predecessor and exact checkpoint. A saved request
is not dispatched again merely because its response was lost. Missing records,
changed sources or targets, conflicting history, rejected output and uncertain
operations stop processing for reconciliation.

The repair does not invent missing customer logic or certify business behavior.
APEX generation, import/runtime evidence and human business acceptance remain
separate outcomes. The export must use the exact active reviewed candidate and
its full retained provenance.
