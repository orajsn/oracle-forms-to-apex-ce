# Understand a saved conversion

Open a project's **Output** step, then expand **Saved progress and form
responses** on the run you want to inspect. Each card retains its own stage
checkpoints, source-version reference and per-form responses. Reopening a
project does not require starting conversion again.

The original form and source labels come from that run's retained source
snapshot. If you rename or replace a Form later, its earlier output keeps its
original labels. An older deployment that has not reported those labels shows
the module reference and explains the gap rather than substituting newer names.

## Know what finished

- **APEX generated:** the application output is retained. Per-form generation
  does not establish complete-project technical verification.
- **Technical verification:** release checks need separate evidence. An
  attention message identifies the next action and who can help.
- **Business behavior:** genuine human validation is still required; viewing
  history or refreshing status cannot accept it.

**Check run status** reads the existing project/run state. It does not generate,
import or accept an application. If the result of an earlier operation is
uncertain, check status and follow the reported next action. Do not create
another conversion merely to resume technical checks. A retry/continuation
requires an explicitly safe action from the server; this feature adds none.

Stage activity is a saved report, not proof that a process is running now. No
progress percentage, missing check or unavailable result is assumed successful.
An earlier-source output cannot certify your currently selected files. Existing
review/download rules still apply.
