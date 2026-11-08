# Review saved mapping and continue

A large Forms module can be analyzed in sections. A later section may repeat
the same screen declaration even though an earlier section already owns that
screen. This is a technical duplication, not necessarily a missing form or
missing business rule.

FOX can remove that declaration only when it exactly matches the earlier one,
its source Block has one proven prior owner, and the current references are
Items or Triggers belonging to that Block. Different titles, competing owners,
unrelated objects or behavioral changes are not guessed away.

The original mapping stays intact. Only the repeated declaration is removed
from a separately derived candidate. Every owned object, claim, action,
relationship, question and assumption is preserved. Independent review still
has to approve the whole candidate before processing continues.

## What the user sees

An eligible stopped run offers **Review saved mapping and continue**. The screen
distinguishes sections already reviewed, the saved mapping awaiting review, and
sections not yet started. The original code-unit selection stays locked, and
the user confirms the processing scope again.

The first new operation is independent review of the saved mapping—not another
generation request. A rejected review stops before the next section. An unknown
submission or model outcome must be checked, not resubmitted automatically.

## What this does not mean

A technically valid projection is not AI approval or business acceptance. It
does not supply missing packages, database definitions or the meaning of
redacted literals. Those remain explicit limitations or remediation work.

An APEX file becomes available only through the normal validation, unique import,
runtime and export checks. Existing applications and earlier failed results are
not overwritten. The original unreported result remains unreported; FOX does
not manufacture successful history to make a continuation appear complete.
