# Continue with a reviewed result

FOX can reuse an exact, independently reviewed clause analysis when an eligible
mapping repair stopped before database work. It continues the same run; it does
not restart the whole form, replace prior evidence or assume business acceptance.
This is a bounded prototype recovery path, not a universal Forms conversion claim.

## Business-user flow

1. Open the project's native APEX prototype section and choose **Check repair plan**.
   This only reads the saved state; it does not invoke AI or start a conversion.
2. If reviewed-result continuation is available, FOX explains that the saved
   clause analysis and its independent review will not run again. One new review
   checks the next section's projection before unfinished sections continue.
3. Choose **Review prototype scope**. The previously approved source selection
   must match and remains locked. Confirm the three processing acknowledgements.
4. Choose **Continue with reviewed result** once. Follow that same run's status.
   If the response is uncertain, check the recorded state; do not repeat a request
   merely because the browser stopped waiting.

The old failed attempt remains visible in history. AI approval, deterministic
source checks, APEX generation, runtime verification and human business acceptance
are distinct. A new interpretation is not automatically an implemented APEX action.
Missing dependencies and unsupported behavior remain explicit remediation items.

## Operator prerequisites

The original source, selected code units, owner, target and two preceding
continuation records must be intact. Only the recognized sealed repair response
that removed two unsupported clause claims without replacing their required
behavior is eligible. Pending calls, unfamiliar records, changed source or
database-stage work are not eligible for this path.

The dedicated tool-free clause workflow and its registration helpers are in
`deployment/forms_clause_analysis_profiles.py`,
`deployment/forms_clause_analysis_registration.py` and the matching prompt.
They reuse configured model connections; registration is not activation or proof
that inference succeeded. Processing approval still applies to the selected
source and configured model route.

Preserve the complete original diagnostic: whole clause request, actual model
invocation/environment evidence, deterministic assembly, derived candidate and
separate independent review. The strict retained-proof reader checks the complete
14-file archive against an independently trusted manifest. Its Python file is
identity evidence only and is never executed.

After that check, stage only the exact 13 JSON members and an operator-controlled
descriptor under the configured data root:

```text
prototype-clause-proofs/<run-id>/
  descriptor.json
  json/<fixed JSON evidence members>
```

The descriptor pins the job, project, owner, original snapshot/source/target,
additional analysis role, assembler identity, original manifest and derived
candidate. Staging directories must be private, process-owned and free of linked
ancestors; files must be bounded regular files without hardlinks or group/world
write permission. Do not supply arbitrary paths through HTTP. File presence is
not owner consent, and no evidence Python belongs in staging or transport.

The existing authenticated epoch API binds the descriptor digest, predecessor,
checkpoint and three fresh confirmations. It appends epoch 3 and queues the same
run once. The additional analysis role authorizes reuse of its completed proof
only; it does not replace the production mapper or authorize new clause calls.
The original target profile and source snapshot remain unchanged.

## What still gates the output

The converter reconstructs the complete active source/review history from exact
JSON evidence. Deterministic rendering and SQLcl validation, a unique
non-overwriting import, applicable authenticated runtime checks and the exact
retained export must still succeed. The continuation does not bypass any of them.
It neither proves clean-schema reimport nor compatibility with an unspecified
customer database. Human business acceptance remains a separate decision.

Local authored-provider tests and a source release are not live conversion proof.
Operators must verify the installed release and actual hosted journey separately.
