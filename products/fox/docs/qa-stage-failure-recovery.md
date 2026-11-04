# Diagnose a stopped project QA handoff

This operator-only reader covers a specific failure after a project has been
generated and clean-imported, but before browser-test staging. It does not
recover, retry, close or promote the run. Business users should see that their
APEX output exists and that an administrator must repair verification; they
must not be asked to restart containers or repeat a conversion.

`qa.operator.qa_stage_reconciliation.assess_capture` checks a protected capture
against independently reviewed installation, release and converter identities.
Its supported case requires:

- One known original claim and the complete, unchanged 17-file journal through
  the unfinished `qa_stage` intent, with no later-stage completion or intent.
- Matching generated package, clean plan, allocation, synthetic schema/import
  receipts, target-version policy and native page/table metadata. All completed
  operations remain part of the record, not candidates for replay.
- A failed/stopped verifier, no observed SQLcl/browser processes, no stage
  directory or corresponding images, and no launch/dispatch receipt.
- A positive read-only reproduction of the specified missing verification
  module in the exact converter, bound to the original QA source.
- No technical proof or human acceptance.

The reader never opens a connection or file itself. A capture or a successful
classification is not proof of live ownership or exclusion. A separate guarded
operator must establish those facts, retain/export original evidence, re-observe
the exact current state and use a separately reviewed disposition or
continuation protocol. That live protocol is not provided by this reader.

The separate protected backend offers explicit
`initialize_qa_stage_failure_ledger(apply=True)` and
`close_qa_stage_failure(...)` primitives. The latter requires exact reviewed
assessment bytes and a callback that freshly re-observes/classifies under the
operator's real exclusion. It appends a failure once, preserving original
queue/run/claim rows and job files. Its SQLite record has update/delete fences;
changed source, mixed failure families or lost metadata block admission. An
identical recorded append is read back without replay. These primitives do not
obtain a host lease, create a backup, close a journal seal, restart services,
run browser tests or authorize an automatic retry. No public mutation endpoint
is added. They are not a substitute for the guarded host recovery protocol.

Do not apply the earlier `clean_check`-only failure closure here. An imported
application already exists. Do not fabricate completion records, reset the
claim, delete the application, repeat completed model/import operations or mark
the package verified. Unknown or mixed evidence remains stopped for inspection.

`project_qa_contracts.prepare_evidence` validates the retained import metadata
without accepting runtime credentials. The ordinary browser-runner handoff
still uses `prepare_inputs`, which additionally requires both protected test
identities. Credential-free inspection does not bypass runner authentication.

Local regression fixtures exercise both registered APEX version profiles.
They contain authored synthetic observations and are not evidence of a live
APEX installation or browser-test pass.
