# Forward transition of the existing JSN pair

`current_pair_transition.py` is a separate administrator path for an already
installed project-aware pair. It never calls the legacy G cutover or an old
verification pump. It is not a general customer-tenancy deployment command.

The caller supplies a canonical plan and independent SHA-256 binding the old
and new installation, old/new verifier units, measured helpers, recovery reader
and hosted snapshot configuration. The current verifier unit must point to the
old pinned installation. Old source is verified before importing its canonical
admission, real operator lock and snapshot authority. New checks run in fresh
children; old and new Python namespaces are not mixed.

Commands are `inspect`, `apply --apply` and read-only `status`, each with
`--plan` and `--plan-sha256`. Inspection checks current resources, stopped
candidates, source/profile/runtime boundaries, service syntax and backup limits.
On a labelled host it also checks the two new nonsecret profile files against
their working access-label references before any service stop. Prepare only
those exact new-file labels when required. Do not disable SELinux, recursively
relabel shared data, change key/wallet permissions or alter source bytes.
Only an explicit apply can drain public access, stop the old pair, capture a
full backup and test an isolated restore, retain the old containers, assign/start
the new pair and verify its actual connectivity. It then replaces the verifier
unit, observes a genuine first idle claim and releases HTTPS. The normal verifier
may keep polling inside its bounded batch; an idle claim is not relabelled as a
completed batch. Any already-completed session's normal seal is still checked.
The observer waits up to three minutes for that first recorded claim, covering
the measured cold-start delay without restarting the service or inventing a
claim when the bound expires.

Original journals and failures are exported and retained unchanged. A closed
precheck is not a successful session or permission to retry its claim. The
transition creates no application and does not run conversion, model inference,
live restore, resource deletion or new OCI infrastructure. Technical conversion
proof and genuine human business acceptance remain separate later gates.

Every command effect uses create-only intent/process/exit records. There is no
automatic rollback or replay. If a response is lost, use `status` to inspect the
original process and exact phase records. Do not call apply again: an existing
attempt is preserved, and an unresolved phase needs explicit reconciliation.
The old containers must not be restarted on new state merely to recover a URL.

## Explicit prototype-history preservation

The optional `preclaim_preservation` reference binds a reviewed baseline to one
known stopped history. It is not a request to run that history again.

- `fox-reviewed-preclaim-terminal-baseline-v1` preserves an unclaimed validation.
- `fox-reviewed-claimed-validation-terminal-baseline-v1` preserves the original
  consumed validation request before a validation result exists.
- `fox-reviewed-schema-prewrite-terminal-baseline-v1` preserves a successful
  retained validation followed by a terminal `prepare_schema` request that did
  not enter schema writing. This narrow variant requires the existing consumed
  validation-maintenance claim/handoff history; it is not a generic failed-job
  classifier.

The schema-before-write variant uses a separate protected reader purpose and
packet map. It reconstructs the schema request from the original candidate and
matching validation receipt, checks the log and recovery history, and rejects
schema SQL, write intents, later-stage artifacts or any unknown files. Both
trees, current owner/source, measured technical reconstruction, actual operator
lease, producer state, fresh readback and stopped-writer checks remain required.
The terminal handler must be the exact declared stage on the pinned old pair.

Successful preservation means only that the transition can retain that failed
history honestly. Ordinary admission stays blocked, retry remains unavailable,
and no run is closed, accepted or relabelled successful. Audit-session closure
and any subsequent conversion continuation retain their own separate gates.
Never replace an old baseline's hashes merely to make a different failure fit.
