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
