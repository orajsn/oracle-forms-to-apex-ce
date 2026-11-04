# Prepare an existing JSN pair for an upgrade

These administrator tools prepare configuration and **stopped** replacement
containers. They do not switch the live site, retire a journal, run conversion,
import an app or grant business acceptance. They are not a customer-tenancy
installation command. The existing JSN-only scope remains enforced.

The original schema-1 activation plan still describes the first G-to-project
installation. Do not reuse that cutover controller for a current paired upgrade.
The controller explicitly rejects a schema-2 upgrade plan.

## Preparation

1. Build an immutable paired source bundle and both images using the documented
   offline builder. Retain the successful build receipts and image/source labels.
2. Pin the current installation document by its independently verified path and
   SHA-256, not a container name or an assumed historical baseline.
3. Inspect with `prepare_project_upgrade.py`, supplying the source-bundle digest
   and current installation reference. Only `--apply` creates the new private
   configuration directory. It refuses an existing attempt rather than overwriting
   or replaying it.
4. Use the emitted schema-2 plan with `activate_project_release.py inspect`, then
   explicitly `create --apply`. Creation preserves existing mount, user, security,
   resource and network boundaries, replacing only the bound profiles, images and
   release environment. New containers remain stopped.

The new configuration retains the existing protected access references, state
root and interpreter. It selects the exact registered target from the measured
bundle; it does not infer a patch version from the live database or environment.
VM/ADB scope and current I/C/R/D/source/profile bindings are rechecked before
preparation effects. The preparer requires actual successful build receipts,
distinct paired image IDs and matching source-bundle labels.

## Before switching the site

Preparation is not activation authority. A forward cutover still needs a current
operator exclusion, fresh idle/history observation, complete verified backup and
isolated restore, retained old journals/artifacts, candidate readiness, exact
new admission/installation bindings and a controlled service transition. Never
manufacture `SESSION_COMPLETE`, erase an old claim or replay uncertain model,
DDL or import work to make an upgrade look successful.

Retired ancestry may need a new destination binding. The offline
`readdress_project_history.py` helper preserves every historical source/proof
fact and embeds the original attestation, installation reference and destination
bytes under a hash-labelled provenance path. It proposes an exact plan before
sealing; it does not repeat the original checks or claim that the current hosted
producer has been retired. Current journal export, exclusion and the live
transition remain separate cutover evidence. An invalid old authorization,
changed parent bytes or future issuance cannot be repaired by repackaging them.

If a response is lost, inspect the existing plan, original process/exit records
and exact containers. The `status` command is read-only and does not create,
start, stop, adopt or retry anything. A partial preparation remains an operator
attention state until its original outcome is established.
