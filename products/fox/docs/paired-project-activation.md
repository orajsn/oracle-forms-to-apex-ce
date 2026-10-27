# Existing-lab activation boundary

The retained-history upgrade has ordered stop, capture, isolated restore,
activate, readiness and public-release phases. They require genuine held
operator leases and source-bound capabilities, not a `ready` flag or a copied
receipt. The public source is not sufficient authorization or private state to
perform these phases.

`cutover_project_release.py` deliberately has no direct service-action CLI.
`project_release_readiness.py` checks connectivity/identity without generating
an app or accepting its behavior. Use the separately maintained, exact approved
deployment runbook for an authorized existing installation.

Preserve originals and reconcile the same attempt after a lost reply. Do not
repeat closure, DDL or import. A prior release is not a serving fallback once a
candidate starts or project-format data appears. Fresh installation remains a
separate unfinished route; never bypass admission to simulate it.
