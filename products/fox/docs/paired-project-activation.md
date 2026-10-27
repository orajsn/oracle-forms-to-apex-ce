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

## Installer prerequisites found on Oracle Linux 8

The tested systemd 239 adapter leaves the frozen service program unchanged.
It writes `WorkingDirectory` as a plain, validated absolute POSIX path, while
preserving `ExecStart` quoting, restart policy and all other service settings.
Before starting, validate the real unit with `systemd-analyze --user
--generators=no verify`, supplying the actual loaded generated network unit as
an additional input. Never invent a dependency, run generators, or suppress a
failed parser result to make a check pass.

The configured private state root must contain owner-private `clean-install`
and `project-clean-install` working directories before starting the verifier.
The current journal implementation requires the native working root to exist;
read-only admission does not create it. Validate ownership, mode, canonical
paths and absence of links. Do not modify another installation's state or
reinterpret a failed startup as an idle claim.

The real lab has passed paired application/read-only connectivity checks, but
its verifier startup is still held at this directory prerequisite. Public
release and the installed multi-form conversion proof are not completed by
these source changes. Fresh customer installation remains unfinished.

## Specific forward continuations

The controller contains narrowly guarded forward cases for a converter already
started while FOX is still never-started, and a verifier unit rejected by the
systemd parser before execution. They retain parent intents/exits and require
actual current identities and locks. They are not general retry commands. A
unit repaired and subsequently executed cannot use the parse-repair case again.

Internal MCP discovery uses the existing OPAF image's `curl`, with bearer
headers delivered through protected stdin. It checks unauthenticated rejection,
the MCP session, and the exact five tool names without invoking conversion or
models. No Python installation or public port is added to OPAF.
