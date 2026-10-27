# Operations and support boundary

## Preserve state

Keep project/source/run storage, converter jobs, operation journals, keys,
wallets and protected secret references on persistent private storage. None is
part of the public source repository. Never use a source checkout as a backup
of a running system or commit run evidence to make a test pass.

Pre-profile legacy history is retained read-only. A missing profile is not a
default for new work: only the complete old source schema with matching hashes,
byte counts, terminal run and retained SQLite source rows is recognized by the
upgrade compatibility check. No snapshot is relabelled, granted processing
approval or rerun. Empty/ambiguous records or project markers still stop it.

## Diagnose before retry

| Observation | Safe next action |
| --- | --- |
| Missing source/DDL/key | Supply authoritative definitions; reassess a new source version |
| Unsupported business behavior | Obtain an explicit human decision; do not guess |
| Model/connection failure before side effects | Inspect the same run and its documented retry eligibility |
| Unknown schema/import result | Read-only reconcile exact target/job identity; do not replay |
| Invalid APEXlang | Keep import blocked and repair/regenerate a new bound result |
| Verification failed | Preserve evidence; distinguish technical failure from business rejection |
| Incomplete fresh installation | Report the missing route; do not fabricate history or disable admission |

Use the deployment's real run/status record, not a PID number or a green health
endpoint alone. Do not restart an unknown operation to clear an error message.

## Upgrade, backup and rollback

The existing-lab upgrade code binds source, paired image IDs, provider settings,
stopped candidate IDs and a genuine retained-history handoff. Its protected
backup captures a quiesced set and verifies an isolated restore before public
release. The upgrade is not an empty-host installer. Private historical records
are deliberately not supplied here.

Preserve the prior release/images and never use replacement/removal flags as a
recovery shortcut. Once a new release starts or writes project-format state,
an older release cannot simply resume serving that state. Use a reviewed
project-aware repair/maintenance path. Do not restore old application files
while leaving newer target tables/apps unreconciled.

Windows local assessment has its own Ctrl+C and exact-session resume route;
see [installation](fox-installation-v1.md). Cloud resource stop/start needs the
deployment's exact guarded operator runbook and authority, not guessed commands.

## Release criteria

A deployed pair, a generated ZIP, an offline passing suite and a human-accepted
application are four different claims. Before a connected release is demo-ready,
prove the shipped UI, multi-form conversion, compatible SQLcl validation, new
unique app import, native search/create/edit/save/cancel, interruption recovery
and exact downloads with labelled synthetic data. Record gaps honestly.

FOX is experimental, not an Oracle-supported product or production migration
service. Customer deployment requires its own approved target, prerequisites,
processing permission, installation and acceptance evidence.
