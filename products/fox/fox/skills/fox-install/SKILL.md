---
name: fox-install
description: "Check prerequisites, set up, verify or resume FOX from a supplied checkout or release. Use for FOX installation and operator handoff, not Forms conversion or business acceptance."
---

# FOX installation

Help the operator use the selected release's actual installation route. This is optional setup assistance: FOX business users do not need Codex or this skill to use an installed product.

## Resolve the product and authority

- Resolve the supplied checkout/release, not this skill's installation directory. A standalone FOX runtime root has `requirements-lock.txt`, `package.json`, `scripts/start-local.ps1` and `fox/local_assessment.py`. Some development workspaces contain that runtime under `fox/`, with separate packaging tools at the parent root. A frozen hosted source bundle instead contains `qa/operator/hosted_service.py`, `converter/forms2apex/target_profile.py` and built `fox/dist` assets, with its source inventory outside the bundle. These are different layouts, not interchangeable installers. Set the selected roots explicitly and use only files actually supplied.
- Read the selected release's `docs/fox-installation-v1.md` and applicable repository instructions. Older assessment bundles use `docs/fox-installation.md`; a missing newer guide alone does not invalidate them. If neither guide exists, inspect its README and declared entry point before proposing a route.
- A hosted source-only bundle may contain neither guide nor README. Request or locate its separately supplied release guide/checksum declaration; do not treat a module entrypoint as an installer or label the bundle corrupt merely because documentation is outside it.
- Distinguish FOX from the separate Oracle Forms-to-APEX CE skill/workbench. A skill folder or `install.py` without the FOX runtime is not a FOX installation. Do not silently switch products or invent a missing installer.
- Preserve the requested mode: check, install local assessment, prepare a bundle, inspect an existing authorized hosted service, or set up a new connected service. A check request is read-only. Reuse permission for the exact requested scope, but do not infer cloud/customer deployment, software download, public exposure or global skill installation from it.

## Check before changes

For the approved public repository, FOX is under `products/fox`; the repository's
root `install.py` installs the CE skill, not the FOX product. Resolve the selected
checkout/release and operator-approved installation directory explicitly.
Where its actual setup entry point offers `inspect`, run:

```text
<python> scripts/fox-setup.py inspect --installation-root <selected-directory>
```

This classifies only that directory. A missing directory can lead to a reviewed
installation plan, but does not authorize downloads or imply machine-wide
absence. A source checkout, assessment session or retained deployment state
requires its own checks, never overwrite/adoption. Exit 0 is a completed
observation, not installed or conversion-ready. Continue through the selected
release's real route; do not invent an install command where none is shipped.

Inspect the selected interpreter, lockfiles, launcher, built UI, storage location and requested loopback port. Use installed dependency metadata rather than importing `fox.app`: that import initializes storage. A source build needs Python and Node/npm compatible with its declared files; a reviewed bundle with built assets may not need Node.

When the supplied parent-level package includes `scripts/fox-setup.py`, its schema and a release declaration, inspect its CLI and run documented `check` using the intended runtime interpreter. Current source offers read-only `inspect`, `check` and create-only `prepare`. Its developer-only `storage-plan` / `storage-initialize` phase reuses S0 on nonroot Linux; it is not a complete install/start/activate/restore command. Read `docs/installer-storage-step.md` only when that specific phase is requested and supplied. Require the exact reviewed plan hash and explicit apply authority, preserve partial attempts, and never call storage-only completion installed or conversion-ready. Older releases may omit newer commands; follow their actual CLI. The development example is deliberately unfrozen and should report `NOT_READY`; never invent hashes to make it pass. A standalone Git checkout without this packager can still use the documented local route, but must not be reported as a checked frozen bundle.

Report missing prerequisites and the proposed changes. An intact package or passing prerequisite check is not a running service, Oracle compatibility certification or conversion readiness.

## Use the supported local route

Follow the selected guide's real commands. For the current Windows checkout, from the runtime root:

```powershell
# Only after dependency installation/build is authorized:
py -3.12 -m venv .venv
.venv/Scripts/python.exe -m pip install -r requirements-lock.txt
npm ci
npm run build

# Operator starts the UI and supplies the password at its secure prompt:
./scripts/start-local.ps1 -Port 8100
```

Inspect an existing `.venv` instead of recreating it. `npm ci` replaces generated `node_modules`; do not apply it to an unrelated/shared environment. Stop on each failed command. For a frozen bundle, follow its declaration and do not rebuild frozen assets in place. Do not change system Python, execution policy or firewall settings to bypass a failed prerequisite.

The current launcher defaults new sessions to `fox-local` and supports `-Username` for an explicit login identifier. Follow the printed effective username; older releases may differ. Passwords use the secure prompt/protected stdin, never arguments, environment, logs or source. The internal Python entry point also accepts `--username`, but it is not a general interactive CLI: its remaining request is protected stdin. Prefer the PowerShell wrapper.

This route binds only `127.0.0.1` and disables conversion/OPAF/APEX connections. Verify `/api/health`, the expected product/version and disabled worker, then the authorized assessment flow. A listener alone does not prove successful login or assessment. Do not enable conversion through inherited environment variables or expose this preview publicly.

Fresh sessions use `native-project-v1` for multi-form assessment in the matching built UI. A `READY` shared plan is planning only; Process remains disabled. Resume preserves the exact saved profile: older `native-table-form-v1` sessions retain their earlier assessment view. Neither request arguments nor inherited environment may select an arbitrary profile. Do not edit saved markers to upgrade them; use a separate new session when the newer view is requested.

Binary preparation requires separately approved, already-installed Oracle Forms/Java tools. Supply both `-OracleHome` and `-JavaExe` explicitly; readable-source assessment needs neither. Presence checks do not prove compatibility, extraction completeness or entitlement. Do not download, copy or redistribute Oracle software as part of FOX without appropriate authority and rights. Keep raw binaries local and require review before readable-source handoff.

## Preserve and resume

The launcher prints an exact `session-` identifier and stores owner-private state under `work/local-assessment`. Stop with Ctrl+C in its launcher terminal. Resume only the selected session using `-ResumeSession` and its original password, port and optional tool paths. Omit `-Username` to use the saved identity, or supply its exact original value; a different username must not rebind saved projects.

Resume restores projects and source history, not preparation execution. Retain interrupted files; do not retry extraction/import automatically, remove locks, select the newest folder, repair permissions silently or create replacement storage. A timeout or absent process is not proof that a write completed or stopped; inspect the same retained attempt first.

## Package or connected setup

For requested bundle preparation, use the supplied preparer with a reviewed frozen declaration and a new destination. `PREPARED_NOT_INSTALLED` is the handoff state, not activation. Exclude credentials, wallets, private keys, customer files and Oracle media. Development candidates under `work/` are not released installers.

For an existing authorized hosted service, inspect its deployment-bound runbook/configuration and current status before acting. Never copy a lab address, user, target identity, credential or dated rollout command into another installation.

If the selected installation-tools checkout supplies `deployment/prepare_project_release.py`, `build_project_release.py` and `activate_project_release.py`, first read its `docs/paired-project-release-build.md` and applicable activation guide. They describe the existing JSN migration path: a built source/image pair is not activation, and the candidate creator creates stopped containers only. Use a short output path for Windows builds; do not delete a failed attempt or reinterpret a timeout as permission to repeat a state-changing phase.

A new connected deployment needs a coherent released UI/API, converter and background verifier, configured target/secret references, install/start/status/recovery entry points and approved end-to-end evidence. An existing-history migration is not a fresh-install route. The current hosted supervisor requires genuine retained-history admission; copying the lab's jobs/proofs, creating a fictional retirement record, or disabling that gate cannot initialize an empty installation. If the selected release lacks a distinct supported fresh route, name that exact gap and stop the fresh deployment; do not substitute assessment-only startup or grant privileges to force readiness.

For an upgrade with interrupted history, distinguish read-only inspection from the permanent closure/export step. Honor an execution guard's request for exact human approval, and keep the serving release unchanged while it is pending. Do not retry through another tool or bypass the handoff. Keep generated output, technical verification and business acceptance separate throughout installation tests.

## Handoff

State what was actually achieved: checked, prepared, installed, started, assessment-ready or conversion-ready. Include observed versions, URL, protected login method, exact private session/storage reference, stop/resume instructions and remaining actions. Keep generated output, technical verification and human business acceptance separate. Never create business acceptance as an installation test.
