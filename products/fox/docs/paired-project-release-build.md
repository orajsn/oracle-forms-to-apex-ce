# Paired release tooling scope

`deployment/prepare_project_release.py` assembles an immutable source bundle;
`build_project_release.py` builds its paired FOX/converter images; and
`activate_project_release.py` prepares stopped candidates. They are the
existing guarded JSN upgrade route, not a general fresh installer. The current
builder inherits existing lab images and is not a clean standalone image build.

Read each tool's actual CLI before use. A built source bundle or stopped
container is not a running product. Use a short Windows destination, retain
failed artifacts and never mutate a frozen bundle. Do not use old service files
with removal/replacement flags or relabel shared storage to make probes pass.

Activation requires the actual approved installation, source/image/provider
identities, retained-history handoff and private consistent backup/restore
receipts. Those records are intentionally excluded from this public repository.
Their absence must not be repaired with invented matching JSON or another lab's
secrets. See [activation boundary](paired-project-activation.md).

## Converter QA dependency closure

The converter image must also contain the fixed six-file pure QA namespace:
`__init__.py`, `intake.py`, `native_source.py`, `project_conversion.py`,
`native_qa_plan.py` and `project_qa_plan.py`. These are byte-for-byte projections
of the same reviewed FOX sources, not the frontend application or a per-job
installation. The corrected build context copies that namespace and imports
the project QA derivation functions during the image build.

Archive validation checks the complete projection against its independently
pinned source bundle. Historical archives without this projection still
validate as historical evidence; that does not make them technically ready.

The first real two-form UI trial generated its package but stopped at the
clean-verification precheck because the deployed image lacked this dependency.
The failed trial is retained. Corrected image source is prepared, but replacement
image activation, same-job recovery and full runtime proof remain separate work.
Do not hot-patch root-owned application code, rewrite an old image identity,
restart the failed supervisor blindly, or replay the conversion/import.

## Build after the original G bootstrap

The optional `--deployment-file <installed-D.json> --deployment-sha256 <D-SHA>`
pair explicitly selects the actual current deployment for `stage`, `inspect`
and `build`. Both flags are required together. The owner-private canonical D
must bind the exact three running container IDs/images and FOX's selected
release/profile. The VM identity, JSN compartment and region stay fixed.
Omitting the pair retains the original G-only path; no fallback is inferred.

Stage/build receipts bind D and compare process/start/static-configuration
identities before and after work. Build uses only cached base images with
`--pull=never --network=none`, checks actual rootless storage capacity, and
records the original process's exit and Linux identity. A lost response or
existing intent requires inspection of that same attempt, not another build.
No command in this route can activate or replace a service.

The corrected image has now built and passed an isolated image-contract probe:
75 files matched the frozen payload, and two synthetic forms produced one
in-memory application, six page sources and complete QA-plan coverage. The
probe had no host mounts, network or public ports. It did not execute SQLcl,
Oracle imports, model calls or runtime browser QA. The candidate is **not
activated**, and the original failed job is still not technically verified.
