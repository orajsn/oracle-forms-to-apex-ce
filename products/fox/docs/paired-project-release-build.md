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
