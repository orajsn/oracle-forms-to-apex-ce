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
