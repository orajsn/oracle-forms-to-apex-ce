# Single-folder installer storage phase

This is an implemented developer phase behind the future guided setup. It is
not the complete connected installer, a service launcher or a customer release.

From the product root, using its isolated supported Python on nonroot Linux:

```text
<python> scripts/fox-setup.py storage-plan --installation-root /home/operator/fox-instance
<python> scripts/fox-setup.py storage-initialize --installation-root /home/operator/fox-instance --expected-plan-sha256 <reviewed-plan-hash> --apply
```

The first command is read-only and returns the actual source-bound plan/hash.
The second requires explicit approval of those exact bytes. The wizard will
retain this plan internally; business users do not assemble documents or copy
hashes. No database/model credential is a command-line argument.

One selected folder derives `data`, `jobs`, `operator` and `storage-records`.
`qa/operator/installer_storage.py` invokes the existing `fresh_storage` S0
producer and inspector; it introduces no second schema initializer, installation
ID, queue engine or connected-admission format. Its private setup plan is
retained beside the S0 evidence, not inside the public application mount.

The parent must already be an owned local directory with safe ancestors. An
ordinary owned 0755 parent is accepted. Setup creates only its new 0700 instance
folder and never chmods the parent. Unknown existing directories, writable or
linked ancestors, source overlap and existing data cannot be silently adopted.

Repeated setup inspects the same completed S0 and returns
`STORAGE_REUSED_NOT_INSTALLED`, with the original identity and completion hash.
A retained exact setup plan may continue only if the S0 inspector confirms no
producer attempt started. Partial roots, producer failures, changed receipts,
active SQLite sidecars or uncertain writes require review; no reset/delete or
automatic replay is performed. Partial artifacts remain available.

The results deliberately keep conversion readiness, connected admission,
service startup and automatic replay false. Remaining backend initialization,
release/image/runtime binding, protected verifier and live transition must use
their existing contracts before a full installation can be declared ready.
This is a pre-startup phase. A running installation with active SQLite WAL or
later configuration must use its normal installed-runtime checks, not rerun
bootstrap to force an empty state or discard later records.
The assessment-only ZIP lacks these modules and reports
`STORAGE_STEP_COMPONENTS_MISSING`, rather than switching to another route.

Tests exercise the actual nonroot POSIX filesystem, private SQLite S0 and real
CLI plan/initialize/repeat. Windows runs pure validation and explicitly skips
POSIX apply cases. No test contacts Oracle, a model, OCI or a live container.
