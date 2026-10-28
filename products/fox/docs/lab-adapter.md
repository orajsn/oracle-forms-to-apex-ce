# Existing-lab adapter, not customer configuration

`qa/run-jsn-qa.sh` and `qa/lib/assert-jsn-vm.sh` are reviewed legacy lab
sources required by the existing QA source closure, not a fresh/customer
launcher. They publish no credentials. The VM guard keeps explicit identity
checks even when Python optimization is enabled. Neither script is executed
by the fresh queue packet/program builder.

The connected operator/deployment modules preserve an explicit JSN resource
allowlist. The checked-in `target-profile.jsn*.json` and project OPAF profiles
contain non-secret target IDs, origins, published workflow IDs and integrity
fingerprints used by the development adapter and offline tests.

These references grant no OCI access. No API key, SSH key, wallet, password,
DPAPI payload, saved SQLcl connection or historical admission archive is supplied.
The local SSH-key/DPAPI references resolve beneath the operator's home; they do
not create those files. An existing-lab command must still prove its exact host,
compartment, database and release before any effect.

Some developer journey tests also refer to the lab's public origin or a local
Playwright installation. They are opt-in lab diagnostics, not a portable install
route. Do not point them at a different customer, copy private history, fabricate
matching release hashes or disable guards. The default source tests use no live
OCI/OPAF/database credentials.

A general connected customer adapter and complete empty-host installation are
unfinished. Their absence is a release gap, not an instruction to change pinned
identities manually. The Windows local assessment route is separately usable.
