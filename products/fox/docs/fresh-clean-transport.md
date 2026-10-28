# Fresh clean-install transport

Status: source integration and local protocol tests, not a running fresh
verifier, an admission authority or a new Oracle installation.

The existing native and project clean-install CLIs now select a fresh host
program when the concrete C3/R4/F provider is selected. Legacy selection keeps
the existing templates. A failed fresh source/configuration check never falls
back to the legacy SSH/container names. Compilation happens before retrieving
the ADMIN secret and performs no process, credential or SQL operation.

The compiler embeds the selected installation's role names, image references,
users, mounts and upstream hashes. They are not request overrides. It reuses the
same measured source reader and native/project phase executors, not a second
DDL/import engine. R4 requires `fresh_clean_transport.py` in its operator source
closure; frozen old releases must not be changed in place.

Before a child dispatch, the generated program checks the pinned JSN host,
operator owner, complete declared mount set, private-path separation, actual
container ID/image/user/root-filesystem settings and environment. It reads the
actual public P/F/A records using the measured application readers and verifies
their hashes, installation identity and upstream bindings. It does not add a
FOX database mount to the converter or treat this record check as the missing
concrete host admission/lease.

The converter environment now includes independent fresh provider, projection,
backend and release pins, plus the selected target/workspace/schema, saved
connection and tool paths. The existing fresh observer requires these bindings
before staged/live container measurement. Loader injection is rejected.

The child is addressed by the inspected ID with explicit declared user, cleared
loader variables and isolated Python. Fixed container source paths are supplied
by the protected loader, never a caller's Python path. Code bytes and secrets
travel through protected stdin, not command arguments or logs. The exact source
reader/executor and operator-code digest must match the selected release.
Public records and role identities are rechecked afterwards. A changed or
uncertain result stops without replay or permission repair.

Podman's explicit user selection and stdin-only invocation are documented in
the [official exec reference](https://docs.podman.io/en/v4.4/markdown/podman-exec.1.html).
The actual installed engine/image/namespace behaviour still needs runtime proof;
these tests do not claim an actual Podman launch.

## Preserved phase and privacy rules

The same clean engines own allocate → schema → import → verify, durable intents,
unique IDs/aliases, completed-phase skipping and uncertainty handling. There is
no automatic retry of a dangling SQL intent, replacement app, table reset,
privilege expansion or business acceptance. Source and execution failures stay
closed. No password is returned by the compiler or recorded in diagnostics.

## Verification and remaining work

`qa/operator/tests/test_fresh_clean_transport.py` creates real private S0/F and
selected source/configuration, then executes the actual generated host programs
at synthetic IMDS/Podman/child-process boundaries. It checks normal/alternate
roles/users, source CLI routing, pre-admission refusal, wrong code/image/settings,
uncertain child output, post-dispatch identity drift and the still-closed general
provider. Synthetic A and the explicit future-authority fixture placeholder are
not live admission. Child results are explicitly synthetic, not Oracle evidence.

The existing native/project CLI and multi-form clean-engine tests remain part
of regression coverage. The latter use the actual package/plan/SQL generation,
but authored SQLcl responses: they do not establish a successful Oracle import.
The bundled sample contains only synthetic schema/XML input, no records or raw
Forms binaries, and is not an approved real customer conversion.

General fresh execution and ADMIN retrieval still refuse. Concrete held-lease
admission, complete QA/collection/promotion bindings, real service installation,
actual container and Oracle execution, full UI-to-native-APEX proof and customer
onboarding/distribution remain required. Do not accept R4 in the old authority
or enable execution merely because a generated program passes these tests.
