# Managed Linux setup runtime

The development launcher can now prepare its own private, verified Python and
open the existing browser setup wizard. An operator no longer has to assemble
a Python3.12 environment or run pip for this setup phase.

From the FOX product root on the supported nonroot Linux baseline:

```text
bash scripts/install-fox.sh
```

The OS supplies its basic Python3.6-or-newer bootstrap interpreter; tested here
with Oracle Linux8's Python3.6.8. FOX then manages a separate Python3.12.16 and
defusedxml0.7.1. The currently pinned archive is Linux x86_64/glibc, not an
automatic ARM/musl/Windows fallback. The default cache is a private versioned
folder in the current account's real home directory, resolved without trusting
an inherited HOME override. It is separate from project/job storage.

The initial interactive run asks for download approval. Approved unattended
preparation can use `--allow-download`; check-only requests must not use that
flag. Downloads go only to the fixed public artifact URLs/hash pins in
`deployment/bootstrap_runtime.py`. No Oracle media is downloaded. The source
snapshot is still a development preview, not a full customer installer release.

## Checks and reuse

```text
bash scripts/install-fox.sh --inspect
bash scripts/install-fox.sh --prepare-only --allow-download
```

The first command creates nothing and downloads nothing. The second prepares
only the wizard runtime. Exit0 means this component was verified, not that FOX
is installed or connected. The normal launcher enters the same loopback wizard
after verification and prints its private setup code only to the operator.

Artifacts are verified before extraction or execution. Archive paths, links,
sizes and member types are checked. Only the exact approved XML wheel is added
to the isolated interpreter; no pip invocation, system package installation or
global Python modification is performed. Upstream files and license notices
are retained. The existing source and project storage cannot be cache roots.

Repeated launch verifies all executable/package files against the trusted
artifact contents, not just a self-declared receipt. Changed artifacts,
unexpected files or executable drift stop before probing/launching the runtime.
Do not manually add packages or edit this cache; later application services need
their own matched dependencies and runtime bindings.

## Interrupted preparation

A matching retained intent with verified downloads can continue before
extraction without redownloading or overwriting those files. If extraction
finished but the final receipt was not written, the entire existing tree must
match the pinned artifacts before the read-only probe and receipt completion.
Partial/changed executable trees and unknown folders remain for inspection;
the launcher does not delete or repair them silently. `--inspect` never
completes a partial stage.

Offline tests/preparation can supply both `--python-archive <file>` and
`--xml-wheel <file>`. Their bytes must match the same fixed pins; arbitrary
versions/media are rejected. `--runtime-root <absolute-owned-path>` selects an
explicit private cache location without changing existing parent permissions.

## Remaining product work

This runtime supports the wizard/storage phase, not the full application,
converter, SQLcl, Oracle Forms tooling, OPAF, target onboarding or protected
verifier. Full connected installation, update/recovery, third-party distribution
review and a clean-host native APEX output remain release gates. The optional
install skill must not report product installation from this component result.
