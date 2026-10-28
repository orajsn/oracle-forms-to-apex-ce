# FOX: Form to APEX

FOX is a product-oriented Oracle Forms modernization prototype: one project
contains multiple Forms modules and produces one native APEX application/export.
The web UI manages multiple projects, source versions, conversion runs, findings
and result review. Business users do not need Codex, prompts or QA commands.

```text
Project → Upload/prepare → Resolve gaps → Process → Native APEX output
                                              → Technical checks
                                              → Human business review
```

Generated output, technical verification and human business acceptance are
separate. Complete source evidence does not guarantee equivalent business
behavior. Missing definitions and unsupported constructs are explicit findings;
FOX must not invent keys, omit selected forms silently or guess human meaning.

## Development status

This is experimental source, not an Oracle product, Support commitment or
production migration factory. The multi-form implementation and local tests
are ahead of the deployed lab release. A new host's fully connected installer,
runtime admission and shipped end-to-end acceptance remain unfinished. A
passing local test is not a validated customer conversion.

The local Windows route provides preparation and assessment, not connected
APEX generation. Connected development currently uses the explicitly guarded
JSN lab adapter. Non-secret target identifiers/guards in that adapter are
reference scope, not portable customer defaults or credentials. Do not change
them to bypass a failed gate or point a demo at production.

## Linux setup preview

Run `bash scripts/install-fox.sh` from this product folder as a nonroot
operator. It checks/prepares a private pinned Python runtime with download
consent, then opens the loopback setup wizard. This currently prepares storage
only, not connected FOX services. Read the [managed setup runtime guide](docs/managed-setup-runtime.md)
before use. `--inspect` checks that runtime without downloads or file changes.

## Supported conversion profile

The initial native profile supports a narrow synthetic prototype: reviewed
table-backed forms, explicit supplied keys, deterministic report/form pages,
search and insert/update behavior. It composes selected modules into one app
and records source/page/storage traceability. Unsupported libraries, triggers,
LOVs, reports, external calls and web/Forms behavior need evidence and an
explicit remediation decision. It is not a universal Forms transpiler.

Only redacted readable source is sent for approved AI processing. Oracle Forms
tools remain necessary to authoritatively convert raw FMB/MMB/OLB/PLL modules.
No Oracle installer, wallet, private key, customer source or production record
is part of this source distribution.

## Components

- `fox/`: React/TypeScript UI and Python API, preparation and persistent jobs.
- `converter/`: internal MCP tools, deterministic native generation, validation
  and guarded import/export.
- `qa/`: developer-only operator, clean-import, runtime and integrity checks.
- `scripts/`, `tools/`, `deployment/`: setup/build checks and guarded development
  adapters. A source helper is not an activation command.
- `fox/skills/fox-install/`: optional Codex installation assistance, not a runtime
  dependency or authority to deploy a customer environment.

Start with [installation](docs/fox-installation-v1.md),
[user flow](docs/fox-user-guide.md), [architecture](docs/architecture.md) and
[operations/support boundaries](docs/operations.md). The root CE skill's
`install.py` does not install these components.

Developer checks are documented in [verification](docs/verification.md).
Read the [lab-adapter boundary](docs/lab-adapter.md) before considering any
connected deployment/operator code. Third-party distribution limits are in
[THIRD_PARTY.md](THIRD_PARTY.md).

## Source and safety

The original CE repository content and public history are preserved. FOX source
is maintained here without importing the former private Git history. Credentials,
live private state, run outputs and historical deployment attestations are not
source prerequisites and must not be committed to make a test pass.

Use inferred stubs and synthetic records only for the POC; do not connect to a
legacy production database. APEX output is importable only against its declared
compatible target after the required validation/import checks. Human review
remains responsible for business acceptance.

Repository license and trademark terms remain in the root `LICENSE.txt` and
README. Oracle tools and third-party dependencies retain their separate terms.
