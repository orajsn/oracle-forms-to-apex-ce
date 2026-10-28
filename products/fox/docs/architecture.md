# FOX architecture

```text
Business user
    │
    ▼
React/TypeScript workbench ── Python API ── private project/source/run storage
    │                              │
    │                      persistent background queue
    │                              │
Local preparation           embedded OPAF mapper → independent reviewer
(Oracle tooling)                   │
    │                       internal bearer-authenticated MCP
Readable approved source           │
                            deterministic native renderer
                                   │
                            SQLcl validation gate
                                   │
                            guarded synthetic schema + unique import/export
                                   │
                            developer-only runtime verification
                                   │
                            exact output package → human business review
```

## Components

The development administrator setup path is separate from this conversion path:
`install-fox.sh` → OS bootstrap Python → pinned private setup runtime → loopback
browser wizard → verified single-folder storage (S0) → protected access/OPAF
input files. See [protected settings](installer-connections-step.md).
It does not install/start
the business services or establish the Oracle/OPAF/verifier connections yet.
See [managed setup runtime](managed-setup-runtime.md). Those connected phases
and a clean installed multi-form output remain distribution gates.

- `fox/fox` and `fox/web`: project UI/API, source history, plans, queues,
  embedded OPAF transport and release presentation.
- `converter/forms2apex`: inventory, deterministic native pages, source/review
  binding, SQLcl and explicit target/schema/import recovery guards.
- `converter/fox_source_contract`: build-time byte-identical mirror of the
  three pure intake/planning modules; verify with the supplied sync tool.
- `qa/operator`: developer-only verification supervision, bounded evidence,
  retained-history migration and unfinished fresh-runtime building blocks.
- `qa/product-project-journey`: isolated synthetic UI/API/delivery tests.

The [fresh queue container adapter](fresh-queue-transport.md) now reuses the
existing queue behind actual local startup-fence checks. It does not enable
the R4 host executor or supervisor. Fresh host admission and the remaining
clean-install/QA/promotion bindings are still required; no running fresh
verifier or customer-installation proof is claimed.

The [fresh clean transport](fresh-clean-transport.md) now carries selected
installation names, mounts, users and public bindings into the existing native
and multi-form clean engines. It adds no cross-service database mount and no
second import engine. Host admission, the remaining QA/promotion transports
and actual installed output remain unfinished.

Five internal MCP interfaces remain: `inspect_forms_job`, `generate_apex_draft`,
`validate_apex_draft`, `import_validated_draft`, `get_job_status`. They are not
public browser endpoints. A configured model URL does not establish readiness.

The current lab uses OCI instance-principal model authentication with separate
mapper/reviewer invocations. Approved redacted source is the AI boundary; no
standalone Codex session is part of the business-user runtime. Local embeddings
have no external key/endpoint. Regional/model availability must be revalidated
for each approved deployment rather than copied from this snapshot.

SQLite and immutable content hashes track projects, source versions and runs.
Schema and application import intents are separate. Unknown side-effect outcomes
require read-only reconciliation; no automatic DDL/import replay, table reset or
existing-app overwrite. Ordinary source names receive project-bound synthetic
storage mappings. Legacy pre-prefixed profiles have narrower isolation semantics.

This is a single-operator prototype, not a multi-tenant SaaS security boundary.
Public hosting, TLS, authentication, database rights and customer isolation remain
deployment decisions. Oracle software and a compatible APEX target are external
prerequisites; this repository does not redistribute their installers.
