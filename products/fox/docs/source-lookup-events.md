# Connected source lookup handlers

FOX now translates complete source SELECT-INTO lookup triggers into native APEX
pages and processes. This implements lookup behavior rather than only preserving
it as review SQL or describing its gap.

A record's **Lookups** link opens the generated actions while retaining existing
related-record links. Source POST-QUERY runs after initializing a selected synthetic
record. Source POST-CHANGE is adapted to an explicit **Apply lookup** action. A
new lookup input is a criteria draft, not a customer record creation or save.

## Preserved behavior

- Complete same-block SELECT lists, input/output references, table names and
  bounded equality predicates are rebuilt from a closed source AST.
- Exactly-one-row behavior is retained. No row limit, aggregate, deduplication or
  successful dummy response is inserted.
- NO_DATA_FOUND-only handlers reset outputs on zero rows and propagate other
  errors. WHEN OTHERS handlers retain their original ordered null resets.
- NUMBER and VARCHAR2 outputs use typed locals. SQL references to generated locals
  are block-qualified to prevent a source column capturing a variable name.
- Input whitespace, source byte/character limits and field edit restrictions are
  retained. A fetched read-only input is reloaded server-side. New criteria can be
  entered only where the source insert flags permit. Case display is separate
  from internal fetched values; wider editable-fetched casing requires its own
  changed-value context and remains a reported gap.
- Existing report navigation, original XML, source-unit identities and earlier
  output history remain preserved. Unrecognized statements, cross-block inputs,
  computed input providers and occupied report-action slots remain explicit gaps.

## Original database interfaces are disabled by default

The generated processes retain the original read-query interfaces. FOX does not
invent their data, recreate missing tables or run those queries during conversion.
Each handler has a namespaced application readiness item with Restricted session
state protection and no enabled default. Native server-side process conditions
prevent invoking/parsing the original SQL when the interface is disabled. The
readiness/context guards sit outside the source exception handler.

Before enabling a handler in an authorized Oracle/APEX target, verify its original
objects/columns, datatypes, privileges, row authorization, character/numeric rules
and cardinality. Enabling an original read interface changes the default synthetic
runtime data scope and requires separate target authority. Readiness cannot be set
from browser URL or posted state. The generated lookup pages offer no customer
Save/DML process. Source authentication, full Forms lifecycle and transactions
remain separate conversion work.

The package's lookup-plan.json, lookup-receipt.json and lookup-activation.md retain
source/event/field provenance and the exact readiness items. The normal discrepancy
UI identifies these generated adaptations and their unresolved target requirements.
Generated/connected is not activated, Oracle-compiled, runtime verified or business
accepted. SQLcl /nolog validates the APEXlang format without original database reads.

## Evidence model

The synthetic source_lookups.xml example contains two reset policies and both
supported event adapters. Tests cover complete source recognition, cardinality,
null resets, type/source binding, name collisions, tampering, original field
restrictions, default-disabled gates and retention of older saved outputs.

Relevant Oracle references:

- [PL/SQL column precedence and block-qualified variables](https://docs.oracle.com/en/database/oracle/oracle-database/21/lnpls/plsql-name-resolution.html)
- [Restricted application items](https://docs.oracle.com/en/database/oracle/apex/26.1/htmdb/managing-application-items.html)

Installed target behavior, implicit session-state processing and business acceptance
require separate verification; no such execution is established by local source or
format tests.
