# Source-linked record context

FOX 0.34.0 adds reusable read-navigation mappings for explicit Forms relations.
It also encodes complete parent-value assignments as review-only PL/SQL. These are
separate capabilities: a relation view is not a converted write lifecycle, and
emitted assignment code is not counted as active converted behavior.

## Related-record views

The source must declare a same-module Join relation containing one to four direct
parent/child field equalities joined by AND. The engine checks module/field identity,
datatypes, synthetic DDL and the source-to-target trace. Computed or ambiguous keys,
unknown calculation modes, mixed types, unsupported syntax, branching ambiguity
and cycles remain explicit relation gaps.

Each supported relation creates a dedicated read-only detail page. A link passes
only the selected parent's synthetic FOX_ROW_ID. The page filters child rows with
an EXISTS query that checks that exact parent row and every original join pair.
No customer primary key or uniqueness constraint is inferred. Composite keys stay
separate comparisons; they are not concatenated into an invented key.

The parent item and page require session checksums. Its value persists server-side
for report refreshes and is not resubmitted as an AJAX item. New links clear the
context page before setting the selected parent. With no established context or
a deleted parent, no rows match. A later visit without a new link can retain the
previous selection; this is explicit manual web navigation, not Forms record-buffer
or automatic-query equivalence. See Oracle's [session-state protection guidance](https://docs.oracle.com/en/database/oracle/apex/26.1/htmdb/preventing-url-tampering.html).

Existing calculations and validation links remain in the cloned reports. Outgoing
relation links are also carried into intermediate detail views so a multi-level
chain can be followed. Base standalone reports remain available separately.
Source AutoQuery, Deferred, DeleteRecord and PreventMasterlessOperations settings
are retained as unimplemented lifecycle details. No cascading delete, save or
customer-table mutation is introduced by these read-only views.

## Parent-value assignment code

The finite rule accepts a complete block-owned PRE-INSERT or PRE-UPDATE value
copy, such as `:child_value := :parent_value;`, with exact direct relation, source
and native field bindings. Extra active statements, ambiguous events/references,
computed fields, incompatible types and unproven parent context are rejected.

The output `fox-package/assignment-review.sql` contains namespaced package
procedures that copy an IN value to an OUT value. Each original event has its own
binding manifest. No source text is inserted as executable SQL, and no SELECT,
DML, COMMIT, database trigger or APEX save process is added.

This SQL is **generated but not installed, Oracle-compiled or event-wired**. The
caller still needs a verified parent-value provider, native insert/update event
wiring and the applicable validation/permission guards. The artifact is for review;
it is not installed automatically with the application. Those source units remain
in Not yet converted, with an explanation that the copy rule is encoded but its
write lifecycle is pending. The generated/adapted code-unit count is unchanged.

## Evidence and progress

The package records relation and assignment plans/receipts, source hashes, exact
trace digests, the assignment SQL hash and all remaining gaps. The website exposes
read-only relationship counts and unwired assignment counts separately from code
units. Older artifacts without this summary remain valid under their original proof.

Whole-package SQLcl /nolog validation checks the generated APEXlang, not execution
of review SQL or an installed APEX application. Synthetic local query-model checks
exercise parent isolation and composite predicates; they are not Oracle runtime
or business acceptance. A real target must verify URL protection, navigation,
query refresh behavior, data semantics and any future write-event activation.

`examples/xml-mapping/record_context.xml` is a public synthetic chain with a
calculation and two assignment events, suitable for reproducing the operator path.
