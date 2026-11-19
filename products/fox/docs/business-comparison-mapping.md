# Local comparison functions and actionable conversion gaps

FOX 0.33.0 converts a complete, pure two-VARCHAR2 equality helper and supported
numeric formula callers. It recognizes the function body, not a hardcoded routine
name. Different forms can use the same helper/control names without sharing bindings.

## Executable mapping

A supported helper initializes a NUMBER result to zero, sets it to one only when
its two VARCHAR2 arguments are equal, and returns that result. Extra statements,
side effects, ambiguous local declarations and unsupported bodies stay unconverted.
A caller can supply bounded character literals, same-row VARCHAR2 fields,
concatenation, or a qualified source-free control text item in the same module.

The generated report expression uses native SQL CASE and casts both complete
arguments to VARCHAR2. This preserves nonpadded VARCHAR2 comparison for literal-only
calls too; it does not trim, change case, add concatenation delimiters or substitute
values for NULL. Oracle documents [character literal semantics](https://docs.oracle.com/en/database/oracle/oracle-database/26/sqlrf/Literals.html),
[CASE](https://docs.oracle.com/en/database/oracle/oracle-database/26/sqlrf/CASE-Expressions.html)
and [concatenation](https://docs.oracle.com/en/database/oracle/oracle-database/26/sqlrf/Concatenation-Operator.html).

Arguments must fit the SQL VARCHAR2 bound under conservative declared-length
checks. A wider argument remains a context/mapping gap; no truncation is introduced.
Target column collation compatible with USING_NLS_COMP and matching source
comparison session settings are explicit prerequisites. Datatype casts do not
establish collation equivalence. Target execution must check trailing blanks,
NULL/empty values and case/accent pairs under the actual settings.

Referenced controls retain their source-derived APEX items. The generator makes
per-session storage explicit and adds one Apply control values submit action to
that control page. Oracle documents [how page submission stores session values](https://docs.oracle.com/en/database/oracle/apex/26.1/apxdc/how-apex-manages-user-session-state.html).
This is an explicit web adaptation: reports use persisted synthetic rows and
submitted session values. Original Forms events that populate those controls,
loaded-record summaries and duplicate-record workflows are not inferred.
No standalone database function or customer-table DML is added by this rule.

The helper body is counted once only when at least one complete supported caller
is emitted. Its source hash and caller operation IDs are retained. An unused
recognized helper remains unconverted; multiple callers do not inflate the body
count. Source-object structure and code-unit behavior remain separate measures.

## Explain why each unit remains unconverted

The package includes `fox-package/mapping-gaps.json`; the project Output view
shows these explanations under Not yet converted. Each entry has source filename,
unit name, XML line, reason, owner and next action.

| Category | Meaning | Owner |
| --- | --- | --- |
| FOX mapping gap | Source is present, but this complete pattern is not implemented | FOX engine |
| Record/context gap | Parent-child, session, computation or caller context still needs wiring | FOX engine |
| Missing source | Positive source evidence identifies a required definition that was not supplied | Source owner |
| Review needed | Ambiguous reference, conflicting source or encoding needs resolution | Reviewer |

An unfamiliar function is not automatically missing customer code: it may be an
Oracle built-in or an unresolved target. Lexical table/routine/library candidates
are retained as unverified evidence, never promoted to confirmed missing input.
These are primary per-unit blockers; external dependencies may still need review.
Declarative behavior outside inventoried code units also has its own mapping scope.

## Preserve completed results across upgrades

Fresh generation still rebuilds the candidate under the current installed catalog
and runs SQLcl before publication. A queued job with a changed catalog stops before
compilation; an old candidate cannot be relabelled as newly validated.

Completed historical jobs retain their original counts and catalog. After owner
and durable DB-event authentication of the original consent snapshot and result,
a read-only verifier checks original source bytes/binding, catalog fingerprints,
candidate/final hashes, compiler log, every APEX member and exact metadata-only
sealing. It invokes no generator, compiler or provider. Altered/missing evidence
remains blocked. This is not a standalone-upload acceptance path and grants no
new execution, import, runtime or business acceptance authority.

Older packages without detailed gap reports remain downloadable with their
original coverage; the UI states that detailed reasons are unavailable for them.

## Reusable examples

`examples/xml-mapping/local_compare.xml` and `local_compare_second.xml` use the
same helper/control/block names in separate modules. Generate them together with
`tools/generate_xml_apex.py` to exercise module isolation, concatenation, literal
trailing blanks and helper deduplication. They are public synthetic fixtures,
not customer source or Oracle runtime acceptance evidence.
