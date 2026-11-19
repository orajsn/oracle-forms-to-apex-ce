# Source rules, review code and active APEX behavior

FOX maps original XML using installed, versioned deterministic rules. It rebuilds
source facts and hashes before generation and validates the exact APEXlang package
with SQLcl before marking the format validated. No model call is needed for these
rules. A source unit is counted as generated/adapted only when its complete
supported behavior has a native target binding.

## Rules encoded in this increment

- Complete database block ORDER BY clauses with one to six direct columns become
  initial interactive-report sorts. Direction and Oracle NULL placement are
  retained, including on related report pages. Users can change saved-report
  sorting; equal-key order remains unspecified. Explicit source database column names bind to the matching item, including
  renamed items. Ambiguous aliases, expressions and computed columns remain gaps. Target collation
  compatibility requires separate verification.
- Complete finite procedures/triggers containing IF conditions, scalar literal
  assignments, supported block/item permission changes, literal MESSAGE calls
  and FORM_TRIGGER_FAILURE generate typed PL/SQL review procedures. Supported
  local calls must resolve within the same module and have complete supported
  bodies; recursion and unknown/external statements are rejected as whole units.
- Default permission resets precede conditional overrides. A missing ELSE keeps
  the previous scalar value. Oracle three-valued conditions are preserved.
  Warnings remain ordered warnings, including repeats; failure terminates the
  remaining caller statements. Source-only property targets are explicit when a
  native widget does not exist. FORM_SUCCESS is a required input only for a pure
  status check; mixed effects cannot use a stale success snapshot.

Policy procedures return ordered effects and typed scalar values. They are
**generated_unwired**: not installed, Oracle-compiled, invoked by an APEX event or
used as authorization. Event order, current-record state, dirty-buffer providers,
compatible datatypes/collation and server-side permission enforcement are required
before activation. SQLcl checks APEXlang; it does not compile these review SQL
packages. The UI shows policy review counts separately from converted units.

## Reusable next steps and dependency boundaries

Do not treat every unconverted unit as missing customer source. Separate:

1. Complete source expressions/routines needing an engine mapping.
2. Complete source needing record buffers, summaries, navigation/query/clear
   ordering or transaction adapters. A loaded-record summary is not necessarily
   equivalent to a database-wide aggregate or uniqueness constraint.
3. Supplied SQL needing verified schema, type, key and session bindings. Preserve
   query cardinality, exception handling and commit order; do not infer them.
4. Calls whose external contract is absent: request definitions or verified target
   bindings, including argument/result types, errors, side effects and transactions.
5. Reports needing a query/layout/service contract and safe target authentication.
   A source report caller is not the report implementation.

A complete caller can be analyzed without inventing its external implementation.
Likewise, source no-ops and disabled keys must not inflate meaningful conversion
progress. Retain unreachable source and report it; never silently repair business
logic while claiming equivalent conversion.

The synthetic example `examples/xml-mapping/policy_rules.xml` exercises ordering,
warning-only validation, no-ELSE assignment, reset/override permissions, a local
call and a failure guard. Renaming source modules/items uses the same rules.
Original sources and previous run packages remain preserved across catalog updates.
