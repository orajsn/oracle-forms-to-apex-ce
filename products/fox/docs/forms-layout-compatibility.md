# Forms layout metadata

Updated 4 November 2026. Source behavior, not a hosted deployment receipt.

FOX's native project assessor recognizes Oracle Forms `Coordinate` objects as
desktop layout metadata, alongside the existing canvas and window handling.
Screen units, character-cell dimensions and font scaling do not require a
business decision before generating a native APEX layout.

The original XML is retained unchanged and remains bound by the source and
plan hashes. FOX does not claim pixel-for-pixel reproduction of a Forms screen.
APEX lays out the supported native pages for the web instead.

This is not a blanket ignore policy. Code attributes, nested objects/text in a
`Coordinate`, foreign namespaces and ambiguous properties still receive their
normal checks. Missing table definitions, dependencies, triggers and unsupported
business behavior remain explicit findings; they cannot safely be discarded to
obtain an APEX file.

## Regression coverage

- A synthetic fixture mirrors actual Oracle 14c XML2Forms → FMB → Forms2XML
  output, including Oracle's automatically emitted `Coordinate` object.
- The unchanged extracted XML passes project planning with its explicit
  structure-only DDL, without removing the object or changing the source hash.
- Known coordinate/canvas/window metadata can coexist in a ready project.
- Layout changes produce new source/plan hashes, not different table semantics.
- A normal authenticated upload and conversion submission succeeds against an
  isolated FOX test instance, preserving the original XML in its snapshot.
- Negative tests retain business-code, dependency, unknown-object, namespace,
  conflicting-property and nested-content stops. No model/database is called.

This change fixes a metadata compatibility issue. It does not itself prove
APEX generation, SQLcl validation, successful import, runtime behavior or human
business acceptance. Existing live deployments need a new measured paired
release; do not patch an old frozen bundle or replay an interrupted job.
