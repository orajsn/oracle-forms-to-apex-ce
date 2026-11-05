# Resolve source once, across your Forms

In a project's **Resolve** step, FOX groups assessed source dependencies shared
by several Forms. A request retains every known form, block, button/item,
trigger or program caller from the assessment. It is not a claim that every
possible runtime dependency was discovered.

1. Open **Show all affected callers** to understand where the source is needed.
2. Copy an individual request or download the current request list for the
   application owner or DBA. The list requests readable source, not records or
   credentials. If clipboard access is unavailable, copy the visible text.
3. Choose **Add requested source**, add the files to this same project, and return
   to Resolve. FOX reassesses the selected source version; do not create a new
   project merely to supply a missing dependency.

For example, two approval buttons can share one package-body request. If the
specification is already supplied, FOX asks for the missing body rather than
asking for both again. A supplied body lacking the expected routine is shown
as **Routine not confirmed**, not silently accepted.

## What these states mean

- **Source missing:** provide the requested source or resolve the finding.
- **Routine not confirmed:** check the named routine and its source with the
  source owner. A matching filename alone does not prove that it exists.
- **Source available · mapping not verified:** no missing source is reported for
  that dependency. Conversion may still need supported mapping or a human
  decision. Review all detailed form findings before proceeding.

Requests are bound to the assessed source and plan hashes. A download from an
older version is rejected after source changes; refresh rather than use an old
list. Large or incomplete assessments retain their individual findings instead
of reporting a misleading zero missing-source count.

This feature does not expand behavioral translation, bypass a blocker or import
an application. Raw FMB/MMB/OLB and PLL still require the supported Oracle
preparation route before readable source is assessed. Generated APEX, technical
verification and genuine human business acceptance remain separate.
