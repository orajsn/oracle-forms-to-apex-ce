# Public preview 0.37.0

Deployment checkpoint: 20 November 2026. This describes the accepted 0.37.0 build,
not unfinished development from a later branch. Deployment did not add conversion
rules beyond the existing release.

## Try the workflow

1. Sign in with the existing preview account and reload an old browser tab.
2. Create a project, upload the FMB, and use hosted Forms preparation. Select
   development-preserve only for source you are authorized to process on that host.
3. Review the prepared Oracle XML and add the prepared form to the project.
4. Open **Convert → Reusable XML mapping**. Review its code-unit count and confirm
   local source processing plus the explicit synthetic/session-draft scope.
5. Choose **Generate APEX package**. Open **APEX output** to inspect the generated
   units, encoded-but-unwired rules, unfinished mappings and reference candidates.
6. Choose **Download native APEXlang package**. Read the bundled import guidance,
   compatibility metadata and synthetic supporting-schema instructions.

This route runs installed deterministic mappings, not a new OPAF/model request.
Other AI-assisted routes are separate. The output is an APEXlang ZIP for a compatible
SQLcl compiler, not a conventional SQL export ready for APEX Builder's SQL-import
screen. No target database connection or automatic deployment is part of this run.

## What was observed

One real FMB completed Oracle extraction, source adoption, package generation and
authenticated download. Its 53 code units were accounted for as:

| Status | Units | Meaning |
| --- | ---: | --- |
| Generated/adapted | 6 | A supported target mapping was emitted. |
| Encoded, not wired | 9 | Review code exists but is not connected to target events/context. |
| Not implemented | 38 | Conversion work remains; the output lists it explicitly. |

The separate reference report contained 76 groups and 153 occurrences. These are
not counts of missing files or proof that every reference is executed.

Actual SQLcl 26.1.2.0 `/nolog` validation passed on the exact browser-downloaded
package. Status filters, mobile no-overflow checks and anonymous-download denial
passed. The observed generation-through-download-and-UI-check portion took about
21 seconds; it excludes Forms preparation and the earlier UI wait. It is not an
end-to-end latency guarantee or a comparative performance benchmark.

## Known issue and safe continuation

On the first attempt, preparation/adoption succeeded but the mapping panel did not
display its code-unit count within the test wait. No generation had been submitted.
Reopening the same saved project recovered and allowed one generation. The source
was not reuploaded or reprocessed. The cause has not been established.

If status remains unloaded after adoption, refresh mapping status or reopen the
saved project. Check existing runs before submitting again. Do not upload again
or create a duplicate run merely because a browser wait ended.

## Limits

- Partial native APEX generation and format validation are not full Forms parity.
- Target import, Oracle/APEX runtime and business behavior were not tested in this
  checkpoint. Exact target compatibility must follow the package metadata; the
  compiler version is not evidence of a successful target import.
- Synthetic/read-only/session-draft behavior does not enable customer-table writes.
- Existing login, private data and rollback files were preserved. No new cloud
  infrastructure, network rule, AI call or database import was required.
- Customer source, XML, packages, screenshots and operational credentials are not
  published in this repository.
