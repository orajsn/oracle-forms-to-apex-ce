# Partial APEX drafts

FOX 0.5.0 adds a deliberately partial route for early demonstrations and further
development in APEX. It does not change what a complete conversion means.

## User flow

1. Open a project and upload its approved readable sources as usual.
2. Choose **Explore partial draft**, or open **Convert → Partial draft / demo**.
3. Select **Preview what can be generated**. Read the included components,
   forms left out, skipped behavior and corrective actions.
4. Confirm the listed omissions and choose **Create draft source version**.
   This saves a separate branch. It does not yet generate an APEX application.
5. Review that branch, confirm the normal processing statements and generate
   through embedded OPAF, independent review and the normal technical gates.
6. After technical verification passes, choose **Download development draft**.
   Review its import instructions and continue development in native APEX.

Business acceptance remains a separate human decision. The existing accepted
package button still requires it; a development download does not manufacture
an acceptance record or modify the proof/package.

## What can be left out

Known unmapped business code, referenced library/package behavior, reports and
non-database controls can be explicitly omitted when a supported table-backed
field subset is proven. Missing dependencies stay in the original assessment
and are named in the scope report. Omitted actions are absent, not working
substitutes or yet-generated disabled-placeholder components.

A form without a supported authoritative table definition, explicit key and
unambiguous field mapping is left out entirely. Conflicting source definitions,
restricted operations, unsupported data sources, unsafe/malformed source and
capacity limits cannot be bypassed. If no supported form remains, no draft is
created. This increment does not invent a schema from missing DDL.

## Source and output boundaries

```text
Original saved source version (unchanged)
  → source-bound preview + explicit omission confirmation
  → separate derived XML / supplied DDL + scope evidence
  → ordinary whole-project assessment
  → ordinary OPAF mapping / independent review
  → ordinary SQLcl / non-overwriting import / runtime verification
  → exact native APEX development package
  → user edits in APEX; separate human business review
```

The draft version stays frozen with its receipt. **Return to original sources**
to add dependencies or correct source material, then prepare a newly assessed
scope. The original source manifest and draft-scope fingerprint remain linked.
The complete scope report is carried as comments in one draft DDL source and
can also be downloaded separately. Neither SQL comments nor UI state authorize
an import: the normal server/converter source and technical-proof checks remain
mandatory.

After editing in APEX, a later FOX generation is a separate application/package.
There is no round-trip merge of APEX edits and no automatic overwrite.

## Versions and portability

The handoff shows the exact recorded APEX/database/SQLcl test versions when a
valid technical proof supplies them. Otherwise it says they are not established.
Those versions are not a blanket compatibility or import-success guarantee.
Use a compatible approved test target, the package README, reviewed synthetic
schema script, new application ID/alias and target-specific authentication.

Raw FMB/MMB/OLB/PLL preparation still requires supported Oracle tooling. This
source increment does not establish a new live conversion, host installation
or hosted deployment; see the release notes and product roadmap.
