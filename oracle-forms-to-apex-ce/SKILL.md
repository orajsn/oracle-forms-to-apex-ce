---
name: oracle-forms-to-apex-ce
description: Assess and prototype Oracle Forms modernization to Oracle APEX on Windows, Linux, or macOS. Use for FMB, MMB, OLB, PLL/PLD, RDF, Forms XML, DDL, screenshots, or archives when the user wants prerequisite checks, Forms-to-XML conversion, evidence-backed inventory, an APEX target design, validated APEXlang, a local or OCI APEX import, a runtime URL, or export collateral. Route binary conversion through supported Oracle Forms tooling on Windows/Linux or an approved remote worker; do not use for production deployment or claim one-click behavioral equivalence.
---

# Oracle Forms-to-APEX CE Workbench

## Outcome

Turn supplied Oracle Forms evidence into a conservative migration assessment and, when prerequisites and source evidence permit, a validated Oracle APEX proof of concept. Preserve business meaning over visual mimicry and keep facts, inference, and unknowns distinct.

## Operating Modes

- `check`: Inspect the workstation without changing it.
- `assess`: Convert when supported, inventory supplied sources, and report gaps; do not generate or import an app.
- `poc`: Assess, design, generate, validate, import, smoke-test, and export a bounded non-production POC.
- `export`: Produce APEXlang, conventional APEX SQL, assessment, gaps, and screenshots from an existing validated POC.

Default to `check` before `assess` or `poc`. Never install software, elevate privileges, expose a port, submit files to a remote worker, import an application, or delete a case without explicit user approval.

## Platform Model

The portable core uses Python 3.10 or newer and the Python standard library.

- Windows: run the full workflow when Oracle Forms Builder/Forms2XML, SQLcl, and an APEX target are available.
- Linux: run the full workflow when the corresponding Oracle Forms tools, SQLcl, and an APEX target are available.
- macOS: inspect, inventory, design, generate, and validate with SQLcl. For `.fmb`, `.mmb`, `.olb`, or `.pll` binaries, require preconverted XML/PLD or use an explicitly approved Windows/Linux conversion worker.
- Any platform: when only readable XML, PLD, SQL, screenshots, or process evidence is supplied, continue without Oracle Forms Builder and record the missing binary-conversion evidence.

Resolve an available Python 3 command for the host (`py -3`, `python3`, or `python`) and use it for the commands below. Do not download or execute a platform adapter without approval and checksum verification.

## Workflow

### 1. Establish the case

1. Identify the requested mode, platform, and supplied files.
2. Create a case folder under the current workspace `work/` and user-facing outputs under `outputs/`.
3. Preserve originals, record SHA-256 hashes, and extract archives into a separate working folder.
4. Reject encrypted archives, unsafe paths, symlinks, installers presented as customer sources, and credentials in prompts or logs.

### 2. Check prerequisites

Run:

```text
<python3> <skill-dir>/scripts/preflight.py --mode check
```

Use `references/compatibility-profile.md` to classify every component as `REUSE`, `MISSING`, `INCOMPATIBLE`, `BLOCKED`, or `NOT_REQUIRED`. If a component is missing, give the official source and installation order, then stop unless the user explicitly asks for installation assistance.

### 3. Convert binary Forms modules

Use Oracle tooling, never ad hoc binary parsing, as the authoritative conversion path.

```text
<python3> <skill-dir>/scripts/convert_forms.py \
  --input <file-or-directory> \
  --output-dir <case-output>/forms_xml
```

- Convert `.fmb`, `.mmb`, and `.olb` with Oracle `frmf2xml`/Forms2XML.
- Validate generated XML with `frmxmlv` when available.
- Export `.pll` to `.pld` with Oracle Forms Builder. Do not describe printable strings from a PLL binary as authoritative source.
- Treat `.rdf` as an external Oracle Reports source. Inventory it, but do not invent report SQL, parameters, triggers, or layout when readable report source is unavailable.
- On macOS, stop at binary conversion unless an approved Windows/Linux conversion worker or preconverted XML/PLD is available.

### 4. Build the evidence inventory

Run:

```text
<python3> <skill-dir>/scripts/analyze_forms.py \
  --input <case-output> \
  --output-dir <case-output>/inventory
```

Inventory modules, blocks, canvases, windows, items, triggers, program units, record groups, report registrations, attached libraries, PLD routines, and candidate database dependencies. Candidate dependencies are search evidence, not proof that the object exists or is complete.

### 5. Interpret conservatively

Read `references/migration-boundaries.md` and classify conclusions:

- `Proven`: directly supported by supplied source or successful tool output.
- `Likely`: strong inference with stated evidence.
- `Possible`: design option or weak inference requiring confirmation.
- `Cannot conclude`: missing or conflicting evidence.

Explain the business process, authoritative files, runtime flow, security concerns, and missing dependencies. Never imply that a registered report name proves its RDF, query, parameters, or output layout were supplied.

### 6. Design the APEX target

Read `references/apex-mapping-guide.md`. Produce pages, regions, data sources, validations, processes, authorizations, reports, supporting objects, and manual-review gaps. Retain reviewed database APIs when practical; do not reproduce exposed credentials, client-machine licensing checks, unrestricted dynamic SQL, or arbitrary executable launchers.

### 7. Generate and validate APEXlang

Use the Oracle APEX/SQLcl skill set available through SQLcl `skills sync` when available. Start from a SQLcl-generated APEXlang project or a real export from the target APEX release. If exact syntax cannot be proven, generate design-only pseudo-APEXlang and label it clearly.

Validate canonical APEXlang with:

```text
<python3> <skill-dir>/scripts/validate_apexlang.py \
  --input <apexlang-project>
```

Only call an artifact importable after successful SQLcl validation and a successful import into a compatible APEX environment.

### 8. Import and verify

Before importing, confirm the target workspace, parsing schema, application ID strategy, authentication, and supporting objects. Use a case-specific schema/workspace or an explicitly approved shared POC workspace. Never connect to production.

After import:

1. Create a temporary runtime user without exposing its password in committed files.
2. Open the exact ORDS runtime URL.
3. Smoke-test login, navigation, key pages, disabled gaps, and static assets.
4. Capture desktop and mobile screenshots when the POC is user-facing.
5. Export both APEXlang and conventional `fNNN.sql` when supported.

### 9. Deliver

Use `assets/assessment-template.md` and `assets/gap-report-template.md`. Deliver:

- source manifest and hashes
- conversion and validation evidence
- Forms, PL/SQL, report, and dependency inventories
- business-process assessment
- APEX target specification
- validated APEXlang or clearly labeled pseudo-APEXlang
- conventional APEX SQL export when available
- approved runtime URL and login instructions without embedding passwords
- screenshots and manual gap report

## Stop Conditions

- With binary Forms files but no supported Oracle converter, report the blocker and installation or approved remote-worker route.
- On macOS with raw Forms binaries, do not attempt ad hoc parsing; request XML/PLD or an approved Windows/Linux conversion step.
- With only FMB/XML, build only what the form proves; leave database, report, and dependent-module behavior as gaps.
- With invalid APEXlang, do not import or call it importable.
- With credentials in legacy source, redact values and flag manual security remediation.
- With missing production data or APIs, use synthetic data only when clearly labeled and approved.
- After three materially different failures, stop and report the evidence and next required action.

## Example Invocations

- "Check whether my laptop is ready for a Forms-to-APEX POC."
- "Assess these FMB and PLL files but do not build an app."
- "Build a validated local APEX POC and give me the localhost URL."
- "Export this POC as APEXlang and standard APEX SQL for handoff."
