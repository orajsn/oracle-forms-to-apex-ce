# Source-linked business-rule generation

FOX 0.30.0 includes an operator CLI and Python library for a first, finite set of
Forms business rules. Start with the original preserved Forms XML and its matching
FOX native APEX package. The normal web generation action does not yet invoke
this tool. Generation does not call a model or connect to an Oracle database.

## Supported behavior

| Complete source pattern | Generated APEX behavior | Explicit adaptation |
| --- | --- | --- |
| Numeric item formula `CEIL(:input)` | SQL projection in the owning report | Reads persisted synthetic rows, not an unsaved Forms record buffer |
| Item trigger with a numeric `NVL(:input,0)=0` guard, message, `FORM_TRIGGER_FAILURE`, then item focus | A report row link and validation-only page with a Continue button, native validations and request-bound focus code | Button submission replaces the keyboard event; repeated identical messages become one APEX notification |

The second pattern also carries an applicable source item minimum as a separate
validation. With minimum 1, null and zero fail the primary rule; -1 and 0.5 fail
the minimum; 1 passes both predicates. These are generation semantics; actual
APEX interaction and Oracle execution still need target verification. The page
loads an existing row and does **not** save, perform DML or commit.

The parser requires a complete supported unit and exact owner, numeric type,
item, table, column and page bindings. Extra active statements, ambiguous encoded
text, unsupported calls or missing dependencies do not silently disappear. The
coverage ledger retains those units and their reason. Recognizing one expression
inside an otherwise unsupported unit is insufficient to mark it generated.

## Run the operator tool

Use the existing FOX Python environment with both the FOX and converter
requirements installed. SQLcl is required only when asking for format validation.
From the repository root, substituting your private file paths:

```bash
python -B products/fox/tools/generate_forms_behavior.py \
  --parent-package /private/input/parent-package.zip \
  --xml /private/input/original.xml \
  --output /private/output/behavior-run-1 \
  --validate-sqlcl
```

Repeat `--xml` for every original XML file in the parent manifest. Exact content
hashes restore their original logical filenames. Extra, missing, duplicated or
changed input is rejected. The output directory must not already exist. Optional
`--unit <source-unit-id>` selects a narrower set and may be repeated; omitted
units keep an explicit coverage disposition.

The existing export-only validator uses `FOX_EXPORT_SQLCL_PATH` when configured;
set it to your installed SQLcl executable if discovery is insufficient. It runs
SQLcl `/nolog` and validates the entire APEXlang project without a database login.
If validation fails or is unavailable, the command fails and preserves the
candidate/evidence for diagnosis. Do not treat a remaining candidate as validated.

Without `--validate-sqlcl`, the result is explicitly
`GENERATED_VALIDATION_PENDING`. A successful real compiler check produces
`FORMAT_VALIDATED`; it does not imply successful database import or behavior.

## Outputs and evidence

- `candidate.zip`: generated components with fresh validation still pending.
- `behavior-plan.json` and `generation-receipt.json`: source bindings, generated
  operations, renderer provenance, explicit adaptations and all-unit coverage.
- `APEXlang-behavior-package.zip`: produced only after successful requested
  format validation, with candidate-bound compiler evidence.
- `format-validation.json` and compiler logs: exact candidate/package hashes and
  format validation result, when requested.
- `result.json`: final coverage counts, output hashes and honest runtime/business
  flags. A failure before completion may leave no result file.

Inside the final ZIP, `fox-package/behavior-coverage.json` lists every source unit.
The current metadata and source-to-target trace describe this derivative.
`fox-package/parent/` preserves original metadata, remediation, trace and README.
Original AI reviews remain evidence for the original mapping only. They do not
approve new business code, and the old package's compiler result is not reused.
Other parent source and review payloads remain preserved.

Keep private packages, XML, generated business code and evidence out of the public
source repository. Preserve `.apex/` when extracting the project. The parent
supporting schema is synthetic; production schema, transaction boundaries,
external dependencies and application behavior require separate resolution.

## Extend the generator

The source parser and target binder live in `fox/fox/forms_behavior_plan.py`;
`converter/forms2apex/native_behavior.py` renders the finite operation contract;
`fox/fox/behavior_package.py` assembles and validates a new derivative. Use the
assembler to rebuild source authority instead of accepting caller-authored plans.

Add another pattern only with complete source semantics, explicit target wiring,
negative tests for unsupported variants, a truthful coverage disposition and fresh
whole-package validation. Preserve previous packages and original review evidence.
Runtime verification and business acceptance remain distinct milestones.
