# Synthetic reusable mapping examples

These two small, hand-authored Forms XML fixtures are public examples, not customer
sources or exports from a live Forms runtime. They demonstrate the same generic
mapping engine across different modules and names:

- `invoice.xml`: native structure, arithmetic/NVL/ROUND total, and numeric guard
  with a separate minimum and explicit Continue/focus web adaptation.
- `stock.xml`: native structure and two formulas using FLOOR, NVL, ABS, subtraction
  and division. An external trigger deliberately remains unsupported.

Both can be supplied together to generate one APEXlang application. See the
[XML mapping operator guide](../../docs/xml-mapping-engine.md#operator-usage).
Synthetic source and format validation do not establish Oracle runtime behavior,
complete transaction handling or business acceptance.

The local_compare.xml and local_compare_second.xml pair adds same-named local
comparison helpers/controls in two different modules. Each has two callers,
including a trailing-blank literal case, to exercise safe module binding and
helper deduplication. See the business comparison mapping guide for target
collation/session requirements and unverified runtime boundaries.
