# Conservative APEX Mapping Guide

| Oracle Forms concept | Initial APEX target | Review requirement |
|---|---|---|
| Window/canvas | Page and regions | Recompose for web workflow; do not mimic coordinates blindly |
| Database block | Form, grid, or report backed by reviewed SQL/API | Confirm keys, locking, validation, and commit behavior |
| Control block | Page items and session state | Confirm lifecycle and defaults |
| WHEN-BUTTON-PRESSED | Button plus server-side process/dynamic action | Separate UI behavior from database transaction logic |
| PRE/POST triggers | Validations, computations, page processes, or database API | Confirm ordering and transaction semantics |
| LOV/record group | Shared LOV or autocomplete | Review query, security, and cardinality |
| Forms global | Application item, preference, or authenticated context | Never use as proof of identity |
| Menu/tree navigator | Navigation menu, tree, cards, or search | Apply authorization before rendering targets |
| Report object | APEX report, document generator, or retained report adapter | Requires RDF/query/parameter/output evidence |
| Oracle Graphics | APEX chart/dashboard or external analytics | No direct runtime conversion |
| PLL routine | Database package, shared APEX process, or client behavior | Keep reusable business logic server-side when practical |

Prefer database APIs for important transactions. Keep launch targets disabled until their source and authorization rules are reviewed.
