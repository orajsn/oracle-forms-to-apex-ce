# Migration Boundaries

## Evidence hierarchy

1. Oracle-generated Forms XML, PLD, readable RDF/report source, DDL, package source, and successful compiler output.
2. Screenshots, sample reports, representative data, and owner-provided process descriptions.
3. Binary strings and naming conventions, used only as supporting clues.
4. Design inference, always labeled and manually reviewed.

## Do not overclaim

- An FMB conversion exposes the objects stored in that module; it does not supply referenced Forms, menus, libraries, database objects, or report sources.
- A report registration proves only that the form knew a report name.
- A table or package reference does not prove that its DDL or implementation was supplied.
- A valid APEXlang project proves syntax compatibility, not business equivalence.
- A successful import proves deployment, not functional or performance parity.

## Security rewrites

Do not port embedded database passwords, credentials in report URLs, client-machine serial checks, unrestricted dynamic SQL, arbitrary file execution, or trusting Forms globals as authentication. Replace them with APEX authentication, authorization schemes, reviewed database APIs, server-side secrets, and auditable processes.

## Minimum manual review

- business owner confirms workflows and labels
- DBA confirms schema objects and privileges
- security owner approves authentication and sensitive-data handling
- report owner confirms parameters, calculations, and output samples
- tester confirms expected behavior with representative cases
