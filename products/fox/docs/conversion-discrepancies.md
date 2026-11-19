# Continue conversion and keep discrepancies visible

FOX generates the supported parts of a form and keeps remaining work visible in
the generated package and conversion UI. A missing or unverified dependency does
not, by itself, prevent independent supported mappings from being generated.
Malformed source, invalid source bindings and failed package validation still
stop a result from being presented as valid.

The source-unit view accounts for every original code unit once:

- **Generated or adapted:** native target code was generated; its adaptation
  notes explain how the web behavior differs from Forms. Runtime checks remain.
- **Encoded, awaiting connection:** review code exists but its event, state or
  target effects have not been connected. These units remain unfinished.
- **Not yet implemented:** the source is retained and FOX still needs a complete
  mapping. The UI shows the source file/line, explanation and next action.

The reference view is separate. Repeated references are grouped within their
original source module, with each source occurrence retained. It distinguishes
known Forms behavior, supplied local routines, database objects, report
registrations and other routine or source-link candidates. A reference is not
proof that a file is missing, a function is reachable, or an interface works.
A report registration does not supply its query or layout. Existing database
routines may be reused through verified bindings rather than rewritten.

## Source evidence and saved history

The package includes a discrepancy report and separately hash-bound reference
evidence. The reference scan interprets supported encoded TAB/LF/CR separators
outside source literals so a comment does not hide later calls. Ambiguous decoding
keeps original candidates with an explicit evidence limitation. Names remain
lexical candidates, not a compiler or runtime claim.

This additional reporting analysis does not alter original XML, code-unit hashes,
legacy source identity or the conversion ledger. Generated/adapted counts are not
increased by discovering more references. The immutable report is checked against
its ledger/catalog, source locations and artifact hashes before the API serves it.
Fresh generation rebuilds evidence from originals. Historical reads keep the saved
classification without running a newer classifier or replaying generation.

Older saved runs without this report retain their original gap view and downloads.
Current UI parsing rejects inconsistent counts, duplicate unit identities,
unsupported claims and mismatched linked source coordinates. Genuine repeated
reference occurrences at the same XML element are allowed. Text is rendered as
text, including source values resembling HTML.

Generation, offline format validation, installed APEX behavior and business
acceptance remain separate facts. This feature improves transparency and source
reference discovery; it is not another batch of converted business rules.
