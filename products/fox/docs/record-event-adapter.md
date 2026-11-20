# Connect source rules to draft-record actions

The generated related-record page can now open **Validate draft records** when
the complete source proves the supported duplicate-validation pipeline. Users
edit a record and choose Keep draft, Previous record, Next record or New draft
record. The source check runs before the draft is accepted or navigation proceeds.
Customer tables are not saved by this screen.

## Source proof and reusable mapping

The bounded rule recognizes an entire block-owned WHEN-VALIDATE-RECORD trigger:
assign a control key from direct character fields, evaluate a control SUM over
same-block comparison results, then issue literal messages and fail when the sum
exceeds one. The formula and complete same-module equality helper must match the
exact key references and order. A proven incoming source relation supplies the
parent context. Extra statements, ambiguous fields and repeated key references
are rejected rather than partially translated.

Original XML, trigger/formula/helper bodies, metadata, native targets and source
hashes remain bound. The assembler rebuilds the plan immediately before rendering;
the renderer checks its catalog against the source-derived immutable parent.
Supporting units do not become additional conversion claims. Generated, format
validated, installed, runtime verified and business accepted remain separate.

## Record and event behavior

- A named APEX collection holds loaded drafts for one operation and parent within
  the current application/session. Initial loading uses the source relation and
  synthetic row identities; it does not query every record as a uniqueness test.
- When a key field declares CopyValueFromItem from the selected parent, FOX
  verifies the exact incoming join and parent column. Both the first draft and
  each new draft receive that server value. The draft page protects the copied
  field and checks its value against the locked parent before changing records.
  This enforces the selected relationship throughout the session draft. A parent
  with a missing or oversized key needs a valid value before drafting can begin.
- Browser-rendered parent, sequence and revision values use protected request-only
  items. The server checks them against collection state, takes a NOWAIT lock on
  the synthetic parent and rechecks before mutation. Unknown actions and stale
  requests fail without updating drafts. Locking/concurrency still needs an
  installed-target check.
- The current edited record is included once. Other loaded edited records remain
  in the comparison. NULL does not equal NULL. Concatenation gains no delimiter,
  so source collisions such as AB+C and A+BC remain source behavior.
- The source control assignment and SUM precede duplicate failure. Failed values
  stay in the draft, the revision advances, messages retain their order and the
  user remains on the same record. APEX inline validation redisplay skips the
  loader; the source event is adapted to explicit submit buttons.
- Required and length checks happen before the record trigger. BYTE limits use
  LENGTHB. Text items do not trim whitespace. Case restrictions affect edited
  values, while queried/internal values remain unchanged. A client input flag
  distinguishes editing and a server RAW comparison detects changed values; the
  flag is not an authorization decision. Display casing is separate from the
  stored value. Oracle UPPER/LOWER, source encoding and comparison compatibility
  require target verification; the reference model limits typed case conversion
  to ASCII rather than claiming Python Unicode casing equals Oracle.

The adapter supports up to 1,000 loaded records and four distinct key fields.
It never silently truncates the record set or values. A complete validation body
that exceeds the conservative native 3,950-byte limit stays an explicit capacity
gap. No page or navigation link is emitted for that unsupported operation.

New drafts contain only the mapped key fields. Deletion, reload/discard lifecycle,
all other Forms events, writes and transaction rules are separate work. Leaving
the screen can discard edits not kept. The collection is a session draft, not a
business commit or a claim of complete Forms buffer equivalence.

## Verification and Oracle references

`examples/xml-mapping/record_buffer.xml` is a renamed synthetic complete pipeline.
Planner/model tests cover NULLs, whitespace, concatenation collisions, edited
rows, required/byte limits, case conversion, stale revisions and malformed proofs.
Native tests inspect emitted event order, source bindings and protected state.
SQLcl `/nolog` validates the APEXlang package format, not PL/SQL execution.

Installed-target checks must cover collection APIs, source-compatible charset and
collation, failed-submit revision checksums, implicit commit behavior, concurrent
tabs and user acceptance before broader use.

Relevant primary references:

- [APEX collections](https://docs.oracle.com/en/database/oracle/apex/24.2/aeapi/APEX_COLLECTION.html)
- [Character member updates and size limits](https://docs.oracle.com/en/database/oracle/apex/24.2/aeapi/UPDATE_MEMBER_ATTRIBUTE-Procedure-Signature-1.html)
- [Validation redisplay](https://docs.oracle.com/en/database/oracle/apex/24.2/htmdb/understanding-validations.html)
- [APEX processing and implicit commit points](https://docs.oracle.com/en/database/oracle/apex/24.2/htmdb/how-does-page-processing-and-page-rendering-work.html)
- [Forms 6i reference, Case Restriction, printed page 584](https://docs.oracle.com/cd/A97338_01/doc/forms.6i/a73074/A73074_01.pdf)

The legacy Forms reference explains the input/display distinction; it is not
evidence that an unidentified customer Forms version or target runtime was tested.
