# FOX changelog

FOX software versions use `fox-v<major>.<minor>.<patch>` Git tags, separate from
the CE repository's tags. A source release is not proof of deployment or a
successful conversion. See [release policy](docs/release-policy.md).

Independently pinned deployment-only corrections have a separate
[deployment-tool changelog](deployment/CHANGELOG.md); they do not change the
application version or relabel existing images.

## Documentation updates - 2026-11-21

### [testing] Verify settled bag focus and the complete entry reset

An installed APEX 26.1.6 app retained focus on the intended next field after
initialization. Keeping a new session draft with a bag code and an empty
destination reached the reset branch. The app cleared the code, focused the
header destination and cleared the marker after a single acknowledgement.
The final rendered page retained destination focus. The consignment end-of-list
and explicit draft assignment checks also passed. The assignment fixture had
a null summary. All three synthetic business tables matched their starting rows.

The same engine generated SQLcl-validated packages for two distinct Forms XML
inputs. Their active-route queries ran locally on synthetic data and preserved
each form's original filtering and join conditions. The second input has local
generation and query evidence. Its lookup return fields still require wiring.

### [testing] Verify field commands on an installed 0.50.0 APEX app

In an isolated APEX 26.1.6 app, both source-directed focus moves worked by
keyboard and button. All four empty query handlers consumed only their own
field's command. A manifest without details kept its empty selection. A
separate read-only session exercised the saved entry check and explicitly
invoked the generated local routine. The routine focused its bound field and
copied the saved summary to the session display. No original caller was
inferred. Oracle parsed seven generated statements, the compiled export was
verified, and full snapshots of all three synthetic business tables matched.

### [testing] Verify selected-record delete checks in Oracle APEX

An isolated APEX 26.1.6 app generated from 0.49.0 passed seven browser stages
using six existing synthetic records. The two manifests showed two and zero
bags, each selected bag showed one consignment, and neither consignment
had child rows. All four bag and consignment checks reported an unavailable
external permission result. Oracle parsed 12 generated queries and the compiled
export was verified. Full comparisons of all three business tables matched
before and after the run. External permission, audit and deletion execution
remain unverified.

### [testing] Verify saved weight correction and composite bag links in APEX

An isolated APEX 26.1.6 app generated from 0.48.0 passed both bag-to-consignment
selections, Cancel, rejection and correction of a zero input, and return to the
same manifest. One valid Save reduced the missing-weight count from two to one.
Restoring the original weight and route returned all three synthetic tables to
their verified starting state. The installed app used the saved project
identity. Seventeen statements passed target parsing and the compiled export
was verified. The broader approval transaction and concurrent editing remain
outside this runtime result.

## Documentation updates - 2026-11-20

### [testing] Verify the corrected synthetic Save in installed APEX
The 0.41.0 draft approval check passed all eight installed browser stages.
The 0.42.1 Save check reused one synthetic parent in the isolated APEX 26.1.6
workspace and finished with exactly two related rows. Eleven database
checkpoints covered empty Save, insert, repeat Save, duplicate rejection,
independent parent-route changes, unchanged and edited rows, and rejection of
a stale edit. The stale input stayed visible and prior rows were preserved.
One browser observation after a successful second insert still showed an old
alert. The stored row and its identity were reconciled before the test resumed
without reinserting it. This evidence covers the installed Save workflow.
The 0.43.0 list-return feature has separate target and source-interface checks.

### [testing] Check when a record-entry rule is ready to generate
The discrepancy regression covers both outcomes for the same synthetic rule.
With an explicit target field size, FOX generates the record-entry action.
With the size omitted, FOX lists the rule as encoded and awaiting connection.

### [docs] Record private lookup-engine acceptance
Impact: Private0.38.0 now generates the three additional source lookup handlers
through the ordinary package workflow. Public0.37.0 remains unchanged.
Delivery: Reviewed source/tag published; private0.38.0 active.
Verification: Linux426 checks passed. Exactly one authenticated private browser
submission generated and downloaded the package, with9 generated/adapted units,
9 encoded/unwired and35 unimplemented. All status filters, lookup prerequisite
notice and old/new output checks passed with no browser errors. All424 old private
files and original rows were preserved; only1run+2events added. Public service,
23 captured public files and all ten public non-authentication table snapshots
were preserved. Worker completed once without errors. No original datasource
query, paid model call or Oracle import was executed; hosted evidence stays local
to the VM.
Remaining: Original lookup interfaces remain disabled until trusted target setup
is verified. The generated handlers have no customer Save/DML. Installed Oracle
behavior, broader source lifecycle and business acceptance remain unverified.

## Documentation updates - 2026-11-19

### [testing] Verify private discrepancy filters and saved outputs
Impact: Verifies the released discrepancy workflow; no additional conversion rules.
Change: The browser regression now exercises all status filters explicitly.
Delivery: Private preview 0.37.0 active; public deployment unchanged.
Verification: Linux suite passed366 checks. One authenticated generation produced
and downloaded the new package. The initial checker then used an overly exact
label selector for the status control; a read-only follow-up verified all53 units,
6/9/38 filters,76 reference groups/153 occurrences, desktop/mobile layout and both
old/new downloads. It made zero additional project submissions. All419 prior files
and original non-authentication rows were preserved; only1run+2events were added.
Worker completed once without errors. No provider call or Oracle import. Hosted
customer files/screenshots remain on the private host. The original checker failure
is retained separately from the successful read-only acceptance.
Remaining: Reference candidates and generated adaptations remain unverified in an
installed Oracle/APEX target; full business conversion and acceptance are not implied.


### [docs] Close private draft-record release acceptance
Impact: Private preview 0.36.0 generates the source-bound draft-record validation
screen through the normal package-generation and download workflow.
Delivery: Sanitized source/tag published; private 0.36.0 active. Public unchanged.
Verification: Linux checks passed 287 cases. One authenticated browser submission
completed generation, actual SQLcl /nolog validation and package download, showing
six generated/adapted units, 47 unfinished and one connected draft check. Seven
policy and two assignment review rules remain unwired. No browser errors; previous
package download, all 414 prior files and original non-authentication rows were
preserved. Only one run and two events were added. Worker completed once with zero
errors. The retained outcomes and current healthy private worker were rechecked
read-only after the user-requested pause; no conversion or deployment was repeated.
Remaining: The hosted check verifies FOX generation/download, not execution of
the generated screen inside Oracle APEX. Installed runtime, failed-submit checksum
refresh, concurrency, character compatibility and business acceptance remain
unverified. Customer-table saves and broader source lifecycle are separate work.


### [docs] Record private source-policy acceptance
Impact: Private preview 0.35.0 now exposes native ordering and separate policy
review counts through the normal generation and download workflow.
Delivery: Sanitized source/tag published; private 0.35.0 active. Public unchanged.
Verification: Linux suite passed 217 checks. One authenticated browser submission
completed actual SQLcl /nolog validation and download, with five generated/adapted
units, 48 unfinished, seven policy review rules and two assignment review rules.
No browser errors. Previous package download, all 409 prior files and all original
non-authentication rows were preserved; only one run and two events were added.
Worker completed once with zero errors. Launcher-only failures occurred before
any browser submission and were corrected without replaying conversion. Customer
outputs and browser evidence remain on the private host. No AI call or DB import.
Remaining: Nine encoded review rules still need event/context wiring. Other source
buffer/event, SQL/transaction and external-contract gaps remain explicit. Target
runtime, policy Oracle compilation and business acceptance are unverified.


### [docs] Record private record-context acceptance
Delivery: Private preview 0.34.0 active; public deployment unchanged.
Verification: Linux checks passed 180 cases. One authenticated browser round
completed generation, actual SQLcl 26.1.2 /nolog validation and download on the
private host. The UI reported two read-only relationships and two assignment
rules encoded but not event-wired, separately from four converted/adapted code
units and 49 remaining units. Previous download and all 404 earlier files/rows
were preserved; only the new run and its two mapping events were added. Worker
completed once without errors. No AI call or DB import. Hosted customer files
and browser evidence were kept on the private host, not copied to the laptop.
Remaining: Generated APEX navigation still needs installed-target runtime checks.
Assignment SQL remains review-only: not Oracle-compiled, installed or event-wired.


### [docs] Record private comparison mapping and gap-details acceptance
Impact: The private website now exposes the additional comparison mappings and
source-specific explanations for remaining units.
Delivery: Private preview 0.33.0 active; public deployment unchanged. One new
browser submission generated the retained-source package with four generated or
adapted units and 49 remaining (33 engine mappings, 16 context mappings).
Verification: Isolated Linux suite passed 299 checks. Actual SQLcl 26.1.2 /nolog,
new package download, 49 rendered explanation rows and desktop/mobile no-overflow
checks passed. The previous package downloaded byte-identically across the catalog
upgrade. All 399 prior files and original non-authentication rows were preserved;
only the new run and its two mapping events were added. Worker reported one
GENERATED completion with zero errors. No new AI call or database import.
Remaining: Host-side browser evidence and the new package remain private. Target
collation/session/runtime equivalence and business acceptance are not established.


### [docs] Record private web conversion and saved-package acceptance
Impact: The reusable mapping route is verified in the private FOX website.
Change: One authenticated browser submission used retained original XML, restored
its run after reload, generated a package and downloaded matching bytes. A browser
checker subsequently used the wrong Output-tab label; read-only follow-ups completed
the desktop/mobile checks without another conversion. The run retained two generated
or adapted code units and 51 unsupported units, with full source/dependency ledgers.
Delivery: Private preview 0.32.1 active; public deployment unchanged. The 0.32.0
round exposed the worker outcome reporting issue fixed by 0.32.1. Saved output was
rechecked on the patch and remained byte-identical; no customer run was repeated.
Verification: Linux integration checks passed 75 cases; patch checks passed 27.
Actual SQLcl 26.1.2 /nolog and authenticated browser/download checks passed.
All earlier source/job files and rows were preserved; the patch retained all 399
current files and all non-authentication rows. No new provider call or DB import.
Remaining: Synthetic format-validated output is not full Forms behavior, APEX
runtime verification or business acceptance. Unsupported mappings remain explicit.


### [docs] Normalize mapping component source formatting
Remove an extra trailing blank line reported by the staged whitespace check.
No runtime behavior, generated asset or software version changes.

## [0.55.0] - 2026-11-22

### [feature] Continue mapping after adding supporting source

A project can now generate a package after an operator adds readable SQL, a
package specification or body, or a Forms library source alongside its Forms
XML. The package preserves the supporting bytes as text evidence and records
the complete selected-source hash. The saved result shows which declaration
requests changed compared with the same Forms XML alone. Supporting scripts
are never installed or executed by this workflow.

An earlier package stays bound to its own selection. A changed selection
requires a new request. On completion the workbench refreshes availability
and directs the operator back to the saved mapping result.

### [fix] Retain compiler results in deep Windows project folders

FOX now saves and verifies the full SHA-256-named SQLcl log even when its
Windows path reaches 260 characters. An actual SQLcl run retained its log
at a 287-character path. Reading a changed log still fails verification.

## [0.54.0] - 2026-11-22

### [feature] Save and reopen a row with multiple source-defined choices

An eligible source block now has one editor for its related choices. Picking
a list entry fills only the fields identified by its XML return mappings.
The chooser can show additional text or numeric columns for reference.
Save checks the row revision, required fields and list-validated values before
persisting the mapped fields to private synthetic storage. The same user can
reopen that row in a later session. Conflicting edits require a fresh selection.
The original business save and other source events retain their own coverage.

The conversion result groups supporting definitions by file type and shows
the source location for each request. Registered Forms libraries are identified
separately from screen references. The result identifies referenced menu
modules absent from the supplied XML. The project workbench links to assessed
outstanding requests from conversion and output.

Both original packages passed SQLcl format validation. Eighteen local Oracle
checks exercised two rows, durable saves and reopening across fresh connections,
including stale updates and missing list values. The test supplied APEX
identity values. Installed APEX browser acceptance remains open. The release
regression suite passed 1,694 checks. A separate FOX browser and API test
verified that supplying a missing package body clears its source request.

## [0.53.0] - 2026-11-22

### [feature] Generate more lookup queries and field-event code from Forms XML

FOX now recognizes explicit SELECT ALL, simple single-table lists, direct
column aliases, literal exclusions and ordering by projection position.
For SELECT * FROM DUAL it requires the matching single-column Forms
declaration. Reference reports preserve their source filters, duplicates and
sort order. Original database access still requires a verified interface.

When an optional chooser's field also has a supported POST-CHANGE lookup,
keeping a changed typed key recalculates the companion fields on that draft.
The source lookup and its missing-value failure are checked independently of
the list filter. A failed or ambiguous lookup leaves the draft unchanged.

Complete scalar audit and numeric validation triggers can also produce a
callable PL/SQL package. Its source-linked parameter list identifies the
trusted globals, current field and row outputs required by the event host.
FOX reports these procedures as awaiting wiring.

Two original forms passed SQLcl package validation. All 21 record-group
queries matched the corresponding source queries on local synthetic test
rows. The release regression suite passed 1,615 checks. Installed APEX
execution and Oracle compilation of the optional procedures remain unverified.

## [0.52.0] - 2026-11-21

### [feature] Return a lookup choice to the selected draft row

For an optional list of values on a source block with no existing editor, FOX
can now generate a row editor and a choice page from the XML. Each draft has
its own identity. Applying a choice fills the calling field and its mapped
companion fields together. Display fields receive their source values and
remain read-only in the editor.

The generated choice list uses a private synthetic catalog and applies the
source query's filter. The editor rechecks the selected row, its revision and
the full choice before updating the session draft. Cancel preserves the draft.
The package includes supporting SQL for both tables. It records other Forms
events and the original business save as separate work.

Two original XML inputs passed SQLcl format validation. On local Oracle AI
Database Free, the packaged SQL and PL/SQL applied different three-field
choices to two rows and rejected stale, duplicated, inactive and wrong-row
choices. The test supplied application identity values locally. Installed APEX
browser verification is separate. All 1,491 release regression checks passed.

## [0.51.0] - 2026-11-21

### [feature] Connect XML entry actions to the selected session draft

The generated bag editor can clear the current bag code, move focus to the
header destination, and clear its marker after focus succeeds. Consignment
entry can assign the sum of individually rounded saved detail weights to the
selected bag draft's cost weight. An explicit local procedure can make that
assignment after focusing its source field. The generator records that the
source supplies no caller for this procedure.

The conversion review has separate filters for entry wiring and outstanding
external dependencies. It keeps whole-form commit, unposted detail values and
source lookup requirements visible. Saved-record navigation uses the synthetic
row ID when the XML supplies no ordering. Draft changes are session-scoped.

After an entry action submits, the generated page returns to the selected
record with a signed link. A one-use result tied to that record and draft
revision restores the focus or confirmation on the new page.

Bag entry applies source-directed focus after APEX finishes page initialization.
The reset checks that the destination still holds focus before it acknowledges
the move and clears the marker. Ordinary visits keep their normal cursor behavior.

## [0.50.0] - 2026-11-21

### [feature] Run XML-defined field commands and inspect remaining gaps

On selected saved records, Next follows a literal source field target. Enter
Query and Execute Query respect explicit empty handlers on their owning fields.
The compiler also records complete local item-entry and navigation procedures
with their field assignments, summary calculations and transaction boundaries.

**Show remaining gaps** opens the unfinished source actions together. The
review identifies each owning field or routine and lists referenced database
interfaces, report definitions and Forms session values. An immediately skipped
query after a trigger failure is distinguished from a live branch. Historical
packages retain the classifications recorded when they were generated.

## [0.49.0] - 2026-11-21

### [feature] Check delete requirements for a saved record

FOX recognizes the source check for a master with matching detail rows and
the delete workflows for bags and consignments. The generated checks show
which saved record is selected, which related rows match, and which permission
or audit interface the original form uses. Original routines and row deletion
remain disabled in these pages.

The interface register links an audit call to the key action that marks its
record and later requests posting. A literal database commit requested during
posting is recorded separately from the form-wide commit. The packaged
source plan preserves both boundaries and the composite keys of the child delete.

## [0.48.0] - 2026-11-21

### [feature] Correct a blocking bag weight from approval readiness

The generator connects a missing-weight result to the affected saved bags.
The user can select a bag, enter its actual weight and explicitly save before
checking the same manifest again. The correction uses synthetic tables and
the source field validation, edit permissions and before-update assignment.
It leaves the original approval transaction and external calls pending.

The saved-row check also supports wide blocks: it hashes ordered groups of
fields before concatenation would exceed Oracle's standard SQL string limit.

## [0.47.0] - 2026-11-21

### [feature] Refresh staged query rows for the entered key

FOX recognizes the Forms sequence that clears staged rows for one key,
reloads them from a distinct source table and executes the block query. The
generated APEX screen can refresh that key in a private session collection,
retain matching duplicates and other keys, and apply the block filter and sort.
The source interface and trusted session values require administrator setup.

The package records the full ordered column list, the caller-owned transaction
and each table access. The interface register now recognizes Oracle DELETE
statements that omit FROM. The discrepancy view identifies the remaining work
to reproduce original staging visibility, defaults and transaction lifetime.

## [0.46.0] - 2026-11-21

### [feature] Show source-backed approval readiness on the selected manifest
FOX binds the approval button to its current source permission, selected
header and matching bag and consignment records. A missing or zero actual
weight is checked before a missing destination. The page identifies the
blocking field and a matching bag when one is available. Later checks report
the state of saved rows and identify their position after source commit stages.

The complete caller workflow records three independent commits, local helper
calls and two external calls in source order. The native readiness action
leaves data unchanged. The original whole-form state, commits and external
interfaces need verified providers before business approval can run.

This release also includes the 0.44.1 correction for multi-field master
keys in APEX links. The chooser and receiving page use the same ordered digest.

## [0.45.1] - 2026-11-20

### [performance] Reuse validated XML within one deterministic generation
For the measured 53-unit form, a single package generation previously built
the source packet 77 times and parsed the XML 218 times. Exact-input source
reuse reduced both counts to one. Median time across three warm local runs
fell from 6.43 seconds to 2.47 seconds. These measurements cover generation
on the same Windows environment and exclude SQLcl startup, network and import.

Independent adapters receive their own XML and packet values. Reuse ends
with the generation, including on failure. Changed inputs, another task and
subsequent package verification cannot borrow the previous build's results.
Existing proof/consent checks and bounded retained reads retain their own scope.
All 919 local regression checks passed. The original and renamed 53-unit
packages retained the exact APEX members, source XML and detailed interface
exports from 0.45.0 and passed SQLcl validation without warnings.

## [0.45.0] - 2026-11-20

### [feature] Validate a changed field and trace its required interfaces
Eligible item validation runs on the current draft field when a submitted
value changes. A source warning sets its marker. A duplicate lookup against
all mapped synthetic rows can clear the field and reject the action. The
session retains source-derived assignments and keeps the loaded baseline
separate from current values. The before-write assignment still reads the
current parent at the actual write. Later navigation and the original Forms
commit are separate source events.

Saved mapping runs can provide an authenticated interface CSV. It identifies
the referring action, source location, supplied argument forms, known field
types and static paths through local routines. The package also contains a
structured JSON register when it fits. Formal parameter direction, target
availability and execution require separate verification.

The integrated local suite passed 848 checks, and SQLcl 26.1.2 validated the
original and renamed 53-unit packages without warnings. Both sealed packages
reconstruct exactly. The original now has 20 generated/adapted units, eight
partly connected, three encoded without a connected action and 22 unimplemented.
Its detailed register contains 303 source records and 739 CSV rows, including
15 distinct qualified routine references. Execution of the changed-item event
inside an installed Oracle APEX app remains unverified.

## [0.44.0] - 2026-11-20

### [feature] Coordinate selected masters and their related session drafts
Selecting a saved master now displays its current context and automatically
loads children matching the source relation. The generator preserves the
source's single-key and alternative-key guards. A deferred relation remains
pending. The related draft editor can also show children for its current stored
row while keeping new, dirty or stale input separate.

The master-switch screen checks all retained rows in its supported child draft
buffer. Cancel restores the prior selection. Discard clears only the identified
session buffer after rechecking its revision. Save opens the existing draft
editor. Source-wide commit, other descendant buffers and the full Forms cursor
lifecycle remain open. The discrepancy view identifies these partial effects
without counting the whole source units as converted.

The integrated local suite passed 784 checks. Both 53-unit packages passed
SQLcl 26.1.2 format validation without warnings, and independent review
reconstructed their exact bytes. The original discrepancy view shows 19
generated or adapted, eight partly connected, three encoded with no connected
action, and 23 with no implementation. The same partition was checked using
renamed identifiers and the original desktop/mobile report.

## [0.43.1] - 2026-11-20

### [fix] Identify nested routine bodies and count unquoted references consistently
The dependency report identifies a named nested subprogram body inside its
referring source unit. Forward declarations, comments and quoted business text
do not establish a body. The report points out known Oracle SQL function names
and the target checks for qualified routine references. Runtime resolution
still depends on scope, arguments and the actual database interface.

Capitalization used to change reference totals when the same source unit
spelled an unquoted identifier two ways. The original and a renamed 53-unit
module now each report 86 groups and 183 reference facts. Their source-unit
coverage remains 19 generated or adapted, six awaiting full connection and
28 unimplemented. Historical packages keep their original classifications.
All 728 local integration checks passed. SQLcl 26.1.2 validated both 53-unit
packages without warnings. The original native APEX members matched 0.43.0
byte-for-byte, and the new notes rendered on desktop and mobile.

## [0.43.0] - 2026-11-20

### [feature] Return the selected list row to its source fields
FOX connects an eligible Forms list of values to its calling item in a native
APEX editor. Apply rechecks the current selected record, source permission,
readiness and query inputs. It returns the declared columns to the same session
draft, including display fields, when the selected source row is unambiguous.
The visible choices preserve supported source ordering. The source-unit notes
show each connected return and the reason other declared returns remain open.

The original form has one eligible existing-record caller with two returns.
Another caller is update-disabled and needs a proven new-record context. A third
list has declared returns and no supported calling item in the supplied module.
Source database reads default to disabled. A choice updates session draft fields.
The existing record-group query counts once in source-unit coverage.

All 725 local integration checks passed. SQLcl 26.1.2 validated both the
original package and a renamed example without warnings. Independent review
rebuilt both packages byte-for-byte. The three original list outcomes were
also checked in the local desktop and mobile discrepancy view. Live execution
of a list against its original database interface remains unverified.

## [0.42.1] - 2026-11-20

### [fix] Keep the selected parent after a synthetic save
The installed 0.42.0 app returned to the editor without its request-scoped
parent ID after the first empty Save. APEX logged the missing-parent error
and the database contained zero new detail rows. Save now uses the same
protected return link as the other draft actions. Failed submissions retain
their separate inline error path. The stale-row handler now recognizes the
PL/SQL SQLCODE of +100 for NO_DATA_FOUND.

All 685 local integration checks passed. SQLcl 26.1.2 validated the original
and renamed packages without warnings. The corrected JSN test reuses the
existing synthetic manifest from the 0.42.0 test.

## [0.42.0] - 2026-11-20

### [feature] Save the current related record to synthetic test tables
The draft editor can save a new or edited row when both before-write assignments
are bound to the selected parent. It reads the parent's current value at the
write, checks approval, and protects loaded rows against stale edits. A changed
row updates only the declared fields. An unchanged row keeps its existing route.
The generated process uses non-waiting table locks on the two synthetic tables
to serialize related writes. The source-unit ledger identifies each wired
assignment and the saved-run view reports the corresponding screen.

This action covers a single synthetic row. Customer saves, other field
validations, approval side effects and the original Forms commit sequence remain
open. The existing JSN runtime approval concerns the previous 0.41.0 package.

All 685 integrated checks passed locally. SQLcl 26.1.2 validated the original
and renamed packages without warnings. Independent verification reconstructed
both sealed packages and exercised the emitted write statements on a local SQL
model. The original now has 19 generated or adapted units, six encoded units
awaiting connection and 28 unimplemented units. Installed APEX execution of
synthetic saves and the original business transaction remain unverified.

## [0.41.0] - 2026-11-20

### [feature] Apply selected parent permissions to related drafts
The generated draft editor checks the current stored parent before creating a draft,
retaining a duplicate for correction, or keeping edits while moving between records.
When the source rule makes a draft read-only, the related report remains available.
The mapping ledger records which effects reach the draft. Other field and block
permissions, the approval transaction and customer saves remain separate work.

The discrepancy view shows the source units that directly reference each routine,
database object or Forms command. Users can search by reference name to find those
units. The inventory recognizes standalone calls to same-module routines and known
Forms commands, and preserves the schema in three-part routine names.

All 600 integration checks passed locally. The discrepancy browser check passed
on desktop and mobile layouts. SQLcl 26.1.2 validated both the original and
renamed packages without warnings. The original still has 17 generated or
adapted units, eight encoded units awaiting complete connections and 28
unimplemented units. Two of the eight contribute to the new draft guard.
Installed APEX testing of this version is pending.

## [0.40.0] - 2026-11-20

### [feature] Generate source query, navigation and record-entry actions
Impact: FOX creates a filtered source report, reference choices, guarded detail refreshes and session initialization from complete supported Forms rules. A record-entry page can apply a conditional assignment using explicitly selected rows.
Change: APEX report queries preserve the recognized predicates and source ordering. Protected row selections bind synthetic context. Restricted session values provide trusted globals. Original interfaces require target verification before reads can be enabled. Reference reports identify their LOV return-field requirements. The original-source block filter applies to the dedicated query screen. Session initialization preserves a prior value when its single-row query fails. An entry condition preserves the selected record's previous value on a false or NULL result.
Delivery: Source milestone for the ongoing form conversion.
Verification: The combined Windows suite passed 227 checks, including the local original-package check. SQLcl 26.1.2 validated the exact original and renamed packages with zero warnings. An independent runtime exercise of the preceding 0.39.2 package imported generated application components into the JSN test workspace and completed the synthetic manifest/bag draft workflow.
Remaining: Original interface activation, LOV return to calling fields, transactional approval/save/delete behavior and full business acceptance require further work. Installed verification of 0.39.2 applies to that exact build.

## [0.39.2] - 2026-11-20

### [fix] Inherit the selected parent for new detail drafts
Impact: Entering the first detail or adding another detail now carries forward the parent's business key. Users enter the detail code once. Duplicate entries stay on the current draft for correction.
Change: A source CopyValueFromItem on a duplicate-key field must resolve to a matching master/detail join. The generated page loads the value from the selected synthetic parent, protects it from editing and checks the stored and submitted values before changing the draft. A new lookup action requires a provider for every input. Lookups with additional row-dependent inputs are available on existing records.
Delivery: Published as fox-v0.39.2 and deployed to the private preview. Public 0.39.1 is the last verified public release.
Verification: The original form and a renamed dispatch form were generated and format validated with SQLcl. Model checks exercised initial and subsequent details, duplicate correction, conflicting parent values and the same code under a different parent.
The integrated suite passed 190 cases on Windows and Linux. One authenticated private generation/download verified the inherited field in the delivered package and preserved the previous download.
Remaining: The changes cover session drafts. Execution inside an installed APEX target and customer-table saves require separate verification.

## [0.39.1] - 2026-11-20

### [improvement] One Next step and one confirmation for a hosted form
Impact: The hosted export user no longer chooses a masking mode or needs to
understand what adding a prepared form means. Next saves the prepared source
and proceeds to Convert. A single confirmation covers both local processing
and partial output using synthetic data.
Change: Keep the source-version, permission and blocked-input checks; loading
an existing project does not silently submit a form or approve conversion.
Delivery: Deployed public source `04df588`. In a live browser a real FMB reached
the format-validated APEXlang ZIP in 22 seconds, including sign-in and project
creation. There was no preparation selector, Next advanced to Convert, and one
checkbox authorized generation. Exactly one upload, source adoption and
generation were submitted, with zero page errors. The prior export still
downloaded byte-identically. UI regressions also cover blocked/stale sources
and uncertain submissions. No additional source behavior or import is claimed.
Remaining: The output is still a partial APEXlang ZIP, not an imported app.

## [0.39.0] - 2026-11-20

### [improvement] Guide a single hosted FMB from upload to Convert
Impact: A business user can start with a project name and a raw FMB, see
preparation progress, and continue from the confirmed saved source without
reopening the project or uploading it again. No laptop Forms installation.
Change: Prioritize hosted FMB intake, group other routes, poll preparation
status with bounded read-only checks and tie Continue to the adopted source
version. Keep explicit local processing and partial-conversion approval.
Delivery: Public hosted preview deployed at source `8f62530`.
Verification: The authenticated public browser created a project, uploaded a
real FMB, waited for automatic status, adopted the XML, continued to Convert
and downloaded the result. One POST per step; no reopen, duplicate submission
or page errors. The 21-second observation is for this file on a running host,
not a service guarantee. The exact ZIP matched the SQLcl 26.1.2.0 offline
validation receipt. The partial result showed 9 generated/adapted, 9 encoded
but unwired, and 35 unimplemented units of 53. The earlier project and download
were preserved. No AI call or database import. TypeScript, production build
and modeled browser checks also passed.
Remaining: Extraction and conversion are separate. A generated package can have
unsupported Forms behavior; no target import or runtime equivalence is implied.

## [0.38.2] - 2026-11-20

### [fix] Keep saved XML exports available after parser changes
Impact: A new parser rejecting an old module need not prevent a user from
downloading the already-validated export from that run.
Change: Verify retained original file bytes and the historical unit manifest
without reinterpreting old XML. Bind the UI discrepancy report to the saved
run; keep generation eligibility tied to the current assessment.
Delivery: Source-only patch; no hosted rollout, cloud storage or data migration.
Verification: With the same saved 0.38.0 synthetic ZIP and deliberately rejecting
parser, 0.38.1 returned HTTP 409; 0.38.2 returned HTTP 200 and the original
SHA-256. Local API tests also reopened an isolated SQLite backup plus job files
in a second store, rejected altered evidence, and confirmed no extra run, render
or compiler call. An Edge browser fixture showed Download while Generate stayed
disabled; a mismatched saved report binding hid the link. Compiler was a test
double at creation, not a live Oracle/SQLcl execution.
Remaining: Local artifacts and their job database still require coordinated
backup. See [export recovery](docs/export-durability.md) for the proposed hosted
storage path and its crash-recovery acceptance criteria.

## [0.38.1] - 2026-11-20

### [performance] Open saved conversions without regenerating packages
Impact: Reviewing completed runs takes less time, especially in projects with several saved conversions.
Change: History, detail and download requests now use the same authenticated evidence reader for completed runs across mapping catalog versions. Each read checks the original source, event records, compiler log and both ZIPs.
Delivery: Published as fox-v0.38.1 and deployed to the private preview.
Verification: Four local reads of the same 53-unit package per version took a median of 2.57 seconds before the patch and 0.085 seconds after it. Package builds per read dropped from two to zero. Result details and download bytes matched. On the private preview, one authenticated history request for the same seven saved runs took 2.461 seconds before and 0.579 seconds after the upgrade. All 73 targeted checks passed on both Windows and Linux.
Remaining: History still verifies each listed run and reads its saved artifacts. Timings measure the local verification path.

## [0.38.0] - 2026-11-20

### [feature] Generate connected source lookup event handlers
Impact: Complete SELECT-INTO lookup triggers now generate native APEX pages and
connected processing instead of remaining unimplemented source.
Change: Selected-record POST-QUERY runs after initialization; POST-CHANGE is adapted
to explicit Apply lookup processing. Whole query projections, bindings, exactly-one
cardinality and source-specific NO_DATA_FOUND/WHEN OTHERS reset behavior are retained.
Typed locals are block-qualified against SQL name capture. Source field edit and
length restrictions remain enforced; occupied action slots and unsupported cased
editing stay explicit gaps. Existing report and related-record navigation is kept.
Original read interfaces are preserved behind restricted, unset server readiness
items and native execution conditions; no original query runs during conversion.
Delivery: Reviewed source and local packages prepared. Deployment is separate from
this evidence; the coordinating public0.37 promotion must remain preserved.
Verification: Backend115 checks, integrated141 checks and focused native6 checks
passed (overlapping suites). UI fixture, TypeScript and production build passed.
Actual SQLcl26.1.2 /nolog passed exact original-source and multi-module example
packages. Independent review reconstructed final candidates/sealed ZIPs exactly.
Remaining: Original objects, types, privileges, authorization and target semantics
must be verified before enabling source reads. This emits no customer Save/DML and
does not complete the broader Forms lifecycle. Oracle compilation/runtime and
business acceptance remain unverified. See [source lookup events](docs/source-lookup-events.md).

## [0.37.0] - 2026-11-19

### [improvement] Show discrepancies while supported conversion continues
Impact: Users can inspect every source unit's conversion state, adaptations and
next action without treating each unverified dependency as a reason to stop.
Change: The UI separates generated/adapted, encoded but awaiting connection and
unimplemented units, with searchable source locations. Module-scoped references
are grouped separately as database objects, Forms behavior, local routines,
report registrations and other candidates. Additive source evidence handles
encoded line breaks and simple comma joins that previously hid references, while
preserving original XML, legacy source identity and old saved classifications.
Delivery: Source release prepared; private activation is a separate guarded step.
Verification: Integrated suite passed165 checks; new and existing browser fixtures,
TypeScript and production build passed. Actual generated reports passed the UI
parser. Independent review reconstructed both exact candidates and sealed ZIPs;
SQLcl26.1.2 /nolog passed. APEX member hashes are unchanged from0.36 for the same
inputs and project parameters. Repeated source coordinates remain valid, while
mismatched linked locations and altered evidence are rejected.
Remaining: This adds no converted business units. Reference candidates are not
proof of missing files, reachability or target availability. Oracle/APEX runtime,
external interfaces and business acceptance remain unverified. See
[conversion discrepancies](docs/conversion-discrepancies.md).

## [0.36.0] - 2026-11-19

### [feature] Connect source duplicate checks to draft-record actions
Impact: Supported complete source duplicate-validation pipelines now generate a
native draft screen with Keep, Previous, Next and New actions, instead of leaving
the record event disconnected from its current values and loaded related records.
Change: Source-bound parent/session collections retain edited records and failed
candidates. Protected request-only identity/revision checks, source size/required
rules, edited-only casing and exact concatenation/SUM semantics precede navigation.
Source messages remain ordered; whitespace and fetched internal casing are kept.
A capacity overflow remains an explicit gap with no partial page or false count.
Delivery: Source release prepared; private activation is a separate guarded step.
Verification: Integration 86 checks, native renderer 7, source/model 62 and
converter-only 35 passed (overlapping suites). Relevant unchanged regression295
is retained. Actual local SQLcl26.1.2 /nolog passed exact source and multi-module
example packages; independent review reconstructed both byte-for-byte. Frontend
checks and the emitted input-tracking script browser check passed; the latter used
a synthetic DOM and is not Oracle/APEX runtime evidence.
Remaining: Session drafts do not save customer tables or implement all Forms
lifecycle/transaction rules. Oracle/APEX runtime, failed-submit checksum refresh,
concurrency, source-compatible charset/collation and business acceptance remain
unverified. See [record-event adapter](docs/record-event-adapter.md).

## [0.35.0] - 2026-11-19

### [feature] Encode finite source policies and initial report ordering
Impact: More source logic becomes reusable engine knowledge, with policy review
progress visible separately from executable APEX behavior.
Change: Complete bounded IF rules preserve conditional literal assignments,
permission resets/overrides, ordered warnings, terminal failure and supported
same-module local calls. Typed PL/SQL review procedures retain exact source and
context bindings. Complete direct-column ORDER BY clauses generate native saved
report sorts, respecting explicit database column names, direction and NULL order.
Ambiguous columns and unsupported whole bodies remain gaps. Policy review counts
are source-bound and optional for historical artifacts; no old run is regenerated.
Delivery: Source release prepared; private activation is a separate guarded step.
Verification: Focused integrated suite passed 99 checks; backend policy/assignment
and assembler suite passed 225 checks (overlapping suites, not a unique total).
Actual local SQLcl 26.1.2 /nolog passed exact original-source and multi-module
synthetic example packages. Frontend type/build and browser fixture passed.
Independent source/artifact review is recorded with the release evidence.
Remaining: Policy SQL is generated but not installed, Oracle-compiled or wired to
source events. No writes/permissions are activated. Record-buffer/query/transaction
adapters, verified external contracts and target runtime/business acceptance remain.
See [source-policy rules](docs/source-policy-rules.md) and the synthetic
`examples/xml-mapping/policy_rules.xml`.

## [0.34.0] - 2026-11-19

### [feature] Encode source-defined record context and parent-value assignments
Impact: Generated APEX includes filtered related-record views, with separate
progress for read navigation and assignment code that still needs event wiring.
Change: Explicit same-module AND/equality relations become protected parent-row
links and dedicated detail pages. Existing calculations and validation links stay
intact, including intermediate pages in a relation chain. Complete PRE-INSERT and
PRE-UPDATE parent-value copies produce namespaced pure IN/OUT PL/SQL review code.
These procedures remain in Not yet converted; no save/delete action is enabled.
Delivery: Source release; private deployment and hosted acceptance recorded separately.
Verification: Relation/assignment integration passed 130 checks, emitted-query
model checks passed 9, and API/upgrade integration passed 87 (overlapping suites).
Browser fixture, TypeScript and production build passed. Actual local SQLcl
26.1.2 /nolog accepted customer and synthetic example packages. The customer
package retains four wired/adapted code units, two read-only relationships and
two unwired assignments; the latter are not included in the converted count.
Remaining: Manual navigation and persisted synthetic data are explicit adaptations.
Session selection can persist across report refreshes. Automatic query, unsaved
buffers, cascading deletion and write lifecycle remain unconverted. Assignment
SQL is not installed, Oracle-compiled or event-wired; runtime/business acceptance
is not asserted. Source code-unit coverage is not inflated by relation or review-code counts.

## [0.33.0] - 2026-11-19

### [feature] Convert local comparison logic and explain unconverted source
Impact: Supported local comparison helpers and their formula callers become actual
APEX report expressions. Remaining units explain whether FOX lacks a mapping or
record context, needs a definition, or requires review, instead of one blanket
unsupported label.
Change: A bounded whole-body parser recognizes pure two-VARCHAR2 equality helpers,
resolves same-module calls and emits native CASE with VARCHAR2 casts. Concatenation
and proven control-session values retain source bindings; referenced controls get
explicit persistent session state and an Apply action. Helper coverage is counted
once only when a complete supported caller is emitted. Historical downloads verify
original DB-anchored snapshot/result/candidate/compiler/package evidence across
catalog changes; fresh candidate reconstruction remains strict.
Delivery: Source release; private deployment and hosted acceptance are recorded
separately in dated checkpoints.
Verification: Backend parser/binding/renderer regression passed 283 checks; the
integrated gap/upgrade/web/release set passed 90 checks. The browser fixture,
TypeScript and production build passed. Actual local SQLcl 26.1.2 /nolog accepted
the retained-source package (four generated/adapted units, 49 remaining) and two
same-named synthetic modules (six units generated). Retained actual compiler
output survived a catalog upgrade byte-for-byte with generation/compilation
forbidden. Independent source review cleared the reported semantic/binding issues.
Remaining: The duplicate-record workflow, parent-child write lifecycle and other
unconverted behavior remain explicit. Comparison collation/session compatibility
must be verified on a target; casts do not prove unconditional runtime equivalence.
No target import, business acceptance or new AI call is introduced.

## [0.32.1] - 2026-11-19

### [fix] Count generated mapping jobs as completed worker outcomes
Impact: A successful generated package no longer adds a false incomplete-outcome
error to worker health or leaves the completion count at zero.
Change: Add GENERATED to the worker monitor's completed-outcome vocabulary. This
is a processing outcome, not a runtime, technical-verification or business claim.
Delivery: Source patch; private activation and saved-output recheck are separate.
Verification: The real private 0.32.0 round exposed this reporting mismatch after
successful SQLcl validation/download. Focused monitor and real worker-path
regressions cover GENERATED without compiler replay. Prior artifact stays intact.
Remaining: This corrects monitoring only; no behavior coverage or runtime proof
is added, and the completed customer conversion is not repeated.

## [0.32.0] - 2026-11-19

### [feature] Run reusable XML mappings through the FOX project website
Impact: Users can start a reusable-mapping conversion and download its validated
APEXlang package from the existing project, without a command line or AI request.
Change: Authenticated project routes bind local-processing consent to original
sources, selected version, installed catalog and an idempotent request UUID. The
existing worker saves an immutable source snapshot and fresh SQLcl package proof.
Run history shows exact generated/unsupported counts and source-version identity;
download rechecks source, compiler and package evidence without execution.
Interrupted/unknown operations remain retained and are never automatically retried.
The browser preserves uncertain request identity, rejects stale responses and
keeps unrelated mutations fenced while the outcome needs reconciliation.
Delivery: Source release; hosted activation and actual browser acceptance are
recorded separately in dated checkpoints.
Verification: Thirty focused API checks and two additional rejection cases passed;
154 overlapping worker/fresh-install regressions passed. The synthetic browser
fixture covered deadlines, lost replies, rejection/uncertainty, reload locks and
response ordering. TypeScript and production build passed. An actual local API
run used SQLcl 26.1.2 /nolog, generated four sample behaviors with one explicit
gap, and returned the exact retained ZIP. Read-only status/download did not rerun
the compiler or change stored rows/files. Independent code review cleared.
Remaining: Explicit partial synthetic mapping scope, no customer-schema or full
business equivalence. Format validation does not establish import/runtime or human
acceptance. Existing AI routes remain separate. Fresh-installation admission is
not widened; a dedicated installation binding is required for that mode.

## [0.31.0] - 2026-11-19

### [feature] Reuse installed mappings to generate APEXlang directly from XML
Impact: Operators can generate a source-linked synthetic APEXlang application
from fresh Forms XML without a previous AI job or generated parent package.
Change: A deterministic structural policy feeds the existing native planner and
renderer, then applies supported business mappings. The versioned catalog and
source-to-target ledger distinguish structural objects, implemented code and
unresolved dependencies. Multiple modules share one application; database blocks
default to read-only reports. A bounded numeric expression tree adds arithmetic,
NULL, CEIL/FLOOR/ABS/ROUND/TRUNC/NVL with exact NUMBER bindings and no raw SQL
insertion, implicit casts or invented error handling. Original XML is preserved.
Delivery: Source release with a library/operator CLI. Normal web workflow
integration, hosted deployment and customer-target execution are separate.
Verification: Formula parser/planner/renderer and existing assembly regressions
passed 234 checks; the final overlapping XML/capacity/planner/renderer/release set
passed 182 checks. Independent source/artifact review cleared the final code.
Actual local CLI runs on two synthetic modules and retained original XML both
passed SQLcl 26.1.2 /nolog validation without warnings. The synthetic modules
produced four generated behaviors and one explicit external-call gap; the retained
source kept two generated behaviors and 51 unsupported units. No prior package or
AI request was needed. Original source and earlier packages were preserved.
Remaining: Synthetic structure is not customer-schema equivalence. Relationship,
record-buffer, transaction, external package and unsupported trigger behavior
remain explicit. Formula calculations use persisted rows; the Continue page does
not save. No AI approval, target import/runtime proof or business acceptance is
inferred. See [mapping architecture and operator guide](docs/xml-mapping-engine.md).

## [0.30.0] - 2026-11-18

### [feature] Generate source-linked calculations and native APEX validations
Impact: An operator can generate executable APEX components for two supported
Forms business-rule patterns using the original XML and matching parent package.
Change: A finite whole-unit parser maps a numeric CEIL expression to a report SQL
projection, or a numeric nonzero guard and focus change to a linked validation
page. Source minimum values remain separate validations. Every unit retains its
status, source hashes and explicit web adaptations. The assembler preserves
parent evidence, retires its validation claim for the new package and binds fresh
SQLcl evidence to unchanged generated APEX bytes. No model request is needed.
Delivery: Source release with an operator CLI/library; web generation integration
and deployment are separate. See [operator guide](docs/source-behavior-generation.md).
Verification: Planner/source regressions passed 115 tests; renderer regressions
passed 232 tests; assembly passed 21 tests. The overlapping final renderer and
assembly set passed 57 tests after the page filename correction. Independent
review passed. The retained source produced two generated/wired/adapted units and
51 unsupported units; actual local SQLcl 26.1.2 /nolog validation succeeded with
APEXlang MMD 26.1.0+3102. Counts describe separate, overlapping checks.
Remaining: This is a finite first generator slice, not a complete form conversion.
The validation page loads an existing synthetic row, checks input on Continue
and requests focus; it does not save or commit. Report computation uses persisted
rows. No target import, APEX execution or business-behavior acceptance is claimed.

## [0.29.6] - 2026-11-18

### [fix] Let the saved-output check finish without restarting conversion
Impact: The UI can finish checking a generated package and expose its download
link, instead of cancelling the read after thirty seconds.
Change: Only the read-only output GET uses a bounded ten-minute deadline, with
a visible waiting message. Source/revision checks, response validation, disabled
duplicate clicks, error handling and all backend validators stay unchanged.
Verification: A real browser fixture passed a response delayed beyond thirty
seconds, the bounded timeout, stale-source suppression and backend-error cases.
TypeScript and independent source review passed. The real retained output API
returned the exact package hash after 277 seconds with no generation request.
Delivery: Source published; private browser/download acceptance is recorded in
the dated documentation checkpoint below. Public rollout remains separate.
Remaining: This fixes premature cancellation, not the underlying proof-check cost.
Saved-output verification may still take several minutes. No new model call,
regeneration, database import, runtime proof or business acceptance is introduced.

## [0.29.5] - 2026-11-18

### [fix] Compile exact inherited item-screen links without another AI call
Impact: A fully reviewed retained design can finish compilation when two items
omit the screen already specified by their own source block.
Change: Complete only an absent screen key from the proposed block owned by the same
section, with one explicitly declared screen. Existing null, wrong or ambiguous links
remain rejected. Source text, dispositions, components, claims and all original
AI candidates/reviews stay unchanged. A separate compiler derivation passes the
unchanged whole-design validator; historical reviews are never relabelled as
approval of changed candidates. An external create-only continuation freezes
all original evidence and permits only rendering, offline validation and packaging.
Execution and download authorization use the same derivation, with schema-9
lineage retaining prior provider and prose evidence. No new model operation is allowed.
Verification: 147 pure/helper checks and 83 ordinary pipeline/export regressions
passed. Four portable API/proof checks passed; three overlapping proof cases also
passed independently without a prior seed. Zero new model/auth/runtime-focus calls
were enforced during compilation, download, restart and rejection checks. A real
retained-source diagnostic rendered and passed SQLcl /nolog format validation.
The isolated Linux suite passed 62 tests with no skips, and a read-only probe
reproduced the exact retained-source compiler plan without changing 98 evidence
files or invoking a model. Final installed workflow acceptance remains separate.
Delivery: Candidate source; no public rollout or database import is included.
Remaining: Deterministic constraint completion is not business-behavior acceptance.
The bounded operator action preserves original approvals and does not grant a new
inference/retry allowance. Package format validation does not establish target
importability, runtime correctness or full Forms behavior equivalence.

## [0.29.4] - 2026-11-18

### [fix] Preserve long mapping proposals through independent review
Impact: A retained mapping with bounded long behavior prose can continue without
repeating its mapper or discarding any characters.
Change: V3 represents eligible proposal/unresolved behavior text of 513–2048
characters as at most four ordered segments within the existing scalar limit.
Exact character, whitespace and UTF-8 recomposition is proven; original source
and raw responses remain intact. The unchanged source gate and a new independent
review remain mandatory. An external, create-only continuation record pins four
approved sections, the fifth mapper and existing provider receipts. Only the
pending review and final section's two calls can proceed. Current owner/source/
destination checks and the prior explicit-attempt lineage remain in output proof.
Verification: Pure representation and compatibility checks: 301 passed. Earlier
reference/provider regression: 180 passed, one Windows platform skip. Eight
continuation tests and three API/worker scenarios passed, including exact remaining
calls, package/download, restart and stale/tampered evidence rejection. Independent
source review and the frontend build passed. The isolated Linux suite passed
69 tests with no skips. A read-only retained-source probe passed without provider
calls and checked the initial callback cost against the existing freshness gate.
Counts overlap; these checks do not establish a completed live conversion.
Delivery: Candidate source; private activation and actual package delivery are
separate. No public rollout or new model permission is introduced.
Remaining: Exact text preservation does not establish semantic equivalence.
Package format validation, target runtime verification and business acceptance
remain separate. Unknown provider outcomes are never automatically replayed.

## [0.29.3] - 2026-11-18

### [fix] Capture provider outcomes and bound one explicitly approved new attempt
Impact: Operators can prepare a reviewable, one-attempt action for a specific
uncertain fourth mapper while preserving three approved sections and the
original unknown intent. A new result is labelled as a new attempt, never as
recovery of evidence that was not retained.
Change: Exact owner/source/target, prefix and new SDK-request bindings gate an
explicit unknown-outcome/additional-charge acknowledgement. An independent,
exclusive consumed latch and committed event precede POST; deleted receipts and
duplicate requests cannot restore the allowance. SDK response data is retained
before parsing. Strict provider/source validation precedes create-only adoption,
and subsequent calls use captured receipts. Read-only opens cannot create or
write storage. Package proofs retain the unknown prior outcome and new lineage.
The generic pending-intent rejection remains unchanged.
Verification: Eight local API/worker scenarios passed, including a complete
synthetic package/download, concurrent duplicates, failure/crash/storage-loss
cases and changed actual SDK binding with zero POSTs. Final narrow regression:
84 passed, three Windows platform skips. SDK ISO timestamps and wall-clock latch
times are compared at microsecond precision without inventing finer ordering.
Delivery: Candidate source; Linux checks, activation and any explicitly approved
live attempt remain separate. No public promotion or provider retry occurred
as part of these tests.
Remaining: No exactly-once or billing guarantee. The original outcome is still
unknown. A crash after response capture needs explicit operator reconciliation;
duplicate POST does not adopt or retry automatically. New inference requires a
fresh, specific acknowledgement, and format/runtime/business gates remain separate.

## Provider component source checkpoint — 2026-11-18, before 0.29.3

### [improvement] Retain an opt-in OCI reply before interpreting it
Impact: Explicitly opted-in provider callers can preserve a received reply even
when its model content is invalid, and recover a valid captured reply without
another provider call. This does not change the currently deployed workflow.
Change: Add create-only private intent/response receipts, persist the client
request ID before submission, retain bounded SDK response data before parsing,
and provide an explicit read-only recovery API. Recognized SDK service errors
retain only status/code/request-ID metadata, never messages or auth headers.
Historical schemas/default behavior and the existing pending-intent gate remain.
Verification: 97 synthetic component/regression/opt-in pipeline checks passed;
three Windows symlink-privilege cases skipped. Independent review cleared parent
directory flushing and truthful pre-read error handling after fixes. An authored
validator was used for the pipeline test; no actual SDK/provider/SQLcl call ran.
Delivery: Unreleased source component, not an application release, activation or
public rollout. No application version/tag or existing job is changed by opting
out. See [response receipts](docs/provider-response-receipts.md).
Remaining: Production caller integration and actual Linux persistence/SDK checks;
schema-constrained output and backend-owned model metadata are separate changes.
Windows guarantees cover process interruption only, not OS/power-loss durability.
The component cannot reconstruct missing evidence from earlier calls, establish
exactly-once execution, or authorize retries after unknown external outcomes.

## [0.29.2] - 2026-11-18

### [fix] Continue combined source-identity and reference compatibility
Impact: A response containing an exact duplicate source-binding echo together
with selected chunk references can proceed to independent review without
repeating the saved mapper or earlier approved sections.
Change: V2 verifies the duplicate echo against original source, request and
blueprint bindings, then composes the unchanged V1 reference projection. Original
source, claims, mapper responses and prior reviews remain immutable. Fresh jobs
bind the exact policy before processing. One append-only follow-up pins the two
approved V1 sections and the exact third mapper, enabling V2 only from that
boundary onward. Current owner/source/destination and both durable approval chains
are rechecked. Duplicate submissions never requeue completed or uncertain work.
Delivery: Source release preparation; private continuation and live package
acceptance are recorded separately. Public service is unchanged by this patch.
Verification: 27 focused local API/worker checks, a strengthened saved-output
case, 166 relevant regression checks, independent review and production build.
A read-only probe reconstructed both approved real prefix proofs and eight exact
reference corrections, retaining all 36 original files with zero provider calls.
Remaining: This is exact echo/reference compatibility, not semantic repair.
Combined Item-fact-kind aliases and chunk-reference defects remain unsupported.
Live review, deterministic whole-package validation and download still gate the
result. Target import, runtime correctness and business acceptance are separate.

## [0.29.1] - 2026-11-18

### [fix] Continue mapping after exact source-reference mismatch
Impact: A valid behavioral proposal that cites selected code chunks can use their
exact source-unit references and proceed to independent review without repeating
a completed mapper call.
Change: A separately versioned policy proves selected chunk, complete code bytes,
source unit and owner identity; only evidence-reference IDs change. Original
responses and source remain immutable, with derived proof recorded separately.
Fresh development jobs bind this policy before processing. A tightly scoped,
owner-approved continuation can resume an older development run stopped after
its first sealed mapper, preserving the original snapshot and all prior files.
Duplicate continuation requests never requeue work. Existing source gates,
legacy job semantics and uncertainty/replay controls remain intact.
Delivery: Source release preparation; private same-run acceptance remains to be
recorded separately. Public service is not promoted by this change.
Verification: Synthetic projection, consent, continuation API/worker and package
checks plus independent review. A read-only probe of the retained real mapper
response passed strict source checks after ten exact reference corrections; all
eleven original job files were unchanged and no provider call was made by the probe.
Remaining: Combined envelope/Item-fact-format defects and chunk-reference defects
are outside this narrow policy. No semantic claim, source fact or business value
is invented or repaired. New review, full-package validation and download remain
required; generated output is not business acceptance or a target import guarantee.

## [0.29.0] - 2026-11-17

### [docs] Record private installation and synthetic checks — 2026-11-18
Impact: The existing private preview now serves 0.29.0 with the development-source
processing contract. Public remains 0.27.4.
Verification: 175 local API/worker/package regression tests, 91 Linux synthetic
checks and two browser fixtures passed; production build and independent review
passed. Exact selected source text reached authored mapper and reviewer fixtures.
Installed release files were hash-checked; all 272 pre-existing private files and
original database rows remained unchanged. Test totals overlap across platforms.
Delivery: Source/tag and this changelog are published; private installation is
active. No public promotion, new infrastructure or shared-dependency changes.
Remaining: A fresh real-input provider run has not started pending exact source
and destination approval. Actual live mapping, whole-package SQLcl validation and
installed download acceptance for this new mode are not yet claimed.


### [feature] Generate APEX packages from preserved development source
Impact: Prepared development XML can proceed through selected-code AI mapping,
independent design review, native APEX package generation and offline format
validation without blanket source redaction.
Change: The user explicitly approves unredacted development source. New immutable
consent binds exact source/version, preparation receipts, selected code units and
configured destination; worker checks current owner/provenance/event before each
provider operation and immediately before submission. Package proof retains the
consent binding. Existing redacted approvals, jobs and package hashes keep their
original meaning. Unsupported legacy recovery routes cannot reinterpret new-mode
consent; completed and uncertain operations are never automatically replayed.
Delivery: Source/tag published and private installation active; genuine-input
provider acceptance remains separate. No public promotion is included.
Verification: Synthetic exact-byte consent and legacy compatibility tests, actual
local API/worker execution with authored provider/validator fixtures, browser
fixtures, production build and independent review. These are not live AI evidence.
Remaining: Native output uses synthetic storage; general triggers, program units,
external dependencies and unsupported widget behavior remain explicit remediation.
Design analysis is not verified executable behavior. Format validation does not
prove customer-target import, runtime correctness or business acceptance.

## [0.28.0] - 2026-11-17

### [docs] Record private hosted preparation acceptance — 17 November 2026
Impact: The private preview now supports genuine FMB upload, Oracle XML extraction,
source-preserving review/download and adoption for analysis. Public remains 0.27.4.
Verification: Authenticated desktop/mobile browser flow on 0.28.0 passed against
installed Oracle Forms tooling. Downloaded native/effective XML matched sealed
bytes; all 56 non-empty original code fields survived unchanged. The analysis
screen disabled generation; no provider submission or target-database operation
ran. All 259 pre-existing private files and original database rows were retained.
Local repaired boundary suite: 258 passed, three Windows platform skips. Linux
file/permission suite: 137 passed, no skips. Focused processing regression: 78
passed. New/legacy browser checks, TypeScript/Vite build and independent review
passed; browser fixture tests are separate from the actual hosted acceptance.
Delivery: Source/tag published; existing private preview serves 0.28.0. No public
promotion, dependency installation, new infrastructure or business acceptance.
Remaining: Development-mode AI conversion still requires a separate processing
contract and explicit source/destination authorization. Credential scanning is
not exhaustive; source-owner review remains necessary.


### [feature] Preserve development source during hosted Forms preparation
Impact: Review original Oracle XML and preserve business constants instead of
blanket literal masking when explicitly choosing development preparation.
Change: A separate immutable preparation mode retains original binary and native
OVERRIDDEN/ALL XML, scans possible credentials before effective-view derivation,
and offers owner-bound XML attachments with safe source locations. Findings block
adoption; clean reviewed XML can be added for analysis with policy-bound history.
Older jobs and the legacy masked route retain their existing receipts and meaning.
Both fresh generation routes reject preserved development sources; old redacted-
source approval is not reused as permission for new processing.
Delivery: Source/tag published and private-preview acceptance recorded above.
The public service remains 0.27.4; no public promotion is included.
Verification: Synthetic local preparation/API, provenance, owner/download and
processing-boundary checks; real browser tests with simulated API and production
frontend build. Exact final results are recorded in the release handoff.
Remaining: Credential detection is incomplete by nature and does not replace
source-owner review. Development-mode AI conversion is not enabled. Oracle Forms
extraction, APEX generation, technical verification and business acceptance remain
separate facts; this release does not add a business-behavior conversion claim.

## [0.27.5] - 2026-11-17

### [docs] Record private-preview acceptance — 17 November 2026
Impact: The private preview now demonstrates the grouped findings and faster read
path on the same prepared package. The public service remains 0.27.4.
Verification: Actual authenticated browser checks recovered all 366 findings,
searched qualified references, checked desktop/mobile layout and downloaded
byte-for-byte identical output, with zero project POSTs. All 245 original and
prepared-package files and the original run row were unchanged; the public user
service kept its process identity and health. Shared dependencies were not changed.
Observed readiness was 17.194 to 2.390 seconds, output visible 23.960 to 4.636
seconds, and download 4.881 to 2.263 seconds. These are individual browser runs,
not an SLA. The older private 0.27.3 UI also made a 19.8-second legacy validation
request; the inherited 0.27.4 export-mode guard removes that request. Do not
attribute the whole UI difference solely to this release's document cache; the
isolated three-sample component comparison is reported separately below.
Delivery: Published/tagged source and verified private preview; no public rollout,
new preparation, provider inference, target-database action or business acceptance.
Remaining: Intake/source-fidelity policy and broader behavior conversion are
separate work; this release does not silently change existing source controls.


### [improvement] Review findings by category, reference and next action
Impact: Users can find relevant remaining work without reading a long list of IDs.
Change: Preserve full remediation objects in new and saved package views; add
counted collapsed categories, search, source-provided next actions and qualified
XML references. Unknowns, duplicates and original JSON remain accessible. Search
hides unmatched groups and Clear restores the complete report. Download stays above
review controls; source changes reset the view. No package or API format changes.
Verification: Four focused browser scenarios and the frontend build passed. A local
render using retained real metadata recovered all 366 findings exactly and checked
reference search, desktop/mobile layout and zero writes; that render mocked HTTP.
Delivery: Published/tagged source; subsequent private-preview acceptance is recorded above.
Remaining: No public promotion or new conversion/business acceptance is claimed.

### [performance] Avoid repeated parsing within a saved-read operation
Impact: The supported initial-direct saved-read path does less repeated source work.
Change: Add a separately bounded exact-document store inside the existing fenced
read scope. Detached copies, ordered filename/length/hash identity, context
revocation, file checks and fresh source/selection/approval checks remain intact.
Verification: Against the exact published 0.27.4 baseline on the same host/input,
three alternating samples per variant reduced saved-candidate median time from
2.379738 to 1.142606 seconds (51.99%). Fresh packet builds fell from 43 to 1;
request, adoption and package hashes and original files were unchanged. This is
one retained saved-read component, not total UI or model-inference performance.
Local focused regressions passed 184 cases with four Windows link skips; Linux
passed all 74 targeted integrity cases without skips. Independent review cleared
the source boundaries; no dependency, model or database operation changed.
Delivery: Reviewed source; existing public service remains 0.27.4.
Remaining: Hosted UI observations for this revision are separate from this controlled
component comparison. Development-source preparation policy is unchanged.

## [0.27.4] - 2026-11-17

### [docs] Record the authorized public promotion
Impact: The existing public instance now serves the export-only release.
Change: Document the preserved-store rollout and actual HTTPS acceptance, without
changing software or replaying a conversion.
Verification: Public health reports 0.27.4. Original login, 15 projects, 28 sources,
12 runs, 1,407 retained files and three prepared Forms uploads were preserved.
Real HTTPS browser checks passed for login, project access, export-only controls,
secure cookies and narrow-screen layout, with no page errors or project writes.
The service restart and existing offline compiler were checked. No model calls,
target-database operations, new OCI resources or proxy/network changes occurred.
Delivery: Public deployment verified on 17 November 2026; original installation,
store and snapshot retained. Rollback after new project writes needs reconciliation.
Remaining: This promotion does not prove a new conversion or business equivalence;
the private-preview demonstration project was not merged into the public store.

### [improvement] Prepare export-only FOX for an existing HTTPS site
Impact: Operators can use the export-only service behind their existing HTTPS
address, with a UI that does not offer unavailable database-runtime recovery.
Change: Add an optional canonical HTTPS public_origin to the loopback launcher;
retain exact-Origin CSRF checks, secure cookies and filtered environment settings.
Consume the server-reported delivery mode to hide legacy recovery actions without
changing old evidence, saved package access or the legacy-mode interface.
Delivery: Reviewed source; subsequent guarded public acceptance is recorded above.
Verification: Launcher/API configuration regressions passed 94 tests with one
Windows skip; login, cookie and wrong-Origin scenarios used real in-process API
calls. Three synthetic Edge scenarios passed, including legacy recovery and saved
package controls, and the frontend build passed. A missing read-only mock causing
a timing-dependent extra alert was corrected without weakening its assertion.
Remaining: Customer installations and additional conversion coverage are separate
from the verified existing-instance promotion recorded above.

## [0.27.3] - 2026-11-17

### [docs] Record subsequent private-preview acceptance
Impact: Distinguish the shipped source benchmark from observed hosted behavior.
Change: Record the final private-preview check of the same prepared package.
Verification: Observed readiness was approximately 18.0 seconds versus 45.5 seconds
on the preceding build; download was 4.9 versus 30.2 seconds. These are individual
UI observations, not a controlled throughput test or guaranteed response times.
The downloaded package hash was unchanged; no preparation, model or database
operation was replayed. Original run evidence and public services were preserved.
Delivery: Documentation-only follow-up on 17 November 2026. Software remains
0.27.3; the private preview is verified, while public routing remains unchanged.

### [performance] Reconstruct saved-output proofs once per read
Impact: Eligible initial-direct saved runs spend less time rebuilding the same
proof while checking or downloading a retained APEX package.
Change: Reuse exact packet/plan/target derivations only within one saved-candidate
read. Pin the complete original job at entry and exit, return detached copies,
bound retained values, and reject cross-job/thread/task or execution reuse. Fresh
owner/source/profile checks, compiler checks and existing epoch behavior remain.
Delivery: Reviewed source increment; private-preview API/UI acceptance and public
cutover are separate. No model, database, compiler or preparation replay was used
for the performance benchmark.
Verification: Two alternating samples per variant on the same OCI host and
retained input: baseline 14.854949/14.899097 seconds, new 2.545773/2.515461 seconds.
Median 14.877023 -> 2.530617 seconds, an 82.99% reduction for this step; repeated
baseline reconstruction fell from 12 to 1. Request/adoption outputs and candidate
bytes were identical, with original job files unchanged. Local focused regression:
180 passed, 4 Windows symlink skips. Actual Linux focused checks: 33 passed, no
skips. Independent review cleared the repaired sibling-directory invalidation.
The integrated delivery/performance rerun passed 80 tests with 4 Windows symlink
skips; release consistency, TypeScript and frontend build checks also passed.
Remaining: This is one retained saved-candidate workload, not end-to-end UI,
fresh model inference or universal conversion performance. Six setup errors in
an unchanged historical shared fixture remain documented; its failure was also
reproduced using the original modules and was not counted as a passing test.

## [0.27.2] - 2026-11-17

### [fix] Keep package download visible with large gap reports
Impact: Users do not have to scroll through hundreds of remediation rows to
download a prepared APEX package.
Change: Move the action before long reports and place the complete omissions
list in an initially collapsed, counted native details control. Report content,
source binding, timeout budgets and no-retry behavior are unchanged.
Verification: Frontend build and both focused synthetic Edge scenarios passed
with 300 remediation rows, desktop/mobile layouts, keyboard expansion, complete
report text, stale-link clearing and unchanged request budgets. Lead visual
inspection and independent diff review passed. No backend or package bytes change.
Delivery: UI source patch; isolated-preview visual acceptance follows publication.
Subsequent isolated acceptance: real desktop/mobile checks passed, including all
366 expandable report entries and an identical redownload without preparation.
Original run files and public services remained unchanged.

## [0.27.1] - 2026-11-17

### [fix] Avoid premature saved-output readiness aborts
Impact: A valid saved-design package check has enough time to finish in the UI.
Change: Increase only the saved-package GET allowance from30 to90seconds. The
preparation POST remains180seconds; no retry, source/proof relaxation or backend
cache change is introduced.
Verification: The isolated preview returned an actual eligible readiness result
in28.9seconds, while the initial browser check hit its30-second budget. Browser
regression checks the90-second GET and180-second POST timers, retains unknown-
outcome GET reconciliation, and the frontend builds with matching release metadata.
Delivery: Source patch; private-preview acceptance follows the reviewed commit.
Subsequent isolated acceptance: one explicit UI preparation and actual browser
download passed for a retained real Forms-derived design. The exact complete ZIP
passed SQLcl26.1.2 `/nolog` with network disabled and no wallet; native application
files and the original run/tree remained unchanged. No model replay or target
database operation occurred. Public routing and business acceptance are separate.
Remaining: Backend proof-reconstruction optimization needs a separately tested
read scope. A longer timeout is a reliability fix, not a measured speedup.

## [0.27.0] - 2026-11-17

### [feature] Deliver format-validated APEXlang without target-database gates
Impact: New UI conversions can finish at a downloadable native APEXlang ZIP.
Change: Add immutable export-only delivery, genuine SQLcl `/nolog` validation,
supporting synthetic SQL, compatibility/MMD information, prerequisites and explicit
omissions. Schema preparation, app import, browser tests and reimport are not
required by this route; old jobs keep their original behavior and checks.
Delivery: Reviewed implementation branch; isolated hosted acceptance/public
cutover and a release tag are separate milestones.
Verification: Connected synthetic API/worker/download checks, desktop/mobile
browser scenarios and real connectionless SQLcl validation. A valid real-derived
package passed; deliberately invalid APEXlang was rejected despite process exit0.
Remaining: Hosted authenticated new/saved package download acceptance, a complete
fresh-customer installer/profile and business behavior assessment. No universal
import or behavior guarantee is made.

### [improvement] Reuse a saved design without repeating model calls
Impact: An eligible inactive older run can provide a separately prepared
format-only package even when optional runtime work stopped later.
Change: Add owner/source/candidate-bound readiness, explicit preparation and
separate output/download routes. Original job files, status, database row and
failure evidence remain unchanged. Deliveries and advisory timings live outside
the original job tree. Compiler-log integrity is checked on reuse and download.
Verification: Positive, idempotent, stale/tampered, missing-review, wrong-owner,
active-run and invalid-compiler scenarios; explicit UI action and read-only
reconciliation after unknown responses. No new paid model or target operation
was used for these checks.

### [performance] Reduce OPAF setup work and expose request timings
Impact: Fewer setup round trips on the optional OPAF path and clearer timing
information for both OPAF and direct OCI calls.
Change: Observe the environment once per prepared role invocation, keep intent
before the single POST, reuse a freshly pinned connection within that role when
supported, and retain non-sensitive monotonic timings outside sealed evidence.
Verification: Controlled client/transport tests reduce seven HTTP requests and
seven TLS connections to five requests and one connection with keepalive. With
server-close responses, five separately pinned connections are used. One POST
and no uncertain-call retry are preserved. These are modeled protocol counts,
not a measured cloud latency or throughput improvement. Direct SDK client reuse
already existed and is not counted as a new gain.
Remaining: Comparable live latency measurements, prompt/focus tuning and safe
dependency-aware concurrency; model identities/limits were not changed.

### [fix] Make SQLcl batch input non-interactive on Windows
Impact: Offline validation no longer inherits an invalid console/NUL input handle.
Change: Supply an explicit empty input pipe to batch SQLcl scripts.
Verification: Focused SQLcl regressions and actual valid/invalid connectionless
compiler runs. No Oracle import or database connection was requested.

### [fix] Report package readiness independently of legacy execution
Impact: Setup/session readiness no longer says a database gateway is required
for the default project package flow.
Change: Add pure package-configuration reporting while preserving legacy
execution admission and its checks. A package-ready session does not authorize
a legacy target operation.
Verification: Focused API regressions, including package readiness without
gateway credentials and refusal of a legacy execution request with no new run.

### [maintenance] Add a lean isolated export-preview launcher
Impact: An operator can run the package API and optional Forms worker without
the legacy converter/runtime processes.
Change: Add a separate launcher using the existing instance lock, private UI
credentials and temporary storage; preserve the old launcher. Include the new
export-only guide in the clean distribution. No public routing or cloud
infrastructure change is performed by this source increment.
Verification: Local and non-root Linux launcher tests, not a live deployment.

## [0.26.0] - 2026-11-16

Preview under verification.

### [feature] Direct OCI design and independent review
Impact: Operators can select direct OCI Generative AI for the existing FOX prototype flow.
Change: Add configurable instance-principal design/review roles and provider-specific request evidence; retain OPAF compatibility and deterministic source, target, rendering and SQLcl checks. Add an isolated loopback launcher, runtime factory and archive builder containing the prebuilt UI and offline wheels.
The same-run continuation can retain a source-proven form container after a new independent review, or recheck one definitively failed connectionless validation after an explicit owner approval. Original model calls and failed validation artifacts remain preserved.

Delivery: Implementation branch; no public cutover or release tag.
Verification: Acceptance evidence is being collected; no completed hosted conversion is claimed by this entry.
Remaining: Complete hosted upload, extraction, approved-source processing, UI SQL download, exact-file fresh-ID import and runtime proof; human business acceptance stays separate.

## Documentation updates

### [docs] 2026-11-18 — Record private preserved-source package acceptance

Impact: The verified checkpoint now distinguishes a downloadable prototype from
unimplemented business behavior and target-runtime acceptance.
Change: Record one retained preserved-source flow through Oracle XML intake,
AI mapping/review, native rendering, whole-package SQLcl format validation and
an authenticated browser download. Compiler completion and the UI follow-up
reused the retained evidence and package without another model operation.
Delivery: Source releases through 0.29.6 are published; private 0.29.6 acceptance
passed. The public deployment is unchanged. No software version or tag was moved
for this documentation update.
Verification: Exact downloaded ZIP hash, desktop/mobile layout, no page errors
or project writes, and preservation of prior source/evidence and run rows were
checked. Local/browser and Linux verification scopes remain recorded above.
Remaining: The package is a synthetic-storage prototype with explicit code,
behavior, dependency and mapping remediation. Target import, runtime testing and
business acceptance are not established. Saved-output checks still take minutes;
the UI change fixes cancellation rather than reducing proof-check cost.

### [docs] 2026-11-16 — Record completed 0.25.0 image builds

Impact: The deployment checkpoint now distinguishes completed image builds from
prepared containers, activation and a working end-to-end conversion.

Change: Record that both 0.25.0 images were built on the existing JSN VM, with
original build exits and unchanged-history checks confirmed. The earlier stopped
candidates and existing site were preserved. No service switch, new OCI resource,
model call, schema change or import is claimed by this checkpoint.

Delivery: Documentation only; source remains 0.25.0 and the hosted site remains
0.24.0. Existing version tags and software artifacts are unchanged.
Verification: Original paired-build records and postguards, not launch messages.
Remaining: Prepare the replacement containers, complete the guarded upgrade,
then prove the real hosted conversion, download and exact-file reimport.

### [docs] 2026-11-15 — Make product changes and delivery status clear

Impact: Readers can distinguish a user feature, defect fix, performance result,
test-only change and operational maintenance without interpreting test counts.

- Require primary commit/changelog labels: `[feature]`, `[improvement]`, `[fix]`,
  `[performance]`, `[testing]`, `[maintenance]` or `[docs]`.
- Lead release entries with user impact, specific change, delivery state and
  remaining limitations; verification is supporting evidence.
- Require comparable measurements for performance claims and targeted testing
  alongside implementation. Unchanged valid proof is reused, not routinely rerun.
- Clarify the checkpoint: hosted 0.24.0; published/prepared 0.24.3; goal paused;
  UI download, exact-file reimport and source-derived business-action proof pending.
- Add retrospective categories to the recent 0.24.0–0.24.3 entries without changing
  their original release dates, commits or tags. The recent operations fixes are
  not advertised as new conversion functionality or measured speedups.

Delivery: Documentation only. No new product capability, runtime version bump,
deployment, conversion, database action or resumption of the paused goal.
Verification: Documentation diff/consistency review and a read-only hosted health
response reporting 0.24.0; not end-to-end conversion acceptance.

### 2026-11-15 — Live 0.24.0 conversion checkpoint and download defect

- Record the successful reviewed deployment continuation and active preparation/runtime
  workers. Earlier failed operations remain failed; their evidence was not replaced.
- Record the first approved real-module run reaching native APEX generation,
  authenticated runtime checks and retained SQL/APEXlang export through the hosted flow.
- Disclose the remaining UI download failure: a required-input status string is
  incorrectly compared with a boolean. The focused correction passes 209 local
  checks (5 historical-profile cases skipped) and validates unchanged retained
  real package bytes. It is not yet deployed or claimed as a successful UI download.
- Keep exact downloaded-byte fresh-ID import/runtime verification, broader
  repeatability and human business acceptance explicitly unproven.

Documentation only: no version/tag change, package/receipt rewrite, conversion
replay, new cloud resource or blanket customer-target compatibility claim.

### 2026-11-15 — Restored lab checkpoint and non-intrusive monitoring

- Correct the hosted checkpoint: 0.23.2 is online, but preparation/runtime
  workers remain held. Prepared 0.24.0 containers have not started, and the real
  conversion has no APEX export yet.
- Record that failed pre-swap attempts and saved jobs are preserved separately
  from successful restoration of prior HTTPS access. No upgrade success is claimed.
- Document shell-only observation while a guarded transition runs. A controlled
  live read-only test confirmed that an unrelated Python observer is classified
  as a potential producer. Overlapping status polling strongly supports the
  observed failure mechanism; the historical rejected PID was not retained.
- Require private log creation from inception in operator helpers, and distinguish
  original worker completion from observer or transport completion.

Documentation only: no application or deployment-tool version change, guard
exemption, new cloud resource, conversion retry or new live acceptance claim.

### 2026-11-15 — Published 0.24.0 source and planned native deployment

- Publish FOX 0.24.0 with its matching changelog. Final clean-source regression:
  916 passed, 1 platform skip; frontend checks: 6 browser simulations, 13 modeled
  state tests and TypeScript passed. Prior failed test runs remain separate.
- Verify the offline package, dependency closure and isolated imports. This does
  not establish a hosted conversion, Oracle import or exact-package reimport.
- Document separately pinned deployment tool 0.2.0 and its explicit native mode.
  Hosted FOX remains 0.23.2 until a new guarded transition is actually completed.

### 2026-11-15 — Recovered lab state and separate deployment-tool increment

- Record the restored 0.22.8 lab and the still-pending corrected 0.23.2 deployment.
- Publish deployment tool 0.1.1 with bounded HTTPS warm-up, its own changelog and
  explicit runtime-bundle boundary. The original failed attempts remain preserved.

### 2026-11-14 — Current checkpoint, model routing and historical coverage

- Refresh the repository and FOX READMEs: published source 0.22.16, last verified
  lab 0.22.8, staged-only candidate, paused development and unfinished live acceptance.
- Document task-specific model/effort selection, bounded delegation, actual-run
  reporting and the distinction from embedded OPAF models.
- Require a changelog entry for every pushed FOX update, including documentation.
- Add [32 retrospective source-update entries](docs/historical-changelog.md)
  for commits that did not change a changelog. All 51 existing software release
  tags already have dated entries below; preserve them unchanged.

This is a documentation-only update: no software-version bump, deployment,
conversion, test replay or new runtime acceptance claim. Historical entries are
labelled as backfill; commit/tag dates and Git history are not rewritten.

## [0.25.1] - 2026-11-16

### [fix] Include source-check dependencies in preserved-startup validation

Impact: Prevent the source-check release from being rejected during startup when
previously completed native prototypes must be preserved. No new conversion
pattern or business-equivalence claim is introduced.

Change: Register all three count-check renderer modules in the measured startup
source list. Keep the strict rejection of unmeasured dependencies, original
results and original application IDs. Add a cross-platform COPY-projection check
and a regression using the actual closed startup loader, not ordinary imports.

Delivery: Source correction and registered-target offline bundle prepared;
hosted FOX remains 0.24.0. The 0.25.0 images and stopped candidates are preserved
but must not be activated. The corrected release requires its own coherent
cloud images and installation.

Verification: The actual 0.25.0 materialized files fail under the closed startup
loader. All six new cross-platform cases pass with the correction, including
pre-fix and individual missing-module rejection. The related clean-source
regression reports 108 passed and two existing platform/private-fixture skips.
The integrated corrected release then passes 327 targeted startup, preservation
and packaging tests, again with two existing skips; all six new cases run.
Independent review confirmed that only the three declarations and the new
regression change product behavior. TypeScript and the offline build pass for
the existing registered APEX 26.1.6 profile. Live startup is unproven.

Remaining: Publish and deploy the corrected release, then prove the real hosted
FMB journey, native source-check behavior, UI download and exact-file reimport.

## [0.25.0] - 2026-11-16

### [feature] Choose a source-backed check for the generated APEX prototype

Impact: A business user can find a supported check in the selected Forms source,
see its file/block/button, and explicitly include it in a new native prototype.
The generated app gets a separate check button; the original action is not
silently represented as converted.

Change:

- Add read-only, source-bound discovery and an optional creation-only selection.
  Partial-scope approval starts unchecked and is stored separately from the exact
  source choice. Saved progress and eligible repair inherit the original choice;
  an old run cannot acquire new behavior through a retry.
- Recognize a narrowly supported first `COUNT(0)` predicate that tests matching
  rows for null/zero values. Generate native APEX validation and a separately
  scoped check request, using only already-mapped synthetic tables and fields.
- Require four labelled synthetic cases, exact browser outcomes and independent
  before/after fixture reads. Missing proof cannot release the new profile's
  export. Neither the browser check nor its success message performs approval.
- Keep source lookup bounded to 15 seconds. Refresh, stale responses and failed
  lookup cannot silently remove an approved check and start ordinary conversion;
  proceeding without a check is an explicit choice.
- Use a separate versioned browser runner and versioned renderer closure.
  Historical profiles, their runner bytes and existing application IDs remain
  unchanged. Include the preceding draft-download fix.

Delivery: Source implementation; not a hosted-availability claim. The last
measured lab remains 0.24.0. No new OCI infrastructure, model endpoint, identity
policy or network rule is part of this increment.

Verification: Focused local API/SQLite, source reconstruction, package/closure
and browser-boundary regressions; real local Edge against authored responses;
and SQLcl 26.1.2 connectionless validation of a candidate derived from the
approved real module. These checks do not establish live Oracle runtime or
deployment. Local browser tooling differs from the pinned production runner;
installed-flow testing remains required.

The isolated staged product tree passed 871 tests (seven skips), with no working
tree overlays or changes to unrelated work. A stale continuation-test response
was corrected after reproducing the same failure on the previous frozen release;
its original assertions remain intact. This test-fixture correction does not
change the product's recovery or unavailable-checkpoint rules.

Remaining: This is an isolated saved-row check, not the complete original button.
Negative nonzero values pass, as do empty keys or no matching rows. Later source
logic, unsaved Forms buffers, transaction/exception behavior and business acceptance
remain separate. Actual JSN fixture creation/runtime, hosted UI download and
fresh-ID import of the exact downloaded SQL remain acceptance gates. No universal
Forms conversion or customer-target compatibility guarantee is made.

## [0.24.3] - 2026-11-15

### [maintenance] Back up retained development history before the download-fix rollout

Impact: Operations only; no new converter capability or measured speedup.
Delivery: Published source; replacement deployment remains incomplete.
Category added retrospectively on 15 November 2026; original release history unchanged.

- Increase fixed snapshot capacity from 25,000 to 32,768 entries and from
  160 MiB to 256 MiB total. Keep the 64 MiB member and 8 MiB manifest bounds.
  The derived archive bound is 384 MiB; it is not an extra cloud allocation.
- Preserve all history rather than deleting old jobs to fit the previous bound.
  No automatic expansion, source exclusion or backup/restore bypass is added.
- Retain the preceding download and completed-evidence preservation corrections.

A live read-only measurement found 26,060 entries and a 173,960,035-byte
conservative upper bound. The original upgrade inspection stopped at the
capacity gate before activation; its failure remains recorded. This change
requires a new coherent package and a fresh successful inspection, backup and
isolated restore. The serving lab remains 0.24.0 with auxiliary workers held.
Hosted UI download and exact-downloaded-byte reimport remain unproven.

Verification: 398 clean staged-source tests passed, with 60 platform/historical
skips. Capacity-specific Windows checks passed 39 tests with 55 skips; Linux
snapshot checks passed 34, hosted checks passed 40 with 20 skips, and 17 real
rootless-namespace checks covered 17 of those skips. Three opt-in integration
checks remain unrun. Independent bounded source and evidence review cleared
the change. These local checks are not live backup or deployment acceptance.

The new reader accepts older bounded archives. Older readers may reject archives
above their old limits; use the matching new reader for a new larger backup.
Deployment tool 0.2.3 binds the unchanged controller to this new bundle.

## [0.24.2] - 2026-11-15

### [fix] Preserve each producer's original JSON bytes

Impact: Correct an upgrade blocker; no new Forms behavior is converted.
Delivery: Published source, included in the pending 0.24.3 package.
Category added retrospectively on 15 November 2026; original release history unchanged.

- Correct completed-job preservation for `snapshot.json` and `import.json`:
  the gateway normally adds one trailing newline; the runtime worker does not.
  Equal records must not be rejected solely because these documented formats differ.
- Require exact canonical worker bytes and exact canonical receiver bytes with
  at most that one newline. Preserve each copy's original hash, size and node
  identity separately. No stored evidence is trimmed, rewritten or normalized.
- Keep runtime-request and browser-report copies byte-identical. Reject changed
  values, arbitrary whitespace, byte-order marks, extra newlines and false hashes.
- Add regression cases using the real gateway publisher and worker serializer.

Verification: 91 focused and existing completed-host checks passed. Independent
bounded source review cleared the correction. A live read-only comparison
confirmed the exact one-newline difference in the retained real job and that
all original files stayed unchanged. The full read-only lab diagnostic then
passed with the corrected reader, checking receiver records, staging/browser
evidence, package semantics and unchanged measurements. The reader was an
explicit diagnostic overlay, not an installed patch or maintenance authority.
Coherent deployment and a fresh held baseline remain separate gates.

Clean staged-source regression passed 359 tests with 5 skips, including the
materialized startup/transition and typed-download checks. Original source and
unrelated work remained unchanged. Deployment tool 0.2.2 binds the unchanged
controller bytes to this corrected application bundle.

The prepared 0.24.1 candidates were never activated; they remain stopped with
their evidence preserved. The lab remains on 0.24.0. No model, conversion, schema,
application import or browser test is replayed by this correction. Hosted UI
download and exact-downloaded-byte reimport are not yet claimed.

## [0.24.1] - 2026-11-15

### [fix] Download completed prototypes without discarding their history

Impact: Correct the draft-download gate; this user-visible fix still needs live deployment.
Delivery: Published source, included in the pending 0.24.3 package; actual UI download unproven.
Category added retrospectively on 15 November 2026; original release history unchanged.

- Fix the completed-prototype download check: the required-input result uses
  its canonical status strings, while ordinary runtime checks still require
  boolean true. Reject unknown statuses and invalid page identities.
- Add versioned read-only preservation for completed native prototypes alongside
  stopped historical runs. Bind exact candidate, review, runtime and export
  evidence without renewing expired requests or granting retry authority.
- Retain completed staging and QA trees in upgrade checks. Preserve original
  producer/source identities and reject changed, partial or unexpected history.
- Match protected startup imports to the actual FOX image renderer closure.
  Stopped-source readers verify explicit release inventory and physical origins;
  no development import path or synthetic app directory substitutes for them.

Verification before release integration: 209 download checks passed, with 5
historical-profile cases skipped; the unchanged retained real package passes
the corrected check. Core preservation: 181 passed, 6 skipped. Host/startup:
47 real materialized-layout checks passed; regressions: 573 passed, 5 skipped
and 48 subtests passed. Independent bounded review cleared the corrected source.
These are local/source checks, not proof that this patch is deployed.

Clean staged-source integration then passed 858 tests and 48 subtests, with
11 skips; original source and unrelated work stayed unchanged. A read-only
diagnostic on the real retained lab job also passed using the new pure readers:
the exact export, original source files and job evidence stayed unchanged.
No model, Oracle, conversion or import operation was invoked by that diagnostic.
The matching controller is versioned separately as deployment tool 0.2.1.

Hosted UI download and fresh-ID import/runtime of those exact downloaded bytes
remain separate acceptance steps. No completed model, schema, import or export
operation is replayed; business acceptance and full legacy parity are not claimed.

## [0.24.0] - 2026-11-15

### [feature] Explicit query omissions and same-run continuation

Impact: Users can explicitly continue a supported partial conversion without silently guessing query rules.
Delivery: Hosted 0.24.0; complete business behavior is not claimed.
Category added retrospectively on 15 November 2026; original release history unchanged.

- Recognize only the source-bound, same-block redacted filter and ordering
  assertions that stopped the retained real mapping before review. Reconstruct
  the source/focus, retain the original claims, and derive explicit unresolved
  omissions with actionable questions; do not change the source-fact whitelist.
- Add a business-user choice to continue a partial prototype without that query
  behavior. Require the three processing approvals and a separate omission
  approval. Check this option before unrelated legacy recovery routes.
- Preserve completed mapping/review calls, require a fresh independent review,
  and continue the same run. Bind the decision, original/derived evidence and
  review into worker, converter-authority and download reconstruction.
- Reject stale source/target/checkpoint, missing consent, unknown or out-of-order
  work and competing operations. Preserve the existing validation/import/runtime
  gates and distinguish output from business acceptance.
- Isolate other projects' stopped prototype history for this exact consented
  omission continuation using authenticated, nonce-bound read-only converter
  observations. Recheck rows, ledgers, owners, sources and target in the same
  transaction. Do not change fresh submission, general retry admission or old jobs.
- Include the already-admitted required-input policy when reconstructing a
  saved mapping binding. No immutable snapshot or old policy is rewritten.
- Adapt older UI test fixtures to the new read-only omission probe and keep the
  modeled conversion-state harness separate from its browser-tested progress child.
- Update the public checkpoint: hosted 0.23.2 has passed raw-FMB preparation and
  reached real OPAF mapping; full conversion and package acceptance remain pending.

Verification: 95 pure-helper cases, 443 boundary/regression cases, 101
native regressions and 18 connected local API/worker/authority cases passed.
Provider and Oracle replies in local tests are authored. A read-only check of
the actual saved real mapping passed pure derivation with original files intact
and no new model call. Simulated UI/TypeScript checks passed, including explicit
consent, stale responses, mismatched evidence and unknown-submit protection.
Older format/preclaim browser fixtures and the modeled conversion-state suite
also pass after those fixture corrections. A broader historical repair matrix
was stopped after exceeding the focused run window; it is not counted as a pass.
An intermediate wider run exposed stale authored-provider fixtures, a Windows
test-path limit and a transport-path allowance that was too broad. The follow-up
corrects the fixtures, uses a shorter test root and limits the new paths to omission
descriptors; the failed run remains separate. Actual read-only converter observations also
confirm the existing other-project boundaries without queueing or replaying work.
The hosted runtime remains 0.23.2. Fresh live review, SQLcl/import/runtime/export,
exact-downloaded-package reimport and human acceptance are not established.

## [0.23.2] - 2026-11-15

### Register the protected startup preservation reader

- Include the exact preservation-reader digest in new project release manifests.
  The 0.23.1 hosted attempt exposed its omission: the isolated startup loader
  refused `FOX_UNBOUND_DEPENDENCY` before verifier startup and HTTPS release.
- Retain structural decoding of the explicit older two-module manifest format.
  Older manifests do not gain current readiness, retry or execution permission.
  New manifests require the complete three-module set; unknown modules and
  altered or missing files remain rejected.
- Carry the same explicit legacy constant into the archival handoff's pure
  validator without widening its allowed imports, calls or syntax boundary.
- Test the actual generated digest loop and closed module loader against real
  recovery/preservation code and a read-only SQLite fixture, including the
  previously failing branch. Also exercise the real handoff validator.

Verification: 13 focused tests passed; the isolated clean-layout regression
passed 127 tests and 48 subtests. Earlier checkout-only failures caused by an
absent test profile are retained separately. These are local checks, not hosted
startup or Forms-to-APEX acceptance. The failed 0.23.1 attempt and all job evidence
remain preserved; a coherent new deployment and real-FMB proof are still required.

## [0.23.1] - 2026-11-15

### Recognize current service launchers during guarded upgrades

- Attribute the current FOX and converter attach launchers to their exact
  containers and user services. Recheck process birth, owner, executable,
  command, service state and control group before excluding only those PIDs.
- Keep native preparation, unknown producers, other processes and active locks
  blocking. Stopped-pair checks require inactive services and no launcher PID.
  This adds no retry, job closure, import or business-acceptance permission.

Verification: 179 focused local startup/preservation tests passed and independent
review passed. A broader legacy suite retained 333 passes, three failures and
17 setup errors caused by unavailable private fixtures/profiles; it is not a
passing full regression. Actual Linux checks and activation are separate gates.
The prior 0.23.0 images were built but not activated; they remain unchanged.
End-to-end real-FMB export acceptance is still pending.

## [0.23.0] - 2026-11-15

### Start safe new projects without replaying old runs

- Give fresh prototype submissions a separate, transaction-scoped admission
  check. Unrelated stopped prototypes may be isolated only after a fresh
  authenticated, nonce-bound converter observation; active or uncertain work
  still refuses admission. Existing verification, continuation and retry gates
  are unchanged. The same source bytes may be used in a different new project;
  an existing project's run is never reset or replaced by this route.
- Add a read-only converter observation for genuine receiver absence, runtime
  work not yet dispatched, or a validated completed export. It uses the existing
  stage lock and checks retained requests, receipts and known recovery artifacts.
  It grants no execution, retry, closure or business acceptance. The supported
  single-converter process is required; arbitrary manual processes are not attested.
- Keep old rows, source files and ledgers unchanged across the new submission.
  Reconstruct web-side requests to check actual receipt hashes; do not require
  identity fields that the real converter receipt format does not contain.
- Recognize the product-owned native-schema index as bounded retained metadata
  during startup. Bind its bytes and file identity to existing and absent job
  observations; reject unknown files, links and changes. Preserve all POSIX file
  checks and handle Windows' differing path/handle ctime representations explicitly.
- Repair the legacy preclaim test fixture to use its selected renderer without
  adding a production compatibility alias or relaxing validation.

Verification: 100 authenticated local API/transport/preclaim checks passed using
the real receipt-envelope builder with authored stage outcomes; 171 converter
checks passed with one Windows symlink-creation skip; 183 startup/metadata checks
passed. Independent reviews passed after correcting the receipt-format mismatch.
These are local/component checks, not live Oracle conversion acceptance. A separate
longer-path test rerun failed Windows fixture copying; its failure is preserved.

An isolated, write-denied candidate observation also parsed both retained lab
histories successfully, with full job files and installed code/profile unchanged.
It was not the serving HTTP witness and proves neither serving-process locking,
admission permission nor deployment readiness. Source publication, activation,
the real FMB journey and exact-download reimport remain separate acceptance steps.

## [0.22.16] - 2026-11-14

### Preserve paused runs at different conversion stages

- Stop assuming every paused conversion reached runtime testing. During guarded
  startup, retain earlier unresolved runs alongside the proven runtime candidate,
  with their original state, source, target metadata and full file inventories.
- Represent a genuinely absent converter folder explicitly, bound to its parent
  directory identity. Do not create a folder, discard a run or substitute an
  empty inventory to make startup pass.
- Derive runtime requests and the current target only from the exact runtime
  subset. All paused jobs still participate in database, namespace, staging,
  process and producer checks. Malformed or contradictory stage evidence rejects
  preservation rather than being treated as an earlier failure.

Verification: 138 focused checks passed, including the emitted startup and
receiver collectors, actual local SQLite and file inventories, existing/absent
older receiver folders, malformed file/directory markers, exact runtime subsets,
target selection and unchanged-state refusals. External process and host checks
in these tests are modelled; this is not live startup acceptance.
The mixed-stage path still requires a proven runtime candidate and one runtime
target. It grants no retry, closure, execution, technical verification or human
acceptance. Live upgrade and end-to-end conversion remain unverified.

## [0.22.15] - 2026-11-14

### Reduce repeated checks of saved conversion reviews

- Reuse final historical review views only inside the existing fenced read-only
  operation. Bind every actual input, preview mode and freshly checked member
  identity; return independent copies. Runtime execution never uses this cache.
- Keep installed validator bytes, manifests, members and directory-absence checks
  fresh on every hit. Current database, owner, consent and event checks remain
  outside the cache, with unchanged original validation on misses.
- Keep a separate optional store limited to 128 entries, 4 MiB serialized per
  value and 8 MiB total. Do not consume other verification budgets. These limits
  describe serialized data, not total process memory.

Verification: 39 focused acceptance and 37 neighboring checks passed. Independent
review confirmed the original validation bodies and existing scope logic were
preserved. The small authored fixture was slower because fresh member checks
remain; it is not used as evidence of a speed improvement.

An isolated, read-only comparison on the retained real conversion passed all four
technical checks in about 32.5s, versus 37.2s for the previous candidate. It stored
38 final views (about 1.14 MB); job state and all retained files stayed unchanged.
Diagnostic counters add unquantified overhead. This is a single measured candidate
comparison, not installed performance, a runtime-deadline guarantee or a complete
conversion. No new import, runtime pass, SQL export or business acceptance is
claimed. Deployment and end-to-end verification remain separate.

## [0.22.14] - 2026-11-13

### Reuse source checks and preserve paused conversions

- Reuse structural summaries and final focused review-context data within an
  existing read scope. Avoid storing discarded full-prefix rows. Keep current
  permission, source authenticity and reviewer-provenance checks separate.
- Detach strict JSON trees efficiently, with the original copy behavior for
  unsupported types and mutable aliases. Encode only known evidence-whitelist
  triples in the private cache, restoring the unchanged public tuple API and
  current source-row identity. Logical byte budgets remain unchanged.
- Empty runtime polls keep deadlines and retained-input checks without repeatedly
  rebuilding full authorization. Authorization remains mandatory before dispatch,
  before result reads and before return; worker/browser gates are unchanged.
  Producer-only transient revocation is no longer latched during an empty poll;
  this is not an immediate-cancellation feature. Slow checks cannot renew a deadline.
- Add explicit startup-only preservation for unresolved jobs. Keep ATTENTION,
  blocked admission, no retry and all evidence unchanged. Require exact storage,
  identity, process and journal checks, including overlapping mounts and other
  pending verifier sessions. The audited configuration-only observer may select
  its provider in a fresh interpreter; no execution or credential retrieval is
  permitted. Preserving an old runtime binding does not make it dispatch-ready.

Verification: focused suites passed 304 context checks, 301 copy checks,
393 evidence-index checks, 212 runtime/worker/browser/release checks and
177 startup/transition checks; these suites overlap. Independent reviews passed.
Startup testing has one skip and one deselected expensive fixture. Three separate
legacy fixture setups require an absent operator profile and remain unverified.
Host/process transports and browser commands in these suites are modelled.

A preceding exact-family, read-only comparison reduced the retained case's four
technical checks from about 104s to 38s while preserving its state and all files.
The final evidence-index comparison could not connect by SSH and has no real-case
result. Local codec parity and clone counts are not a runtime-deadline guarantee.
No installed-flow success, new import, runtime pass, SQL export, business acceptance
or deployment is claimed by this source release.

## [0.22.13] - 2026-11-13

### Avoid rebuilding unchanged conversion evidence

- Reuse complete retained-container proofs only within the existing fenced read
  operation, keyed by actual inputs and member bytes. Both installed validator
  byte/manifest guards still run on every hit. No current permission, owner,
  database state or target observation is cached.
- Reuse pure context-screen projections with all source structures and independent
  binding inputs in the key. Return independent copies and preserve original
  validation, error normalization and out-of-scope behavior.
- Keep independent optional stores: four complete proofs and 128 projections,
  each limited to 4 MiB serialized per value and 8 MiB serialized in total.
  Capacity misses recompute normally; mandatory proof budgets and enclosing file
  fences are unchanged. These are serialized-value caps, not process-memory caps.

Verification: the final selected regression run passed 126 tests, including all
75 projection acceptance checks and release metadata checks. All 52 complete-proof
acceptance checks passed in a separate short-path run after the first run hit
Windows' path limit. Six older plan-scope tests still fail fixture setup and their
bodies remain unverified; the selected suite is not all green. Earlier neighboring
runs passed 271 complete-proof and 324 projection-related cases; suites overlap.
Independent reviews covered both stores and the final projection entry limit.

The isolated exact-family comparison passed all four technical checks on the
retained real job without changing its state or files. Measured check time fell
from approximately 104s to 65s; projection calls required 18 full computations
and 61 cache hits, using 127,237 serialized bytes. The earlier four-entry candidate
only produced four hits and took approximately 95s. Diagnostic counters add
unquantified overhead; these are individual read-only measurements, not complete
conversion timings or a performance guarantee. No installed code was replaced.

This source release does not resolve the earlier runtime error, establish the
whole runtime deadline, deploy a new service, export an application or record
business acceptance. No automatic replay or new execution permission is added.

## [0.22.12] - 2026-11-13

### Preserve historical reviews during engine updates

- Ship the exact trusted v1 context validator separately for historical review
  evidence. Keep its original byte hash and every archive/manifest check; never
  execute archived source or change an old proof to accept new validator bytes.
- Let current summary-only validation omit detailed rows it does not return.
  Preserve all validation branches and potentially failing lookups. Default full
  context and nonplain/oversized fallback behavior remain unchanged.
- Keep the historical reader in the FOX and host source projections. The
  converter's separate structural-only QA contract is unchanged.

Verification: 110 focused and 208 neighboring summary checks passed; a separate
105-case compatibility suite passed, including archive/JSON-reader parity,
tamper rejection and isolated package-projection imports. Two representative
pre-existing fixture cases still fail setup and are not counted as passes. No
complete production archive build or deployment is claimed by these checks.

The initial isolated one-module comparison correctly rejected historical proof
because the validator bytes differed. The corrected current-plus-frozen-v1 family
passed all four technical checks on the retained case without changing its files
or ATTENTION state. These isolated checks took approximately 103s versus 104s
previously: no material real-case speed improvement is claimed. A small synthetic
summary-only measurement reduced deepcopy calls from 9,872 to 48, but does not
establish end-to-end performance. Publication is not runtime/export acceptance,
browser-dispatch authority or business acceptance.

## [0.22.11] - 2026-11-13

### Reuse identical source analysis within checks

- Reuse pure Forms document analysis only within an existing fenced read scope,
  keyed by exact ordered filenames, byte lengths and source-byte hashes. Outside
  a scope, or for ineligible inputs, retain the original uncached behavior.
- Return independent copies so one caller cannot change a later result. Keep
  selection, processing permission, owner, profile and review checks separate.
- Use a small optional store: four entries, 4 MiB serialized per value and
  8 MiB serialized total. Capacity misses compute without storing. Required
  proof-cache budgets and file/context fences remain unchanged. These caps do
  not describe total Python process memory or temporary allocations.

Verification: 34 focused tests passed. The broader regression run completed with
259 passes and seven setup errors; all seven errors were reproduced with both
unchanged baseline modules in isolated memory. Those test bodies remain
unverified and are not counted as passes. Independent source review found no
blocking regression. Parser, credential rejection and mandatory fence behavior
remain unchanged.

A synthetic 11,712-byte, 80-block source repeated eight times produced identical
output with eight builds reduced to one; measured wall time was 0.117s versus
0.049s. This small pure-function comparison is not a live authority, conversion
or customer performance guarantee. The change adds no model call, persistent
cache, automatic retry or permission grant. Publication does not imply deployment
or completed end-to-end acceptance.

## [0.22.10] - 2026-11-13

### Allow conversion stages time to finish

- Replace the shared ten-minute socket wait for native prototype stages with
  trusted stage-specific allowances: validation 1080s, schema preparation 2400s,
  import 4800s, runtime verification 3600s and export 3600s.
- Give exact stage GET requests the same allowance as POST, because reading a
  retained result can wait behind the executing stage's lock. Preserve the
  existing validation-continuation wait and other request defaults.
- Keep request bodies, endpoint restrictions, validation, authority freshness,
  stage execution and no-replay rules unchanged. A response loss does not issue
  another POST, poll automatically or mark a job successful.

Verification: 119 targeted routing/endpoint tests and 154 neighboring protocol,
pipeline and import-reconciliation tests passed. Independent source review found
no material issue. External services were modelled; no live job was changed by
these tests. The original neighboring test process completed successfully after
its shell observer timed out; it was not restarted.

These are socket wait allowances, not whole-stage deadlines or a performance
improvement. Target preflight still has no aggregate duration bound; expensive
runtime polling and lost-response reconciliation remain separate work. This
source release does not establish deployment or end-to-end conversion success.

## [0.22.9] - 2026-11-13

### Batch native schema metadata checks

- Read metadata for all native prototype tables in one guarded SQLcl session,
  reducing repeated connection startup without caching target observations.
- Bind every output row to its validated source block and derived table. Retain
  exact column order/type/nullability/length/identity, primary-key and trigger
  checks. Reject missing, duplicated, reordered, cross-table or unexpected output.
- Preserve the saved target, SQLcl exit/stderr checks, source authority,
  freshness, stage semantics and no-replay rules. Control-only plans issue no SQL.

Verification: 529 selected local tests passed with no skips, including 62 new
batching cases and the 37 existing gateway cases. Independent source review
found no material issue. A separate live read-only seven-table comparison passed
the same metadata checks: seven SQLcl sessions took 33.96 seconds; one batched
session took 6.43 seconds. This is one lab observation, not a general performance
guarantee or an end-to-end conversion benchmark. No service or target data was
changed by that comparison.

Known verification limit: 20 existing preclaim fixture setup errors were also
reproduced against the previous HEAD; those fixtures reference an absent legacy
module alias. They are not counted as passes. Larger-target latency within the
single 120-second batch budget remains unmeasured. Publication does not imply
deployment, completed runtime/export acceptance or business equivalence.

## [0.22.8] - 2026-11-12

### Recognize validated jobs consistently during startup

- Fix the startup history reader's validation-only assumption for a conversion
  that has passed validation and stopped before schema writes. Upgrade inspection
  already supported this history; startup admission must verify the same stage.
- Derive the stage from saved history, then use the existing stage-specific
  lineage, successful receipt, original terminal outcome, paired-file witness
  and recheck contracts. Preserve the earlier validation-only paths.
- Keep this recognition limited to startup preservation. It neither makes the
  stopped conversion retryable nor grants ordinary admission, schema execution,
  import, technical verification or business acceptance.

Verification: 67 Linux tests passed with no skips, covering the actual emitted
startup reader against a synthetic saved history, pure technical reconstruction,
paired host checks, SQLite preservation and existing claimed-validation/default
paths. Service and Oracle boundaries in these tests are modelled. An earlier
Windows fixture run was interrupted and is not counted as a pass; a separate
broader run retained three legacy manifest/profile-availability failures.

This is a source correction for an observed startup failure, not proof of a
successful deployment or end-to-end Forms conversion. Live activation and
schema/import/runtime/export acceptance remain separate.

## [0.22.7] - 2026-11-12

### Preserve a recognized pre-schema stop without treating it as success

- Extend the existing paired maintenance reader/controller with an explicit
  schema-before-write history variant. It binds the original candidate and
  successful validation to the consumed validation-repair events and exact
  schema request/intent. Unknown files, schema SQL, write intents and later
  stages remain rejected.
- Keep the purpose separate from ordinary admission and the earlier validation
  variants. Preservation does not close a run, grant retry, execute a stage,
  rewrite a failure, or record technical/business acceptance.
- Wait up to 180 seconds for a genuine first idle claim, covering the measured
  cold-start delay. Claim hashes, startup bounds, attention refusal and normal
  completed-session seals are unchanged; no verifier restart is attempted.

Verification: both new production-shaped reader cases and the existing claimed
validation matrix passed. The old unclaimed acceptance body passed through a
static historical-fixture wrapper; the earlier combined run's dynamic-fixture
setup error and collector-harness failure remain recorded, not counted as passes.
The final combined controller suite passed 157 tests with 12 platform skips,
including the explicit-purpose/stopped-pair tests and 19 clock/journal cases
executing the AST-extracted idle observer. Earlier overlapping suite counts are
not additive.

A separate read-only candidate namespace successfully reconstructed the actual
retained schema-before-write history. It installed nothing and granted no
transition preservation, closure or retry authority. Live paired transition,
the separate idle audit, conversion continuation, import/runtime/export and
human acceptance remain unproven by this source release.

## [0.22.6] - 2026-11-12

### Keep target checks fresh and show recorded conversion progress

- Collect new, real target observations at each protected operation boundary,
  then check current authorization, snapshot and prior receipts before verifying
  that observation. Keep the 300-second expiry, absence checks and exclusive
  write intents; do not refresh an old timestamp or retry an uncertain action.
- Add an authenticated, source-bound, read-only progress endpoint and compact
  six-stage UI. Distinguish requested work, matching local records, attention,
  unavailable metadata and stale responses. Historical rejection reports do
  not override a currently processing run.
- Progress is advisory, not proof of completed conversion, technical
  verification, download eligibility or human business acceptance.
- Make the offline release gate use the public metadata validator, including
  list and text limits, so malformed bundled notes cannot pass that gate and
  then prevent UI startup.

Verification: 153 Windows freshness/gateway/preflight tests passed. The focused
backend set passed 59 tests with one native-file-symlink skip; actual Windows
junction rejection passed. A Linux combined run passed 173 tests with only the
Windows-junction case skipped, covering real POSIX symlinks. Desktop/mobile
browser checks with simulated responses and TypeScript checks passed. A separate
read-only check of the candidate reader against retained real-job metadata
correctly distinguished recorded validation from a schema-stage failure; it
installed nothing and made no database changes.

The canonical built UI also passed an actual authenticated local HTTP/browser
check against the real FastAPI progress route and SQLite store, using synthetic
metadata with the conversion worker disabled. Refresh was GET-only and the
390-pixel view had no horizontal overflow. That test caught an overlong release
note list before publication; the manifest was corrected and seven release
schema/API consistency tests now pass.

This is source/test evidence. Deployment and a successful live schema/import/
runtime/export sequence remain separate. An already claimed failed stage is
not made retryable by this change; its original outcome must be reconciled.

## [0.22.5] - 2026-11-12

### Observe the actual report refresh before checking data

- Arm a bounded native Interactive Report refresh observer before Filter or
  Reset Apply. Accept completion only from the exact initialized report element
  on the expected app/page; clean up the observer afterward.
- Keep the existing single action, request boundaries, save waits and invalid-
  input fences. Issue no extra refresh request and retain only static failure
  codes if the filter action or refresh cannot be confirmed.

Verification:a fresh lead run passed all30 Node tests, and62 adapter tests passed
without skips. An earlier29-pass/1-failure synthetic short-timer run is retained
rather than counted as a pass. An actual
read-only APEX diagnostic observed one row immediately after Filter Apply, then
zero rows only after the matching refresh event. The old already-idle check was
too early. This verifies the cause and bounded source correction, not a complete
runtime rerun or hosted conversion. Business acceptance remains separate.

Post-release verification, 12 November 2026: the exact published 0.22.5 QA code
completed an actual authenticated manual-lab run in 45.305 seconds. All seven
content pages passed. Each of three native forms passed Create, Update, reread
and one required-input client-rejection probe; report search and control items
also passed. Separate read-only database checks confirmed all three updated
synthetic rows and preserved the earlier test row. Independent evidence review
confirmed the original process exit and source/import/artifact bindings.

This is a developer-authored structural candidate from a real Forms module,
not an OPAF-reviewed or automatic hosted conversion. The runtime duration excludes
extraction, inference and import. Clean-schema portability, original business
behavior and human acceptance are not established. No hosted cutover was made.

## [0.22.4] - 2026-11-12

### Wait for native saves and keep retained test records

- Register an exact destination app/page wait before a single Create or Save
  click. An already-idle form is not evidence that its deferred submission has
  finished. Preserve write intents, expiry, source values, row identity,
  confirmation and account checks; never retry an uncertain submission.
- Keep the negative required-input probe's no-POST fence active through verified
  Cancel navigation and the report account check. Release it only before the
  report's legitimate reset request; failures keep the fence active until close.
- Allow prior synthetic records instead of requiring the whole report to be
  empty. The field-error, zero-POST and empty-new-row-key checks remain required.

Verification:26 Node tests and 62 adapter tests passed without skips, including
delayed submits, wrong targets, timeout, revoked authority and late negative POSTs.
A separately controlled actual native Create returned to its report with
"Record saved"; read-only database reconciliation confirmed one retained synthetic
row. Its request was ordinary supported form encoding, so no request allowlist
was broadened. Full multi-form runtime, hosted conversion and business acceptance
remain distinct checks; this source release does not claim them complete.

## [0.22.3] - 2026-11-12

### Use the actual APEX Report submenu interaction

- Click the Report submenu instead of relying on hover. Wait for each reset
  control to be visible and unique, checking the execution fence before clicks.
- Preserve the request allowlist, target checks and existing confirmation step.
  On failure, retain only a static reset-phase/error code for operators, never
  raw browser errors, credentials or page contents.

Verification:17 Node tests and 62 adapter tests passed without skips. A read-only
authenticated diagnostic showed that hover left Reset hidden while clicking
Report exposed it. The previous live test passed navigation, report rendering,
column checks and search, then stopped before any business record write. That
failed attempt remains preserved. Confirmation, full form runtime and deployment
still need their actual checks; this source release does not claim them complete.

## [0.22.2] - 2026-11-12

### Verify native APEX tree navigation correctly

- Recognize exact source-name navigation anchors exposed as APEX tree items,
  including labels hidden by the collapsed sidebar, as well as ordinary links.
- Continue to require one unique observed URL for the exact application and
  expected page. Preserve origin, expiry, authentication and page-identity
  checks; do not invent URLs or click hidden controls.

Verification:14 Node tests passed with no skips, including tree/link roles,
hidden labels, ambiguous targets, foreign apps/origins, wrong pages, non-anchor
elements and expired requests. A read-only authenticated diagnostic of an actual
native app confirmed all four expected entries were hidden-label tree items and
performed zero business POSTs. The previous browser attempt stopped after login,
before page or record checks; that failure is preserved. This source correction
is not a successful runtime rerun, deployment or business acceptance.

## [0.22.1] - 2026-11-12

### Accept Oracle's empty list-entry name

- Preserve an empty Name on a ListItemElement when matching paired Oracle
  OVERRIDDEN and ALL exports. Do not reject the entire module for this standard
  metadata shape, invent a name, or join entries by their position.
- Keep empty distinct from missing, reject duplicate empty sibling identities,
  and continue to reject empty names on other object kinds. Inherited identities,
  foreign namespaces and secret checks retain their existing protections.

Verification:327 effective-view, intake and redaction tests passed with no skips;
independent source review cleared the bounded fix. A second real Oracle-validated
module previously stopped on this exact metadata value. It now produces a local
developer structural candidate with two native form blocks and seven required
inputs; its APEXlang passed actual SQLcl26.1.2 validation without a database
connection. Original code, dependencies and unsupported behavior remain explicit
remediation. This is not hosted conversion, OPAF design review, import/runtime
proof or business acceptance.

## [0.22.0] - 2026-11-12

### Preserve required inputs in native APEX forms

- New prototype runs opt into a source-bound input policy: an explicit Forms
  Required property becomes native APEX value-required validation on supported
  editable database fields. Existing NOT NULL checks remain effective; synthetic
  database nullability is unchanged. Noneditable and unsupported items remain
  remediation work rather than silently becoming mandatory fields.
- Preserve the original renderer and all existing saved-run contracts. Old runs,
  retries and continuations do not silently adopt the new policy. Reject unknown,
  malformed or mismatched policies and renderer profiles.
- Carry the selected profile through package checks, recovery, runtime evidence,
  export and the paired application payload. New-run UI submission opts in while
  retaining the existing explicit consent and independent review gates.
- Add a developer-only runtime probe for missing required input. Its browser
  check exercises client-side rejection; it does not establish server-side
  rejected-write behavior or Forms transaction equivalence.

Verification: the source planner suite passed 285 tests; renderer integration
passed 677, with a further 62 browser-adapter tests and 10 Node tests. Packaging
and package checks passed 118 with 10 skips; isolated payload checks passed 4;
recovery/context checks passed 28. All 13 local UI browser scenarios passed with
mocked APIs. Suites overlap and are not a count of unique end-to-end scenarios.
Historical fixture failures and an initial malformed-package regression were
retained; the regression was fixed and retested. Independent source review cleared
this bounded change.

A developer-authored structural candidate from one real, Oracle-extracted Forms
module contains three native form blocks and six source-required inputs. Its
exact APEXlang ZIP passed SQLcl 26.1.2 validation without a database connection.
This is not an OPAF-reviewed mapping, hosted conversion, import/runtime proof,
clean-package reimport, complete business-logic translation or human acceptance.
Publication does not activate the feature on an existing installation.

## [0.21.6] - 2026-11-12

### Read standard radio-button and required-field metadata

- Recognize Oracle Forms RadioButton objects rather than rejecting an otherwise
  readable module during local redaction. Keep scoped names, IDs and locations.
- Preserve explicit boolean Required properties for subsequent conversion work.
  RadioButtonValue remains masked; no private option value is inferred.
- Keep existing XML namespace, inherited/default-property, DSC identity and
  source-permission boundaries unchanged. Oracle ALL output remains provenance
  evidence, not a substitute for the normal OVERRIDDEN source export.

Verification:900 relevant tests passed,12 were skipped, and9 subtests passed.
The39 new cases had35 failures before the fix and all passed afterward. Two
real Oracle-validated OVERRIDDEN exports passed the updated local redaction,
facts and source-packet path; one contained9 radio buttons. One code unit in
that larger module was withheld by redaction rather than reconstructed.

These are local intake results, not hosted extraction, generated APEX, native
radio/Required validation behavior, import/export or business acceptance.

## [0.21.5] - 2026-11-11

### Back up larger retained development histories

- Increase the bounded upgrade snapshot capacity from 20,000 to 25,000 entries
  and from 128 MiB to 160 MiB. This accommodates retained development history
  without deleting previous evidence or adding infrastructure.
- Keep the 64 MiB member limit and 8 MiB manifest limit unchanged, together with
  archive integrity, unsafe-path, link, SQLite and isolated-restore checks.
- Continue to reject snapshots above the new limits. Every deployment still
  requires its own fresh capacity measurement and successful backup/restore.

Verification: all 33 snapshot tests passed on Linux. Across normal and isolated
rootless Linux runs, 57 of 60 hosted-snapshot scenarios passed; three opt-in
Podman launcher scenarios were not run. Coverage includes exact-capacity and
overflow rejection, streaming archive membership, private ownership, links,
SQLite/WAL preservation, and actual synthetic capture/isolated restore. Windows
checks passed with POSIX-only skips. An initial wrong-checkout namespace run was
preserved and excluded; the corrected run verified the exact source path/hash.

These are local tests, not proof of a successful live upgrade, APEX conversion,
downloaded-package import or business acceptance. Existing frozen releases and
historical evidence remain unchanged.

## [0.21.4] - 2026-11-11

### Preserve stopped validation history during upgrades

- Add a distinct maintenance-only check for a stopped validation request whose
  claim is retained but whose validation has not completed. Preserve original
  continuation/event/attempt, request, snapshot and generated ZIP bindings.
- Use paired read-only collection and actual retained transition provenance
  during upgrade and startup. The existing unclaimed path remains separate.
- Keep ordinary admission blocked and retry unavailable for unresolved work.
  Preservation is not model execution, validation, import or business acceptance.

Verification: all 16 focused Linux tests passed, including the complete synthetic
claimed-history path, rejection matrix, real SQLite selection/consent changes,
record/attempt mutations and final paired-tree preservation. Startup provenance
uses modeled external observations. All five measured code/test files retained
their exact hashes; one new synthetic import-time database was accounted for.

The separate Windows fast batch had 212 passes, three failures caused by absent
legacy profile fixtures and one skip; it is not claimed as an entirely passing
suite. Windows historical-fixture diagnostics ended in a native interpreter
failure, so the complete focused proof was performed on Linux. Original failed
evidence remains retained. No installed upgrade, live validation, import/export
or business acceptance is claimed, and no consumed attempt may be replayed.

## [0.21.3] - 2026-11-11

### Retain export files in writable storage

- Create private export attempts under the existing persistent jobs directory,
  rather than requiring its protected parent to be writable.
- Keep failed or uncertain export files for inspection. No cleanup, automatic
  replay, permission change or unverified package publication is introduced.
- Preserve the existing application/runtime identity, SQLcl validation and
  exact-byte checks. Export scratch is not a dispatchable job and remains
  included in backup inventory.

Verification: 125 relevant local tests passed, including six focused export
cases that failed against the old path and passed after the fix. Tests exercised
real persistent directories and snapshot/queue readers with modelled SQLcl and
browser responses. This is not live Oracle export, clean-install or business
acceptance proof. The stopped real validation claim still requires separately
verified preservation and recovery; this source release does not authorize retry.

## [0.21.2] - 2026-11-11

### Prepare validation files and reuse saved checks

- Use a private system temporary directory for APEX validation. A writable jobs
  directory no longer requires its parent to be writable too. Keep the exact
  retained ZIP, extracted-tree checks, validation log and receipt requirements.
- Keep overlapping read-only epoch, review and model-proof checks inside the
  existing operation-local proof scope during converter-phase reconstruction.
- Preserve exact source-file entry/exit checks and fresh owner, selection,
  target and consent checks. Reuse ends before external execution.
- No persistent cache, cached processing permission, new model call or
  automatic retry is introduced.

Verification: 54 existing FOX regressions, 128 converter tests and the focused
fresh historical-checkpoint test passed. The scratch-path regression failed
before the fix and passed after it. In the synthetic checkpoint comparison,
container-proof computations fell from 21 to 2 and derivations from 12 to 1;
the typed phase, retained files and model-call count were unchanged. Source
mutation and changed owner, consent and target were rejected. The measured
phase took 49.29s before and 9.81s after, excluding fixture preparation; this is
not a live conversion speed guarantee. Existing dependency warnings and a
JUnit property-format warning remain.

These are source-level checks, not proof of deployment or a successful real-file
APEX import/export. Existing consumed validation attempts remain preserved and
still require explicit reconciliation; this release does not authorize replay.

## [0.21.1] - 2026-11-09

### Correct existing-host upgrade admission

- Match the existing hosted container roles: the FOX root filesystem is
  read-only; the converter uses its approved writable root filesystem.
- Require the converter's exact existing jobs bind mount instead of an
  unrelated parent directory. No container setting or mount is changed.
- Retain identity, image, process, unchanged-configuration and paired-job
  preservation checks. This correction grants no conversion retry or import.

39 focused tests and 165 relevant regressions passed; 12 POSIX-only checks were
skipped on Windows. The broader historical suite could not pass without its
private legacy fixtures and is not included in those pass counts.
Local modeled checks cover both approved role configurations and reject changed
paths, mount types, access modes, identities and post-read evidence. These tests
are not proof of a successful hosted upgrade or conversion. The failed 0.21.0
upgrade and its original evidence remain retained; deployment and the real-file
validation/import/export path require separate live verification.

## [0.21.0] - 2026-11-09

### Continue validation of a saved draft

- Offer **Continue validation** when a reviewed draft is retained and the
  converter proves that validation has not started. Reuse the same run and its
  exact approved model outputs; require fresh owner confirmations.
- Keep the original intent and failed handoff. Bind the new continuation to the
  saved source, target, draft, reviews and converter state, then make one exclusive
  first validation claim. Unknown responses never trigger an automatic repeat.
- Show clear recorded/pending states and operator guidance when reconciliation
  is required. Reject stale project/source responses and hide unrelated XML
  intake controls while reviewing this saved-draft action.
- Cache only bounded pure reconstruction work within a single read scope.
  Current owner, source and target permissions remain freshly checked.
- Align trusted validation waits with SQLcl and authorization budgets. These
  are socket waits, not a guarantee of total completion time.
- Use the existing prototype source-snapshot reader consistently, fixing a
  later 2 MB checkpoint limit that rejected already-admitted larger sources.
- Preserve recognized stopped pre-validation history during upgrades only after
  independently checking both retained job trees and current runtime identities.
  Maintenance preservation grants no retry or processing permission.

Local verification covers same-run continuation, exact ZIP download, missing or
changed proof, concurrent submissions, unknown responses, source/project switches
and legacy compatibility. Provider, database and browser outcomes in backend
integration fixtures are simulated. A passing local test or source release does
not prove the hosted application has completed conversion.

SQLcl validation, unique import, authenticated runtime checks and exact export
remain required. A recorded continuation in ATTENTION still needs operator
reconciliation. Business acceptance, clean-schema portability and customer-target
compatibility are separate outcomes.

## [0.20.1] - 2026-11-09

### Reduce repeated checks when resuming

- Reconstruct the exact already-reviewed prefix together when continuing a
  saved mapping. Its validated continuation record, frontier and proof hashes
  determine the boundary; file presence alone is not enough.
- Keep every source and review check. Missing, negative or changed evidence
  stops processing instead of falling back to another model call.
- Close the bounded read-only scope before new work. Fresh owner, consent,
  source and target checks remain in the existing execution path; no persistent
  cache or cached processing permission is introduced.

111 targeted tests passed. A read-only synthetic benchmark reconstructed all
14 authorized retained views in 4.99 seconds with unchanged proofs/files and
no provider or database operations. This is not a live latency guarantee.
Source publication does not change an already-running conversion or prove
deployment, APEX output, or business acceptance.

## [0.20.0] - 2026-11-09

### Review corrected mapping format and continue

- Add a source-bound format policy for an exact repeated binding field and two
  Item metadata kind aliases. Values, evidence, statuses and business behavior
  are unchanged; mismatched or unsupported facts still stop processing.
- Preserve successful legacy owner/context handling. Original model responses
  remain immutable, with separate normalization evidence and fresh independent
  review of the resulting candidate.
- Offer **Review corrected format and continue** for an eligible saved mapping.
  Show reviewed sections, the saved mapping and unstarted work; lock the original
  selection and require three fresh processing confirmations. Duplicate and
  uncertain requests do not automatically queue another attempt.
- Materialize only deterministically derived review artifacts under a separate
  same-run continuation authorization. Do not reset consumed repair records,
  create another mapping epoch or regenerate completed mapping calls.
- Separate protected maintenance preservation of recognized, closed provider
  history from ordinary conversion admission. Preservation grants no review,
  retry, processing, import or business-acceptance authority. Unknown work and
  Oracle-stage artifacts remain blocking.

The format policy does not repair missing business logic or invent source facts.
APEX validation, unique import, runtime verification and exact export gates remain
required. Source publication, deployment, completed conversion and human business
acceptance are separate outcomes.

Local checks cover source-bound normalization, retained-result authority,
duplicate/invalid requests, and an exact ZIP downloaded through FOX using authored
model, SQLcl and browser replies. The UI suite passed 22 checks and TypeScript
checking passed. A read-only check against the retained real job confirms the
continuation plan without adopting it or calling a model/database operation.
These checks are not proof of a completed live conversion.

## [0.19.1] - 2026-11-08

### Preserve completed review failures during upgrades

- Recognize the bounded, sealed post-correction negative-review state as stopped
  work that can be preserved during a software upgrade. Earlier terminal
  classifications retain their existing rules.
- Recheck original history, correction authorization and event, contiguous
  completed independent reviews, and the final result/history/publication.
  Historical reads do not replace or rewrite the physical current result.
- Keep active repairs, pending or orphan calls, unexpected files and Oracle-stage
  artifacts blocking. The retirement reader independently checks the terminal
  classification rather than trusting its label.
- Grant no retry, review approval, application import, conversion success or
  business acceptance through this classification.

This patch changes upgrade preservation, not the generated APEX format or the
conversion's required independent-review and deterministic-validation gates.
Source publication does not establish deployment or a completed real conversion.

## [0.19.0] - 2026-11-08

### Recognize saved Forms column names and continue

- Read direct `DSCName` metadata from the exact saved source when older facts
  omitted a DataSourceColumn name. Preserve historical source and object IDs;
  reject ambiguous, conflicting or unsupported identity metadata.
- Offer **Review recognized names and continue** for the bounded eligible
  retained stop. Project only missing-name explanations, not dispositions,
  business behavior or SQL. Each changed candidate requires a fresh independent
  review; completed mapping calls and original negative results remain intact.
- Show unchanged reviewed sections, mappings needing fresh review and sections
  not started. Require the displayed processing confirmations and reconcile
  recorded or uncertain submissions rather than automatically repeating them.
- Bind supplemental model input to the source and immutable task policy.
  Preserve legacy requests and reconstruct modern historical input separately;
  unexpected metadata sidecars do not establish processing provenance.
- Keep deterministic APEX validation, current authority, unique import, runtime
  verification and exact export checks on the connected path. Name recognition
  is not business-logic conversion or human acceptance.
- Clarify the user recovery path and the separate FOX/converter image roles.

Local connected HTTP tests exercise fresh review through output download using
authored model, SQLcl and browser replies. The combined local UI suite passed
21 tests with no skips. These are not live Oracle or real-file conversion proof.
Publication, deployment and the retained real run require separate verification.

## [0.18.1] - 2026-11-08

### Show the saved run's actual next step

- Replace the premature saved-output banner with waiting, processing, attention
  or generated-prototype wording based on the recorded run.
- Open the existing relevant progress/output surface without starting another
  conversion. Keep current-source readiness ahead of older run history.
- Suppress the banner for invalid history, source bindings or unknown outcomes.
- Keep generated output, technical verification and human acceptance separate.
- Align the readable-upload regression with existing server-side FMB guidance;
  retain its disabled-upload and zero-upload assertions.

The complete local workbench suite passed 97 tests, including both isolated
browser scenarios, with no skips. These use synthetic local fixtures, not a
live conversion. This source release does not prove deployment or APEX output.

## [0.18.0] - 2026-11-08

### Review an invalid response without regenerating the mapping

- Add one source-bound review-correction attempt beneath the saved continuation
  when a structurally invalid AI response attributes context-only objects to the
  current section. Preserve the original response and mapping; a fresh independent
  approval is still required. Genuine semantic rejection remains blocking.
- Supply explicit owned-object, context-object and inherited-screen information
  to the corrected review and new later reviews. Historical requests are unchanged.
- Offer **Review saved mapping again**, with fresh processing confirmations next
  to the action and the original locked code-unit list available on expansion.
  Recorded or uncertain submissions cannot be automatically repeated.
- Preserve the existing supported role-graph-update recovery route. Clear stale
  plans after failed refreshes instead of leaving an old action enabled.
- Reuse immutable technical calculations only within bounded read-only operations.
  Current ownership, source selection, consent, events and target checks remain
  fresh; model, package-transfer and execution boundaries remain enforced.
- Use a 30-second socket-operation timeout for current-authority calls and a
  30-second total UI budget for output readiness. The socket setting is not a
  promise of a 30-second total callback duration. This accommodates measured
  validation tail latency without skipping checks; an unavailable authority
  response grants no permission and no operation is automatically replayed.
  Other request budgets are unchanged.
- Recognize the exact sealed invalid-review stop for upgrade preservation without
  granting retry, import, download or business-acceptance authority.
- Clarify hosted FMB preparation, generated-output requirements and the product
  delivery order in the user guide and roadmap.

Local connected tests cover review correction through output download, current
authority checks and measured request budgets. UI tests cover the action and
uncertain-result handling. These tests use authored provider/Oracle/browser
outcomes, not live Oracle acceptance; protected
read-only planning checks do not constitute a new model review or APEX conversion.
See [review-scope correction](docs/review-scope-correction.md).

## [0.17.0] - 2026-11-08

### Review saved mapping without repeated generation

- Remove an exact duplicate screen declaration only when a previously reviewed
  source Block owns it and the current Item/Trigger references belong to that
  same Block. Conflicts, uncertain ownership and behavioral changes still stop.
- Preserve the raw mapping and every non-screen field. Record the derived
  candidate and source-bound projection evidence; neither is an AI approval.
- Add a bounded sixth continuation for the recognized pre-review stop. Reuse
  the saved mapping, run its independent review first, and start the next mapping
  only after approval. Earlier completed calls are not repeated.
- Apply the same checked projection to eligible later mappings in this
  continuation, with independent review still required for every candidate.
- Show **Review saved mapping and continue**, separating reviewed sections,
  a saved mapping awaiting review and sections not started. Original selections,
  three fresh confirmations and uncertain-submission locks remain in place.
- Preserve the missing fifth result publication as an absence, not a fabricated
  result. Historical bytes, approval events, current authority and exact export
  checks stay bound to the corresponding continuation.
- Recognize only the complete, sealed pre-review stop for upgrade admission.
  Evidence references for source links and dependencies use their canonical
  occurrence IDs; admission grants neither approval nor retry permission.

The projection and continuation have local source/API/browser tests using
authored external responses. Separate read-only checks on retained real evidence
confirmed the screen-only change and unchanged original files. These are not a
completed real-file conversion, deployed release or human business acceptance.
SQLcl validation, a unique import, runtime verification and the exact download
still require their own evidence. See
[saved mapping review](docs/saved-mapping-review.md).

## [0.16.1] - 2026-11-08

### Faster checked continuation requests

- Reuse the same exact historical review view within one read-only planning
  operation. Keep its record identity in the cache key, separate from current
  results, previews and live model execution.
- Close the read-only scope before adoption writes. File-integrity checks still
  run at its boundaries; ownership and approval events are not cached permission.
- Give only continuation-plan reads and continuation submissions a bounded
  45-second wait. Other prototype requests retain their 15-second budget.
- Explain when a read-only plan check times out without suggesting that
  conversion started. An uncertain submission still requires checking the
  existing run and cannot be automatically submitted again.

This patch addresses a measured timing mismatch between a valid retained-plan
response and the browser's earlier request budget. It changes neither the saved
candidate nor the independent approval, and does not bypass APEX validation,
import, runtime checks or human business review. Source publication, deployment
and completed real-file conversion remain separately verified milestones.

## [0.16.0] - 2026-11-08

### Continue remaining sections

- Give the independent reviewer losslessly deduplicated source, mapping and
  shared-screen context. Retain the full audit context separately; do not
  truncate selected code or change the candidate to obtain approval.
- Present previous findings as historical allegations to reassess, rather than
  embedding a response-shaped verdict. Explain shared-screen references for
  items and subordinate triggers while keeping substantive checks mandatory.
- Reuse an exact approved saved review through a bounded fifth continuation.
  Preserve all previous results and failures. Completed sections are not
  regenerated or reviewed again; unfinished sections use the compact context.
- Show **Continue remaining sections**, the retained reviewed count and remaining
  work. Lock the original source selection and require fresh confirmations.
  Uncertain submissions cannot trigger a second processing request.
- Keep historical-result validation separate from the current continuation.
  Check current authority before processing and after reading an export package.
- Recognize only the fully sealed pre-database review stop for upgrade admission;
  that classification grants neither processing permission nor success.

Verification covers lossless context reconstruction, tampered-proof rejection,
local API/worker/HTTP/download behavior with authored external responses, desktop
and mobile UI states, and the isolated upgrade-reader contract. A bounded actual
OPAF review approved the unchanged saved candidate, and read-only checks against
its retained hosted proof preserved the original job. This is not yet evidence
of a complete real-file conversion or a deployed release.

Remaining analysis, SQLcl validation, unique import, authenticated runtime and
downloadable export still require live acceptance. Business acceptance remains
human. See [retained review continuation](docs/retained-review-continuation.md).

## [0.15.0] - 2026-11-08

### Continue with reviewed structure

- Check the source-bound mapping prefix for omitted-parent conflicts, related
  screen references and selected trigger coverage before further AI work.
- Represent an eligible nonvisual container correction as a new, independently
  reviewed proposal. Preserve the original response and reuse only its exact
  approved replacement; do not infer missing business behavior.
- Offer **Continue with corrected structure** for the recognized stopped run.
  Reuse completed root/clause work and the next section's saved mapping. Review
  that section with checked screen context before continuing unfinished work.
- Append a fourth same-run continuation record with exact proof, source, target,
  predecessor and fresh confirmation bindings. Preserve earlier failures and
  byte-bound result history; interrupted publication cannot trigger a replay.
- Recheck current approval events and historical proof before output metadata or
  download, and again after the private package read.
- Reuse technical proof reads only within one bounded operation, with filesystem
  checks at entry and exit. No permission cache crosses requests, model calls or
  package transfers.
- Recognize the fully recorded pre-database rejection through the measured
  upgrade checker, without new runtime dependencies, retry authority or success
  claims.

Verification includes source/context and tamper tests, local API/worker/authority
checks, actual local HTTP route/gateway/ZIP checks with authored external
responses, lost-response and desktop/mobile UI checks, generated upgrade-reader
tests and independent reviews. A bounded real-source container proposal passed
independent OPAF review; read-only checks against its retained OCI evidence
preserved all existing job files. These are separate from deployment acceptance.

Real-file remaining analysis, SQLcl validation, unique import, authenticated
runtime verification and exact downloadable export still require live evidence.
No business acceptance is implied. See
[reviewed structure continuation](docs/reviewed-structure-continuation.md).

## [0.14.0] - 2026-11-08

### Continue with reviewed results

- Add a bounded OPAF contract for interpreting supplied Forms WhereClause and
  OrderByClause text, with source-bound limitations instead of invented facts.
- Reconstruct an explicitly derived candidate from retained analysis, verify
  the exact independent review, and preserve both original responses and history.
- Offer **Continue with reviewed result** for the recognized stopped repair.
  Reuse the completed clause analysis and review; review the next saved section's
  projection once, then continue unfinished sections using the original target.
- Append a third same-run continuation record with exact predecessor, source,
  target and saved-proof bindings plus fresh processing confirmations. Unknown
  outcomes, missing proof and later database work remain blocking.
- Transfer only the required JSON evidence to the converter. Evidence code is
  never executed or transferred, and SQLcl/import/runtime/export gates remain.
- Recognize the narrowly proven sealed repair failure for upgrade admission
  without granting retry, proof adoption, conversion success or business acceptance.

Verification includes retained-proof reconstruction and tamper tests, actual local
API/worker/authority/transport tests with authored external responses, repeated
and concurrent submission checks, modelled browser tests and independent reviews.
A bounded real-source OPAF clause analysis and independent review passed; read-only
checks on the retained OCI job confirmed the saved-proof continuation plan and
preserved its existing files. Separate Linux test copies verified permission and
link rejection without changing the original job.

These checks do not establish a deployed release or a complete real FMB-to-APEX
conversion. Remaining analysis, SQLcl validation, unique import, authenticated
runtime verification and downloadable export acceptance are still required.
See [reviewed-result continuation](docs/reviewed-result-continuation.md).

## [0.13.0] - 2026-11-07

### Source-checked repair and append-only continuation

- Check source-fact claims against the existing exact whitelist and evidence
  rules before new review. AI approval cannot override a failed source check.
- Add a bounded targeted repair and new independent review for an eligible
  saved section. Preserve original responses and prior approvals as history;
  only newly validated proof can become active for export.
- Project only proven repeated context declarations and exact property aliases.
  Preserve excluded records and rationales in versioned evidence and include
  that evidence in the independently bound reviewer request.
- Append source-, target- and checkpoint-bound continuation records with exact
  predecessor hashes, fresh consent and same-run identity. Do not replace the
  earlier continuation record or restart completed model requests.
- Show AI-reviewed and source-checked counts separately. Continue remaining
  sections only after the corrective phase passes; no automatic repair loop.

Verification includes pure source-fact/repair tests, local epoch API and worker
scenarios, interrupted-operation and staged-path guards, and an integrated local
authority/staging/export test with authored external responses. Modelled UI
regressions and independent reviews passed. Read-only checks against the retained
real job confirmed the bounded repair plan and preserved all 69 child-run files
in both container and host-reader checks; those checks invoked no model or import.

Publication and deployment are separate from live repair success. The corrected
candidate, remaining analysis, SQLcl validation, import, runtime checks and export
must still pass. See [source-fact repair](docs/source-fact-repair.md).

## [0.12.0] - 2026-11-07

### Source-reference resolution and saved-progress continuation

- Resolve a claim's code-unit ID to its exact owning Forms object using the
  authoritative request. Reject unknown, conflicting or out-of-scope references;
  do not infer missing business behavior or alter the original AI response.
- Retain a separate source-bound resolution record. Independent review, merge
  and export proof must use and verify the same resolved candidate.
- Add an explicit same-run continuation path for a proven stopped mapping step.
  Reuse completed model checkpoints; preserve the source snapshot, original
  responses, run identity and previously approved sections.
- Require current ownership, source selection, unchanged target, exact checkpoint
  evidence and three fresh processing confirmations. Unknown outcomes and
  database-stage failures do not become eligible for automatic retry.
- Show saved progress and the continuation choice in the prototype conversion UI.

Verification includes local ownership-resolution, same-run API, lost-record,
transaction-orphan, conditional authority-transfer and retained-proof tests;
modelled continuation/retry browser checks; and independent review. Read-only
checks against a real saved job found five reusable reviews and twelve exact
reference resolutions, preserving every original checkpoint in both container
and host-reader contexts. No new model or database operation ran in those checks.

This source change is not proof of a completed live conversion. Deployment,
remaining model work, SQLcl validation, import, runtime checks and exact export
must succeed before the application can be presented as generated. See
[checkpoint continuation](docs/checkpoint-continuation.md).

## [0.11.0] - 2026-11-07

### Explicit first-mapping recovery

- Parse a single model JSON object with an optional single JSON/plain Markdown
  fence. Reject prose, multiple values, duplicate keys and nonfinite values;
  retain the untouched API-response hash. No model content is synthesized.
- Add a read-only recovery check and an explicitly approved, deterministic child
  attempt for a proven incomplete first mapper. Preserve the original source,
  selected code units and failed attempt. Unknown, later-stage, reviewer-rejected
  and chained attempts are not automatically retried.
- Bind new request partitions to schema 2 with at most 32 owned objects each;
  preserve schema-1/250 historical reconstruction. Every source object and whole
  selected code unit remains covered; smaller requests are not omitted Forms.
- Permit only a freshly approved role-profile update with the same destination,
  model and processing boundary. Show the changed-workflow notice in the UI.
- Migrate only the legacy SQLite run-source uniqueness constraint, preserving
  run IDs/rows, primary/foreign keys and transaction rollback. Normal generation
  retains serialized duplicate guards. History accepts only the validated
  deterministic parent/child pair and shows two linked runs, not duplicate data.
- Recognize an exact, sealed, empty first-mapper failure as terminal before any
  executable work. This grants neither success nor retry authority. Generic
  attention, missing proof, later work and unknown operations remain blocking.
- Add separate v3 analysis/review prompt resources that distinguish non-executing
  analysis from source safety flags. Existing workflow resources are preserved.
- Add a partition-aware v4 reviewer that accepts supported module-level analysis
  without demanding screens from a partition that owns no Blocks. Known Block
  and Item mapping, ownership and behavior-evidence requirements remain intact.
  Registration permits only the new reviewer and preserves the existing mapper.

Verification: scoped local API/SQLite/history/rollback and parser regressions;
simulated desktop/mobile recovery UI; independent review; and read-only tests
of the terminal-failure classifier on actual retained proof in both rootless UID
contexts. Legacy fixture cases were tested in an isolated source copy.

**Not a live conversion-readiness claim.** The real-source diagnostic returned
structured behavior analysis. One explicitly approved reviewer-only retest of
that unchanged saved module-level candidate returned `APPROVED`, zero findings;
generation was not repeated and no import occurred. This verifies one partition,
not the whole application. Guarded deployment, a complete real-file
import/runtime/export and human business review remain separate. See
[mapping recovery](docs/prototype-mapping-recovery.md).

## [0.10.0] - 2026-11-07

### Generated prototype output and connected verification adapters

- Add current-project authority checks for every protected prototype stage;
  owner, selected source, consent, retained review and target must still match.
- Connect opt-in converter startup and private host browser verification through
  bounded, expiring requests. Claims and uncertain outcomes are retained without
  automatic model/import/browser replay. No public QA endpoint or Podman socket.
- Add a separate generated-prototype output view and exact package download.
  Stale sources, changed targets or incomplete evidence block download without
  promoting the run to human accepted or strict clean-install verified.
- Include the pure package validator in the app payload. Historical stage proof
  is verified locally; downloading does not reauthorize or replay earlier stages.
- Bind focused OPAF metadata, HTTPS authority and measured worker source into the
  explicit upgrade plan, retaining the existing target and private Forms queue.
- Handle bare/prefixed Podman image IDs, expired queue entries and the measured
  rootless-cgroups-v1 diagnostic. CPU/memory/pids limits are not claimed enforced
  on cgroups v1; the container lifetime remains independently bounded.
- Permit the two standard APEX script endpoints only for the exact application,
  preserving foreign-app, password-change and expired-request rejection.

Verification includes isolated source/package tests, authenticated local API and
simulated UI checks, actual installed-dependency server startup, OCI namespace
handoff/container-lifetime checks, and a separate existing-app login prerequisite.
These do **not** establish a deployed end-to-end real-FMB conversion. A successful
prototype remains synthetic/partial, with explicit remediation; clean reimport,
customer compatibility and business acceptance are separate. See
[prototype output and operator wiring](docs/generated-prototype-output.md).

## [0.9.1] - 2026-11-07

- Add an explicit private-queue option to the guarded upgrade plan. Candidate
  creation and activation must agree on the exact setting; existing deployments
  without the option keep their previous behavior.
- Bind the opted-in candidate plan into the transition's checked references.
  Reject queue paths outside the dedicated private preparation namespace.
- Reuse the existing app data mount and compatible native host. No extra public
  port, mount, SSH credential, database credential or OCI resource is introduced.
- Raise the finite backup entry limit from 10,000 to 20,000 to retain accumulated
  audit history. The 128 MiB total-data, 64 MiB member and 8 MiB manifest limits
  remain in place; backups still fail closed if any limit is exceeded.

The option is deployment configuration, not proof of extraction or conversion.
The actual installed UI/native-worker journey and downstream OPAF/APEX stages
require separate acceptance evidence.

## [0.9.0] - 2026-11-07

### Server-side FMB preparation

- Add a Linux Oracle Forms adapter with headless JDAPI initialization, private
  byte-identical input copies and explicit OVERRIDDEN/ALL exports.
- Compose native extraction, effective metadata and redaction into a retained,
  hash-bound preparation result. Raw files and unredacted outputs stay private;
  source code is not executed or sent to a model by preparation.
- Add a private host queue and authenticated project upload/status/adoption
  routes. Each request binds the owner and selected source version. Unconfirmed
  submissions keep their identity; claimed jobs are never automatically replayed.
- Add raw-FMB controls to the project upload screen, with clear queued, uncertain,
  blocked and prepared states. Adding the result is explicit and does not approve
  AI processing, import an application or accept business behavior.
- Keep the secondary prepared-XML route and existing source history. A previously
  adopted result cannot falsely report that it was added to an older selection.

Verification includes local queue/native-policy regression tests, authenticated
API tests, a canonical local browser journey with a labelled synthetic native
exporter, and an actual OCI real-FMB container-to-host preparation/result check.
That real check preserved the original and independently validated the redacted
result. The source release does not establish deployed browser upload, OPAF
generation, APEX import or a downloadable converted real application.

The browser check exposed and verified a repair for strict-renderer assessment
blocking the project page after redacted-source adoption. Such sources remain
readable for prototype review; the strict generation gate remains unchanged.

Initial hosted scope is **one FMB per request, up to 20 MiB**. MMB/OLB/PLL and
linked dependency preparation are not silently included in that claim. Oracle
tools are separately installed, licensed prerequisites, not redistributed here.
See [operator setup](docs/server-side-fmb-preparation.md).

## [0.8.1] - 2026-11-06

- Package the exact native renderer, source contracts, XML dependency and
  template files into the FOX app image. An isolated projected-app check renders
  a real two-block native candidate without borrowing checkout/site packages.
- Add an operator-only protected closure for retained pre-business QA failures,
  preserving an original-state export before the append-only failed disposition.
  Pipe reads/writes and the reserved-transaction observer have explicit deadlines.
- Preserve failed outcomes and prohibit automatic retry. Closure does not claim
  technical success, human acceptance or a successful Forms conversion.

Local packaging/recovery tests and controlled Linux timeout/permission checks
passed. Installed-version and full-conversion claims still require their own
live verification; the version number alone is not deployment evidence.

## [0.8.0] - 2026-11-06

### Prepared Forms intake and prototype workflow

- Added prepared redacted XML/receipt upload without relaxing the ordinary
  data-loading filter. Exact immutable provenance is revalidated on history
  reads. Comments and processing instructions cannot hide unmasked payloads.

- Added an explicit project prototype assessment/submission path and worker
  branch, preserving the existing strict native-project route. Source versions,
  selected code units, owner permission and processing destination are bound to
  the saved job; uncertain operations are not automatically repeated.
- Added a separate native-prototype UI with readable code-unit labels, explicit
  synthetic-storage scope, refreshed consent after selection changes, and
  actionable configuration/rejection states.
- Added converter authority transport, authenticated stage routes and guarded
  runtime/export adapters. Runtime requires a real authenticated browser runner;
  missing adapters do not produce verification claims.
- Separated generated/exported output from package reimport, clean installation
  and human business acceptance. Export alone cannot mark a package verified.

Local verification includes actual authenticated upload/assessment of one approved
redacted real Forms module, unchanged source hash and all 71 code units retained;
59 prepared-source/API tests; 103 existing history/project regressions; and actual
desktop/mobile browser interaction checks with synthetic API responses. A focused
independent review confirmed the hidden-XML-content repair.

Hosted activation and a complete real-file conversion are **not yet proven**.
The processing profile, trusted converter authorization, production browser
callback and complete-package reimport remain integration work. This release
does not enable them automatically or claim a ready downloadable real application.

## [0.7.0] - 2026-11-05

### Inactive conversion-engine preview

This source checkpoint preserves verified engine work at the user's request.
It is an explicit checkpoint exception to the usual connected-feature release
rhythm: no new end-to-end UI route, hosted activation or successful real Forms
conversion is claimed. See [checkpoint limits](docs/conversion-engine-checkpoint.md).

### Added

- Paired Oracle XML effective-metadata derivation with exact identities,
  default/override provenance and original/code preservation; inherited behavior
  is not silently declared resolved.
- Conservative local redaction with exact whitespace-escape normalization,
  body-free hash receipts and fail-closed credential-command handling.
- Source-bound evidence packets, bounded linked analysis sections, full-object
  blueprint merging and separate independent-review receipt validation.
- Versioned tool-free OPAF understanding/review definitions and additive,
  guarded one-operation registration without replacing existing workflows.
- Native multi-block synthetic prototype planning/rendering, including large
  forms, source-free control display items and read-only report handling.
  Interactive-grid editing falls back explicitly to a read-only report.
- Labelled synthetic benchmark fixtures and scoring that separates valid
  structure, proposed mappings and actual business behavior.

### Verification and limits

- Real local Oracle extraction/effective-metadata checks retained all 9 blocks,
  222 items and 662 recognized objects in the primary acceptance file.
- An authored engineering candidate planned 216 fields and explicitly retained
  six unsupported buttons. Its complete APEXlang project passed actual offline
  SQLcl validation. This was not an OPAF-produced, imported or browser-proven app.
- The initial synthetic OPAF comparison recorded both model and reviewer calls;
  it exposed over-refusal, unnecessary questions and a reviewer false approval
  which deterministic validation rejected. Neither result proves universal quality.
- Original customer source, model-response bodies, credentials and lab journals
  are excluded from this release. Helper checks do not grant transfer or execution
  permission, certify complete PII detection, or record human acceptance.
- Real-file OPAF completion, connected FOX UI, unique import, runtime verification
  and exact native export/download remain pending. Unrelated recovery/transport
  work is deliberately excluded rather than published without integration proof.

## [0.6.0] - 2026-11-05

### Added

- Explicit localhost **Extract and assess locally** action for FMB and Forms
  XML. Broad, non-executing facts include all modules/blocks/items, source-bound
  identities/locations, code hashes, lexical reference candidates and findings.
  Normal quoted/numeric SQL in business code is not a blanket assessment refusal.
- Authenticated assessment jobs use the existing loopback/owner/file controls
  and single-extraction reservation. Original selections, readable output,
  assessment and original-input sidecar hashes are retained and rechecked.
  Assessment creates no ready/upload manifest and cannot authorize model calls,
  generation, import, business acceptance or legacy source handoff.
- Responsive all-block/item view, source identity and explicit **Application
  understanding: Not run**. Source tampering revokes facts; unconfirmed POST
  results are not automatically replayed. The new action requires an explicit
  server capability; older preparation remains available separately.
- Offline synthetic blueprint-evaluation fixtures/checks for future model
  comparisons. No model winner or live benchmark is claimed by these fixtures.

### Fixed

- Hosted pages no longer offer a local preparation action that cannot run there;
  both exact localhost origin and explicit server capability are required.
- Presentation accepts the exact safe wildcard locations emitted for unknown
  XML wrappers, retaining known blocks/items and their uninterpreted finding.
- Saved-history browser fixtures resolve Windows' lazy platform metadata before
  their unchanged external-action guard. Readiness now checks HTTP health/child
  exit, so a failed fixture cannot masquerade as an application login timeout.

### Verification and limits

- Actual installed Oracle extraction and the authenticated local API assessed
  two privately retained real FMBs: 9 blocks/222 items/54 triggers and 51 blocks/
  414 items/95 triggers. Originals were unchanged; only metadata was returned.
- Source/unit, API/race/tamper and canonical local browser checks use labelled
  synthetic fixtures. Browser fake-native evidence is separate from actual
  Oracle extraction proof. Desktop/mobile screenshots are retained locally.
- This is G1 of the OPAF-first goal, not complete conversion. OPAF understanding,
  model A/B inference, broader native generation and the real-file APEX export
  acceptance case remain unfinished. No customer source or credentials are
  included here. Existing hosted intake/generation gates remain unchanged.
- No model switch, cloud/database mutation, deployment or human acceptance is
  established by this source increment. Preserve earlier failed evidence and
  the retained verifier fault; do not replay it to obtain a green result.

## [0.5.0] - 2026-11-05

### Added

- Complete-conversion / partial-demo scope selection. A read-only preview lists
  included forms, omitted forms, skipped behavior and corrective actions. An
  explicit confirmation creates a separate derived source version; originals
  and their blocking findings remain available.
- Partial drafts recompose only proven table-backed fields and supplied DDL.
  Known code/library/report/control-item omissions are recorded, not executed
  or presented as translated. Missing keys, conflicting definitions, restricted
  operations and uncertain field mappings do not become invented working forms.
- Draft scope remains visible on saved project/run views, has an owner-scoped
  report download and is included as comments in packaged source evidence.
  Draft source branches are frozen: return to the original version to correct
  dependencies. Lost creation responses reconcile against the exact saved
  scope without replaying the operation.
- A separate development-draft download rechecks the existing complete native
  technical proof and returns the unchanged package bytes. It records no human
  acceptance. The accepted-package download and its human gate are unchanged.
- Contextual next actions, responsive scope cards, a configuration/service
  readiness view and APEX handoff instructions using recorded test versions.

### Fixed

- Derived draft sources fail closed if their saved scope receipt is missing,
  corrupt or belongs to a different owner. Assessment, queueing, acceptance and
  development download cannot silently reinterpret such a branch as complete.
- Clean-checkout browser regressions build the current UI in memory instead of
  depending on ignored build assets. Legacy consent checks require the actual
  stronger source-revision/current-consent and busy guards.

### Verification and limits

- Local API/storage, source-planning, normal queue-submission, exact-byte native
  release and UI regression scenarios are covered. The canonical browser path
  uses a real isolated local API and SQLite with synthetic sources and no worker.
- These checks do not establish a live OPAF conversion, real FMB/PLL extraction,
  SQLcl/Oracle execution or business acceptance. Hosted deployment and its
  retained verifier failure remain separate work; this is a source increment.
- Omitted actions are absent, not newly implemented disabled-placeholder APEX
  components. Wider native component mapping and fresh-host installation remain
  tracked in the product roadmap. No new OCI resources or dependencies added.

## [0.4.2] - 2026-11-05

### Fixed

- Native-project runtime QA now reads the unique username entry emitted by the
  generated APEX Navigation Bar, instead of requiring an account-button class
  that this template does not render.
- Account comparison remains mandatory and case-insensitive. Missing, wrong,
  empty or duplicate labels still fail; no arbitrary page text is accepted.

### Verification and limits

- 168 focused browser-adapter/project-runtime/input/profile checks passed using
  synthetic models. The real read-only APEX26.1.6 DOM observation confirmed one
  matching username entry and zero matches for the old selector, without CRUD,
  conversion or import. This is not a full runtime-QA pass.
- TypeScript/Vite, three release-API checks and release consistency passed;
  two dependency deprecation warnings remain.
- Source patch only. Earlier failed attempts are retained and unverified; no
  promotion, acceptance, replay or automatic retry is authorized by this fix.
- A fresh measured deployment and a safe failed-attempt disposition are still
  required before the corrected runtime checks can run normally.

## [0.4.1] - 2026-11-05

### Fixed

- Version-two hosted recovery plans include exact, hash-pinned admission and
  source-inventory files when they sit outside normal protected directories.
  Their parent directories are not implicitly added to the capture.
- Version-two current-pair transitions can use an explicitly pinned recovery
  helper from the new measured bundle without modifying the older installed
  source or replacing its normal module namespace. Version-one plans retain
  their original reader and field contract.
- Pure transition path contracts now remain POSIX-shaped during Windows checks.
  Offline rollback tests no longer depend on ignored private operator history.

### Limits

- This is deployment-tooling support, not a completed backup or permission to
  switch a running release. A real held operator lock, exact installation,
  stopped-writer checks, capture and isolated restore proof are still required.
- No replay, conversion, import, human-review or download gate changes. A new
  measured build is required; older images are never relabelled.
- See [recovery plan versioning](docs/deployment-recovery.md).

### Verification

- Windows deployment contracts: 64 passed, 36 platform/namespace skips;
  release API: three passed. Two dependency deprecation warnings remain.
- Linux contracts, pinned import, adapter and lease checks: 106 passed, with
  17 namespace checks separately exercised under rootless Podman: all 17 passed.
  Exact-file capture/isolated restore excludes an unapproved neighboring file.
- Frontend regression: 301 passed, including real local API/browser source and
  saved-history flows. TypeScript/Vite and release consistency checks passed.
- Local namespace fixtures do not establish a live JSN backup, database import,
  model invocation or human acceptance.

## [0.4.0] - 2026-11-05

### Added

- Saved progress and per-form responses on every project output, available after
  reopening the project. Original form/source labels are derived from each
  validated retained run, never borrowed from a newer source version.
- Read-only status checking on normal saved-run views as well as attention
  states. Viewing history does not replay conversion, import or human review.
- Explicit unavailable original-label and malformed-detail handling. Saved
  checkpoints are not presented as proof of a live process.
- Real local API/browser coverage of reopening an output and renaming its source
  without changing retained work or granting acceptance/download.

### Limits

- No new behavioral translation or import/verification/review permissions.
  Generated per-form output remains separate from complete-project technical
  checks and genuine human acceptance.
- Source release only. Local tests use synthetic Oracle/OPAF transports, not a
  live database import or runtime proof. See [saved history](docs/saved-run-history.md).

### Verification

- Clean-source Windows backend: 331 passed, two explicit POSIX-only skips.
  Native Linux retained-history/package-reader checks: 138 passed.
- Frontend: 301 checks passed, including a real local API/SQLite browser flow
  that reopens output, renames selected source and preserves the original run.
- TypeScript/Vite build and release consistency passed. Desktop/mobile renders
  were inspected. Two dependency deprecation warnings remain.
- External Oracle/OPAF transports in package fixtures are synthetic. No live
  import, model invocation, runtime APEX proof or human acceptance is claimed.

## [0.3.0] - 2026-11-05

### Added

- Grouped source requests across Forms, retaining every assessed caller and
  keeping schema-qualified objects separate.
- Specific missing package-part and unconfirmed-routine actions, copyable
  owner/DBA requests and a source-version-bound request download.
- A same-project add-source path with reassessment. Source availability is
  explicitly distinct from translated behavior and conversion readiness.
- Desktop/mobile coverage of real local API upload and reassessment, with
  stale request exports rejected after a source change.

### Limits

- No expansion of behavioral translation or relaxation of conversion, import,
  technical-verification or human-review gates. Raw binaries still require
  supported Oracle preparation. See [source requests](docs/source-requests.md).
- Request grouping summarizes assessed dependencies; it does not guarantee that
  every runtime dependency is discoverable. Incomplete/oversized lists retain
  detailed findings rather than reporting confirmed zero requests.
- Source release only; this entry is not an installed release or Oracle
  conversion claim. Verification receipts are recorded with the increment.

### Verification

- Clean-source backend regression: 195 tests passed. Focused Linux assessment
  and request checks: 32 passed. Two dependency deprecation warnings remain.
- Frontend presentation, source-history and request checks: 293 passed,
  including a real local API/SQLite upload and reassessment browser scenario.
- TypeScript/Vite build and release consistency checks passed. Desktop/mobile
  screenshots were visually inspected; no Oracle/model call or human business
  acceptance was performed. The source-history test harness now includes the
  release panel added in 0.2.0.

## [0.2.0] - 2026-11-05

### Added

- A version and **What changed** panel in both workspace layouts.
- A public, read-only software identity endpoint shared with health reporting.
- Clear UI/server mismatch and unavailable-status messages, with a read-only retry.
- A canonical software release manifest and consistency checks for package and
  changelog versions. No extra runtime service or dependency is required.

### Limits

- Experimental source preview. This increment does not expand conversion coverage
  or certify a target database, native runtime flow or customer installation.
- Generated APEX, technical verification and human business acceptance remain
  distinct; no import, verification or download gate is relaxed.
- UI notes identify the loaded UI release. A different/unconfirmed server is
  explicitly labelled; publishing this version does not update a running host.

### Verification

- Clean-source API, submission gates, health and packaging: 102 tests passed;
  two explicit skips and two dependency deprecation warnings remain.
- Release presentation: four focused checks passed. TypeScript/Vite build passed.
- Headless desktop/mobile product-flow scenario passed with synthetic API only;
  release-note screenshots were visually inspected. No live conversion, Oracle
  connection or human business acceptance was performed by these checks.

An optional skip is not a pass or an installed-flow claim. Cloud activation and
installed native-output evidence are separate from this software increment.

## Earlier experimental source

Packages previously reported `0.1.0` without a FOX release changelog. Existing
history is preserved; this file does not retroactively call those commits
versioned, deployed or technically verified releases.
