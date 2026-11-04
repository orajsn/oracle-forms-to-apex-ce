# Dependency guidance: source and UI slice

Implemented in source on 4 November 2026. This document is not a live-deployment
or full Forms-to-APEX readiness receipt.

## Business-user experience

For supported static references FOX now shows:

- The original source file and known form/block/item or button/trigger/program
  ancestry. Unknown parents are not invented. A code-relative line is explicitly
  distinguished from an XML file line number.
- The referenced package and routine, or referenced Forms module.
- Which package parts are missing: specification, body, or both. Instructions
  name the object and acceptable .pks/.pkb/readable SQL formats, not a fictitious
  filename the user must already possess.
- Why the finding matters, who can help and a source-bound Add requested files
  action. Files are added to the same project and reassessed as a new version.
- Separate source availability and lexical routine-declaration evidence.
  Package files being present does not mean the required routine was found,
  compiled, signature-checked or translated into supported APEX behavior.

The Review forms view contains a dependency card; Resolve includes the same
known source path, impact and next action. Existing consent, conversion,
technical verification and genuine human acceptance gates remain separate.

## Parser boundaries

The scanner retains distinct calls from different buttons/routines instead of
collapsing every reference to the same package. Same-length PL/SQL masks avoid
counting calls/declarations inside comments, string literals or q-quoted
strings, and retain line offsets. Schema-qualified package candidates keep
their qualifier. This is a bounded static candidate scanner, not a complete
PL/SQL parser, compiler, dependency-completeness proof or runtime resolver.

Routine declaration candidates are checked in both supplied package parts.
Module-local declarations remain scoped to the current FormModule. Unknown or
complex declarations stay unconfirmed; they are not labelled converted or
guessed. Overloads, signatures, implementation validity, duplicate/conflicting
package definitions and dynamic references require further supported analysis.
Quoted identifiers and sophisticated PL/SQL name resolution are not claimed.

The native table-form profile still does not translate arbitrary custom
package calls or button/trigger behavior. A source-resolution success must
therefore expose any remaining mapping limitation. Do not generate a fake
success by treating declarations as working business logic.

## Oracle built-in recognition

Thirteen FTREE routine names were verified against the installed Oracle Forms
14.1.2 Form Builder Help: `forms/doc/US/fmdevhlp/f1_help.jar`, including topics
`builtd_f/find_tree_node_built_in.html` and
`builta_c/add_tree_node_built_in.html`. FOX no longer asks for a custom FTREE
specification/body for these calls. An unknown FTREE member gets an explicit
version/member-confirmation action instead of a fictitious file request.
Tree behavior remains unconverted remediation, not an automatic APEX mapping.

The catalog is deliberately limited, not a claim to classify every Oracle
built-in or customer package. The installed help remains an Oracle prerequisite;
it is not redistributed in this repository. Oracle identifies Form Builder
Help as an application-development reference on its
[Forms product page](https://www.oracle.com/application-development/technologies/forms/forms.html).

## Verification

Backend tests exercise exact object location, partial package availability,
wrong routine declarations, comments/strings, separate call sites, schema
qualification and the limited built-in behavior. An actual isolated FOX API
test uploads a missing body into the same project, obtains a changed source
version, clears the missing-source finding and retains the unsupported behavior
finding without creating a run, calling a model or recording acceptance.

React contract/render tests consume the real Python assessor's synthetic
output. The opt-in browser scenario renders the actual workbench at desktop
and 390px widths, follows Add requested files, uploads a synthetic body and
shows the new declaration result without allowing generation. Browser response
handling is simulated; the API/storage test is separate. No browser UI proof
here is a hosted, Oracle, model or end-to-end conversion proof.

```text
cd fox
python -B -m pytest tests/test_dependency_guidance.py tests/test_dependency_guidance_api.py
node --test tests/test_project_workbench.mjs
npm run build
```

The normal UI test skips its browser scenario unless an operator explicitly
enables `FOX_UI_BROWSER=1`, supplies an existing Playwright package directory
through `FOX_TEST_NODE_MODULES`, and selects a new workspace-relative
`FOX_UI_ARTIFACT_DIR`. It uses installed Edge with no network or live target.
It installs nothing. These commands are developer QA, not business-user steps.

## Remaining delivery work

G3/G4 are in progress, not complete: broader built-in/version coverage, full
routine/signature resolution, dynamic-reference analysis and supported business
code conversion remain separate work. The hosted verifier/target-version
recovery, newly measured paired rollout and actual native APEX output proof
are still required. Preserve all interrupted jobs and immutable evidence; do
not hot-patch frozen code or replay uncertain imports to deploy this UI change.
