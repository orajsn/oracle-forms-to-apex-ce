# FOX user flow

One project represents one application being modernized. Upload related modules
and their readable dependencies into that project; create separate projects for
separate applications. Selected supported forms become pages in one APEX app,
not one unrelated app per uploaded file.

1. **Create project.** Give the application a recognizable name.
2. **Prepare and upload.** Convert raw Oracle binaries with approved local Forms
   tooling. Upload redacted XML/text, library source and table/package definitions.
3. **Resolve findings.** Review each module, missing object and unsupported
   construct. Supply missing files. When human interpretation is needed, the
   affected conversion stops with a specific decision rather than inventing it.
4. **Process.** In a connected installation, embedded OPAF mapping and independent
   review feed deterministic APEX generation and SQLcl validation. Local assessment
   mode does not offer this connected action.
5. **Review results.** Inspect per-form traceability, exceptions and target
   requirements. Generated, technically verified and business accepted are
   separate states. An error is not an invitation to click Process repeatedly.
6. **Download.** Obtain the exact eligible package, native APEX SQL/APEXlang,
   schema requirements and remediation evidence according to the release gates.
   Import only into a compatible, approved non-production target.
7. **Validate behavior.** A genuine business reviewer decides whether the
   application behaves as intended. Technical verification cannot accept it.

Source edits create a new source version. Previous runs and artifacts remain
bound to their original source hash; they do not silently become current.

The initial native profile is deliberately narrow: one table-backed block per
form, explicit identity primary key, 2–20 NUMBER/DATE/VARCHAR2 columns and
report/search/insert/update pages. The intake budget is 50 readable files and
300 KB total, including dependencies/DDL, not 50 forms plus unlimited assets.
Navigation order does not prove the original business process. Reports, complex
LOVs, libraries/triggers, master-detail and external calls may need remediation.

No universal import or behavioral-equivalence guarantee is made. Never upload
credentials, production records, customer identifiers or restricted material.

## When technical checks need attention

The updated workbench keeps **APEX generated** distinct from technical
verification and human acceptance. If the managed verifier reports attention,
or its status/contact cannot be established, the technical-check step no longer
appears to be actively progressing. The saved generated output remains visible;
review and download do not become available without their required evidence.

Use **Check run status** to refresh the existing result. This is read-only: it
does not submit another conversion, select sources, retry SQL/import, or accept
anything. Give FOX support the run ID. Do not create a new run to bypass an
uncertain result. A retry or continuation needs a separately established safe
operator path; no QA tools are exposed to business users.

This clearer failure presentation has passed desktop/mobile isolated browser
tests in source. It has not yet been activated in the existing lab. The lab's
first multi-form trial is generated but not technically verified because its
converter lacks the shared QA module; the original failed observation remains
retained. Source publication does not establish end-to-end readiness.
