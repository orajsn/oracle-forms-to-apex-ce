# FOX user flow

One project represents one application being modernized. Upload related modules
and their readable dependencies into that project; create separate projects for
separate applications. Selected supported forms become pages in one APEX app,
not one unrelated app per uploaded file.

1. **Create project.** Give the application a recognizable name.
2. **Prepare and upload.** In a hosted installation with its Forms worker
   configured, choose **Forms FMB file**, **Prepare FMB**, then **Add prepared
   form to project**. Extraction runs on the server; the browser does not need
   Forms Builder. The current hosted route accepts one FMB per request, not a
   complete library/menu bundle. Other modules can use the separate supported
   preparation path and readable-source upload. See
   [server-side FMB preparation](server-side-fmb-preparation.md).
3. **Resolve findings.** Review each module, missing object and unsupported
   construct. Supply missing files. When human interpretation is needed, the
   complete conversion stops with a specific decision rather than inventing it.
   For an early demo, use **Convert → Partial draft / demo** to preview and
   explicitly omit unsupported behavior; see [partial drafts](partial-drafts.md).
4. **Process.** In a connected installation, embedded OPAF mapping and independent
   review feed deterministic APEX generation and SQLcl validation. Local assessment
   mode does not offer this connected action.
5. **Review results.** Inspect per-form traceability, exceptions and target
   requirements. Generated, technically verified and business accepted are
   separate states. An error is not an invitation to click Process repeatedly.
6. **Download.** For a generated prototype, use **View prototype output** and
   **Download generated prototype** when its validation, import, runtime and
   export evidence pass. This does not claim an independent reimport or clean
   installation of the final package. The stricter **Download development draft**
   path requires its normal technical proof; accepted-package download additionally
   needs genuine human review. Each package includes its applicable target and
   schema requirements. See [generated prototype output](generated-prototype-output.md).
   Import only into a compatible, approved non-production target.
7. **Validate behavior.** A genuine business reviewer decides whether the
   application behaves as intended. Technical verification cannot accept it.

Source edits create a new source version. Previous runs and artifacts remain
bound to their original source hash; they do not silently become current.

For complex forms, the authenticated localhost app now offers **Extract and
assess locally**. This inventories all FMB/XML blocks and code metadata even
when ordinary business SQL does not fit the old conversion recipe. It stays
local: no project source handoff, OPAF call or generation occurs. See
[broad local assessment](broad-local-assessment.md) for the precise boundaries.

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
uncertain result. Where **Check repair plan** offers **Review saved mapping
again**, FOX has identified a specific invalid AI review response. It preserves
the mapping and requests one new independent review with fresh processing
confirmation. See [review-scope correction](review-scope-correction.md). Genuine
semantic rejection and unknown operations do not become approvals. Other failures
still need their applicable recovery path; QA tools stay outside the business UI.

If **Review recognized names and continue** appears, FOX found column names
already stored in the original Form but missed by the older analysis. You do
not need to upload another file for that naming issue. The panel separates
unchanged saved sections, mappings needing a fresh review, and sections not yet
started. Confirm the displayed processing scope to continue the same run.
FOX preserves the original mappings and reviews; it does not repeat completed
mapping calls or turn an old negative review into an approval. Further processing
requires fresh independent approval and the usual APEX validation. If submission
is uncertain, check the existing run rather than submitting again. This bounded
repair does not resolve missing business logic, libraries or database definitions.

Check the installed version and the evidence for the selected run. Local tests,
source publication and a healthy deployment do not establish end-to-end conversion
readiness. Earlier failed observations remain in run history.
