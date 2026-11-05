# Broad local Forms assessment

FOX0.6.0 adds the first part of the OPAF-first conversion path: observe the whole
source before deciding how to design an APEX application. It is not broad native
conversion, an AI review, or permission to submit the source to a provider.

## User path

1. Start the supported authenticated localhost assessment application with the
   configured Oracle Forms backend. The hosted page is not an extraction worker.
2. Create/open a project, then open local preparation. Select the FMB or readable
   Forms XML. Related files may be included but are explicitly unassessed by this
   action unless they are FMB/XML.
3. Choose **Extract and assess locally**. Installed Oracle tools extract FMB
   binaries; the pure parser inventories the resulting XML without executing it.
4. Inspect all observed blocks/items, source locations, trigger counts and review
   requirements. Full code/reference metadata is retained in the local assessment
   artifact; the screen does not yet display individual code/reference rows.
   Original and extracted identities are separate.
5. **Application understanding: Not run** means exactly that. The local facts
   have not added sources to the current project or run OPAF. The original
   prepared-set route remains separate and retains its existing eligibility rules.

No arbitrary path/command or backend can be selected over HTTP. Local peer,
Host, Origin, authenticated owner, file count/size and safe basename checks apply.
Missing tooling, malformed/unsafe source and suspected secrets remain controlled
failures. Ordinary SQL/PLSQL constants do not prevent non-executing XML facts.

## Evidence, not assumptions

- The portable pure facts reader is `fox/forms_facts.py`. It returns source hash/
  byte identity, stable element locations/IDs, objects, blocks, items, code metadata,
  links, dependency candidates and findings. It returns no code bodies or arbitrary
  property values and does not execute SQL, callbacks or model requests.
- A data/control classification is stated only from explicit supported source
  metadata. Missing values, dynamic targets and unsupported XML stay unknown.
  A candidate reference is not proof a database object exists or was supplied.
- Assessment jobs retain original selections and readable bytes privately. Exact
  assessment/input-sidecar/original/readable hashes are checked before serving
  facts. Changed bytes revoke availability; unknown request outcomes do not cause
  automatic retries. Never reuse a changed artifact to certify current sources.
- The UI lists every observed block, not a chosen single-block template. Unknown
  wrappers retain known objects and explicit uninterpreted-element findings.

Private local artifacts contain source. Do not publish them or treat the absence
of a detected secret as redaction/processing approval. Raw files remain local.

## What is not finished

The next phase will send approved relevant evidence to a versioned OPAF
understanding/review workflow and validate its blueprint against these facts.
The broader native generator, exact real-source APEX package proof and guarded
hosted rollout are still required. These are not implied by a parser pass or
the offline synthetic blueprint evaluator. The existing narrow native conversion
profile and hosted DML eligibility checks have not been silently weakened.

Normal Forms FMB/MMB/OLB/PLL preparation remains documented separately. This
explicit assessment action initially inventories FMB and Forms XML; it does not
claim related library or report source was understood because a file is present.
