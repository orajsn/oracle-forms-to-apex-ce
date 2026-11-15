# FOX deployment tools

These revisions apply only to independently pinned deployment tools outside the
measured application bundle. They do not rename or replace a FOX application
release, image, installation or historical inspection.

## [0.2.2] - 2026-11-15

- Rebind the unchanged controller and cutover tool to FOX 0.24.2, which corrects
  producer-specific JSON serialization checks in the bundled completed-host reader.
  This increment changes the tested-bundle declaration, not controller behavior.
- Preserve the published 0.24.1 package and its never-activated installation.
  Require a new measured build and fresh held baseline; diagnostic overlays are
  not installation, maintenance or activation authority.

Verification: 91 focused host cases and 359 clean-source checks passed (5 skips).
The complete read-only diagnostic passed against retained real lab evidence using
an explicitly identified corrected-reader overlay; all measured data remained
unchanged. Actual coherent deployment, UI download and exact-byte reimport remain
separate acceptance steps.

## [0.2.1] - 2026-11-15

- Accept versioned mixed inert baselines only when each completed native
  prototype has exact reviewed, validated, runtime-tested and exported evidence.
  Preserve old failures, original producer identities and historical timestamps.
- Bind completed staging and browser-evidence trees without deleting, moving,
  replaying or changing their acceptance. Unexpected or changed members reject.
- Give stopped technical readers an explicit verified release-root/inventory
  binding. Running readers continue to use the actual image source closure.
- Require the matching FOX 0.24.1 bundled readers. This tool release retains
  ordinary strict admission, backup/restore and readiness checks; native-mode
  completion still does not claim strict-output or business acceptance.

Verification: 47 materialized-layout checks passed; host/controller regressions
passed 573 tests and 48 subtests, with 5 platform skips. Clean staged-source
integration passed 858 tests and 48 subtests, with 11 skips. A read-only check
against the retained real lab job passed without changing its package, original
source or job files. That diagnostic is not a maintenance baseline, cutover,
hosted UI download or fresh-ID import proof. Actual deployment remains separate.

## [0.2.0] - 2026-11-15

- Add the explicit schema-2 mode `native-prototype-strict-stopped-v1`. Its exact
  plan digest binds the choice. Schema 1 and the default strict path are unchanged.
- Require a fresh inert preservation baseline and the configured prototype
  authority. Retain the ordinary backup, isolated restore, old-data preservation,
  pair checks, source admission, readiness and HTTPS checks.
- Keep the strict verifier enabled but stopped with a clean exit. Do not start it
  or claim a first-idle witness in this mode. Native per-job review, validation,
  import, runtime and download gates remain separate and unchanged.
- Under the existing old lease, bootstrap only genuine `release.json` and
  `worker.lock` metadata for the new release. Reject collisions, drift or extra
  members; create no session, claim or job. Preserve this metadata through HTTPS
  release so a subsequent upgrade can acquire its real lease.
- Use a distinct native completion that explicitly denies strict accepted output,
  canonical strict completion, conversion success and human acceptance. Pin this
  tool separately from the unchanged verified FOX 0.24.0 bundle.

Verification: private candidate checks passed 192 tests with 3 platform skips,
including actual local journal locking and subsequent lease acquisition. Default
strict-method AST fingerprints are pinned to the prior published controller.
Clean public integration passed 193 tests with 3 platform skips. Actual native
upgrade remains a separate acceptance step. No hosted upgrade, model call or
completed Forms conversion is claimed.

See [native operating mode](NATIVE_MODE.md) for the boundary and required evidence.

## [0.1.1] - 2026-11-15

- After the existing single TLS start, allow bounded read-only warm-up checks.
  Retry only connection refused/reset/aborted/timeout and HTTP 502/503. Never
  repeat the service action or accept a late result beyond the monotonic budget.
- Preserve certificate/hostname validation, no proxy or redirects, the exact
  HTTP 200 FOX response and explicit healthy/enabled worker checks. Authentication,
  certificate, redirect, malformed JSON and wrong-service responses fail immediately.
- Add a bounded optional timeout to the existing public checker, retaining its
  no-argument behavior and return shape. Pin both tools together in a fresh plan.
- Keep the measured FOX 0.23.2 bundle unchanged; these tools are outside its
  runtime inventory and archive. A new inspection and actual activation are required.

Verification: 47 focused local tests passed. Related deployment regressions:
235 passed and 53 skipped (49 platform/POSIX/rootless/symlink prerequisites and
four retained-lab fixtures). AST checks preserve the original apply method except
the health-call substitution. No live controller or Forms conversion pass is claimed.
A separate recovery observed connection refused on its first health read and a
healthy response on its second; the earlier masked failure is not reclassified.

## [0.1.0] - 2026-11-11

- Include the already-measured `fox_source_contract` package in the isolated
  transition proof loader. Require all four modules and exact canonical mirror
  hashes; do not add an ambient import-path fallback.
- Preserve physical module-origin checks and every source, review, lease,
  validation, import and no-replay boundary.
- Tested against the FOX0.21.5 application bundle recorded in `RELEASE.json`. Existing
  application images and installation remain unchanged. Use a new controller
  hash, tool directory, transition plan and inspection before activation.

Verification:110 focused Linux tests passed without skips, including22 isolated
loader/missing-member/tamper/origin checks. A broader Linux run had123 passes and
11 failures caused by an absent private-profile fixture before transition logic;
it is not an entirely passing suite. Windows nearby tests had122 passes/12 skips.

The corrected pure read also reconstructed a retained real draft on the existing
lab host. Before/after job trees matched; no model, SQLcl, Oracle, conversion or
import was invoked. This is not a successful transition or completed APEX flow.
