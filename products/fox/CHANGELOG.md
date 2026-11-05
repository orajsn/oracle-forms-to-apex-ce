# FOX changelog

FOX software versions use `fox-v<major>.<minor>.<patch>` Git tags, separate from
the CE repository's tags. A source release is not proof of deployment or a
successful conversion. See [release policy](docs/release-policy.md).

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
