# FOX changelog

FOX software versions use `fox-v<major>.<minor>.<patch>` Git tags, separate from
the CE repository's tags. A source release is not proof of deployment or a
successful conversion. See [release policy](docs/release-policy.md).

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
