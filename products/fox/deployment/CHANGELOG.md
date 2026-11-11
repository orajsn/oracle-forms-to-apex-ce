# FOX deployment tools

These revisions apply only to independently pinned deployment tools outside the
measured application bundle. They do not rename or replace a FOX application
release, image, installation or historical inspection.

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
