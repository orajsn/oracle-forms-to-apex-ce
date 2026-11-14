# FOX deployment tools

These revisions apply only to independently pinned deployment tools outside the
measured application bundle. They do not rename or replace a FOX application
release, image, installation or historical inspection.

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
