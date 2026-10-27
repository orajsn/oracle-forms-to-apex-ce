# Development snapshot checks — 27 October 2026

Checks were run against the exported public subtree, using existing isolated
Python 3.12.14/pytest 9.1.1 and a new lockfile-installed UI dependency directory.
No cloud conversion, customer source, live APEX import or human acceptance was
performed by these checks.

- Pure source-contract mirror: CURRENT, exact byte hashes matched.
- Selected Python project plan/API/native renderer/source-binding suite:
  **167 passed**. Test storage was isolated; external integration settings cleared.
- Existing-lab transport unit suite after home-relative path sanitization:
  **23 passed**, external OCI/SSH/DPAPI boundaries mocked.
- TypeScript check and Vite production build: **passed**. Generated distribution
  and dependency installations are not committed.
- UI producer/presentation/render contracts: **70 passed, 2 opt-in browser cases
  skipped**. This is not a headless-browser or live runtime proof.
- Synthetic package/runner-input binding suite after four reviewed JSON
  fixtures were included: **43 passed**. ZIPs and credential values are authored
  in-memory test data, not real run evidence or account credentials.

The initial Python run lacked a parent scratch directory; the corrected run
used a separate existing scratch parent. The first UI run lacked checkout-local
dependencies; the lockfile installation corrected that prerequisite. A broader
QA parser test then identified four omitted synthetic JSON fixtures; their
reviewed inclusion and separate rerun passed all 43 cases.
Original failure records are retained privately, not erased.

The source review checks staged bytes for forbidden private/generated paths,
known private/customer markers, high-confidence credential patterns and Python
syntax. These checks are not universal secret detection or a complete code audit.
Original CE files are byte-preserved except the intentional README navigation.
Existing trailing blank lines in byte-sensitive APEX resources are preserved;
they are not normalized merely to satisfy whitespace style checks.

The complete developer/integration suite is not claimed to pass in an empty
checkout: some tests depend on Oracle tools, approved lab settings or protected
historical evidence. Fresh connected installation and shipped multi-form
conversion/import/browser/recovery acceptance remain incomplete release gates.

## Cutover lease-latency correction

The controller now relies on the real `CaptureAuthority.require_active()` to
validate its exact owning context once at each boundary, instead of immediately
repeating that same expensive history read. Type/source/owner checks and the
30-second stop window remain unchanged. Synthetic virtual-time regression
proves a 16-second delegated read reaches dispatch in time, a late stop is still
rejected and a failed lease cannot dispatch. Windows controller regression:
108 passed/48 platform skips; the three focused cases also passed on Linux.
External transport/service effects are synthetic in these tests. This code
correction does not itself establish a successful live cutover.

## Retained pre-profile history

An older complete legacy snapshot may lack `conversion_profile`. The original
application's legacy default is now checked without rewriting that snapshot:
exact old schema, source hashes/byte counts, manifest, terminal run identity and
every retained source row must match the read-only SQLite record. Unknown or
incomplete records, active runs, project fields/markers and mismatched sources
still reject. This grants no processing, import or business-acceptance authority.

The development checkout's selected controller matrix passed Linux **162/16
skips** and Windows **108/70 skips**, over 178 cases. The public checkout passed
Linux **158/20 skips** and Windows **104/74 skips**: four retained-lab-manifest
cases additionally skip because private history is intentionally absent. The
22 real POSIX legacy-v0 file/SQLite cases passed in both Linux checkouts.
Platform-dependent/rootless coverage remains qualified; these unit results are
not live activation or generated-application acceptance.
The fixed source scan also passed an actual read-only lab check without changing
the original snapshots or database. Existing G containers and app evidence remain
separate from the new product's pending end-to-end acceptance.
