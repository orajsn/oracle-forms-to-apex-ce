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
