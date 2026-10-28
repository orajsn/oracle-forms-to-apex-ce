# Guided FOX setup: implemented storage phase

The administrator can now start a real browser wizard through the same setup
entry point, using the supplied source and an isolated supported Python on
nonroot Linux:

```text
<python> scripts/fox-setup.py setup
```

The launcher prints a literal loopback URL with an automatically selected port
and a private setup code. Open that URL and enter the code, choose an instance
folder, review the plan, and confirm storage preparation. No manual construction
of internal roots or hash documents is needed in the browser. If the server is
remote, use an explicitly approved loopback access method; do not expose this
administrative listener publicly. An optional `--port` chooses an unprivileged
loopback port, not a bind address.

The code expires after 30 minutes, stays in page/process memory and is not a
URL parameter, browser-storage item, application password or database secret.
Run setup interactively, not under a service that records its bootstrap output.
Restarting produces a new code, not new application storage. Stop the launcher
with Ctrl+C. The wizard never starts the conversion service or an Oracle/model
connection. It is not the public business-user interface.

## What works

- Review preflights the selected parent and source-bound plan without writes.
- Confirmation invokes the existing single-folder/S0 initializer.
- A repeated HTTP approval cannot resubmit a known action or failed attempt.
- Recheck performs genuine read-only storage inspection. Unknown outcomes and
  partial writes stay visible and are never automatically replayed.
- A restarted wizard can inspect the exact completed storage phase instead of
  initializing it again. Unknown directories are not adopted.
- The UI shows readable status and next actions, with diagnostic codes for the
  operator. Dynamic text uses `textContent`, never supplied HTML.

The listener binds only `127.0.0.1`. State requests require the private setup
code; writes additionally require the exact local Origin and Host. Request
sizes, headers and body reads are bounded, and arbitrary files/paths are not
served. A single request handler serializes phase changes. No credentials or
request parameters are written to access logs.

## What remains

The interface visibly distinguishes storage from connections, services and
verification. The latter phases, the managed runtime bootstrap/distribution,
Oracle tooling/worker setup, complete fresh admission and full multi-form APEX
journey remain unfinished. **Storage prepared is not FOX installed or
conversion-ready.** This is development source, not a customer installer release.

The operator skill calls this real entry point only within the approved route;
it must not claim successful installation because a wizard page opens. The
[storage contract](installer-storage-step.md) and existing fresh runtime gates
remain authoritative.

## Developer checks

`tests/test_fox_setup_wizard.py` exercises genuine loopback HTTP plus nonroot
storage and CLI startup/shutdown. `tests/run_setup_wizard_browser.mjs` uses an
already-installed Playwright/browser and an explicit isolated Python. It runs
against `tests/serve_setup_wizard.py`, retains synthetic state/screenshots, and
closes its owned listener through stdin. It performs no Oracle/model calls.
See the verification guide for optional browser-test environment settings.
