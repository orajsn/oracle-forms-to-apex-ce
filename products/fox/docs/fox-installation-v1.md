# Install the FOX development preview

This source snapshot has two different routes. Windows local preparation and
assessment can run independently. Connected conversion uses the guarded JSN lab
adapter; a supported fresh customer installer is not yet complete. The CE
repository's root `install.py` installs the CE skill, not FOX.

## Guided setup preview on Linux

From `products/fox`, run `bash scripts/install-fox.sh`. The launcher handles the
private setup interpreter and XML dependency, then enters the browser wizard.
The initial download needs the operator's consent; a verified existing cache is
rechecked without downloads. System Python and project data are unchanged.
The [runtime guide](managed-setup-runtime.md) covers inspection, explicit
unattended preparation, fixed offline artifacts and interruption handling.

The wizard also saves [protected access/OPAF inputs](installer-connections-step.md)
for the registered JSN synthetic-test target. This is real local configuration,
not connectivity testing, password rotation or customer target onboarding.

This implements the wizard runtime, storage and input phases, not complete connected
installation. No successful exit or page view means the product is installed.
The basic OS bootstrap Python is provided by the supported Linux baseline;
end users do not configure it, install pip packages or run setup themselves.

## Local assessment on Windows

Before changing a selected installation directory, the product-root setup helper
offers read-only discovery. From `products/fox`, using the selected Python:

```text
<python> scripts/fox-setup.py inspect --installation-root <selected-directory>
```

It distinguishes a missing/empty path, a source checkout, the separate CE skill,
assessment metadata and retained deployment state. It creates nothing, does not
start FOX or open a database/credential, and reports only closed status/action
codes. It inspects the selected directory only, not the entire machine. Exit 0
means observation succeeded, never installation or conversion readiness. Existing
state still requires its actual route's ownership/runtime checks. Full connected
installation and its wizard are not released by this discovery increment.

The setup helper also exposes a developer-only [single-folder storage
phase](installer-storage-step.md). It derives the private internal locations
from one folder and reuses the existing S0 initializer. It is not the complete
connected installer: even a completed storage phase remains `NOT_INSTALLED`.

The same storage phase now has a real [browser setup wizard](setup-wizard.md):
`<python> scripts/fox-setup.py setup` on nonroot Linux. Choose the instance
folder, review its actual plan and confirm it in the browser. Internal roots
and hashes stay behind the UI. The remaining connected phases are explicitly
unfinished; this is not yet the full customer installer.

Prerequisites: CPython 3.12, PowerShell and Node/npm compatible with the checked-in
lockfile. Use a short, private checkout path. From `products/fox/fox`:

```powershell
py -3.12 -m venv .venv
# Stop if this or any subsequent command fails. Preserve an existing environment.
.venv/Scripts/python.exe -m pip install -r requirements-lock.txt
npm ci
npm run build
./scripts/start-local.ps1 -Port 8100
```

Dependency installation and a source build require the operator's approval.
Never overwrite an unrelated environment. Choose the password at the protected
prompt. The default new-session username is `fox-local`; use the effective name
printed by the launcher. Open `http://127.0.0.1:8100`, not a public listener.

Check `/api/health`, sign in, create a project and assess readable XML/text/DDL.
The local worker and connected conversion are deliberately disabled. A READY
assessment is not a generated APEX application. This is one operator identity,
not customer tenant/user administration.

Stop with Ctrl+C in the launcher's terminal. Preserve the printed session ID,
password and private `work/local-assessment` directory. Resume the same session:

```powershell
./scripts/start-local.ps1 -Port 8100 -ResumeSession 'session-<exact-saved-id>'
```

Do not edit markers, remove locks or select the newest folder to recover state.

## Raw Forms preparation

Oracle Forms Builder/Forms2XML and compatible Java are separately installed,
licensed prerequisites, not bundled binaries. Supply verified absolute tool paths
to the launcher with `-OracleHome` and `-JavaExe`. FMB/MMB/OLB use Oracle's XML
conversion tooling; PLL requires an authoritative readable library extraction.
Printable strings from a binary are not source. Review the output before upload.

Without these tools, use approved preconverted XML/PLD/SQL. Keep raw binaries
local. No production database or customer records are needed for the prototype.

## Connected conversion

The supplied deployment/operator code contains an explicit existing-lab guard.
Non-secret lab identifiers and TLS/workflow fingerprints are scope references,
not portable defaults. Never substitute another target to bypass a guard.
Historical deployment receipts and secrets are intentionally absent.

A connected installation needs matched FOX/converter/operator source and images,
OPAF model/reviewer definitions, protected secret references, internal authenticated
MCP, a compatible APEX/SQLcl target, persistent journals, admission, and actual
synthetic end-to-end proof. An empty installation cannot copy old lab history or
manufacture a retirement record. Fresh-runtime helper modules are development
work, not a released installer. Stop when that route is requested but unavailable.

See [architecture](architecture.md), [operations](operations.md) and
[verification](verification.md). The optional installation skill is maintained in
`fox/skills/fox-install`; it is not a runtime dependency or deployment authority.
