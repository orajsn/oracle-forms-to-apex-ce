# Install the FOX development preview

This source snapshot has two different routes. Windows local preparation and
assessment can run independently. Connected conversion uses the guarded JSN lab
adapter; a supported fresh customer installer is not yet complete. The CE
repository's root `install.py` installs the CE skill, not FOX.

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
