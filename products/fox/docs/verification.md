# Source verification

Clean transport regression is in `qa/operator/tests/test_fresh_clean_transport.py`,
alongside `test_clean_install.py`, `test_project_clean_install.py` and
`test_project_clean_operator.py`. The last uses the real project package/plan/SQL
components with synthetic SQLcl responses. The host transport uses actual private
source/storage with synthetic IMDS/Podman/child boundaries. These are not live
Oracle imports or actual container execution. Read the
[transport scope](fresh-clean-transport.md); a compiled program is not admission.

The fresh queue component and legacy queue regression can be tested with the
selected isolated interpreter:

```text
<test-python> -I -B -m pytest -p no:cacheprovider qa/operator/tests/test_fresh_queue.py qa/operator/tests/test_product_queue_transport.py
```

Its real S0/F/SQLite cases require nonroot Linux and skip on Windows. Normal
component cases use synthetic admission records and explicit future-authority
placeholders, not genuine host admission. The generated helper uses the actual
queue/fence code; this is not a full container wrapper or connected install test.
Read [fresh queue scope](fresh-queue-transport.md). Test scratch is independent
of a private development `work` folder or venv. Dependencies must already be
installed in the selected isolated test environment; these tests install nothing.

Run commands from `products/fox`. These tests are offline/local checks; they
do not contact a live APEX target, certify Oracle compatibility or accept a
business process. Use an isolated environment with the pinned application
dependencies and an approved pytest installation. Do not use system Python.

```powershell
$env:PYTHONPATH = '.;fox;converter'
$env:PYTHONDONTWRITEBYTECODE = '1'
fox/.venv/Scripts/python.exe -B tools/sync_fox_source_contract.py --check
fox/.venv/Scripts/python.exe -B -m pytest -p no:cacheprovider `
  fox/tests/test_project_conversion.py fox/tests/test_project_api.py `
  converter/tests/test_native_project.py converter/tests/test_project_source.py
```

On Linux use the selected isolated interpreter and `PYTHONPATH=.:fox:converter`.
The canonical FOX test fixture clears inherited integration settings and creates
new test storage. Tests may create ordinary scratch state; they are not a
read-only production diagnostic.

UI source checking/build runs from `fox` with the committed lockfile:

```text
npm ci
npm run build
node --test tests/test_project_workbench.mjs tests/test_project_main_ui.mjs
```

The repository also includes deeper developer suites. Some intentionally require
an existing JSN deployment, Oracle tools, separately approved integration
settings or protected historical evidence. They are not the portable default
suite. Do not copy private history, relax a guard or enable a live connection
merely to turn those tests green.

The publication review records selected source hashes and the actual clean-
checkout commands/results separately. It excludes generated artifacts,
credentials and customer files. Source unit counts never substitute for shipped
runtime import/browser proof. Fresh connected installation and full end-to-end
acceptance remain release gates, not claims made by this source snapshot.

## Installation discovery

The same setup entry point now distinguishes selected missing/empty directories,
source checkouts, CE skill roots, assessment metadata and retained installation
state without starting an app or reading databases/credentials:

```text
<selected-python> scripts/fox-setup.py inspect --installation-root <selected-directory>
<test-python> -B -m pytest -p no:cacheprovider tests/test_fox_installation_discovery.py
```

The suite uses its own synthetic metadata and checks preserved file contents,
no application/database/network execution, conflicting markers, bounded
inventory, changes during observation, linked roots where the test host permits
them, and closed diagnostics. A successful inspection is not installation,
release verification or permission to initialize/reuse the directory. The
connected installer and wizard must consume the actual storage/runtime gates.

The [storage phase](installer-storage-step.md) has additional genuine nonroot
Linux tests, including actual CLI plan/initialize/repeat, preserved identity,
pre-producer continuation, interrupted producer refusal and ordinary parent
permissions without silent chmod:

```text
<test-python> -I -B -m pytest -p no:cacheprovider tests/test_fox_installer_storage.py tests/test_fox_installation_discovery.py
```

Use a private Linux filesystem for temporary state, outside the checkout. The
POSIX apply tests explicitly skip on Windows or root; a skip is not a Linux
pass. These tests still prove only local setup phases, not connected service
installation, Oracle/model execution or customer distribution readiness.

## Browser setup wizard

The optional real bootstrap test is `tests/test_fox_bootstrap_integration.py`.
It requires explicit pinned upstream artifacts through
`FOX_BOOTSTRAP_PYTHON_ARCHIVE` and `FOX_BOOTSTRAP_XML_WHEEL`, plus nonroot Linux.
It exercises the actual OS-Python launcher, cold/warm cache, interruption
checkpoints, real wizard startup/shutdown and rejection of altered code before
execution. Without the artifacts it is skipped, not a successful installation
test. Pure archive/guard checks are in `tests/test_fox_bootstrap_runtime.py`.
The installed setup runtime contains no pytest dependency; the isolated test
driver is separate. See [managed setup runtime](managed-setup-runtime.md).

`tests/test_fox_setup_wizard.py` covers real loopback HTTP, origin/host/auth/body
bounds, session expiry, genuine nonroot storage, duplicate approval suppression,
unknown-outcome recheck and actual CLI startup/shutdown. These are local setup
tests, not a conversion-service installation proof.

`tests/test_fox_installer_connections.py` uses genuine private Linux storage,
synthetic passwords, actual project profile/client loaders and authenticated
loopback save. It checks repeat/restart preservation, partial-write refusal,
drift and closed diagnostics without live service/Oracle/model calls. Set
`FOX_SETUP_TEST_CONNECTIONS=1` for the optional browser journey to save synthetic
settings, recheck them, verify cleared password inputs and close its owned
listener. The result must still show connectivity unchecked and conversion not ready.

The optional developer browser journey requires existing Playwright/browser and
an explicit isolated Python; it does not download either. Run
`node tests/run_setup_wizard_browser.mjs` with `FOX_SETUP_TEST_PYTHON`, a new
absolute `FOX_SETUP_TEST_OUTPUT` and, if needed, `FOX_TEST_NODE_MODULES` and
`FOX_SETUP_BROWSER_CHANNEL`. For a Windows browser against local WSL Linux,
also select `FOX_SETUP_WSL_DISTRO` and `FOX_SETUP_WSL_USER`; Git Bash callers
must preserve the Linux Python environment value rather than applying MSYS path
conversion to it. The helper owns a synthetic private instance and closes its
listener via stdin; it never reuses an existing FOX service. Screenshots and
results remain outside source publication, without tokens. Read the
[wizard boundary](setup-wizard.md) before considering a customer installation.
