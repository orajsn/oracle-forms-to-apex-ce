# Source verification

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
