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
