"""Guard multifile export validation; no SQLcl process or database is used."""
import json
from pathlib import Path
import re
import subprocess
from types import SimpleNamespace

import pytest
from forms2apex.starter import TEMPLATE_ID

from forms2apex import release
from forms2apex.security import alias_for_job


JOB = 'fox-' + 'd' * 20
ALIAS = alias_for_job(JOB)
BINDING = {'schema_version': 1, 'job_id': JOB, 'draft_sha256': 'a' * 64}
FILES = {
    'application.apx': 'app SYNTHETIC ( userInterface { currentTheme: @universal-theme } )',
    '.apex/apexlang.json': '{"mmdVersion":"26.1.0+3102"}',
    'pages/p00001-home.apx': 'page 1 ( name: Home )',
    'shared-components/themes/universal-theme/theme.apx': 'theme universal-theme ()',
    'shared-components/lists.apx': 'list navigation-bar ()',
    'shared-components/authentications.apx': 'authentication oracle-apex-accounts ()',
    'supporting-objects/supporting-objects.apx': 'scriptFile: deinstall.sql',
    'supporting-objects/deinstall.sql': '-- intentionally empty synthetic script',
}


@pytest.fixture
def exported(tmp_path_factory, monkeypatch):
    root = tmp_path_factory.mktemp('ep')
    (root / 'migration-spec.json').write_text(json.dumps({'template_id':TEMPLATE_ID}),encoding='utf-8')
    (root / 'imported-application.json').write_text(json.dumps({'application_id': 123,
        'application_alias': ALIAS, 'workspace': 'FORMS2APEX_POC'}), encoding='utf-8')
    case = SimpleNamespace(root=root, omitted=None, seen=[])
    case.workflow = SimpleNamespace(settings=SimpleNamespace(sqlcl_path=root / 'sql', apex_workspace='FORMS2APEX_POC'),
        assert_artifact_binding=lambda job_id: dict(BINDING))

    def export_script(path, args, commands, cwd, **kwargs):
        assert 'apex export ' in '\n'.join(commands)
        assert not any('apex import ' in command for command in commands)
        (cwd / 'f123.sql').write_text('-- synthetic export\n' + 'x' * 1100, encoding='utf-8')
        project = cwd / ALIAS.lower()
        for name, text in FILES.items():
            if name == case.omitted:
                continue
            file = project / name
            file.parent.mkdir(parents=True, exist_ok=True)
            file.write_text(text, encoding='utf-8')
        return subprocess.CompletedProcess([], 0, 'FOX_EXPORT_MATCH=1', '')

    def validate_script(path, args, commands, cwd, **kwargs):
        assert args == ['-S', '/nolog']
        assert len(commands) == 1
        match = re.fullmatch(r'apex validate -input "([^"]+)"', commands[0])
        assert match is not None
        project = Path(match.group(1))
        case.seen.append(project)
        # Regression: a single application.apx file silently loses the rest of
        # the project context. The real retained-project /nolog run is separate.
        assert project.is_dir(), 'Validate the exported project directory, not application.apx alone'
        assert project.name == ALIAS.lower()
        assert cwd == project.parent
        missing = [name for name in FILES if not (project / name).is_file()]
        if missing:
            return subprocess.CompletedProcess([], 0, 'APEXLang Compile Errors\nREFERENCE_NOT_FOUND: ' + missing[0], '')
        return subprocess.CompletedProcess([], 0, 'Validation successful.', '')

    monkeypatch.setattr(release, '_run_script', export_script)
    monkeypatch.setattr('forms2apex.sqlcl._run_script', validate_script)
    return case


def ensure(case):
    return release._ensure_export(case.workflow, case.root, JOB, BINDING, 123, ALIAS,
                                  ['-S', '-L', '-name', 'F2A_APEX'], 'guard')


def test_multifile_export_validates_directory_and_seals_every_reference(exported):
    path = ensure(exported)
    assert len(exported.seen) == 1
    manifest = json.loads((path / '.export-complete.json').read_text())
    assert manifest['apexlang_validation_passed'] is True
    assert {ALIAS.lower() + '/' + name for name in FILES}.issubset(manifest['files'])
    assert 'Validation successful.' in (path / 'apexlang-validation.log').read_text()


@pytest.mark.parametrize('missing', [
    'shared-components/themes/universal-theme/theme.apx',
    'shared-components/lists.apx',
    'shared-components/authentications.apx',
    'supporting-objects/deinstall.sql',
    '.apex/apexlang.json',
])
def test_directory_validation_does_not_bypass_missing_references(exported, missing):
    exported.omitted = missing
    with pytest.raises(RuntimeError, match='failed SQLcl validation'):
        ensure(exported)
    assert len(exported.seen) == 1
    assert not (exported.root / 'export').exists()
    assert not (exported.root / 'package-reimport-intent.json').exists()
    attempts = list(exported.root.glob('.export-attempt-*'))
    assert len(attempts) == 1
    assert not (attempts[0] / '.export-complete.json').exists()
    assert 'REFERENCE_NOT_FOUND' in (attempts[0] / 'apexlang-validation.log').read_text()
