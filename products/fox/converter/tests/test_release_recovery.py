"""Local fault-injection tests. SQLcl and runtime HTTP are always mocked."""
import json
import hashlib
import re
import subprocess
import zipfile
from pathlib import Path
from types import SimpleNamespace

import pytest

from forms2apex import release
from forms2apex.security import alias_for_job


JOB = 'fox-' + 'b' * 20
BINDING = {'schema_version': 1, 'job_id': JOB, 'draft_sha256': 'c' * 64}
ALIAS = alias_for_job(JOB)


def put_json(path, value):
    path.write_text(json.dumps(value), encoding='utf-8')


@pytest.fixture
def job(tmp_path_factory, monkeypatch):
    root = tmp_path_factory.mktemp('recovery')
    (root / 'intake').mkdir()
    put_json(root / 'intake/manifest.json', {'source_manifest_sha256': 'd' * 64})
    put_json(root / 'migration-spec.json', {'reviewer': {'verdict': 'approve'}})
    put_json(root / 'imported-application.json', {'application_id': 123,
        'application_alias': ALIAS, 'workspace': 'FORMS2APEX_POC',
        'application_url': 'https://example.invalid/ords/synthetic'})
    for name in ('normalized-forms-inventory.json', 'migration-and-exception-report.json', 'validation-results.log'):
        (root / name).write_text('{}', encoding='utf-8')
    calls = []
    workflow = SimpleNamespace(
        store=SimpleNamespace(require=lambda job_id: root),
        settings=SimpleNamespace(apex_workspace='FORMS2APEX_POC', sqlcl_connection_name='F2A_APEX', sqlcl_path=root / 'sql'),
        assert_artifact_binding=lambda job_id: dict(BINDING),
        status=lambda job_id: {'state': 'IMPORTED', 'validation': {'passed': True}},
    )

    def sqlcl(path, args, commands, cwd, **kwargs):
        script = '\n'.join(commands)
        if 'apex export ' in script:
            calls.append('export')
            assert "FOX target identity mismatch" in script
            (cwd / 'f123.sql').write_text('-- synthetic export\n' + 'x' * 1100, encoding='utf-8')
            app = cwd / ALIAS.lower()
            (app / 'supporting-objects').mkdir(parents=True)
            (app / 'application.apx').write_text('app SYNTHETIC ()', encoding='utf-8')
            (app / 'supporting-objects/objects.apx').write_text('scriptFile: deinstall.sql', encoding='utf-8')
            (app / 'supporting-objects/deinstall.sql').write_text('-- no synthetic cleanup', encoding='utf-8')
            output = 'FOX_EXPORT_MATCH=1'
        elif 'apex validate ' in script:
            calls.append('validate_export')
            assert args == ['-S', '/nolog']
            project = Path(re.search(r'apex validate -input "([^"]+)"', script).group(1))
            assert project.is_dir()
            assert (project / 'supporting-objects/deinstall.sql').is_file()
            output = 'Validation successful'
        elif 'FOX_ALIAS_COUNT=' in script:
            calls.append('reimport_precheck')
            output = 'FOX_ALIAS_COUNT=0'
        elif 'apex_application_install.set_workspace' in script:
            calls.append('reimport')
            assert (root / 'package-reimport-intent.json').is_file()
            assert "FOX target identity mismatch" in script
            output = 'FOX_REIMPORT_MATCH=1'
        else:
            pytest.fail('Unexpected SQLcl invocation')
        return subprocess.CompletedProcess(args, 0, output, '')

    monkeypatch.setattr(release, '_run_script', sqlcl)
    monkeypatch.setattr('forms2apex.sqlcl._run_script', sqlcl)
    monkeypatch.setattr(release, 'runtime_login_check', lambda url: {'passed': True, 'scope': 'login_page_reachability'})
    return SimpleNamespace(root=root, workflow=workflow, calls=calls, sqlcl=sqlcl)


def finish(job):
    return release.finalize_release(job.workflow, JOB)


def forbid_external(monkeypatch):
    def forbidden(*args, **kwargs):
        pytest.fail('Recovery must not call SQLcl or HTTP')
    monkeypatch.setattr(release, '_run_script', forbidden)
    monkeypatch.setattr('forms2apex.sqlcl._run_script', forbidden)
    monkeypatch.setattr(release, 'runtime_login_check', forbidden)


def test_export_validates_actual_output_and_binds_every_member(job, monkeypatch):
    evidence = finish(job)
    assert evidence['application_id'] == 123
    assert job.calls == ['export', 'validate_export', 'reimport_precheck', 'reimport']
    complete = json.loads((job.root / 'export/.export-complete.json').read_text())
    assert complete['artifact_binding'] == BINDING
    assert f'{ALIAS.lower()}/supporting-objects/deinstall.sql' in complete['files']
    assert complete['apexlang_validation_passed'] is True
    assert (job.root / 'release-publication.json').is_file()
    before = {p.relative_to(job.root): p.read_bytes() for p in job.root.rglob('*') if p.is_file()}
    forbid_external(monkeypatch)
    assert finish(job) == evidence
    assert before == {p.relative_to(job.root): p.read_bytes() for p in job.root.rglob('*') if p.is_file()}


@pytest.mark.parametrize('failure', ['timeout', 'nonzero', 'missing_application', 'invalid_apexlang'])
def test_interrupted_or_incomplete_export_can_retry_only_read_only_export(job, monkeypatch, failure):
    def failing(path, args, commands, cwd, **kwargs):
        if 'apex export ' in '\n'.join(commands):
            if failure == 'timeout':
                (cwd / 'partial.sql').write_text('partial', encoding='utf-8')
                raise subprocess.TimeoutExpired('mock-sqlcl', 1)
            result = job.sqlcl(path, args, commands, cwd, **kwargs)
            if failure == 'nonzero':
                return subprocess.CompletedProcess(args, 1, result.stdout, 'interrupted')
            if failure == 'missing_application':
                (cwd / ALIAS.lower() / 'application.apx').unlink()
            return result
        if failure == 'invalid_apexlang':
            return subprocess.CompletedProcess(args, 0, 'APEXLang Compile Errors: missing referenced asset', '')
        return job.sqlcl(path, args, commands, cwd, **kwargs)
    monkeypatch.setattr(release, '_run_script', failing)
    monkeypatch.setattr('forms2apex.sqlcl._run_script', failing)
    with pytest.raises((RuntimeError, subprocess.TimeoutExpired)):
        finish(job)
    assert not (job.root / 'export').exists()
    assert not (job.root / 'package-reimport-intent.json').exists()
    abandoned = list(job.root.glob('.export-attempt-*'))
    assert len(abandoned) == 1
    preserved = {p.relative_to(abandoned[0]): p.read_bytes() for p in abandoned[0].rglob('*') if p.is_file()}
    monkeypatch.setattr(release, '_run_script', job.sqlcl)
    monkeypatch.setattr('forms2apex.sqlcl._run_script', job.sqlcl)
    finish(job)
    assert job.calls.count('reimport') == 1
    assert preserved == {p.relative_to(abandoned[0]): p.read_bytes() for p in abandoned[0].rglob('*') if p.is_file()}


def test_old_partial_export_is_preserved_not_recertified(job):
    old = job.root / 'export'
    old.mkdir()
    (old / 'f123.sql').write_text('incomplete old export', encoding='utf-8')
    finish(job)
    preserved = list(job.root.glob('.export-preserved-*'))
    assert len(preserved) == 1
    assert (preserved[0] / 'f123.sql').read_text() == 'incomplete old export'
    assert job.calls.count('export') == 1


def test_export_complete_before_directory_rename_is_safe_to_retry(job, monkeypatch):
    original = Path.rename
    def interrupted(path, target):
        if Path(target) == job.root / 'export':
            raise OSError('simulated crash before export promotion')
        return original(path, target)
    monkeypatch.setattr(Path, 'rename', interrupted)
    with pytest.raises(OSError, match='simulated'):
        finish(job)
    assert list(job.root.glob('.export-attempt-*/.export-complete.json'))
    assert not (job.root / 'package-reimport-intent.json').exists()
    monkeypatch.setattr(Path, 'rename', original)
    finish(job)
    assert job.calls.count('export') == 2
    assert job.calls.count('reimport') == 1


@pytest.mark.parametrize('phase', ['database_call', 'receipt_write'])
def test_uncertain_sql_reimport_is_never_replayed(job, monkeypatch, phase):
    if phase == 'database_call':
        def timeout(path, args, commands, cwd, **kwargs):
            result = job.sqlcl(path, args, commands, cwd, **kwargs)
            if 'FOX_REIMPORT_MATCH=' in '\n'.join(commands):
                raise subprocess.TimeoutExpired('mock-sqlcl', 1)
            return result
        monkeypatch.setattr(release, '_run_script', timeout)
    else:
        original = release._atomic_json
        def disk_error(path, value):
            if path.name == 'package-reimport.json':
                raise OSError('simulated receipt disk failure')
            return original(path, value)
        monkeypatch.setattr(release, '_atomic_json', disk_error)
    with pytest.raises((OSError, subprocess.TimeoutExpired)):
        finish(job)
    assert (job.root / 'package-reimport-intent.json').is_file()
    assert not (job.root / 'package-reimport.json').exists()
    forbid_external(monkeypatch)
    with pytest.raises(RuntimeError, match='operator reconciliation'):
        finish(job)
    assert job.calls.count('reimport') == 1


def test_unjournaled_staging_failure_rebuilds_package_without_reimport(job, monkeypatch):
    original = release._verify_package_members
    monkeypatch.setattr(release, '_verify_package_members', lambda *a: (_ for _ in ()).throw(OSError('simulated crash')))
    with pytest.raises(OSError, match='simulated'):
        finish(job)
    assert not (job.root / 'release-publication.json').exists()
    assert not (job.root / 'apex-package.zip').exists()
    assert (job.root / 'package-reimport.json').is_file()
    monkeypatch.setattr(release, '_verify_package_members', original)
    finish(job)
    assert job.calls.count('export') == 1
    assert job.calls.count('reimport') == 1
    assert len(list(job.root.glob('.release-publication-*'))) == 2


def interrupt_publication(job, monkeypatch, count, after=False):
    original = Path.replace
    observed = []
    def interrupted(path, target):
        target = Path(target)
        if target.parent == job.root and target.name in release._PUBLICATION_FILES:
            observed.append(target.name)
            if len(observed) == count:
                if after:
                    original(path, target)
                raise OSError('simulated publication interruption')
        return original(path, target)
    monkeypatch.setattr(Path, 'replace', interrupted)
    with pytest.raises(OSError, match='publication interruption'):
        finish(job)
    monkeypatch.setattr(Path, 'replace', original)
    assert (job.root / 'release-publication.json').is_file()
    return json.loads((job.root / 'release-publication.json').read_text())


@pytest.mark.parametrize('count', [1, 2, 3])
@pytest.mark.parametrize('after', [False, True])
def test_every_publication_boundary_recovers_without_external_calls(job, monkeypatch, count, after):
    interrupt_publication(job, monkeypatch, count, after)
    forbid_external(monkeypatch)
    result = finish(job)
    assert result['package_reimport_passed'] is True
    assert release._verify_cached_release(job.root, JOB, BINDING) == result


@pytest.mark.parametrize('changed', ['stage_package', 'published_evidence', 'receipt', 'export_asset', 'journal_binding'])
def test_pending_publication_rejects_any_changed_component(job, monkeypatch, changed):
    journal = interrupt_publication(job, monkeypatch, 2)
    if changed == 'stage_package':
        path = job.root / journal['stage_directory'] / 'apex-package.zip'
        path.write_bytes(path.read_bytes() + b'changed')
    elif changed == 'published_evidence':
        path = job.root / 'release-evidence.json'
        path.write_bytes(path.read_bytes() + b'changed')
    elif changed == 'receipt':
        path = job.root / 'package-reimport.json'
        value = json.loads(path.read_text())
        value['application_id'] += 1
        put_json(path, value)
    elif changed == 'export_asset':
        (job.root / 'export' / ALIAS.lower() / 'supporting-objects/deinstall.sql').write_text('changed', encoding='utf-8')
    else:
        journal['artifact_binding'] = {**BINDING, 'draft_sha256': 'e' * 64}
        put_json(job.root / 'release-publication.json', journal)
    before = {p.relative_to(job.root): p.read_bytes() for p in job.root.rglob('*') if p.is_file()}
    forbid_external(monkeypatch)
    with pytest.raises(RuntimeError):
        finish(job)
    assert before == {p.relative_to(job.root): p.read_bytes() for p in job.root.rglob('*') if p.is_file()}


def test_completed_export_rejects_late_missing_referenced_asset(job, monkeypatch):
    finish(job)
    (job.root / 'export' / ALIAS.lower() / 'supporting-objects/deinstall.sql').unlink()
    forbid_external(monkeypatch)
    with pytest.raises(RuntimeError, match='changed or are incomplete'):
        finish(job)


def test_imported_identity_change_during_export_does_not_seal_output(job, monkeypatch):
    def change_identity(path, args, commands, cwd, **kwargs):
        result = job.sqlcl(path, args, commands, cwd, **kwargs)
        value = json.loads((job.root / 'imported-application.json').read_text())
        value['application_id'] = 456
        put_json(job.root / 'imported-application.json', value)
        return result
    monkeypatch.setattr(release, '_run_script', change_identity)
    with pytest.raises(RuntimeError, match='identity changed during export'):
        finish(job)
    assert not (job.root / 'export').exists()
    assert 'reimport' not in job.calls


def test_legacy_export_with_receipt_is_not_silently_resealed(job, monkeypatch):
    finish(job)
    # Simulate a legacy job stopped after reimport, before publication existed.
    for name in (*release._PUBLICATION_FILES, 'release-publication.json', 'export/.export-complete.json'):
        (job.root / name).unlink()
    forbid_external(monkeypatch)
    with pytest.raises(RuntimeError, match='Legacy export'):
        finish(job)
    assert not (job.root / 'export/.export-complete.json').exists()


@pytest.mark.parametrize('change', ['omit', 'modify', 'extra'])
def test_package_must_contain_exact_validated_apexlang_tree(job, change):
    finish(job)
    package = job.root / 'apex-package.zip'
    with zipfile.ZipFile(package) as archive:
        members = {name: archive.read(name) for name in archive.namelist() if name != 'manifest.json'}
    name = 'apexlang/supporting-objects/deinstall.sql'
    if change == 'omit':
        del members[name]
    elif change == 'modify':
        members[name] = b'-- unexpected changed supporting object'
    else:
        members['apexlang/unreviewed.sql'] = b'-- unexpected extra file'
    members['manifest.json'] = json.dumps({name: hashlib.sha256(raw).hexdigest() for name, raw in members.items()}).encode()
    with zipfile.ZipFile(package, 'w') as archive:
        for name, raw in members.items():
            archive.writestr(name, raw)
    with pytest.raises(RuntimeError, match='package integrity'):
        release._verify_package_members(package, job.root / 'release-evidence.json', job.root / 'export/f123.sql',
            job.root / 'package-reimport.json', job.root / 'export' / ALIAS.lower())


def test_publication_journal_cannot_redirect_outside_job(job, monkeypatch):
    journal = interrupt_publication(job, monkeypatch, 1)
    journal['stage_directory'] = '../unrelated'
    put_json(job.root / 'release-publication.json', journal)
    forbid_external(monkeypatch)
    with pytest.raises(RuntimeError, match='journal is not bound'):
        finish(job)


def test_deleted_pending_package_is_not_regenerated_or_recertified(job, monkeypatch):
    journal = interrupt_publication(job, monkeypatch, 1)
    (job.root / journal['stage_directory'] / 'apex-package.zip').unlink()
    forbid_external(monkeypatch)
    with pytest.raises(RuntimeError, match='component missing or changed'):
        finish(job)
    assert not (job.root / 'apex-package.zip').exists()


def test_changed_sql_during_reimport_never_receives_verified_receipt(job, monkeypatch):
    def change_sql(path, args, commands, cwd, **kwargs):
        result = job.sqlcl(path, args, commands, cwd, **kwargs)
        if 'FOX_REIMPORT_MATCH=' in '\n'.join(commands):
            (job.root / 'export/f123.sql').write_text('-- changed during mock reimport', encoding='utf-8')
        return result
    monkeypatch.setattr(release, '_run_script', change_sql)
    with pytest.raises(RuntimeError, match='SQL export changed during reimport'):
        finish(job)
    assert (job.root / 'package-reimport-intent.json').is_file()
    assert not (job.root / 'package-reimport.json').exists()
    assert not (job.root / 'apex-package.zip').exists()
    forbid_external(monkeypatch)
    with pytest.raises(RuntimeError, match='changed or are incomplete'):
        finish(job)
