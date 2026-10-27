"""Unit/security tests. Fake native output is NOT Oracle compatibility evidence."""
import json
import os
from pathlib import Path
import pytest
import fox.extractor as extractor
from fox.extractor import (ExtractionError, OracleFormsBackend, prepare,
                           source_files, verify, safe_name, validate_pll_xml, digest)
from fox.intake import checked_source, inventory
from fox.prepared_source import (MAX_MANIFEST_BYTES, UPLOAD_MANIFEST_NAME,
                                 parse_upload_manifest, verify_upload_manifest)


@pytest.mark.skipif(os.name != 'nt', reason='Windows UTF-16 budget')
def test_windows_path_budget_counts_utf16_and_normalized_absolute_paths(tmp_path):
    prefix = len(str(tmp_path.absolute()).encode('utf-16-le')) // 2 + 1
    path = tmp_path / ('x' * (240 - prefix - 2) + '\U0001f512')
    extractor._validate_windows_paths([path, path.parent / 'unused/..' / path.name])
    with pytest.raises(extractor.PathBudgetError) as error:
        extractor._validate_windows_paths([Path(str(path) + 'x')])
    assert str(error.value) == extractor.PATH_BUDGET_MESSAGE
    assert str(tmp_path) not in str(error.value)


@pytest.mark.parametrize('extension', ['fmb', 'mmb', 'olb', 'pll'])
def test_derived_native_basename_checked_before_any_tools(extension, tmp_path, monkeypatch):
    native = OracleFormsBackend(tmp_path, tmp_path / 'java.exe')
    monkeypatch.setattr(native, 'check', lambda: pytest.fail('must reject before tool checks'))
    monkeypatch.setattr(native, 'run', lambda *args: pytest.fail('must not run tools'))
    with pytest.raises(extractor.PathBudgetError):
        native.extract(tmp_path / ('n' * 116 + '.' + extension), tmp_path / 'out')


@pytest.mark.skipif(os.name != 'nt', reason='Windows path budget before staging')
def test_path_budget_precedes_output_mkdir_scratch_and_backend(sources, tmp_path, monkeypatch):
    output = tmp_path / ('long' * 40)
    with monkeypatch.context() as patcher:
        patcher.setattr(Path, 'mkdir', lambda *args, **kwargs: pytest.fail('no output mkdir'))
        patcher.setattr(extractor.tempfile, 'TemporaryDirectory', lambda *args, **kwargs: pytest.fail('no scratch staging'))
        with pytest.raises(extractor.PathBudgetError):
            prepare(sources, output, FakeOracle(), 'budget-1')
    assert not output.exists()
    assert (sources / 'demo.xml').read_bytes().startswith(b'<Module>')


@pytest.mark.skipif(os.name != 'nt', reason='Windows configured/native/temp path budget')
@pytest.mark.parametrize('field', ['home', 'java', 'jars', 'javac', 'pll_helper', 'temporary'])
def test_native_known_paths_checked_before_tool_calls(field, tmp_path, monkeypatch):
    native = OracleFormsBackend(tmp_path, tmp_path / 'java.exe')
    long = tmp_path / ('x' * 240)
    if field == 'temporary':
        monkeypatch.setattr(extractor.tempfile, 'gettempdir', lambda: str(long))
    else:
        setattr(native, field, [long] if field == 'jars' else long)
    monkeypatch.setattr(native, 'check', lambda: pytest.fail('must reject before tool checks'))
    monkeypatch.setattr(native, 'run', lambda *args: pytest.fail('must not run tools'))
    with pytest.raises(extractor.PathBudgetError):
        native.extract(tmp_path / 'library.pll', tmp_path / 'out')


@pytest.mark.skipif(os.name != 'nt', reason='Windows classpath entries checked individually')
def test_native_classpath_entries_are_not_counted_as_one_path(tmp_path):
    native = OracleFormsBackend(tmp_path, tmp_path / 'java.exe')
    native.jars = [Path(extractor.tempfile.gettempdir()) / ('j' * 150 + str(i) + '.jar') for i in range(3)]
    assert len(os.pathsep.join(map(str, native.jars))) > 240
    extractor.validate_path_budget(tmp_path / 'source', tmp_path / 'out', ['module.fmb'], 'budget-1', native)


@pytest.fixture
def sources(tmp_path):
    p = tmp_path / 'input'
    p.mkdir()
    (p / 'demo.xml').write_text('<Module><FormModule Name="DEMO"/></Module>', encoding='utf-8')
    return p


def test_readable_prepare_and_verify(sources, tmp_path):
    job = prepare(sources, tmp_path / 'jobs', job_id='unit-1')
    assert verify(job)['status'] == 'VERIFIED_REVIEW_REQUIRED'
    assert verify(job)['approved_for_upload'] is False
    assert set(p.name for p in (job / 'ready').iterdir()) == {'demo.xml', UPLOAD_MANIFEST_NAME}
    manifest = json.loads((job / 'manifest.json').read_text())
    assert manifest['inputs'][0]['name'] == 'demo.xml'
    assert manifest['upload_manifest_name'] == UPLOAD_MANIFEST_NAME
    assert verify(job)['files'] == 1
    assert str(sources) not in (job / 'manifest.json').read_text()
    with pytest.raises(FileExistsError):
        prepare(sources, tmp_path / 'jobs', job_id='unit-1')


@pytest.mark.parametrize('payload', ['<invalid', '<!DOCTYPE x [<!ENTITY a "x">]><x>&a;</x>',
    '<x password="supersecret"/>', '<x>INSERT INTO records VALUES(1)</x>',
    '<x>person@example.com</x>', '<x>\x00</x>'])
def test_malformed_sensitive_and_data_blocked(sources, tmp_path, payload):
    (sources / 'demo.xml').write_text(payload)
    with pytest.raises(ValueError):
        prepare(sources, tmp_path / 'jobs', job_id='blocked')
    job = tmp_path / 'jobs/blocked'
    assert json.loads((job / 'status.json').read_text())['status'] == 'BLOCKED'
    assert not (job / 'ready').exists()


@pytest.mark.parametrize('name', ['../evil.xml', 'a..xml', 'a.xml:secret', 'a&b.xml',
    'a"b.xml', 'CON.xml', 'a.xml ', '-flag.xml'])
def test_unsafe_names(name):
    with pytest.raises(ExtractionError):
        safe_name(name)


def test_archives_blocked(sources, tmp_path):
    (sources / 'bundle.zip').write_bytes(b'PK')
    with pytest.raises(ExtractionError):
        prepare(sources, tmp_path / 'jobs')


def test_binary_not_treated_as_readable(sources, tmp_path):
    (sources / 'library.pll').write_text('This is text but still requires native extraction.')
    with pytest.raises(ExtractionError, match='Binary input'):
        prepare(sources, tmp_path / 'jobs')


def test_duplicate_basename(sources):
    nested = sources / 'nested'
    nested.mkdir()
    (nested / 'DEMO.xml').write_text('<x/>')
    with pytest.raises(ExtractionError, match='Duplicate'):
        source_files(sources)


def test_no_nested_outputs(sources):
    with pytest.raises(ExtractionError):
        prepare(sources, sources / 'outputs')


@pytest.mark.parametrize('kind', ['content', 'extra', 'manifest', 'input_hash', 'status'])
def test_modified_package_blocked(sources, tmp_path, kind):
    job = prepare(sources, tmp_path / 'jobs')
    if kind == 'content':
        (job / 'ready/demo.xml').write_text('<x/>')
    elif kind == 'extra':
        (job / 'ready/raw.fmb').write_bytes(b'raw')
    elif kind in ('manifest', 'input_hash'):
        manifest = json.loads((job / 'manifest.json').read_text())
        if kind == 'manifest':
            manifest['files'][0]['name'] = '../outside.xml'
        else:
            manifest['inputs'][0]['sha256'] = '0' * 64
        (job / 'manifest.json').write_text(json.dumps(manifest))
    else:
        (job / 'status.json').write_text('{"status":"BLOCKED"}')
    with pytest.raises(ExtractionError):
        verify(job)


def test_bom_preserved(sources, tmp_path):
    raw = b'\xef\xbb\xbf<Module/>\r\n'
    (sources / 'demo.xml').write_bytes(raw)
    job = prepare(sources, tmp_path / 'jobs')
    assert (job / 'ready/demo.xml').read_bytes() == raw
    public = parse_upload_manifest((job / 'ready' / UPLOAD_MANIFEST_NAME).read_bytes())
    assert public['files'] == [{'name': 'demo.xml', 'sha256': digest(raw), 'bytes': len(raw)}]
    verify(job)


def test_public_sidecar_contains_only_readable_metadata(sources, tmp_path):
    nested = sources / 'private-input-folder'
    nested.mkdir()
    (nested / 'form.fmb').write_bytes(b'unit-test-only-not-real-fmb')
    job = prepare(sources, tmp_path / 'jobs', FakeOracle(), 'public-1')
    raw = (job / 'ready' / UPLOAD_MANIFEST_NAME).read_bytes()
    value = parse_upload_manifest(raw)
    private = json.loads((job / 'manifest.json').read_text())
    status = json.loads((job / 'status.json').read_text())
    report = json.loads((job / 'inventory.json').read_text())
    assert value['extraction_job_id'] == 'public-1'
    assert value['readable_source_hash'] == private['readable_source_hash'] == report['source_hash']
    assert len(value['files']) == len(private['files']) == len(report['files']) == status['files'] == 2
    assert UPLOAD_MANIFEST_NAME not in [item['name'] for item in value['files']]
    assert all(set(item) == {'name', 'sha256', 'bytes'} for item in value['files'])
    assert set(value) == {'format', 'schema_version', 'extraction_job_id', 'readable_source_hash', 'files'}
    for private_detail in (str(sources).encode(), b'private-input-folder', b'form.fmb',
                           b'FAKE-UNIT-TEST-ONLY', b'backend', b'approval', b'inputs', b'<Module>'):
        assert private_detail not in raw
    selected = [checked_source(item['name'], (job / 'ready' / item['name']).read_bytes())
                for item in private['files']]
    assert verify_upload_manifest(raw, selected) == value
    assert verify(job)['files'] == 2


def test_legacy_private_v1_without_marker_still_verifies(sources, tmp_path):
    job = prepare(sources, tmp_path / 'jobs', job_id='legacy-1')
    private_path = job / 'manifest.json'
    private = json.loads(private_path.read_text())
    private.pop('upload_manifest_name')
    private_path.write_text(json.dumps(private), encoding='utf-8')
    (job / 'ready' / UPLOAD_MANIFEST_NAME).unlink()
    assert private['schema_version'] == 1
    assert verify(job)['status'] == 'VERIFIED_REVIEW_REQUIRED'
    assert verify(job)['files'] == 1


def test_legacy_marker_absent_does_not_silently_accept_sidecar(sources, tmp_path):
    job = prepare(sources, tmp_path / 'jobs')
    private_path = job / 'manifest.json'
    private = json.loads(private_path.read_text())
    private.pop('upload_manifest_name')
    private_path.write_text(json.dumps(private), encoding='utf-8')
    with pytest.raises(ExtractionError, match='differ'):
        verify(job)


@pytest.mark.parametrize('marker', ['other.json', '../fox-readable-upload.json',
                                   UPLOAD_MANIFEST_NAME.upper(), '', None, True, 1, [], {}])
def test_unknown_public_marker_rejected(sources, tmp_path, marker):
    job = prepare(sources, tmp_path / 'jobs')
    private_path = job / 'manifest.json'
    private = json.loads(private_path.read_text())
    private['upload_manifest_name'] = marker
    private_path.write_text(json.dumps(private), encoding='utf-8')
    with pytest.raises(ExtractionError, match='marker'):
        verify(job)


@pytest.mark.parametrize('change', ['missing', 'extra', 'renamed', 'directory',
                                   'hash', 'bytes', 'name', 'job_id', 'invalid_json',
                                   'unknown_field', 'too_large', 'symlink', 'hardlink'])
def test_public_sidecar_tampering_rejected(sources, tmp_path, change):
    job = prepare(sources, tmp_path / 'jobs', job_id='tamper-1')
    path = job / 'ready' / UPLOAD_MANIFEST_NAME
    value = json.loads(path.read_bytes())
    if change == 'missing':
        path.unlink()
    elif change == 'extra':
        (job / 'ready' / 'other-upload.json').write_bytes(path.read_bytes())
    elif change == 'renamed':
        path.rename(job / 'ready' / 'other-upload.json')
    elif change == 'directory':
        path.unlink()
        path.mkdir()
    elif change == 'invalid_json':
        path.write_bytes(b'{"private":"C:/private/do-not-echo",')
    elif change == 'too_large':
        path.write_bytes(b' ' * (MAX_MANIFEST_BYTES + 1))
    elif change in {'symlink', 'hardlink'}:
        external = job / 'sidecar-local-copy.json'
        external.write_bytes(path.read_bytes())
        path.unlink()
        if change == 'hardlink':
            os.link(external, path)
        else:
            try:
                path.symlink_to(external)
            except OSError:
                pytest.skip('OS does not permit creating symlinks for this test user.')
    else:
        if change == 'hash':
            value['files'][0]['sha256'] = '0' * 64
        elif change == 'bytes':
            value['files'][0]['bytes'] += 1
        elif change == 'name':
            value['files'][0]['name'] = 'DEMO.xml'
        elif change == 'job_id':
            value['extraction_job_id'] = 'different-job'
        else:
            value['backend'] = 'C:/private/do-not-echo'
        path.write_text(json.dumps(value), encoding='utf-8')
    with pytest.raises(ExtractionError) as err:
        verify(job)
    assert 'private/do-not-echo' not in str(err.value)


def test_hardlink_blocked(sources):
    os.link(sources / 'demo.xml', sources / 'linked.xml')
    with pytest.raises(ExtractionError, match='links'):
        source_files(sources)


def test_symlink_blocked(sources):
    try:
        (sources / 'link.xml').symlink_to(sources / 'demo.xml')
    except OSError:
        pytest.skip('OS does not permit creating symlinks for this test user.')
    with pytest.raises(ExtractionError, match='links'):
        source_files(sources)


class FakeOracle:
    name = 'FAKE-UNIT-TEST-ONLY'
    def extract(self, source, destination):
        output = destination / (source.stem + '_fmb.xml')
        output.write_text('<Module><FormModule Name="TEST"/></Module>')
        return output


def test_extensible_backend_keeps_raw_out(sources, tmp_path):
    (sources / 'form.fmb').write_bytes(b'unit-test-only-not-real-fmb')
    job = prepare(sources, tmp_path / 'jobs', FakeOracle())
    assert not list(job.rglob('*.fmb'))
    assert verify(job)['files'] == 2


def test_source_mutation_blocks_release(sources, tmp_path):
    original = sources / 'form.fmb'
    original.write_bytes(b'fake')
    class Mutator(FakeOracle):
        def extract(self, source, destination):
            original.write_bytes(b'changed')
            return super().extract(source, destination)
    with pytest.raises(ExtractionError, match='Source changed'):
        prepare(sources, tmp_path / 'jobs', Mutator(), 'changed')
    assert not (tmp_path / 'jobs/changed/ready').exists()


def test_output_collision_blocks(sources, tmp_path):
    (sources / 'form.fmb').write_bytes(b'fake')
    (sources / 'form_fmb.xml').write_text('<x/>')
    with pytest.raises(ExtractionError, match='collision'):
        prepare(sources, tmp_path / 'jobs', FakeOracle())


def test_native_no_shell_no_credentials(monkeypatch, tmp_path):
    import subprocess
    observed = {}
    def fake_run(args, **kwargs):
        observed.update(kwargs)
        return subprocess.CompletedProcess(args, 0, b'Completed')
    monkeypatch.setenv('JAVA_TOOL_OPTIONS', '-javaagent:untrusted.jar')
    monkeypatch.setenv('TWO_TASK', 'production')
    monkeypatch.setattr(subprocess, 'run', fake_run)
    backend = OracleFormsBackend(tmp_path, tmp_path / 'java.exe')
    backend.run(['java', 'fake'], tmp_path, tmp_path)
    assert observed['shell'] is False
    assert 'JAVA_TOOL_OPTIONS' not in observed['env']
    assert 'TWO_TASK' not in observed['env']
    assert observed['stdin'] == subprocess.DEVNULL


def test_native_errors_never_echo_source(monkeypatch, tmp_path):
    import subprocess
    monkeypatch.setattr(subprocess, 'run', lambda *a, **kw:
        subprocess.CompletedProcess(a, 0, b'ERROR password=never-print-this'))
    backend = OracleFormsBackend(tmp_path, tmp_path / 'java.exe')
    with pytest.raises(ExtractionError) as err:
        backend.run(['java'], tmp_path, tmp_path)
    assert 'never-print' not in str(err.value)


def test_pll_requires_local_compiler(monkeypatch, tmp_path):
    backend = OracleFormsBackend(tmp_path, tmp_path / 'java.exe')
    monkeypatch.setattr(backend, 'check', lambda: {})
    with pytest.raises(ExtractionError, match='JDK compiler'):
        backend.extract(tmp_path / 'source.pll', tmp_path)


def library_xml():
    spec='PACKAGE SAMPLE IS PROCEDURE run_demo; END;'
    body='PACKAGE BODY SAMPLE IS PROCEDURE run_demo IS BEGIN missing_api.call_it(); END; END;'
    return (f'<Module xmlns="urn:fox:forms-library:v1" Format="FOX-JDAPI-LIBRARY-1" DatabaseConnected="false">'
        '<LibraryModule Name="LIB" SourceFile="lib.pll" ProgramUnitCount="2" AttachedLibraryCount="1">'
        '<AttachedLibrary Name="OTHER"/>'
        f'<ProgramUnit Name="SAMPLE" ProgramUnitType="3" TextSHA256="{digest(spec.encode())}"><ProgramUnitText>{spec}</ProgramUnitText></ProgramUnit>'
        f'<ProgramUnit Name="SAMPLE" ProgramUnitType="4" TextSHA256="{digest(body.encode())}"><ProgramUnitText>{body}</ProgramUnitText></ProgramUnit>'
        '</LibraryModule></Module>').encode()


def test_pll_source_and_package_pair_preserved():
    raw=library_xml()
    validate_pll_xml(raw)
    form=checked_source('form.xml',b'<Module><FormModule Name="F"><AttachedLibrary Name="LIB"/><Trigger TriggerText="SAMPLE.run_demo();"/></FormModule></Module>')
    report=inventory([checked_source('lib_pll.xml',raw),form])
    refs={d['target']:d['status'] for d in report['dependencies']}
    assert refs['LIB']=='SOURCE_PRESENT'
    assert refs['SAMPLE']=='SOURCE_PRESENT'
    assert refs['OTHER']=='MISSING'
    assert refs['MISSING_API']=='MISSING'


@pytest.mark.parametrize('old,new', [(b'ProgramUnitCount="2"', b'ProgramUnitCount="3"'),
    (b'missing_api',b'changed_api'), (b'DatabaseConnected="false"',b'DatabaseConnected="true"'),
    (b'AttachedLibraryCount="1"',b'AttachedLibraryCount="2"'),
    (b'ProgramUnitType="4"',b'ProgramUnitType="3"')])
def test_pll_partial_or_changed_source_blocked(old,new):
    with pytest.raises(ExtractionError):
        validate_pll_xml(library_xml().replace(old,new))
