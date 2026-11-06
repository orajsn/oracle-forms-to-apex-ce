"""Synthetic native outputs only. Real derivation/redaction/validation, no Oracle proof."""
import json
import os
from pathlib import Path
import stat
from xml.sax.saxutils import quoteattr

import pytest

from fox import native_preparation as prep
from fox.extractor import ExtractionError, NS, digest
from fox.intake import checked_source
from fox.prototype_source import validate_redacted_prototype_source

PRIVATE_LITERAL = 'SYNTHETIC_PRIVATE_LITERAL_DO_NOT_FORWARD'
CODE = "BEGIN INSERT INTO AUDIT_LOG VALUES (:B.I, '" + PRIVATE_LITERAL + "', 97); GO_ITEM('B.I'); END;"


def pair(code=CODE):
    original = (f'<Module xmlns="{NS[1:-1]}"><FormModule Name="SYNTHETIC"><Block Name="B">'
                '<Item Name="I"/><Trigger Name="SAVE" TriggerText=' + quoteattr(code) +
                '/></Block></FormModule></Module>').encode()
    expanded = (f'<Module xmlns="{NS[1:-1]}" xmlns:S_overridden="{NS[1:-1]}" xmlns:S_default="{NS[1:-1]}">'
                '<FormModule S_overridden:Name="SYNTHETIC"><Block S_overridden:Name="B" S_default:DatabaseBlock="false">'
                '<Item S_overridden:Name="I" S_default:ItemType="Text Item" S_default:DataType="Char" '
                'S_default:MaximumLength="80"/><Trigger S_overridden:Name="SAVE" TriggerText=' + quoteattr(code) +
                '/></Block></FormModule></Module>').encode()
    return {'OVERRIDDEN': original, 'ALL': expanded}


class FakeNative:
    name = 'fake-native-tests-only'

    def __init__(self, mode, outputs, calls):
        self.dump_mode, self.outputs, self.calls = mode, outputs, calls

    def extract(self, source, destination):
        self.calls.append((self.dump_mode, source, source.read_bytes(), destination))
        target = destination / (source.stem + '_fmb.xml')
        target.write_bytes(self.outputs[self.dump_mode])
        return target


@pytest.fixture
def source(tmp_path):
    folder = tmp_path / 'selected'
    folder.mkdir()
    path = folder / 'synthetic.fmb'
    path.write_bytes(b'SYNTHETIC_NOT_A_REAL_ORACLE_BINARY')
    return path


def factory(outputs=None, calls=None):
    outputs = pair() if outputs is None else outputs
    calls = [] if calls is None else calls
    return lambda mode: FakeNative(mode, outputs, calls)


def run(source, tmp_path, **kwargs):
    return prep.prepare_native_source(source, tmp_path / 'jobs', job_id='synthetic-job',
                                      backend_factory=kwargs.pop('backend_factory', factory()), **kwargs)


def blocked(tmp_path, stage=None):
    job = tmp_path / 'jobs/synthetic-job'
    status = json.loads((job / 'status.json').read_bytes())
    assert status['status'] == 'BLOCKED'
    if stage:
        assert status['stage'] == stage
    assert not (job / 'manifest.json').exists()
    return job


def test_real_policy_pipeline_preserves_raw_pair_and_masks_dml(source, tmp_path):
    original_binary, original_xml = source.read_bytes(), pair()['OVERRIDDEN']
    with pytest.raises(ValueError, match='DML cannot'):
        checked_source('synthetic_fmb.xml', original_xml)
    calls = []
    job = run(source, tmp_path, backend_factory=factory(calls=calls))
    assert [call[0] for call in calls] == ['OVERRIDDEN', 'ALL']
    assert all(call[1] == source and call[2] == original_binary for call in calls)
    assert source.read_bytes() == original_binary
    assert list(source.parent.iterdir()) == [source]
    assert (job / 'original/synthetic.fmb').read_bytes() == original_binary
    for mode, raw in pair().items():
        assert (job / 'native' / mode.lower() / 'synthetic_fmb.xml').read_bytes() == raw
    effective = (job / 'effective/synthetic_fmb.xml').read_bytes()
    assert PRIVATE_LITERAL.encode() in effective and b'DatabaseBlock="false"' in effective
    redacted = (job / 'redacted/synthetic_fmb.xml').read_bytes()
    receipt = json.loads((job / 'redacted/redaction-receipt.json').read_bytes())
    assert PRIVATE_LITERAL.encode() not in redacted and b'97' not in redacted
    assert b'FOX_ANALYSIS_ONLY_NON_EXECUTABLE' in redacted and b'INSERT INTO AUDIT_LOG' in redacted
    checked = validate_redacted_prototype_source('synthetic_fmb.xml', redacted, receipt)
    assert checked['sha256'] == digest(redacted)
    with pytest.raises(ValueError, match='DML cannot'):
        checked_source('synthetic_fmb.xml', redacted)
    manifest = json.loads((job / 'manifest.json').read_bytes())
    assert manifest['status'] == prep.STATUS == 'PREPARED_REDACTED_REVIEW_REQUIRED'
    assert json.loads((job / 'status.json').read_bytes())['status'] == prep.STATUS
    assert manifest['source'] == {'name': source.name, 'sha256': digest(original_binary), 'bytes': len(original_binary)}
    assert len(manifest['files']) == 7
    for record in manifest['files']:
        raw = (job / record['path']).read_bytes()
        assert record['sha256'] == digest(raw) and record['bytes'] == len(raw)
    assert {row['input_sha256'] for row in manifest['tool_runs']} == {digest(original_binary)}
    assert manifest['redacted_source']['sha256'] == checked['sha256']
    body_free = json.dumps(manifest)
    for excluded in (PRIVATE_LITERAL, CODE, 'TriggerText', '"redacted_xml":', '"text":',
                     'INSERT INTO AUDIT_LOG', str(source.parent)):
        assert excluded not in body_free
    assert manifest['safety']['original_unchanged'] and manifest['safety']['raw_sources_local_only']
    assert not any(manifest['safety'][key] for key in ('network_calls', 'model_calls', 'database_calls',
                    'model_submission_allowed', 'import_allowed', 'native_generation_allowed', 'business_accepted'))
    assert any('No DDL was supplied or verified' in value for value in manifest['limitations'])


def test_default_factory_constructs_linux_backends_with_explicit_homes_and_modes(source, tmp_path, monkeypatch):
    calls, construction = [], []

    def construct(home, java_home, *, dump_mode):
        construction.append((home, java_home, dump_mode))
        return FakeNative(dump_mode, pair(), calls)

    monkeypatch.setattr(prep, 'LinuxOracleFormsBackend', construct)
    home, java_home = tmp_path / 'oracle', tmp_path / 'jdk'
    job = prep.prepare_native_source(source, tmp_path / 'jobs', oracle_home=home, java_home=java_home)
    assert construction == [(home, java_home, 'OVERRIDDEN'), (home, java_home, 'ALL')]
    assert json.loads((job / 'status.json').read_bytes())['status'] == prep.STATUS


def test_same_source_produces_deterministic_body_free_manifest(source, tmp_path):
    manifests = []
    for name in ('first', 'second'):
        job = prep.prepare_native_source(source, tmp_path / name, job_id='same-job-id', backend_factory=factory())
        manifests.append((job / 'manifest.json').read_bytes())
    assert manifests[0] == manifests[1]


@pytest.mark.parametrize('extension', ['.pll', '.mmb', '.olb', '.xml', '.sql', '.zip'])
def test_other_formats_are_explicitly_unsupported_not_silently_ignored(source, tmp_path, extension):
    other = source.with_suffix(extension)
    other.write_bytes(b'SYNTHETIC_OTHER_INPUT')
    with pytest.raises(prep.NativePreparationError, match='one FMB file only'):
        run(other, tmp_path)
    assert not (tmp_path / 'jobs').exists()


@pytest.mark.parametrize('job_id', ['../unsafe', '', False, 'a' * 81, 'bad/path'])
def test_unsafe_job_id_rejected_before_output_creation(source, tmp_path, job_id):
    with pytest.raises(prep.NativePreparationError):
        prep.prepare_native_source(source, tmp_path / 'jobs', job_id=job_id, backend_factory=factory())
    assert not (tmp_path / 'jobs').exists()


def test_existing_job_is_never_overwritten(source, tmp_path):
    job = run(source, tmp_path)
    original = (job / 'manifest.json').read_bytes()
    with pytest.raises(prep.NativePreparationError):
        run(source, tmp_path)
    assert (job / 'manifest.json').read_bytes() == original


def test_output_cannot_be_inside_original_directory(source):
    with pytest.raises(prep.NativePreparationError, match='separate non-nested'):
        prep.prepare_native_source(source, source.parent / 'jobs', backend_factory=factory())
    assert list(source.parent.iterdir()) == [source]


@pytest.mark.parametrize('kwargs', [{}, {'oracle_home': 'relative-home', 'java_home': 'relative-java'},
                                  {'backend_factory': 1}])
def test_missing_or_unsafe_configuration_is_blocked(source, tmp_path, kwargs):
    with pytest.raises(prep.NativePreparationError):
        prep.prepare_native_source(source, tmp_path / 'jobs', **kwargs)
    assert not (tmp_path / 'jobs').exists()


@pytest.mark.parametrize('mode', ['OVERRIDDEN', 'ALL'])
def test_tool_failure_preserves_private_evidence_and_exposes_no_native_text(source, tmp_path, capsys, mode):
    calls, original = [], source.read_bytes()

    def configured(dump_mode):
        backend = FakeNative(dump_mode, pair(), calls)
        if dump_mode == mode:
            backend.extract = lambda *args: (_ for _ in ()).throw(ExtractionError('PRIVATE_NATIVE_DIAGNOSTIC ' + PRIVATE_LITERAL))
        return backend

    with pytest.raises(prep.NativePreparationError) as error:
        run(source, tmp_path, backend_factory=configured)
    job = blocked(tmp_path, 'NATIVE_' + mode)
    assert (job / 'original/synthetic.fmb').read_bytes() == original == source.read_bytes()
    assert PRIVATE_LITERAL not in str(error.value) and 'PRIVATE_NATIVE' not in str(error.value)
    assert PRIVATE_LITERAL not in (job / 'status.json').read_text()
    assert capsys.readouterr() == ('', '')
    assert not list((job / 'redacted').iterdir())


def test_original_mutation_between_exports_cannot_bind_a_false_pair(source, tmp_path):
    original = source.read_bytes()

    def configured(mode):
        backend = FakeNative(mode, pair(), [])
        real_extract = backend.extract

        def extract(path, destination):
            result = real_extract(path, destination)
            if mode == 'OVERRIDDEN':
                source.write_bytes(b'SYNTHETIC_MUTATION_BY_TEST')
            return result

        backend.extract = extract
        return backend

    with pytest.raises(prep.NativePreparationError):
        run(source, tmp_path, backend_factory=configured)
    job = blocked(tmp_path, 'NATIVE_OVERRIDDEN')
    assert (job / 'original/synthetic.fmb').read_bytes() == original


def test_wrong_dump_mode_declared_by_factory_blocks_before_second_extract(source, tmp_path):
    calls = []
    with pytest.raises(prep.NativePreparationError):
        run(source, tmp_path, backend_factory=lambda mode: FakeNative('OVERRIDDEN', pair(), calls))
    blocked(tmp_path, 'NATIVE_ALL')
    assert [call[0] for call in calls] == ['OVERRIDDEN']


@pytest.mark.parametrize('fault', ['mismatch', 'malformed', 'credentials'])
def test_real_derivation_gates_block_invalid_pair_without_releasing_redacted_output(source, tmp_path, fault):
    outputs = pair()
    if fault == 'mismatch':
        outputs['ALL'] = outputs['ALL'].replace(b':Name="B"', b':Name="OTHER"')
    elif fault == 'malformed':
        outputs['ALL'] = b'<invalid'
    else:
        outputs = pair("BEGIN password := 'SYNTHETIC_PRIVATE_PASSWORD'; END;")
    with pytest.raises(prep.NativePreparationError):
        run(source, tmp_path, backend_factory=factory(outputs))
    job = blocked(tmp_path)
    assert not list((job / 'redacted').iterdir())
    assert (job / 'native/overridden/synthetic_fmb.xml').read_bytes() == outputs['OVERRIDDEN']


def test_backend_returning_outside_artifact_is_rejected(source, tmp_path):
    external = tmp_path / 'outside.xml'
    external.write_bytes(pair()['OVERRIDDEN'])

    def configured(mode):
        backend = FakeNative(mode, pair(), [])
        backend.extract = lambda *args: external
        return backend

    with pytest.raises(prep.NativePreparationError):
        run(source, tmp_path, backend_factory=configured)
    blocked(tmp_path, 'NATIVE_OVERRIDDEN')
    assert external.read_bytes() == pair()['OVERRIDDEN']


@pytest.mark.parametrize('kind', ['symlink', 'hardlink'])
def test_linked_native_xml_never_enters_prepared_prototype(source, tmp_path, kind):
    external = tmp_path / 'external.xml'
    external.write_bytes(pair()['OVERRIDDEN'])
    if kind == 'symlink':
        probe = tmp_path / 'symlink-probe'
        try:
            probe.symlink_to(external)
        except OSError:
            pytest.skip('Host cannot create symlinks; repeat on Linux.')

    def configured(mode):
        backend = FakeNative(mode, pair(), [])

        def extract(path, destination):
            target = destination / 'synthetic_fmb.xml'
            if kind == 'symlink':
                target.symlink_to(external)
            else:
                os.link(external, target)
            return target

        backend.extract = extract
        return backend

    with pytest.raises(prep.NativePreparationError):
        run(source, tmp_path, backend_factory=configured)
    blocked(tmp_path, 'NATIVE_OVERRIDDEN')


@pytest.mark.skipif(os.name == 'nt', reason='POSIX host permission check, not Windows ACL proof')
def test_private_job_and_original_modes(source, tmp_path):
    job = run(source, tmp_path)
    assert stat.S_IMODE(job.stat().st_mode) == 0o700
    assert stat.S_IMODE((job / 'original/synthetic.fmb').stat().st_mode) == 0o600
