"""Local synthetic queue tests: real policy gates, no Oracle/live-flow claim."""
import json
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor

import pytest

from fox import hosted_forms_jobs as jobs
from fox.extractor import NS, digest
from fox.native_preparation import prepare_native_source

RAW = b'SYNTHETIC_FMB_NOT_ORACLE'
BINDING = {'project_id': 'project-1', 'owner_id': 'admin.name@example.test',
           'source_set_sha256': 'a' * 64, 'selected_source_set_id': None}


@pytest.fixture
def queue(tmp_path):
    return jobs.HostedFormsJobs(tmp_path / 'q')


def submit(queue, **changes):
    args = dict(BINDING, request_id='request-1', name='synthetic.fmb', raw=RAW)
    args.update(changes)
    return queue.submit(**args)


def status(queue, job_id='request-1'):
    return queue.status(job_id, project_id=BINDING['project_id'], owner_id=BINDING['owner_id'])


def result(queue, **changes):
    return queue.read_result('request-1', **(BINDING | changes))


class SyntheticBackend:
    name = 'synthetic-test-only'

    def __init__(self, mode):
        self.dump_mode = mode

    def extract(self, source, destination):
        xml = f'<Module xmlns="{NS[1:-1]}"><FormModule Name="SYNTHETIC"><Block Name="B"><Item Name="I"/></Block></FormModule></Module>'.encode()
        target = destination / (source.stem + '_fmb.xml')
        target.write_bytes(xml)
        return target


def prepare(source, output_root, *, job_id):
    # Actual deterministic native-preparation pipeline, synthetic backend only.
    assert source.parent != output_root
    assert not output_root.is_relative_to(source.parent)
    assert not source.parent.is_relative_to(output_root)
    return prepare_native_source(source, output_root, job_id=job_id, backend_factory=SyntheticBackend)


def test_idempotent_submission_retains_original_and_binding(queue):
    first = submit(queue)
    assert first == submit(queue)
    assert first['status'] == 'QUEUED'
    manifest_path = queue.root / 'request-1/input-manifest.json'
    before = manifest_path.read_bytes()
    manifest = json.loads(before)
    assert manifest['source'] == {'name': 'synthetic.fmb', 'sha256': digest(RAW), 'bytes': len(RAW)}
    assert (queue.root / 'request-1/input/synthetic.fmb').read_bytes() == RAW
    assert all(manifest[key] == value for key, value in BINDING.items())
    assert queue.list_pending() == ['request-1']
    assert queue.list_jobs(project_id=BINDING['project_id'], owner_id=BINDING['owner_id']) == [first]
    assert queue.list_jobs(project_id='other', owner_id=BINDING['owner_id']) == []
    assert manifest_path.read_bytes() == before


@pytest.mark.parametrize('changes', [dict(raw=b'CHANGED'), dict(name='other.fmb'),
    dict(project_id='other'), dict(owner_id='other'), dict(source_set_sha256='b' * 64),
    dict(selected_source_set_id='selected-1')])
def test_idempotency_conflicts_compare_all_binding_fields(queue, changes):
    submit(queue)
    with pytest.raises(jobs.HostedFormsJobConflict):
        submit(queue, **changes)


@pytest.mark.parametrize('changes', [dict(request_id='../bad'), dict(request_id='CON'),
    dict(request_id='a' * 81), dict(name='../test.fmb'), dict(name='NUL.fmb'),
    dict(name='file.fmb:stream'), dict(name='file.fmb.'), dict(name='file.xml'),
    dict(name='file.pll'), dict(name='file.zip'), dict(raw=b''), dict(raw='text'),
    dict(source_set_sha256='bad'), dict(project_id='..'), dict(owner_id='a\nb'),
    dict(selected_source_set_id='../bad')])
def test_unsafe_submission_never_accepts(queue, changes):
    with pytest.raises(jobs.HostedFormsJobError):
        submit(queue, **changes)
    assert not queue.root.exists()


def test_explicit_absolute_local_root_and_limits(tmp_path):
    for value in ('relative', tmp_path / '..' / 'q', '//server/share'):
        with pytest.raises(jobs.HostedFormsJobError):
            jobs.HostedFormsJobs(value)
    queue = jobs.HostedFormsJobs(tmp_path / 'q', max_raw_bytes=3)
    with pytest.raises(jobs.HostedFormsJobError):
        submit(queue)
    assert not queue.root.exists()


def test_pending_and_retained_raw_quotas_preserve_existing(tmp_path):
    queue = jobs.HostedFormsJobs(tmp_path / 'pending', max_pending=1)
    submit(queue)
    with pytest.raises(jobs.HostedFormsJobConflict, match='capacity'):
        submit(queue, request_id='request-2')
    assert submit(queue)['status'] == 'QUEUED'  # retries don't consume quota
    queue = jobs.HostedFormsJobs(tmp_path / 'retained', max_retained_raw_bytes=len(RAW))
    submit(queue)
    queue.process('request-1', prepare=lambda *a, **k: (_ for _ in ()).throw(ValueError('PRIVATE')))
    with pytest.raises(jobs.HostedFormsJobConflict, match='capacity'):
        submit(queue, request_id='request-2')


def test_process_and_internal_result_revalidate_actual_policy(queue):
    submit(queue)
    assert queue.process('request-1', prepare=prepare)['status'] == jobs.PREPARED
    checked = result(queue)
    assert set(checked) == {'document', 'receipt'}
    assert set(checked['document']) == {'name', 'sha256', 'bytes', 'text'}
    assert checked['document']['sha256'] == checked['receipt']['redacted_sha256']
    assert not status(queue)['model_submission_allowed']
    assert queue.list_pending() == []
    assert 'text' not in json.dumps(status(queue))
    assert str(queue.root) not in json.dumps(status(queue))


@pytest.mark.parametrize('changes', [dict(project_id='other'), dict(owner_id='other'),
    dict(source_set_sha256='b' * 64), dict(selected_source_set_id='selected-2')])
def test_read_result_binds_current_source_selection(queue, changes):
    submit(queue)
    queue.process('request-1', prepare=prepare)
    with pytest.raises(jobs.HostedFormsJobError):
        result(queue, **changes)


def test_selected_source_version_matches_exactly(queue):
    submit(queue, selected_source_set_id='selected-1')
    queue.process('request-1', prepare=prepare)
    with pytest.raises(jobs.HostedFormsJobError):
        result(queue)
    assert result(queue, selected_source_set_id='selected-1')['document']['name'] == 'synthetic_fmb.xml'


def test_duplicate_claim_never_invokes_second_callback(queue):
    submit(queue)
    calls = []

    def callback(*args, **kwargs):
        calls.append(1)
        return prepare(*args, **kwargs)

    with ThreadPoolExecutor(max_workers=2) as pool:
        outputs = list(pool.map(lambda _: queue.process('request-1', prepare=callback), range(2)))
    assert len(calls) == 1
    assert {row['status'] for row in outputs} <= {jobs.PREPARED, 'PROCESSING_UNKNOWN'}
    assert queue.process('request-1', prepare=callback)['status'] == jobs.PREPARED
    assert len(calls) == 1


def test_interrupted_claim_is_unknown_and_never_replayed(queue):
    submit(queue)

    def interrupted(*args, **kwargs):
        raise KeyboardInterrupt()

    with pytest.raises(KeyboardInterrupt):
        queue.process('request-1', prepare=interrupted)
    assert status(queue)['status'] == 'PROCESSING_UNKNOWN'
    assert queue.list_pending() == []
    assert queue.process('request-1', prepare=lambda *a, **k: pytest.fail('must not replay'))['status'] == 'PROCESSING_UNKNOWN'
    with pytest.raises(jobs.HostedFormsJobError):
        result(queue)


@pytest.mark.parametrize('marker', ['claim.json', 'result.json', 'failure.json'])
def test_partial_crash_markers_remain_claimed_unknown(queue, marker):
    submit(queue)
    job = queue.root / 'request-1'
    (job / 'claim.json').write_bytes(b'')
    (job / marker).write_bytes(b'')
    assert status(queue)['status'] == 'PROCESSING_UNKNOWN'
    assert queue.list_pending() == []
    assert queue.process('request-1', prepare=lambda *a, **k: pytest.fail('replay'))['status'] == 'PROCESSING_UNKNOWN'


def test_native_failure_is_body_free_and_never_replayed(queue, capsys):
    submit(queue)

    def failed(*args, **kwargs):
        raise RuntimeError('PRIVATE_NATIVE_ERROR source text password=NEVER_ECHO')

    assert queue.process('request-1', prepare=failed)['status'] == 'BLOCKED'
    assert queue.process('request-1', prepare=lambda *a, **k: pytest.fail('replay'))['status'] == 'BLOCKED'
    assert 'PRIVATE' not in json.dumps(status(queue))
    assert not capsys.readouterr().out


@pytest.mark.parametrize('target', ['input/synthetic.fmb', 'input-manifest.json', 'ready.json'])
def test_changed_input_or_manifest_is_rejected_before_processing(queue, target):
    submit(queue)
    (queue.root / 'request-1' / target).write_bytes(b'CHANGED')
    with pytest.raises(jobs.HostedFormsJobError):
        queue.process('request-1', prepare=lambda *a, **k: pytest.fail('changed input'))


@pytest.mark.parametrize('target', ['manifest.json', 'redacted/synthetic_fmb.xml', 'redacted/redaction-receipt.json'])
def test_prepared_manifest_xml_or_receipt_tamper_is_rejected(queue, target):
    submit(queue)
    queue.process('request-1', prepare=prepare)
    (queue.root / 'request-1/prepared/request-1' / target).write_bytes(b'CHANGED')
    with pytest.raises(jobs.HostedFormsJobError):
        result(queue)


def test_manifest_resealed_receipt_tamper_still_hits_strict_policy(queue):
    submit(queue)

    def tampered(source, output, *, job_id):
        prepared = prepare(source, output, job_id=job_id)
        path = prepared / 'redacted/redaction-receipt.json'
        receipt = json.loads(path.read_bytes())
        receipt['safety']['model_submission_allowed'] = True
        path.write_text(json.dumps(receipt), encoding='utf-8')
        manifest_path = prepared / 'manifest.json'
        manifest = json.loads(manifest_path.read_bytes())
        for entry in manifest['files']:
            if entry['role'] == 'redaction_receipt':
                entry.update(sha256=digest(path.read_bytes()), bytes=len(path.read_bytes()))
        manifest_path.write_text(json.dumps(manifest), encoding='utf-8')
        return prepared

    assert queue.process('request-1', prepare=tampered)['status'] == 'BLOCKED'


@pytest.mark.parametrize('bad_path', ['../escape.xml', '/absolute.xml', 'C:/outside.xml', 'redacted\\x.xml'])
def test_prepared_manifest_cannot_escape_job(queue, bad_path):
    submit(queue)

    def escaped(source, output, *, job_id):
        prepared = prepare(source, output, job_id=job_id)
        path = prepared / 'manifest.json'
        manifest = json.loads(path.read_bytes())
        manifest['files'][0]['path'] = bad_path
        path.write_text(json.dumps(manifest), encoding='utf-8')
        return prepared

    assert queue.process('request-1', prepare=escaped)['status'] == 'BLOCKED'


def test_symlink_input_and_root_are_rejected(tmp_path):
    outside = tmp_path / 'outside'
    outside.mkdir()
    link = tmp_path / 'linked'
    try:
        link.symlink_to(outside, target_is_directory=True)
    except OSError:
        pytest.skip('Windows symlink privilege unavailable')
    with pytest.raises(jobs.HostedFormsJobError):
        jobs.HostedFormsJobs(link / 'q')
    queue = jobs.HostedFormsJobs(tmp_path / 'q')
    submit(queue)
    original = queue.root / 'request-1/input/synthetic.fmb'
    retained = outside / 'same.fmb'
    original.rename(retained)
    original.symlink_to(retained)
    with pytest.raises(jobs.HostedFormsJobError):
        queue.process('request-1', prepare=prepare)


def test_unknown_or_incomplete_job_cannot_be_resubmitted(queue):
    queue.root.mkdir()
    (queue.root / 'request-1').mkdir()
    with pytest.raises(jobs.HostedFormsJobConflict):
        submit(queue)
    with pytest.raises(jobs.HostedFormsJobError):
        status(queue, 'unknown')
