"""Local host-runner tests with explicit synthetic native output."""
import json

from fox.hosted_forms_jobs import HostedFormsJobs
from fox.native_preparation import prepare_native_source
from fox import hosted_forms_worker as worker
from test_native_preparation import factory


def queue(tmp_path):
    q = HostedFormsJobs(tmp_path / 'queue')
    q.submit(request_id='one', project_id='synthetic-project', owner_id='synthetic-user',
             source_set_sha256='a' * 64, name='synthetic.fmb', raw=b'SYNTHETIC_NOT_REAL_FMB')
    return q


def test_bounded_batch_uses_preparation_once_and_never_replays(tmp_path):
    q = queue(tmp_path)
    calls = []
    def prepare(source, output, **kw):
        calls.append(1)
        return prepare_native_source(source, output, backend_factory=factory(), **kw)
    assert worker.run_once(q, prepare) == [{'job_id': 'one', 'status': 'PREPARED_REDACTED_REVIEW_REQUIRED'}]
    assert worker.run_once(q, prepare) == []
    assert calls == [1]


def test_missing_native_tools_do_not_claim_queued_jobs(tmp_path, monkeypatch, capsys):
    q = queue(tmp_path)
    class Unavailable:
        def __init__(self, *a, **kw):
            pass
        def check(self):
            raise ValueError('SYNTHETIC_PRIVATE_PATH_OR_ERROR')
    monkeypatch.setattr(worker, 'LinuxOracleFormsBackend', Unavailable)
    result = worker.main(['--queue-root', str(q.root), '--oracle-home', str(tmp_path / 'oracle'),
                          '--java-home', str(tmp_path / 'java'), '--temp-root', str(tmp_path / 'tmp')])
    assert result == 1
    assert q.list_pending() == ['one']
    output = capsys.readouterr().out
    assert json.loads(output) == {'status': 'NATIVE_TOOLS_NOT_READY', 'jobs_claimed': 0}
    assert 'SYNTHETIC_PRIVATE_PATH_OR_ERROR' not in output


def test_failed_job_is_retained_and_not_automatically_reclaimed(tmp_path):
    q = queue(tmp_path)
    def fail(*args, **kwargs):
        raise ValueError('Private tool diagnostic not for stdout')
    result = worker.run_once(q, fail)
    assert result == [{'job_id': 'one', 'status': 'BLOCKED'}]
    assert worker.run_once(q, fail) == []
    assert (q.root / 'one/input/synthetic.fmb').read_bytes() == b'SYNTHETIC_NOT_REAL_FMB'
