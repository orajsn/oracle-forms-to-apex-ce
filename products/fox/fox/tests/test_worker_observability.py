"""Local-only heartbeat/fault tests; no credentials or provider calls."""
from contextlib import contextmanager
import json
from pathlib import Path
import sqlite3
from unittest.mock import Mock

from fastapi.testclient import TestClient
import pytest

from fox.worker_observability import WorkerMonitor, observed_poll
from fox.app import create_app, password_hash


JOB = 'fox-' + 'a' * 20
SECRET = 'synthetic-secret-marker-never-publish'


@pytest.fixture
def monitored():
    now = [0.0]
    events = []
    monitor = WorkerMonitor(clock=lambda: now[0], utc=lambda: '2026-10-17T00:00:00+00:00', emit=events.append)
    monitor.started()
    return monitor, now, events


@pytest.fixture
def queue(tmp_path):
    database = tmp_path / 'synthetic.sqlite3'
    @contextmanager
    def db():
        connection = sqlite3.connect(database)
        connection.row_factory = sqlite3.Row
        try:
            with connection:
                yield connection
        finally:
            connection.close()
    with db() as connection:
        connection.execute('CREATE TABLE runs(id TEXT PRIMARY KEY,state TEXT,created REAL)')
    return db, tmp_path


def enqueue(db, state='QUEUED', job=JOB):
    with db() as connection:
        connection.execute('INSERT INTO runs VALUES(?,?,?)', (job, state, 1.0))


def test_idle_heartbeat_is_fresh_and_rate_limited(monitored, queue):
    monitor, now, events = monitored
    db, root = queue
    process = Mock()
    for _ in range(12):
        observed_poll(process, db, root, monitor)
        now[0] += 2
    process.assert_not_called()
    snapshot = monitor.snapshot(thread_alive=True)
    assert snapshot['healthy'] is True
    assert snapshot['state'] == 'idle'
    assert snapshot['polls_completed'] == 12
    assert len([event for event in events if event['event'] == 'heartbeat']) == 1


def test_db_poll_failure_is_visible_and_secret_free(monitored):
    monitor, _, events = monitored
    def db():raise sqlite3.OperationalError(SECRET)
    process = Mock()
    observed_poll(process, db, Path('.'), monitor)
    process.assert_not_called()
    snapshot = monitor.snapshot(thread_alive=True)
    assert snapshot['healthy'] is False
    assert snapshot['error_code'] == 'WORKER_POLL_ERROR'
    assert events[-1]['event'] == 'worker_error'
    assert SECRET not in json.dumps([snapshot, events])
    # An attempted next poll is not itself evidence of recovery.
    monitor.polling()
    assert monitor.snapshot(thread_alive=True)['healthy'] is False


def test_successful_poll_recovers_after_db_error(monitored, queue):
    monitor, _, events = monitored
    monitor.failed('WORKER_POLL_ERROR')
    db, root = queue
    observed_poll(Mock(), db, root, monitor)
    assert monitor.snapshot(thread_alive=True)['healthy'] is True
    assert monitor.snapshot(thread_alive=True)['errors_observed'] == 1
    assert events[-1]['event'] == 'worker_recovered'


def test_stale_idle_worker_is_detected_without_io(monitored):
    monitor, now, _ = monitored
    now[0] = 16
    snapshot = monitor.snapshot(thread_alive=True)
    assert snapshot['healthy'] is False
    assert snapshot['error_code'] == 'WORKER_HEARTBEAT_STALE'


def test_dead_worker_is_detected_even_with_fresh_heartbeat(monitored):
    monitor, _, _ = monitored
    assert monitor.snapshot(thread_alive=False)['error_code'] == 'WORKER_NOT_RUNNING'


def test_busy_job_has_separate_overdue_threshold_and_no_action(monitored):
    monitor, now, events = monitored
    monitor.busy(JOB)
    now[0] = 600
    assert monitor.snapshot(thread_alive=True)['healthy'] is True
    now[0] = 3601
    snapshot = monitor.snapshot(thread_alive=True)
    assert snapshot['healthy'] is False
    assert snapshot['error_code'] == 'WORKER_JOB_OVERDUE'
    assert events[-1]['event'] == 'job_started'  # Health read never cancels/retries.
    assert 'job_id' not in snapshot


@pytest.mark.parametrize('outcome', ['QA_REQUIRED', 'REVIEW_REQUIRED', 'ATTENTION'])
def test_job_outcome_is_observed_without_changing_worker_contract(monitored, queue, outcome):
    monitor, _, events = monitored
    db, root = queue
    enqueue(db)
    def process(factory, job_root):
        assert job_root == root
        with factory() as connection:
            connection.execute('UPDATE runs SET state=? WHERE id=?', (outcome, JOB))
        return None  # Existing process_one contract remains unchanged.
    observed_poll(process, db, root, monitor)
    snapshot = monitor.snapshot(thread_alive=True)
    assert snapshot['healthy'] is True
    assert snapshot['jobs_completed'] == 1
    assert snapshot['last_outcome'] == outcome
    assert events[-1]['event'] == 'job_outcome'
    assert events[-1]['outcome'] == outcome
    assert events[-1]['job_id'] == JOB


def test_escaped_worker_exception_is_not_silently_swallowed(monitored, queue):
    monitor, _, events = monitored
    db, root = queue
    enqueue(db)
    def process(*args):raise RuntimeError(SECRET)
    observed_poll(process, db, root, monitor)
    assert monitor.snapshot(thread_alive=True)['error_code'] == 'WORKER_EXECUTION_ERROR'
    assert SECRET not in json.dumps(events)


def test_orphaned_processing_requires_reconciliation_without_replay(monitored, queue):
    monitor, _, events = monitored
    db, root = queue
    enqueue(db, state='PROCESSING')
    process = Mock()
    observed_poll(process, db, root, monitor)
    process.assert_not_called()
    assert monitor.snapshot(thread_alive=True)['error_code'] == 'WORKER_RECONCILIATION_REQUIRED'
    with db() as connection:
        assert connection.execute('SELECT state FROM runs').fetchone()[0] == 'PROCESSING'


def test_incomplete_return_does_not_fake_job_success(monitored, queue):
    monitor, _, _ = monitored
    db, root = queue
    enqueue(db)
    observed_poll(lambda *args: None, db, root, monitor)
    assert monitor.snapshot(thread_alive=True)['error_code'] == 'WORKER_INCOMPLETE_OUTCOME'


def test_untrusted_job_identifier_is_not_logged(monitored):
    monitor, _, events = monitored
    monitor.busy(SECRET)
    monitor.failed('WORKER_EXECUTION_ERROR', SECRET)
    assert all('job_id' not in event for event in events)
    assert SECRET not in json.dumps(events)


def test_disabled_worker_explicitly_preserves_read_only_api_health():
    monitor = WorkerMonitor(enabled=False, emit=lambda event: None)
    snapshot = monitor.snapshot(thread_alive=False)
    assert snapshot['healthy'] is True
    assert snapshot['state'] == 'disabled'
    assert snapshot['enabled'] is False


def test_health_endpoint_preserves_healthy_keys_and_headers(tmp_path, monkeypatch):
    monkeypatch.setenv('FOX_PASSWORD_HASH', password_hash('synthetic-test-password'))
    app = create_app(tmp_path, enable_worker=False)
    with TestClient(app) as client:
        response = client.get('/api/health')
    assert response.status_code == 200
    assert {key: response.json()[key] for key in ('status', 'product', 'version')} == {
        'status': 'ok', 'product': 'FOX', 'version': '0.1.0'}
    assert response.json()['worker']['state'] == 'disabled'
    assert response.headers['cache-control'] == 'no-store'


@pytest.mark.parametrize('error_code', ['WORKER_POLL_ERROR', 'WORKER_HEARTBEAT_STALE', 'WORKER_NOT_RUNNING'])
def test_health_endpoint_reports_unavailable_worker_without_raw_detail(tmp_path, monkeypatch, error_code):
    monkeypatch.setenv('FOX_PASSWORD_HASH', password_hash('synthetic-test-password'))
    app = create_app(tmp_path, enable_worker=False)
    snapshot = {'schema_version': 1, 'enabled': True, 'healthy': False,
                'state': 'error', 'error_code': error_code}
    monkeypatch.setattr(app.state.worker_monitor, 'snapshot', lambda **kwargs: snapshot)
    with TestClient(app) as client:
        response = client.get('/api/health')
    assert response.status_code == 503
    assert response.json()['status'] == 'degraded'
    assert response.json()['product'] == 'FOX'
    assert response.json()['worker']['error_code'] == error_code
    assert 'traceback' not in response.text.lower()


def test_thread_loop_uses_observer_errors_instead_of_swallowing(tmp_path, monkeypatch):
    import threading
    import fox.worker_observability as module
    monkeypatch.setenv('FOX_PASSWORD_HASH', password_hash('synthetic-test-password'))
    completed = threading.Event()
    def failing_poll(process, db, root, monitor):
        monitor.failed('WORKER_POLL_ERROR')
        completed.set()
    monkeypatch.setattr(module, 'observed_poll', failing_poll)
    app = create_app(tmp_path, enable_worker=True)
    with TestClient(app) as client:
        assert completed.wait(2)
        response = client.get('/api/health')
        assert response.status_code == 503
        assert response.json()['worker']['error_code'] == 'WORKER_POLL_ERROR'
