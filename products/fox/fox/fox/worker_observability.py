"""Secret-free, in-process health for FOX's single conversion worker.

Health contract v1: healthy/disabled workers retain /api/health HTTP 200 with
status=ok; failed polling, an absent/stale worker, overdue work, or an orphaned
PROCESSING row produce HTTP 503/status=degraded. This is worker availability,
not OPAF/APEX connectivity or business acceptance. No health read calls a provider.

Idle/polling heartbeat threshold: 15 seconds. Active-job threshold: 3600 seconds,
since a model/SQLcl operation may legitimately block one poll for minutes. The
busy threshold reports overdue work only; it never cancels, retries or requeues.
Job outcomes and errors are structured enum-only logs. Normal idle heartbeats
are logged at most once per 30 seconds. No exception object/text, database row
content, source, credentials, username or customer metadata enters these logs.
"""
from __future__ import annotations

from datetime import datetime, timezone
import json
import logging
import re
import threading
import time


LOGGER = logging.getLogger('fox.worker.health')
if not LOGGER.handlers:
    LOGGER.addHandler(logging.StreamHandler())
LOGGER.setLevel(logging.INFO)
LOGGER.propagate = False

_JOB = re.compile(r'fox-[a-f0-9]{20}\Z')
_OUTCOMES = {'QA_REQUIRED', 'REVIEW_REQUIRED', 'VERIFIED', 'ACCEPTED', 'ATTENTION'}
_ERRORS = {'WORKER_POLL_ERROR', 'WORKER_EXECUTION_ERROR', 'WORKER_OUTCOME_READ_ERROR',
           'WORKER_INCOMPLETE_OUTCOME', 'WORKER_RECONCILIATION_REQUIRED'}


def _utc():
    return datetime.now(timezone.utc).isoformat()


def _emit(event):
    # All fields are assembled from controlled constants/scalars below.
    LOGGER.log(logging.WARNING if event['event'] == 'worker_error' else logging.INFO,
               json.dumps(event, sort_keys=True, separators=(',', ':')))


class WorkerMonitor:
    def __init__(self, enabled=True, *, clock=time.monotonic, utc=_utc, emit=_emit,
                 stale_after=15.0, busy_after=3600.0, heartbeat_interval=30.0):
        if not (0 < stale_after < busy_after and heartbeat_interval > 0):
            raise ValueError('Invalid worker health thresholds')
        self.enabled = bool(enabled)
        self._clock, self._utc, self._emit = clock, utc, emit
        self._stale_after, self._busy_after = stale_after, busy_after
        self._heartbeat_interval = heartbeat_interval
        self._lock = threading.Lock()
        self._state = 'starting' if self.enabled else 'disabled'
        self._seen = clock()
        self._seen_utc = utc()
        self._busy_since = None
        self._last_heartbeat_log = None
        self._error = None
        self._last_outcome = None
        self._polls = self._completed = self._errors = 0

    def _touch(self):
        self._seen = self._clock()
        self._seen_utc = self._utc()

    def _event(self, event, job_id=None):
        value = {'schema_version': 1, 'component': 'fox-worker', 'event': event,
                 'at_utc': self._seen_utc, 'state': self._state,
                 'error_code': self._error, 'polls_completed': self._polls,
                 'jobs_completed': self._completed, 'errors_observed': self._errors}
        if isinstance(job_id, str) and _JOB.fullmatch(job_id):
            value['job_id'] = job_id
        if event == 'job_outcome':
            value['outcome'] = self._last_outcome
        return value

    def started(self):
        with self._lock:
            self._touch()
            self._state, self._error, self._busy_since = 'idle', None, None
            event = self._event('worker_started')
        self._emit(event)

    def polling(self):
        with self._lock:
            self._touch()
            # A failed worker does not become healthy merely by attempting again.
            if self._error is None:
                self._state = 'polling'

    def busy(self, job_id):
        with self._lock:
            self._touch()
            self._busy_since = self._seen
            self._state = 'busy'
            self._error = None
            event = self._event('job_started', job_id)
        self._emit(event)

    def completed(self, outcome=None, job_id=None):
        if outcome is not None and outcome not in _OUTCOMES:
            raise ValueError('Unsupported worker outcome')
        with self._lock:
            recovered = self._error is not None
            self._touch()
            self._state, self._error, self._busy_since = 'idle', None, None
            self._polls += 1
            event = None
            if outcome is not None:
                self._completed += 1
                self._last_outcome = outcome
                event = self._event('job_outcome', job_id)
            elif recovered:
                event = self._event('worker_recovered')
            elif self._last_heartbeat_log is None or self._seen - self._last_heartbeat_log >= self._heartbeat_interval:
                self._last_heartbeat_log = self._seen
                event = self._event('heartbeat')
        if event:
            self._emit(event)

    def failed(self, code, job_id=None):
        if code not in _ERRORS:
            raise ValueError('Unsupported worker error code')
        with self._lock:
            self._touch()
            self._state, self._error, self._busy_since = 'error', code, None
            self._errors += 1
            event = self._event('worker_error', job_id)
        self._emit(event)

    def stopping(self):
        with self._lock:
            self._touch()
            self._state = 'stopping' if self.enabled else 'disabled'

    def stopped(self):
        with self._lock:
            self._touch()
            self._state = 'stopped'
            event = self._event('worker_stopped')
        self._emit(event)

    def snapshot(self, *, thread_alive=None):
        """No I/O, secrets, source rows, job identifiers or exception text."""
        with self._lock:
            age = max(0.0, self._clock() - self._seen)
            busy_age = None if self._busy_since is None else max(0.0, self._clock() - self._busy_since)
            state, error = self._state, self._error
            healthy = True
            if self.enabled:
                if thread_alive is False or state in {'stopped', 'stopping'}:
                    healthy, error = False, 'WORKER_NOT_RUNNING'
                elif error:
                    healthy = False
                elif state == 'busy' and busy_age is not None and busy_age > self._busy_after:
                    healthy, state, error = False, 'stale', 'WORKER_JOB_OVERDUE'
                elif state != 'busy' and age > self._stale_after:
                    healthy, state, error = False, 'stale', 'WORKER_HEARTBEAT_STALE'
            return {'schema_version': 1, 'enabled': self.enabled, 'healthy': healthy,
                    'state': state, 'error_code': error, 'last_heartbeat_utc': self._seen_utc,
                    'heartbeat_age_seconds': round(age, 3),
                    'busy_age_seconds': None if busy_age is None else round(busy_age, 3),
                    'idle_stale_after_seconds': self._stale_after,
                    'busy_overdue_after_seconds': self._busy_after,
                    'polls_completed': self._polls, 'jobs_completed': self._completed,
                    'errors_observed': self._errors, 'last_outcome': self._last_outcome}


def observed_poll(process_one, db, root, monitor):
    """Observe one single-worker operation; never retry/requeue external work.

    The lightweight queue read makes outcome tracking deterministic without
    changing process_one's existing public function contract. A newly enqueued
    job after an idle read simply waits until the next normal two-second poll.
    """
    monitor.polling()
    try:
        with db() as connection:
            if connection.execute("SELECT COUNT(*) FROM runs WHERE state='PROCESSING'").fetchone()[0]:
                monitor.failed('WORKER_RECONCILIATION_REQUIRED')
                return
            row = connection.execute("SELECT id FROM runs WHERE state='QUEUED' ORDER BY created LIMIT 1").fetchone()
    except Exception:
        monitor.failed('WORKER_POLL_ERROR')
        return
    if row is None:
        monitor.completed()
        return
    job_id = row['id']
    monitor.busy(job_id)
    try:
        process_one(db, root)
    except Exception:
        monitor.failed('WORKER_EXECUTION_ERROR', job_id)
        return
    try:
        with db() as connection:
            result = connection.execute('SELECT state FROM runs WHERE id=?', (job_id,)).fetchone()
        outcome = result['state'] if result is not None else None
    except Exception:
        monitor.failed('WORKER_OUTCOME_READ_ERROR', job_id)
        return
    if outcome not in _OUTCOMES:
        monitor.failed('WORKER_INCOMPLETE_OUTCOME', job_id)
        return
    monitor.completed(outcome, job_id)
