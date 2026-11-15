"""Synthetic retained histories only, never live Oracle/browser acceptance."""
from copy import deepcopy
from datetime import datetime, timedelta, timezone
import base64
import builtins
import hashlib
import io
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import zipfile

import pytest

from fox import paused_stage_preservation as inert
from fox.completed_prototype_preservation import validate_completed_fox
from fox.verification_recovery import preclaim_tree
from fox.verification_recovery import admission_status
from test_paused_stage_preservation import inert_case, mixed_inert_case
from test_prototype_candidate_format_download import (
    queued, prepared, connected, settings, no_external_actions, tmp_path,
)
from test_prototype_job import queued as base_queued

REAL_RUN = subprocess.run
REAL_POPEN = subprocess.Popen


def save(path, value):
    path.write_text(json.dumps(value, sort_keys=True, separators=(',', ':')), encoding='utf-8')


@pytest.fixture
def completed_case(connected):
    root, job, db, profile, item, export_request, callbacks, model = connected
    stage = job / 'prototype-converter'
    request = deepcopy(export_request)
    request['prior_receipts'].pop('verify_runtime')
    receipt = json.loads((stage / 'verify_runtime.json').read_bytes())['runtime_receipt']
    started = datetime.fromisoformat(receipt['started_at_utc'])
    packet = {'schema_version': 1, 'scope': 'fox-prototype-runtime-dispatch-v1', 'request': request,
        'imported': request['prior_receipts']['import'],
        'artifact_binding': json.loads((stage / 'snapshot.json').read_bytes()),
        'binding': inert.runtime_identity(request, request['prior_receipts']['import'],
            json.loads((stage / 'snapshot.json').read_bytes())),
        'trace': json.loads((job / 'prototype-pipeline/rendered.json').read_bytes())['trace'],
        'issued_at_utc': (started-timedelta(seconds=30)).isoformat(),
        'deadline_at_utc': (started+timedelta(seconds=90)).isoformat(),
        'target': {'workspace': 'FORMS2APEX_POC', 'db_name': 'ASZ8EQWFM8UNCA2_JSNF2APEX',
            'ords_origin': 'https://asz8eqwfm8unca2-jsnf2apex.adb.us-ashburn-1.oraclecloudapps.com'},
        'producer': {'component': 'fox-prototype-runtime-bridge', 'code_sha256': 'a'*64}}
    save(stage / 'runtime-request.json', packet)
    save(stage / 'runtime-claim.json', {'dispatch_sha256': inert.hashed(packet), 'worker_sha256': 'b'*64,
        'state': 'CLAIMED_NO_AUTOMATIC_REPLAY'})
    save(stage / 'runtime-receipt.json', receipt)
    save(stage / 'runtime-result.json', {'schema_version': 1, 'scope': 'fox-prototype-runtime-result-v1',
        'dispatch_sha256': inert.hashed(packet), 'worker_sha256': 'b'*64, 'binding': packet['binding'],
        'receipt_sha256': inert.hashed(receipt)})
    snapshot = json.loads((job / 'source-snapshot.json').read_bytes())
    target = json.loads(profile.read_bytes())
    return root, job, db, stage, packet, target, item


def receiver(case, **kwargs):
    _, job, _, stage, _, _, _ = case
    return inert.completed_receiver(stage, inert.completed_projection(job),
        producer_sha256=kwargs.get('producer_sha256', 'a'*64), worker_sha256=kwargs.get('worker_sha256', 'b'*64))


def test_complete_historical_packet_does_not_renew_deadline_or_use_current_source(completed_case, monkeypatch):
    from forms2apex import prototype_runtime_bridge as live
    c = completed_case; _, job, _, stage, packet, target, item = c
    before = preclaim_tree(job); calls = deepcopy(item.calls)
    class Future(datetime):
        @classmethod
        def now(cls, tz=None):
            return datetime.fromisoformat(packet['deadline_at_utc']) + timedelta(days=1)
    monkeypatch.setattr(live, 'datetime', Future)
    with pytest.raises(RuntimeError, match='EXPIRED_UNKNOWN_NO_REPLAY'):
        live.validate_packet(packet)
    monkeypatch.setattr(live, 'packet_for', lambda *a, **k: pytest.fail('No deadline/hash substitution'))
    monkeypatch.setattr(live, 'remaining_seconds', lambda *a, **k: pytest.fail('No execution deadline call'))
    monkeypatch.setattr(live, 'code_sha256', lambda *a, **k: pytest.fail('No current producer adoption'))
    assert receiver(c) == packet
    raw = (stage / 'prototype-package.zip').read_bytes()
    assert validate_completed_fox(job, target, package_raw=raw) == inert.completed_projection(job)
    assert preclaim_tree(job) == before and item.calls == calls


@pytest.mark.parametrize('name', ['runtime-claim.json', 'runtime-result.json', 'runtime-receipt.json',
    'export-request.json', 'export.json', 'prototype-package.zip', 'runtime-evidence/browser-report.json'])
def test_missing_completion_never_becomes_pending_or_opaque(completed_case, name):
    (completed_case[3] / name).unlink()
    with pytest.raises((RuntimeError, KeyError, FileNotFoundError)):
        receiver(completed_case)


@pytest.mark.parametrize('fault', ['producer', 'worker', 'target', 'trace', 'claim', 'result', 'receipt',
    'package', 'artifact', 'extra-marker', 'extra-artifact', 'request', 'export', 'late', 'early', 'duration',
    'validate-request', 'prepare_schema-request', 'import-request', 'typed-result', 'export-attempt'])
def test_changed_or_extra_historical_proof_rejected(completed_case, fault):
    c = completed_case; stage = c[3]
    if fault in ('producer', 'worker'):
        with pytest.raises(inert.PreservationError):
            receiver(c, **{fault+'_sha256': 'f'*64})
        return
    if fault in ('package', 'artifact'):
        (stage / ('prototype-package.zip' if fault == 'package' else 'runtime-evidence/browser-report.json')).write_bytes(b'changed')
    elif fault in ('extra-marker', 'extra-artifact'):
        (stage / ('runtime-unknown.json' if fault == 'extra-marker' else 'runtime-evidence/extra.json')).write_bytes(b'{}')
    else:
        name = {'claim':'runtime-claim.json', 'result':'runtime-result.json', 'receipt':'runtime-receipt.json',
            'request':'verify_runtime-request.json', 'export':'export-request.json', 'typed-result':'runtime-result.json',
            'export-attempt':'export-attempt.json'}.get(fault,
                fault+'.json' if fault.endswith('-request') else 'runtime-request.json')
        value = json.loads((stage / name).read_bytes())
        if fault == 'target': value['target']['workspace'] = 'OTHER'
        elif fault == 'trace': value['trace']['tampered'] = True
        elif fault == 'late': value['deadline_at_utc'] = value['issued_at_utc']
        elif fault == 'early': value['issued_at_utc'] = value['deadline_at_utc']
        elif fault == 'duration': value['deadline_at_utc'] = (datetime.fromisoformat(value['issued_at_utc'])+timedelta(days=1)).isoformat()
        elif fault == 'typed-result': value['schema_version'] = True
        else: value['unexpected'] = True
        save(stage / name, value)
    with pytest.raises((RuntimeError, KeyError, ValueError)):
        receiver(c)


def test_emitted_stdlib_receiver_exact_package_and_unchanged_trees(completed_case, monkeypatch):
    root, job, _, stage, packet, _, _ = completed_case
    payload = {'receiver_jobs': str(job.parent), 'jobs': [job.name],
        'completed': {job.name: inert.completed_projection(job)}, 'producer_sha256': 'a'*64, 'worker_sha256': 'b'*64}
    before = preclaim_tree(job)
    # The queue fixture forbids product subprocesses. This test alone starts
    # the explicit isolated stdlib reader, never a product executor.
    with monkeypatch.context() as child:
        child.setattr(subprocess, 'Popen', REAL_POPEN)
        result = REAL_RUN([sys.executable, '-I', '-B', '-c', inert.receiver_collector_source()],
            input=json.dumps(payload).encode(), capture_output=True, timeout=30, check=False)
    assert result.returncode == 0, result.stderr.decode()
    value = json.loads(result.stdout)
    assert set(value) == {'receiver', 'identities', 'requests', 'completed_packages'}
    assert value['identities'] == {job.name: packet['binding']}
    assert value['requests'] == {job.name: inert.hashed(packet['request'])}
    assert base64.b64decode(value['completed_packages'][job.name], validate=True) == (stage / 'prototype-package.zip').read_bytes()
    assert preclaim_tree(job) == before


def test_full_semantic_check_rejects_package_and_source_changes(completed_case):
    _, job, _, stage, _, target, _ = completed_case
    with pytest.raises((RuntimeError, ValueError, zipfile.BadZipFile)):
        validate_completed_fox(job, target, package_raw=b'not-a-package')
    with pytest.raises((RuntimeError, ValueError)):
        validate_completed_fox(job, {**target, 'target_profile_sha256': 'f'*64},
            package_raw=(stage / 'prototype-package.zip').read_bytes())


def test_reader_does_not_write_spawn_or_connect_after_fixture(completed_case, monkeypatch):
    import socket
    _, job, _, stage, _, target, _ = completed_case
    raw = (stage / 'prototype-package.zip').read_bytes(); before = preclaim_tree(job)
    original_open = builtins.open
    original_io_open = io.open
    original_os_open = os.open
    def readonly_open(file, mode='r', *args, **kwargs):
        assert not any(flag in mode for flag in 'wax+')
        return original_open(file, mode, *args, **kwargs)
    def forbidden(*a, **k): pytest.fail('Read-only completion check attempted execution/network')
    def readonly_io_open(file, mode='r', *args, **kwargs):
        assert not any(flag in mode for flag in 'wax+')
        return original_io_open(file, mode, *args, **kwargs)
    def readonly_os_open(file, flags, *args, **kwargs):
        assert not flags & (os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_TRUNC | os.O_APPEND)
        return original_os_open(file, flags, *args, **kwargs)
    monkeypatch.setattr(builtins, 'open', readonly_open)
    monkeypatch.setattr(io, 'open', readonly_io_open)
    monkeypatch.setattr(os, 'open', readonly_os_open)
    monkeypatch.setattr(subprocess, 'run', forbidden)
    monkeypatch.setattr(subprocess, 'Popen', forbidden)
    monkeypatch.setattr(socket, 'socket', forbidden)
    assert receiver(completed_case)
    assert validate_completed_fox(job, target, package_raw=raw)
    assert preclaim_tree(job) == before


def test_v1_cannot_adopt_generated_and_v2_requires_exact_host_floor(completed_case):
    root, job, db_factory, _, _, _, _ = completed_case
    database = root / 'fox.sqlite3'
    with sqlite3.connect(database.as_uri()+'?mode=ro', uri=True) as db:
        db.row_factory = sqlite3.Row; db.execute('PRAGMA query_only=ON'); db.execute('BEGIN')
        observed = inert.observe_fox(database, db)
    assert observed['jobs'][job.name]['boundary'] == inert.COMPLETED
    assert inert.runtime_target(observed['jobs'])['target_profile_sha256']
    tree = inert.receiver_job_tree(job.parent, job.name, completed=True)
    baseline = {'schema_version': 1, 'scope': inert.BASELINE_SCOPE, **observed,
        'receiver': {job.name: tree}, 'runtime': {}}
    with pytest.raises(inert.PreservationError): inert.validate_baseline(baseline)
    baseline.update(schema_version=2, scope=inert.BASELINE_SCOPE_V2, completed_host={job.name: {
        'staging': {'files': {}, 'directories': {}, 'namespace': {}},
        'qa': {'files': {}, 'directories': {}, 'namespace': {}}}})
    assert inert.validate_baseline(baseline) is baseline
    baseline['completed_host']['extra'] = baseline['completed_host'][job.name]
    with pytest.raises(inert.PreservationError): inert.validate_baseline(baseline)


@pytest.mark.parametrize('runtime_state', ['running', 'stopped'])
def test_mixed_completed_and_attention_paired_floor_is_readonly_and_not_admission(completed_case, runtime_state):
    root, job, _, stage, _, _, _ = completed_case
    database = root / 'fox.sqlite3'
    snapshot = json.loads((job / 'source-snapshot.json').read_bytes())
    with sqlite3.connect(database) as db:
        db.row_factory = sqlite3.Row
        row = dict(db.execute('SELECT * FROM runs WHERE id=?', (job.name,)).fetchone())
        for index, runtime in enumerate((False, True)):
            old = {**row, 'id': 'fox-'+str(index+1)*20, 'state': 'ATTENTION'}
            db.execute('INSERT INTO runs ('+','.join(old)+') VALUES ('+','.join('?' for _ in old)+')', tuple(old.values()))
            path = job.parent / old['id']; path.mkdir()
            save(path / 'source-snapshot.json', snapshot)
            if runtime:
                pipeline = path / 'prototype-pipeline'; pipeline.mkdir()
                save(pipeline / 'verify_runtime-intent.json', {'request_sha256': 'e'*64})
    def observe():
        with sqlite3.connect(database.as_uri()+'?mode=ro', uri=True) as db:
            db.row_factory = sqlite3.Row; db.execute('PRAGMA query_only=ON'); db.execute('BEGIN')
            return inert.observe_fox(database, db)
    observed = observe()
    receiver_trees = {name: inert.receiver_job_tree(job.parent, name, completed=entry['boundary'] == inert.COMPLETED)
                      for name, entry in observed['jobs'].items()}
    baseline = {'schema_version': 2, 'scope': inert.BASELINE_SCOPE_V2, **observed,
        'receiver': receiver_trees, 'runtime': {'synthetic': 'not-a-host-observation'},
        'completed_host': {job.name: {'staging': preclaim_tree(stage), 'qa': preclaim_tree(stage)}}}
    now = datetime.now(timezone.utc)
    identity = {**{key: 'f'*64 for key in ('pair_sha256', 'lease_sha256', 'release_sha256', 'source_sha256', 'profile_sha256')},
        'runtime_state': runtime_state, 'stopped_writer_sha256': 'a'*64 if runtime_state == 'stopped' else None,
        'admission': {'enabled': True, 'release_sha256': 'f'*64}}
    expected = {'baseline': baseline, 'baseline_sha256': inert.hashed(baseline), 'identity': identity}
    packet = {'schema_version': 2, 'scope': inert.READ_SCOPE_V2, 'binding': expected['baseline_sha256'],
        'identity': identity, 'observed_at_utc': now.isoformat(), 'expires_at_utc': (now+timedelta(seconds=30)).isoformat(),
        'fox': observed, 'receiver': receiver_trees, 'host': {'runtime_sha256': inert.hashed(baseline['runtime']),
            'receiver_sha256': inert.hashed(receiver_trees), 'observation_sha256': 'b'*64, 'blockers': [],
            'completed_host_sha256': inert.hashed(baseline['completed_host'])}}
    before = database.read_bytes(), {name: preclaim_tree(job.parent/name) for name in observed['jobs']}
    assert {value['boundary'] for value in observed['jobs'].values()} == {inert.COMPLETED, inert.RUNTIME_CANDIDATE, inert.OPAQUE_BOUNDARY}
    assert inert.runtime_target(observed['jobs'])['target_profile_sha256'] == snapshot['prototype']['target_profile_sha256']
    for name, entry in observed['jobs'].items():
        assert admission_status(entry['row'], None)['blocks_admission'] is True
        with sqlite3.connect(database.as_uri()+'?mode=ro', uri=True) as db:
            db.row_factory = sqlite3.Row; db.execute('PRAGMA query_only=ON'); db.execute('BEGIN')
            result = inert.validate_pair(database, db, name, packet, expected, now=now)
        assert result['preservation_state'] == inert.STATE_V2
        assert result['admission']['blocks_admission'] is True and result['admission']['retry_eligible'] is False
        assert result['preserved']['closure_claimed'] is result['preserved']['continuation_authorized'] is False
        assert result['preserved']['unresolved'] is (entry['boundary'] != inert.COMPLETED)
    assert before == (database.read_bytes(), {name: preclaim_tree(job.parent/name) for name in observed['jobs']})
    packet['host']['completed_host_sha256'] = '0'*64
    with sqlite3.connect(database.as_uri()+'?mode=ro', uri=True) as db:
        db.row_factory = sqlite3.Row; db.execute('PRAGMA query_only=ON'); db.execute('BEGIN')
        with pytest.raises(inert.PreservationError, match='COMPLETED_HOST_CHANGED'):
            inert.validate_pair(database, db, job.name, packet, expected, now=now)


def test_completed_tree_does_not_adopt_replaced_identical_bytes(tmp_path):
    root = tmp_path / 'retained'; root.mkdir()
    path = root / 'proof.json'; path.write_bytes(b'{"retained":true}')
    old_bytes = preclaim_tree(root); old_nodes = inert.completed_tree(root)
    replacement = tmp_path / 'replacement.json'; replacement.write_bytes(path.read_bytes())
    replacement.replace(path)
    assert preclaim_tree(root) == old_bytes
    assert inert.completed_tree(root) != old_nodes


def test_completed_tree_rejects_linked_proof(tmp_path):
    root = tmp_path / 'retained'; root.mkdir()
    path = root / 'proof.json'; path.write_bytes(b'{"retained":true}')
    try:
        (root / 'linked.json').symlink_to(path)
    except OSError:
        pytest.skip('Windows symlink permission unavailable')
    with pytest.raises(RuntimeError): inert.completed_tree(root)
