"""Actual retained files with modelled host OS/engine; no live-flow claim."""
from copy import deepcopy
from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path
import shutil
from types import SimpleNamespace

import pytest

from fox import paused_stage_preservation as inert, verification_recovery as recovery
from forms2apex.project_reviews import canonical, read_object
from qa.operator import paused_stage_host as host, prototype_runtime_worker as worker
from qa.operator.tests.test_paused_stage_startup import host_model
from qa.operator.tests.test_prototype_runtime_worker import bridge_case, runtime_case, dispatch
from test_paused_stage_preservation import mixed_inert_case, inert_case


@pytest.fixture
def completed_host_case(bridge_case, mixed_inert_case, monkeypatch):
    b, c = bridge_case, mixed_inert_case
    dispatch(b)
    assert worker.run_once(b.config, b.request['job_id'])['state'] == 'PUBLISHED'
    job = b.request['job_id']; stage = b.staging / job / 'prototype-converter'
    qa = b.config.browser.config.qa_root
    identity = b.packet['binding']; attempt = qa / ('prototype-' + inert.hashed(identity))
    # The existing synthetic browser fixture intentionally emits no real Node
    # dispatch ledger. Add an explicit authored ledger for this source-only
    # preservation test, not as evidence of a browser/Oracle operation.
    report = read_object(stage / 'runtime-evidence/browser-report.json')
    packet = read_object(stage / 'runtime-request.json')
    target = read_object(attempt / 'target.json'); intent = read_object(attempt / 'launch-intent.json')
    old = datetime.now(timezone.utc) - timedelta(days=30)
    packet.update(issued_at_utc=old.isoformat(), deadline_at_utc=(old + timedelta(seconds=480)).isoformat())
    target.update(deadline_at_utc=(old + timedelta(seconds=400)).isoformat(),
                  request_deadline_at_utc=packet['deadline_at_utc'])
    intent.update(deadline_at_utc=target['deadline_at_utc'], request_deadline_at_utc=packet['deadline_at_utc'])
    report.update(started_at_utc=(old + timedelta(seconds=1)).isoformat(),
                  completed_at_utc=(old + timedelta(seconds=60)).isoformat())
    for path, value in ((stage / 'runtime-request.json', packet),
                        (stage / 'runtime-evidence/browser-report.json', report),
                        (attempt / 'target.json', target), (attempt / 'launch-intent.json', intent),
                        (attempt / 'progress.json', report)):
        path.write_bytes(canonical(value))
    sequence = 0; rows = {row['source_block_id']: row for row in report['retained_rows']}
    for block in b.request['rendering_spec']['blocks']:
        if block['native_component'] != 'form':continue
        required = next((field for field in block['fields'] if field.get('value_required')), None)
        if required:
            sequence += 1
            (attempt / f'required-input-{sequence:03}.json').write_bytes(canonical({
                'binding': identity, 'source_block_id': block['source_block_id'],
                'source_item_id': required['source_item_id'],
                'state': 'INVALID_SUBMIT_ATTEMPT_STARTED_NO_AUTOMATIC_REPLAY'}))
        for button, key in (('Create', None), ('Save Changes', rows[block['source_block_id']]['primary_key'])):
            sequence += 1
            (attempt / f'write-{sequence:03}.json').write_bytes(canonical({
                'binding': identity, 'source_block_id': block['source_block_id'], 'table_name': block['table_name'],
                'button': button, 'primary_key': key, 'intended_values_sha256': 'a' * 64,
                'state': 'ATTEMPT_STARTED_NO_AUTOMATIC_REPLAY'}))
    receipt = {**report, 'artifacts': [{'path': 'runtime-evidence/browser-report.json',
               'sha256': hashlib.sha256((stage / 'runtime-evidence/browser-report.json').read_bytes()).hexdigest(),
               'bytes': (stage / 'runtime-evidence/browser-report.json').stat().st_size}]}
    destination = c.receiver / job
    shutil.copytree(b.staging / job, destination)
    runtime, pins, items = host_model(c, monkeypatch)
    runtime.update(staging_root=str(b.staging), qa_root=str(qa), qa_image=b.config.browser.config.image_id)
    producer = 'converter/forms2apex/prototype_runtime_bridge.py'
    runtime['sources'][producer] = packet['producer']['code_sha256']
    runtime['sources'].update({'qa/' + name: value for name, value in target['runner_files'].items()})
    sources_root = Path(worker.__file__).resolve().parents[2]
    runtime['sources']['qa/operator/prototype_runtime_worker.py'] = hashlib.sha256(Path(worker.__file__).read_bytes()).hexdigest()
    jobs = deepcopy(c.baseline['jobs'])
    completed = {'runtime_identity': identity, 'runtime_receipt_sha256': inert.hashed(receipt)}
    jobs[job] = {'row': {'created': 3., 'state': 'GENERATED', 'artifact': None}, 'boundary': inert.COMPLETED,
                 'runtime_request_sha256': inert.hashed(packet['request']), 'completed': completed}
    receiver = deepcopy(c.baseline['receiver']); receiver[job] = recovery.preclaim_tree(destination)
    identities = {c.job_id: inert.runtime_identity(c.request, c.request['prior_receipts']['import'], {'opaque': 'preserved'}),
                  job: identity}
    # Windows ACL/owner model only; run the real no-follow/hash/inode reader.
    actual_tree = host.retained_tree
    def tree(path):
        with monkeypatch.context() as patch:
            patch.setattr(host, 'os', SimpleNamespace(name='nt'))
            return actual_tree(path)
    monkeypatch.setattr(host, 'retained_tree', tree)
    expected = {job: {'staging': tree(b.staging / job), 'qa': tree(attempt)}}
    return SimpleNamespace(c=c, job=job, runtime=runtime, pins=pins, items=items, jobs=jobs, receiver=receiver,
        identities=identities, expected=expected, stage=stage, attempt=attempt, old=old, sources_root=sources_root)


def collect(c, **kwargs):
    return host.collect(c.runtime, c.receiver, c.identities, c.jobs, c.pins,
                        storage=c.c.storage, completed_host=c.expected, **kwargs)


@pytest.mark.parametrize('phase', ['old-running', 'old-stopped', 'restored-old', 'new-running'])
def test_historical_complete_keeps_original_host_trees_and_no_deadline_renewal(completed_host_case, phase):
    c = completed_host_case; before = deepcopy(c.expected)
    stopped = phase == 'old-stopped'
    if stopped:
        for item in c.items:item['State'].update(Running=False, Pid=0, Status='exited')
    elif phase == 'new-running':
        old = c.items[1]; old['State'].update(Running=False, Pid=0, Status='exited')
        new = deepcopy(old); new['Id'] = '9' * 64
        new['State'].update(Running=True, Pid=111, ConmonPid=211, Status='running')
        c.items.append(new); c.pins['forms2apex-mcp']['id'] = new['Id']
    result, _ = collect(c, stopped=stopped)
    assert result['completed_host_sha256'] == inert.hashed(before) and result['blockers'] == []
    assert host.completed_host_read(c.runtime, c.identities, c.jobs, c.receiver, before) == before
    assert read_object(c.stage / 'runtime-request.json')['deadline_at_utc'].startswith(c.old.date().isoformat())
    assert not any(item['Image'] == c.runtime['qa_image'] for item in c.items)  # --rm means no invented container ID.


@pytest.mark.parametrize('fault', ['missing-report', 'tampered-report', 'extra-stage', 'extra-qa', 'new-inode',
    'unknown-stage-job', 'unknown-qa-attempt', 'active-process', 'active-lock', 'bound-mount', 'ancestor-mount',
    'live-browser', 'missing-baseline', 'producer-pin'])
def test_completed_history_never_adopts_missing_changed_extra_or_active_work(completed_host_case, monkeypatch, fault):
    c = completed_host_case
    if fault == 'missing-report':(c.stage / 'runtime-evidence/browser-report.json').unlink()
    elif fault == 'tampered-report':(c.stage / 'runtime-evidence/browser-report.json').write_bytes(b'changed')
    elif fault == 'extra-stage':(c.stage / 'unclassified.json').write_bytes(b'{}')
    elif fault == 'extra-qa':(c.attempt / 'filter-failure.json').write_bytes(b'{}')
    elif fault == 'new-inode':
        original = c.attempt / 'target.json'; replacement = c.attempt / 'replacement.json'
        replacement.write_bytes(original.read_bytes()); replacement.replace(original)
    elif fault == 'unknown-stage-job':(Path(c.runtime['staging_root']) / ('fox-' + 'f' * 20)).mkdir()
    elif fault == 'unknown-qa-attempt':(Path(c.runtime['qa_root']) / ('prototype-' + 'f' * 64)).mkdir()
    elif fault == 'active-process':monkeypatch.setattr(host, 'process_inventory', lambda *a, **k: [{'pid': 999}])
    elif fault == 'active-lock':monkeypatch.setattr(host, 'lock_holders', lambda *a: ['actual modelled holder'])
    elif fault in ('bound-mount', 'ancestor-mount'):
        c.items.append({'Id': '9' * 64, 'Image': 'sha256:' + '0' * 64,
            'State': {'Running': False, 'Pid': 0, 'Status': 'exited'},
            'Mounts': [{'Source': str(c.attempt if fault == 'bound-mount' else c.attempt.parent)}]})
    elif fault == 'live-browser':
        c.items.append({'Id': '9' * 64, 'Image': c.runtime['qa_image'],
            'State': {'Running': True, 'Pid': 999, 'Status': 'running'}, 'Mounts': []})
    elif fault == 'missing-baseline':c.expected.clear()
    else:del c.runtime['sources']['converter/forms2apex/prototype_runtime_bridge.py']
    with pytest.raises((RuntimeError, FileNotFoundError)):collect(c)


@pytest.mark.parametrize('name', ['target.json', 'launch-intent.json', 'progress.json', 'write-001.json'])
def test_rehashing_baseline_cannot_turn_bad_original_browser_bytes_into_completion(completed_host_case, name):
    c = completed_host_case
    if name == 'write-001.json':
        path = next(c.attempt.glob('write-*.json'))
    else:path = c.attempt / name
    value = read_object(path)
    if name == 'target.json':value['runner_files']['run-prototype.mjs'] = '0' * 64
    elif name == 'launch-intent.json':value['state'] = 'UNKNOWN'
    elif name == 'progress.json':value['passed'] = False
    else:value['primary_key'] = '999'
    path.write_bytes(canonical(value))
    c.expected[c.job]['qa'] = host.retained_tree(c.attempt)
    with pytest.raises(RuntimeError):collect(c)


def test_default_ordinary_host_path_cannot_adopt_completed_attempt(completed_host_case):
    c = completed_host_case
    with pytest.raises(RuntimeError, match='COMPLETED_HOST_BASELINE_REQUIRED'):
        host.collect(c.runtime, c.receiver, c.identities, c.jobs, c.pins, storage=c.c.storage)


def test_paired_completed_identity_projection_and_version_are_explicit(completed_host_case):
    c = completed_host_case
    fox = {'database': {'synthetic': 'not-a-live-db'}, 'jobs': c.jobs,
           'fox': {job: {'synthetic': 'host-only-test'} for job in c.jobs}}
    baseline = {'schema_version': 2, 'scope': inert.BASELINE_SCOPE_V2, **fox, 'receiver': c.receiver,
                'runtime': c.runtime, 'completed_host': c.expected}
    received = {'receiver': c.receiver, 'identities': c.identities,
                'requests': {job: c.jobs[job]['runtime_request_sha256'] for job in c.identities},
                'completed_packages': {c.job: 'synthetic-host-projection-only'}}
    identity = {'profile_sha256': host.hashed({'profile': 'nonsecret'})}
    result = host.paired(baseline, fox, received, identity, c.pins, storage=c.c.storage)
    assert set(result) == set(c.jobs)
    for value in result.values():
        assert value['readback']['scope'] == inert.READ_SCOPE_V2 and value['readback']['schema_version'] == 2
        assert value['readback']['host']['completed_host_sha256'] == inert.hashed(c.expected)
    received['completed_packages'].clear()
    with pytest.raises(RuntimeError, match='PACKAGE_SET_CHANGED'):
        host.paired(baseline, fox, received, identity, c.pins, storage=c.c.storage)


def test_host_module_origin_is_canonical_public_source():
    root = Path(__file__).resolve().parents[3]
    assert Path(host.__file__).resolve() == root / 'qa/operator/paused_stage_host.py'
