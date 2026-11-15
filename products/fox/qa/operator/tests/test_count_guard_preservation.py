"""Authored retained history, real files/hashes; no browser or Oracle execution.

Only POSIX path validation is modelled on Windows. The real retained_tree reader
still checks links, inodes, immutable reads and byte hashes (Windows ACLs are not
POSIX permission proof). Historical timestamps are fixed, never renewed.
"""
from copy import deepcopy
from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from fox import paused_stage_preservation as inert
from forms2apex import native_blueprint, native_blueprint_required
from forms2apex.prototype_package import expected_runtime_pages, runtime_binding
from qa.operator import paused_stage_host as host
from test_count_guard_integration import request_and_import
from test_native_blueprint import spec as legacy_spec
from test_native_blueprint_required import spec as required_spec


def raw(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'),
                      ensure_ascii=False, allow_nan=False).encode()


def put(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(raw(value))


def case(tmp_path, monkeypatch, profile):
    request, imported, snapshot = request_and_import()
    if profile != 'count':
        request['rendering_spec'] = required_spec() if profile == 'required' else legacy_spec()
        request['project_id'] = request['rendering_spec']['project_id']
        request['source_binding'] = request['rendering_spec']['source_binding']
        request.pop('prior_receipts')
        snapshot = {'template': (native_blueprint_required if profile == 'required' else native_blueprint).context()}
    identity = runtime_binding(request, imported, snapshot)
    assert inert.runtime_identity(request, imported, snapshot) == identity
    if profile != 'count':
        assert 'count_guard_fixture_sha256' not in identity
    job = request['job_id']
    staging, qa = tmp_path / 's', tmp_path / 'q'
    stage = staging / job / 'prototype-converter'
    attempt = qa / ('prototype-' + host.hashed(identity))
    names = (['run-count-guard-v1.mjs', 'lib/contracts.mjs', 'lib/count-guard.mjs']
             if profile == 'count' else ['run-prototype.mjs', 'lib/contracts.mjs'])
    source_root = Path(__file__).resolve().parents[3]
    originals = {}
    for name in names:
        content = (source_root / 'qa' / name).read_bytes()
        destination = attempt / 'source' / name
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(content)
        originals[name] = hashlib.sha256(content).hexdigest()
    producer = 'converter/forms2apex/prototype_runtime_bridge.py'
    runtime = {'staging_root': str(staging), 'qa_root': str(qa), 'qa_image': 'sha256:' + 'f' * 64,
               'sources': {producer: hashlib.sha256((source_root / producer).read_bytes()).hexdigest(),
                           **{'qa/' + name: digest for name, digest in originals.items()}}}
    old = datetime(2026, 1, 2, 3, 4, 5, tzinfo=timezone.utc)
    stamp = lambda seconds: (old + timedelta(seconds=seconds)).isoformat()
    packet = {'request': request, 'binding': identity, 'artifact_binding': snapshot,
              'imported': imported, 'trace': {'synthetic': 'authored-not-executed'},
              'producer': {'component': 'fox-prototype-runtime-bridge', 'code_sha256': runtime['sources'][producer]},
              'target': {'workspace': 'FORMS2APEX_POC', 'db_name': 'SYNTHETIC', 'ords_origin': 'https://synthetic.invalid'},
              'issued_at_utc': stamp(0), 'deadline_at_utc': stamp(270)}
    authority = {'schema_version': 1, 'scope': 'fox-prototype-runtime-credentials-target-v1',
                 **packet['target'], **{key: 'e' * 64 for key in
                     ('credentials_sha256', 'username_sha256', 'authorization_reference_sha256')}}
    target = {'binding': identity, 'spec': request['rendering_spec'], 'trace': packet['trace'],
              'pages': expected_runtime_pages(request['rendering_spec']), 'credential_authority': authority,
              'runner_files': originals, 'code_sha256': host.hashed(originals), 'image_id': runtime['qa_image'],
              'data_retention': 'synthetic_test_rows_retained', 'deadline_at_utc': stamp(260),
              'request_deadline_at_utc': stamp(270),
              'url': packet['target']['ords_origin'] + '/ords/r/forms2apex_poc/' + imported['application_alias'].lower() + '/'}
    if profile == 'count':
        target['count_guard_fixture'] = request['prior_receipts']['prepare_schema']['count_guard_fixture']
    intent = {'binding': identity, 'code_sha256': host.hashed(originals), 'image_id': runtime['qa_image'],
              'state': 'ATTEMPT_STARTED_NO_AUTOMATIC_REPLAY', 'deadline_at_utc': stamp(260),
              'request_deadline_at_utc': stamp(270)}
    report = {'runner': {'kind': 'authenticated_browser', 'tool': 'playwright',
                        'code_sha256': host.hashed(originals), 'image_id': runtime['qa_image']},
              'started_at_utc': stamp(1), 'completed_at_utc': stamp(250),
              'business_behavior_accepted': False, 'retained_rows': []}
    sequence = 0
    if profile == 'count':
        for scenario in ('null', 'zero', 'positive', 'negative'):
            sequence += 1
            put(attempt / f'count-check-{sequence:03}.json', {'binding': identity, 'case': scenario,
                'fixture_sha256': identity['count_guard_fixture_sha256'], 'request': 'FOX_COUNT_GUARD_CHECK',
                'state': 'READ_ONLY_CHECK_ATTEMPT_STARTED_NO_AUTOMATIC_REPLAY'})
    for block in request['rendering_spec']['blocks']:
        if block['native_component'] != 'form':
            continue
        report['retained_rows'].append({'source_block_id': block['source_block_id'], 'primary_key': '41'})
        required = next((field for field in block['fields'] if field['in_edit_form'] and field.get('value_required')), None)
        if profile != 'legacy' and required:
            sequence += 1
            put(attempt / f'required-input-{sequence:03}.json', {'binding': identity,
                'source_block_id': block['source_block_id'], 'source_item_id': required['source_item_id'],
                'state': 'INVALID_SUBMIT_ATTEMPT_STARTED_NO_AUTOMATIC_REPLAY'})
        for button, key in (('Create', None), ('Save Changes', '41')):
            sequence += 1
            put(attempt / f'write-{sequence:03}.json', {'binding': identity,
                'source_block_id': block['source_block_id'], 'table_name': block['table_name'],
                'button': button, 'primary_key': key, 'intended_values_sha256': 'a' * 64,
                'state': 'ATTEMPT_STARTED_NO_AUTOMATIC_REPLAY'})
    for path, value in ((stage / 'runtime-request.json', packet), (stage / 'snapshot.json', snapshot),
        (stage / 'import.json', imported), (stage / 'runtime-evidence/browser-report.json', report),
        (attempt / 'target.json', target), (attempt / 'launch-intent.json', intent), (attempt / 'progress.json', report)):
        put(path, value)
    # Production safe() is POSIX-host policy; local Windows paths are modelled.
    monkeypatch.setattr(host, 'safe', lambda path: Path(path))
    receipt = {**report, 'artifacts': [{'path': 'runtime-evidence/browser-report.json',
        'sha256': hashlib.sha256(raw(report)).hexdigest(), 'bytes': len(raw(report))}]}
    jobs = {job: {'boundary': inert.COMPLETED, 'runtime_request_sha256': host.hashed(request),
                 'completed': {'runtime_identity': identity, 'runtime_receipt_sha256': host.hashed(receipt)}}}
    expected = {job: {'staging': host.retained_tree(stage.parent), 'qa': host.retained_tree(attempt)}}
    receiver = {job: {'files': deepcopy(expected[job]['staging']['files'])}}
    return SimpleNamespace(runtime=runtime, jobs=jobs, identities={job: identity}, expected=expected,
        receiver=receiver, job=job, stage=stage, attempt=attempt, target=target, packet=packet)


def read(c):
    return host.completed_host_read(c.runtime, c.identities, c.jobs, c.receiver, c.expected)


@pytest.mark.parametrize('profile', ['legacy', 'required', 'count'])
def test_original_history_joins_without_execution_or_renewal(tmp_path, monkeypatch, profile):
    c = case(tmp_path, monkeypatch, profile)
    before = deepcopy(c.expected)
    def forbidden(*args, **kwargs):
        pytest.fail('retained history must never execute a subprocess')
    monkeypatch.setattr(host.subprocess, 'run', forbidden)
    assert read(c) == before
    assert read(c) == before
    assert c.packet['deadline_at_utc'] == '2026-01-02T03:08:35+00:00'
    assert host.retained_tree(c.attempt) == before[c.job]['qa']
    if profile == 'count':
        assert (c.attempt / 'write-005.json').is_file()
    else:
        assert not any(path.name.startswith('count-check-') for path in c.attempt.iterdir())


@pytest.mark.parametrize('fault,code', [
    ('helper', 'BROWSER_TARGET_CHANGED'), ('fixture', 'COUNT_FIXTURE_CHANGED'),
    ('ledger', 'COUNT_CHECK_INTENT_CHANGED'), ('extra-artifact', 'BROWSER_EXTRA_OR_MISSING'),
    ('checklist', 'BROWSER_TARGET_CHANGED'), ('old-runner-fallback', 'ORIGINAL_RUNNER_SOURCE_REQUIRED'),
    ('expired-order', 'HISTORICAL_DEADLINE_CHANGED'), ('unknown-outcome', 'BROWSER_INTENT_CHANGED'),
    ('missing-input', None)])
def test_rehash_cannot_adopt_invalid_count_history(tmp_path, monkeypatch, fault, code):
    c = case(tmp_path, monkeypatch, 'count')
    if fault == 'helper':
        (c.attempt / 'source/lib/count-guard.mjs').write_bytes(b'// changed helper')
    elif fault == 'fixture':
        c.target['count_guard_fixture']['prepared'] = False
        put(c.attempt / 'target.json', c.target)
    elif fault == 'ledger':
        path = c.attempt / 'count-check-001.json'
        value = json.loads(path.read_bytes()); value['case'] = 'zero'; put(path, value)
    elif fault == 'extra-artifact':
        put(c.attempt / 'unexpected.json', {'unclassified': True})
    elif fault == 'checklist':
        c.target['pages'][0]['checks'].remove('count_guard_no_approval_request')
        put(c.attempt / 'target.json', c.target)
    elif fault == 'old-runner-fallback':
        del c.runtime['sources']['qa/run-count-guard-v1.mjs']
        c.runtime['sources']['qa/run-prototype.mjs'] = 'a' * 64
    elif fault == 'expired-order':
        c.target['deadline_at_utc'] = '2026-01-02T03:04:06+00:00'
        put(c.attempt / 'target.json', c.target)
        intent = json.loads((c.attempt / 'launch-intent.json').read_bytes())
        intent['deadline_at_utc'] = c.target['deadline_at_utc']; put(c.attempt / 'launch-intent.json', intent)
    elif fault == 'unknown-outcome':
        path = c.attempt / 'launch-intent.json'; value = json.loads(path.read_bytes())
        value['state'] = 'UNKNOWN_OUTCOME_NO_REPLAY'; put(path, value)
    else:
        (c.attempt / 'count-check-004.json').unlink()
    # Rehash adversarial bytes to exercise semantic joins beyond tree equality.
    c.expected[c.job]['qa'] = host.retained_tree(c.attempt)
    with pytest.raises((RuntimeError, FileNotFoundError), match=code):
        read(c)


def test_absent_original_fixture_cannot_mint_count_identity():
    request, imported, snapshot = request_and_import()
    del request['prior_receipts']['prepare_schema']['count_guard_fixture']
    with pytest.raises(inert.PreservationError, match='COUNT_FIXTURE_BINDING_REQUIRED'):
        inert.runtime_identity(request, imported, snapshot)
