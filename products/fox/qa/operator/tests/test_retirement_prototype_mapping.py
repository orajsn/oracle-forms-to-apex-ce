"""Real local retired-history reader with a sealed authored empty mapper.

Historical C/F/G proofs use production validators over synthetic packages. No
network, model, Oracle, subprocess or operator-state mutation is performed.
"""
from copy import deepcopy
import json
from pathlib import Path
import sqlite3
import sys

import pytest

ROOT = Path(__file__).resolve().parents[3]
for folder in (ROOT, ROOT / 'fox', ROOT / 'fox/tests'):
    if str(folder) not in sys.path:
        sys.path.insert(0, str(folder))

from fox import source_history
from fox.intake import checked_source
from fox.opaf import canonical_hash
from fox.prototype_admission import prepare_prototype_admission
from fox.prototype_pipeline import run_prototype_pipeline
from fox import verification_recovery as recovery
from qa.operator import retirement_remote as remote
from qa.operator.tests.test_retirement_remote_backend import historical_case, _read, _snapshot
from test_prototype_pipeline import PROFILE, TARGET
from test_prototype_admission import documents
from test_prototype_mapping_recovery import EmptyMapper

assert Path(remote.__file__).resolve() == ROOT / 'qa/operator/retirement_remote.py'
assert Path(recovery.__file__).resolve() == ROOT / 'fox/fox/verification_recovery.py'


def terminal_parent(case):
    case.root.chmod(0o700)  # Fixture models the protected deployment /data root.
    pid, rid = 'synthetic-prototype', 'fox-' + '4' * 20
    docs = documents()
    with sqlite3.connect(case.database) as db:
        db.row_factory = sqlite3.Row
        db.execute('INSERT INTO projects VALUES(?,?)', (pid, 'synthetic-owner'))
        source_history.create_project_selection(db, pid, 1)
        source_history.publish_upload(db, pid, [checked_source(name, raw) for name, raw in docs], 2, 'synthetic-owner')
        files = source_history.selected_sources(db, pid)
        sid = source_history.selected_source_set_id(db, pid)
        target = deepcopy(TARGET)
        target.update(active=True, scope={'data_mode': 'synthetic_test_only',
            'existing_resources_only': True, 'customer_deployment_authorized': False})
        from fox.forms_understanding_packet import local_packet
        packet = local_packet(docs)
        selected = prepare_prototype_admission(docs, expected_source_binding=packet['source_binding'],
            approved_chunk_hashes={row['id']: row['sha256'] for row in packet['chunks']},
            target_profile_sha256=canonical_hash(target), approved_redacted_source=True,
            approved_external_ai=True, approved_prototype_scope=True)['prototype']
        snapshot = {'project': pid, 'project_id': pid, 'project_name': 'Synthetic prototype',
            'source_hash': source_history._hash(files), 'conversion_profile': 'native-blueprint-prototype-v1',
            'selected_source_set_id': sid, 'files': files, 'prototype': selected,
            'approvals': {'redacted_source': True, 'external_ai': True, 'synthetic_prototype': True,
                          'owner': 'synthetic-owner', 'approved_at': 3.0}}
        db.execute('INSERT INTO runs VALUES(?,?,?,?,?,?,?,?)',
            (rid, pid, snapshot['source_hash'], 'ATTENTION', 'Sealed empty mapper', 3, 4, None))
        db.execute('INSERT INTO events(owner,action,object_id,created) VALUES(?,?,?,?)',
            ('synthetic-owner', 'approved_prototype_conversion', rid, 3.0))
    job = case.root / 'jobs' / rid
    job.mkdir()
    (job / 'source-snapshot.json').write_text(json.dumps(snapshot))
    with pytest.raises(ValueError):
        run_prototype_pipeline(job, docs, project_id=pid, project_name=snapshot['project_name'],
            expected_source_binding=selected['source_binding'], approved_chunk_hashes=selected['approved_chunk_hashes'],
            approved_policy_id=selected['approved_policy_id'], opaf_client=EmptyMapper(), profile=PROFILE,
            target_profile_loader=lambda: deepcopy(target), processing_approval_check=lambda _: True)
    return rid, job


@pytest.mark.parametrize('startup', [False, True])
def test_real_retirement_reader_accepts_known_terminal_failure_without_mutating_history(historical_case, startup):
    case = historical_case
    rid, _ = terminal_parent(case)
    before = _snapshot(case)
    value = _read(case, startup=startup)
    assert value['admission_state'] == 'READY'
    assert value['busy_conversion_count'] == value['waiting_verification_count'] == 0
    assert value['completed_retry']['job_id'] != rid
    assert value['completed_idle_jobs'] == case.history['idle']['completed_jobs']
    assert _snapshot(case) == before


@pytest.mark.parametrize('mutation', ['diagnostic-extra', 'unsealed', 'arbitrary-attention', 'retry-projection'])
def test_remote_reader_never_promotes_unknown_mapping_or_retry_authority(historical_case, monkeypatch, mutation):
    case = historical_case
    rid, job = terminal_parent(case)
    if mutation == 'diagnostic-extra':
        (job / 'prototype-diagnostics').mkdir()
    elif mutation == 'unsealed':
        next(job.glob('prototype-pipeline/focus-*/mapper.json')).unlink()
    elif mutation == 'arbitrary-attention':
        (job / 'source-snapshot.json').write_text('{}')
    else:
        actual = recovery.VerificationRecovery._eligibility
        def altered(self, db, job_id):
            value = actual(self, db, job_id)
            return {**value, 'retry_eligible': True} if job_id == rid else value
        monkeypatch.setattr(recovery.VerificationRecovery, '_eligibility', altered)
    before = _snapshot(case)
    with pytest.raises(remote.RetirementRemoteError, match=(
            'PRECHECK_ELIGIBILITY_INVALID' if mutation == 'retry-projection' else 'UNRESOLVED_OR_ACTIVE_WORK')):
        _read(case, startup=False)
    assert _snapshot(case) == before
