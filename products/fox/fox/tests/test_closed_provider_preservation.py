"""Synthetic closed-call maintenance evidence, never live/provider proof."""
from copy import deepcopy
import base64
import builtins
from datetime import datetime
import hashlib
import inspect
import io
import json
from pathlib import Path
import re
import sys

import pytest

from fox import verification_recovery as recovery
from fox import prototype_dsc_identity_repair as dsc, prototype_mapping_epochs as epochs
from fox import prototype_context_screen_epoch as screen
from fox.opaf import canonical_hash
from fox.forms_design_review import validate_design_review
from test_prototype_post_correction_terminal import (terminal_case, exact_historical_nine,
    historical_dsc_source, container_source_model, tmp_path, settings)
from test_prototype_container_terminal import inventory, edit, combine, generated_reader
from qa.operator.tests.test_retirement_remote_backend import historical_case, _read
from test_prototype_pipeline import SyntheticOpaf


def save(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(json.dumps(value, sort_keys=True).encode())


def seal(directory, role, payload, output, target, case, room):
    model = SyntheticOpaf()
    identity = {'job_id': case[3], 'source_hash': case[5]['prototype']['source_binding']}
    binding = {'role': target['opaf']['roles'][role], 'request_sha256': canonical_hash(payload), **identity}
    environment = model.observe_environment(binding['role'], identity, role_name=role, target_profile=target)
    invocation = {**binding['role'], 'room_id': room, 'request_sha256': canonical_hash(payload),
        'response_sha256': canonical_hash(output), 'started_at_utc': '2026-11-06T00:00:01+00:00',
        'completed_at_utc': '2026-11-06T00:00:02+00:00'}
    for suffix, value in (('-target.json', target), ('-intent.json', binding),
        ('.json', {'binding': binding, 'output': output, 'output_sha256': canonical_hash(output),
            'invocation': invocation, 'model_environment': environment,
            'model_environment_sha256': canonical_hash(environment)})):
        save(directory / (role + suffix), value)


@pytest.fixture
def closed_case(terminal_case):
    case = terminal_case
    job, snapshot, target = case[4], case[5], case[10]['target_profile']
    original = (job / 'source-snapshot.json').read_bytes()
    # The cache retains complete job-local evidence, not private external
    # operator staging directories. Exercise pure derive and independently
    # validate the actual immutable historical chain in the maintenance reader.
    from fox import prototype_clause_epoch as clause, prototype_container_epoch as container
    from fox import prototype_partition_review_epoch as partition
    for module, kind in ((clause, 'clause'), (container, 'container'), (partition, 'partition')):
        stage = module._stage(job)
        proof = job / 'prototype-pipeline' / module.PREFIX
        for path in (proof / (kind + '-proof')).rglob('*'):
            if path.is_file():
                destination = stage / 'json' / path.relative_to(proof / (kind + '-proof'))
                destination.parent.mkdir(parents=True, exist_ok=True)
                destination.write_bytes(path.read_bytes())
        (stage / 'descriptor.json').write_bytes((proof / (kind + '-proof-descriptor.json')).read_bytes())
    epoch = epochs.read(job / screen.RECORD)
    packet, plan = epochs.reconstruct(job, snapshot, original, target)
    before = {name: hashlib.sha256(raw).hexdigest() for name, raw in inventory(case).items()}
    root = job / 'prototype-pipeline'
    # Preserve the exact old publication bytes, including its historical path.
    # The pure derive builder's existing-history branch reads these immutable
    # hashes without reconstructing that historical absolute runtime location.
    # This temporary synthetic record is replaced below, before any assertion.
    save(root / dsc.RECORD, {'before_files': before})
    (root / dsc.PREFIX / 'historical-publication.json').write_bytes(
        (job / 'prototype-result-publications/epoch-000006/publication.json').read_bytes())
    (job / dsc.RESULT_BASE).mkdir(parents=True)
    (job / dsc.RESULT_BASE / 'previous-result.json').write_bytes((job / 'prototype-result.json').read_bytes())
    proposed, supplement, projections, _ = dsc.derive(root, epoch, packet, plan, target)
    checkpoint = dsc.checkpoint(epoch, before, proposed)
    record = {'schema_version': 1, 'scope': dsc.SCOPE, 'epoch_number': epoch['epoch_number'],
        'epoch_record_sha256': canonical_hash(epoch), 'job_id': case[3], 'project_id': case[2],
        'snapshot_sha256': hashlib.sha256(original).hexdigest(), 'source_hash': snapshot['source_hash'],
        'source_binding': snapshot['prototype']['source_binding'],
        'target_profile_sha256': canonical_hash(target), 'owner': snapshot['approvals']['owner'],
        'approved_at': epoch['approved_at'] + 10,
        'approvals': {'redacted_source': True, 'external_ai': True, 'synthetic_prototype': True},
        'before_files': before, 'plan': proposed, 'checkpoint_sha256': checkpoint}
    save(root / dsc.RECORD, record)
    save(root / dsc.PREFIX / 'supplement.json', supplement)
    with case[9]() as db:
        db.execute('INSERT INTO events(owner,action,object_id,created) VALUES(?,?,?,?)',
            (record['owner'], dsc.EVENT, dsc.event_id(case[3], record), record['approved_at']))
    for projection in projections:
        directory = root / dsc.PREFIX / projection['focus_id']
        candidate, task = projection['candidate'], projection['task']
        output = {'source_binding': packet['source_binding'], 'focus_binding': task['request']['focus_binding'],
            'candidate_sha256': canonical_hash(candidate), 'verdict': 'APPROVED', 'findings': []}
        for name, value in (('projection-candidate.json', candidate), ('projection-receipt.json', projection['receipt']),
            ('reviewer-request.json', task), ('review-receipt.json', validate_design_review(task['request'], candidate, output))):
            save(directory / name, value)
        seal(directory, 'reviewer', task, output, target, case, 'authored-maintenance-' + projection['focus_id'])
    request = plan['requests'][proposed['historical_focus_count']]
    directory = root / 'epochs/epoch-000006' / request['focus_id']
    save(directory / 'mapper-request.json', request)
    payload = dsc.model_task(directory, 'mapper', request, write=True)
    # Deliberately invalid candidate schema. Its terminal provider envelope is
    # sound; maintenance may retain it without calling it a valid mapping.
    seal(directory, 'mapper', payload, {'invalid_candidate': True}, target, case, 'authored-invalid-frontier')
    return case, directory


def preserved(case):
    with case[9]() as db:
        db.execute('PRAGMA query_only=ON'); db.execute('BEGIN')
        store = recovery.VerificationRecovery(case[1] / 'fox.sqlite3', enabled=True)
        return store._protected_read_status(db, case[3], purpose='maintenance_preservation')


def test_closed_invalid_candidate_is_maintenance_only_readonly(closed_case, monkeypatch):
    case, directory = closed_case
    before = inventory(case)
    def forbidden(*args, **kwargs): pytest.fail('Maintenance attempted a file write.')
    for name in ('write_text', 'write_bytes', 'mkdir', 'unlink', 'rename', 'touch'):
        monkeypatch.setattr(Path, name, forbidden)
    status = preserved(case)
    assert status['preservation_allowed'] is True
    assert status['admission']['blocks_admission'] is True
    assert status['admission']['retry_eligible'] is False
    assert inventory(case) == before
    with case[9]() as db:
        db.execute('BEGIN IMMEDIATE')
        store = recovery.VerificationRecovery(case[1] / 'fox.sqlite3', enabled=True)
        assert store.admission_allowed(db) is False
        with pytest.raises(recovery.RecoveryError, match='PURPOSE_INVALID'):
            store._protected_read_status(db, case[3], purpose='conversion')


@pytest.mark.parametrize('fault', ['missing-envelope', 'envelope-hash', 'request', 'intent', 'target',
    'environment', 'policy', 'metadata-guidance', 'orphan-sidecar', 'unknown', 'oracle', 'transport',
    'later-focus', 'later-intent', 'queued', 'processing', 'owner', 'source', 'event', 'authorization'])
def test_unclosed_corrupt_unknown_or_live_work_refuses_preservation(closed_case, fault):
    case, directory = closed_case
    if fault in ('queued', 'processing', 'owner', 'source', 'event'):
        with case[9]() as db:
            if fault in ('queued', 'processing'): db.execute('UPDATE runs SET state=? WHERE id=?', (fault.upper(), case[3]))
            elif fault == 'owner': db.execute("UPDATE projects SET owner='foreign' WHERE id=?", (case[2],))
            elif fault == 'source': db.execute("UPDATE sources SET text=text||' '")
            else: db.execute('DELETE FROM events WHERE action=?', (dsc.EVENT,))
    elif fault == 'missing-envelope': (directory / 'mapper.json').unlink()
    elif fault == 'envelope-hash': edit(directory / 'mapper.json', lambda x: x.update(output_sha256='0' * 64))
    elif fault == 'request': edit(directory / 'mapper-request.json', lambda x: x.update(focus_binding='0' * 64))
    elif fault == 'intent': edit(directory / 'mapper-intent.json', lambda x: x.update(request_sha256='0' * 64))
    elif fault == 'target': edit(directory / 'mapper-target.json', lambda x: x.update(active=False))
    elif fault == 'environment': edit(directory / 'mapper.json', lambda x: x['model_environment'].update(job_id='fox-' + '0' * 20))
    elif fault in ('policy', 'metadata-guidance'):
        def change(x):
            x['metadata_task_policy' if fault == 'policy' else 'metadata_guidance'] = 'forged'
            x['metadata_task_binding'] = canonical_hash({k: v for k, v in x.items() if k != 'metadata_task_binding'})
        edit(directory / 'mapper-metadata-task.json', change)
    elif fault == 'orphan-sidecar': save(directory / 'reviewer-metadata-task.json', {})
    elif fault == 'unknown': save(case[4] / 'unknown.json', {})
    elif fault == 'oracle': save(case[4] / 'prototype-pipeline/import-intent.json', {})
    elif fault == 'transport': (case[4] / 'prototype-transport').mkdir()
    elif fault == 'later-focus': (directory.parent / ('focus-' + 'f' * 24)).mkdir()
    elif fault == 'later-intent': save(directory / 'reviewer-intent.json', {})
    else: edit(case[4] / 'prototype-pipeline' / dsc.RECORD, lambda x: x.update(checkpoint_sha256='0' * 64))
    before = inventory(case)
    assert preserved(case)['preservation_allowed'] is False
    assert inventory(case) == before


def test_stdlib_reader_and_independent_retirement_recheck(closed_case, historical_case, monkeypatch):
    case, _ = closed_case
    namespace = {'Path': Path, 'json': json, 'hashlib': hashlib, 're': re, 'datetime': datetime}
    real_import = builtins.__import__
    def stdlib(name, *args, **kwargs):
        assert name in ('math', 'os')
        return real_import(name, *args, **kwargs)
    namespace['__builtins__'] = {**vars(builtins), '__import__': stdlib}
    exec(inspect.getsource(recovery.terminal_empty_prototype_mapping) + '\n' +
         inspect.getsource(recovery.terminal_closed_provider_preservation), namespace)
    with case[9]() as db:
        run = dict(db.execute('SELECT * FROM runs WHERE id=?', (case[3],)).fetchone())
        assert namespace['terminal_closed_provider_preservation'](case[1] / 'fox.sqlite3', db, run)
    combine(case, historical_case)
    result, imported, errors = generated_reader(historical_case, monkeypatch)
    assert result.get('status') == 'RETIRED_HISTORY_OBSERVED', errors[-8:]
    assert not imported & {'prototype_dsc_identity_repair.py', 'prototype_candidate_continuation.py'}
    assert _read(historical_case)['admission_state'] == 'READY'
    status = recovery.VerificationRecovery._protected_read_status
    monkeypatch.setattr(recovery.VerificationRecovery, '_protected_read_status', lambda self, db, rid, **kw:
        {'admission': {'blocks_admission': True, 'recovery_state': 'attention', 'retry_eligible': False},
         'preservation_allowed': True, 'preservation_state': 'closed_provider_history'} if rid == case[3] else status(self, db, rid, **kw))
    monkeypatch.setattr(recovery, 'terminal_closed_provider_preservation', lambda *args: False)
    from qa.operator.retirement_remote import RetirementRemoteError
    with pytest.raises(RetirementRemoteError, match='PRESERVATION_UNCONFIRMED'): _read(historical_case)


def test_transition_explicit_purpose_and_independent_predicate(closed_case, historical_case, monkeypatch):
    from deployment import current_pair_transition as transition
    case, _ = closed_case
    combine(case, historical_case)
    source = Path(recovery.__file__).read_bytes()
    def execute(raw):
        packet = {'source': base64.b64encode(raw).decode(), 'sha256': hashlib.sha256(raw).hexdigest(),
                  'paths': sys.path[:], 'data': str(historical_case.root)}
        output = io.StringIO()
        with monkeypatch.context() as patch:
            patch.setattr(sys, 'stdin', io.StringIO(json.dumps(packet)))
            patch.setattr(sys, 'stdout', output)
            exec(compile(transition.BACKEND, '<actual-transition-backend>', 'exec'), {})
        return json.loads(output.getvalue())
    observed = execute(source)
    assert observed['eligibility'][case[3]]['blocks_admission'] is True
    assert observed['preservation'][case[3]] == 'closed_provider_history'
    # A forged reader projection cannot replace the independent tree check.
    forged = source + b'\nterminal_closed_provider_preservation = lambda *args: False\n'
    # Force only the purpose projection to lie; ordinary eligibility is intact.
    forged += ("\n_original_protected = VerificationRecovery._protected_read_status\n"
        "def _forged_protected(self, db, job_id, *, purpose):\n"
        " value = _original_protected(self, db, job_id, purpose=purpose)\n"
        " if job_id == " + repr(case[3]) + ":\n"
        "  value.update(preservation_allowed=True, preservation_state='closed_provider_history')\n"
        " return value\n"
        "VerificationRecovery._protected_read_status = _forged_protected\n").encode()
    with pytest.raises(AssertionError): execute(forged)
