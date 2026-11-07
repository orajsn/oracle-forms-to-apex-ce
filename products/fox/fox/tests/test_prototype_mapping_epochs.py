"""Actual local epoch API/worker; all model and converter replies are authored."""
from contextlib import contextmanager
from copy import deepcopy
import json
from pathlib import Path
import sqlite3

import pytest

from fox import prototype_job, worker, prototype_mapping_epochs as epochs
from fox import forms_design_review
from fox.opaf import canonical_hash, OpafError
from fox.prototype_pipeline import run_prototype_pipeline, authorize_prototype_request
from fox.prototype_mapping_continuation import RECORD as FIRST_RECORD
from fox.prototype_transport import build_authority_bundle
from test_source_history_api import client, settings, no_external_actions, upload
from test_prototype_pipeline import SyntheticOpaf, SyntheticConverter, PROFILE, TARGET


class EpochModel(SyntheticOpaf):
    def __init__(self):
        super().__init__()
        self.special = None
        self.repair_mode = None

    def invoke(self, role, request):
        payload = request
        if role == PROFILE['reviewer']:
            request = {key: payload[key] for key in ('request', 'candidate', 'candidate_sha256')}
        output, invocation = super().invoke(role, request)
        self.calls[-1] = self.calls[-1][0], deepcopy(payload)
        invocation['request_sha256'] = canonical_hash(payload)
        if role == PROFILE['mapper']:
            units = request['code_units']
            number = len([name for name, _ in self.calls if name == 'mapper'])
            if 'repair_context' in request:
                output = deepcopy(request['repair_context']['raw_candidate'])
                if self.repair_mode == 'unknown': raise OSError('Authored uncertain repair')
                for index, row in enumerate(output['blueprint']['claims']):
                    row.update(kind='behavior.intent', status='proposal',
                               value='Select rows whose flag equals seventeen.' if index == 0 else 'Order names descending.')
                    output['blueprint']['actions'].append({'id': request['focus_id'] + '-action-' + str(index), 'claim_ids': [row['id']]})
                if self.repair_mode == 'invalid': output['blueprint']['claims'][0]['value'] = 'Invented metadata'
            elif number == 6:
                unit = units[0]
                output['blueprint']['claims'] = [{'id': request['focus_id'] + '-owner-confusion',
                    'source_object_id': unit['id'], 'kind': 'behavior.intent', 'status': 'proposal',
                    'value': 'Manual behavior review required.', 'evidence_refs': [unit['id']], 'reason': 'Authored fixture.'}]
            elif any(unit['source_attribute'] == 'WhereClause' for unit in units):
                output['blueprint']['claims'] = [{'id': request['focus_id'] + '-clause-' + str(index),
                    'source_object_id': unit['owner_id'], 'kind': 'block.where' if unit['source_attribute'] == 'WhereClause' else 'block.order',
                    'status': 'source_fact', 'value': 'Invented metadata', 'evidence_refs': [unit['id']],
                    'reason': 'Authored unsupported source fact; old AI approval is not truth.'} for index, unit in enumerate(units)]
                self.special = deepcopy(output)
            elif request['owned_objects'][0]['kind'] == 'Item' and self.special is not None:
                block = next(row for row in self.special['blueprint']['objects'] if 'native_component' in row)
                for row in output['blueprint']['objects']: row['screen_id'] = block['screen_id']
                output['blueprint']['screens'] = deepcopy(self.special['blueprint']['screens'])
                extra = deepcopy(block); extra['reason'] = 'Different context layout rationale; inspect independently.'
                output['blueprint']['objects'].append(extra)
                output['blueprint']['claims'] = [{'id': request['focus_id'] + '-context-kind',
                    'source_object_id': block['source_object_id'], 'kind': 'object.kind', 'status': 'source_fact',
                    'value': 'Block', 'evidence_refs': [block['source_object_id']], 'reason': 'Exact context metadata.'}]
                output['blueprint']['claims'].extend({'id': request['focus_id'] + '-alias-' + str(index),
                    'source_object_id': obj['id'], 'kind': 'object.item_type', 'status': 'source_fact',
                    'value': obj['item_type'], 'evidence_refs': [obj['id']], 'reason': 'Exact Item metadata alias.'}
                    for index, obj in enumerate(request['owned_objects'][:2]))
        elif payload.get('review_context', {}).get('operation') == 'repair_review' and self.repair_mode == 'reject':
            output.update(verdict='CHANGES_REQUIRED', findings=[{'source_object_id': None,
                'code': 'REPAIR_NOT_APPROVED', 'detail': 'Authored independent rejection.'}])
        invocation['response_sha256'] = canonical_hash(output)
        return output, invocation


class EpochConverter(SyntheticConverter):
    def run_stage(self, stage, request):
        value = super().run_stage(stage, request)
        value.update(status='COMPLETE', business_behavior_accepted=False)
        return value


@pytest.fixture
def tmp_path(tmp_path_factory):
    # Epoch provenance adds a fixed directory level. Keep Windows acceptance
    # data short rather than weakening any package/path validation.
    return tmp_path_factory.mktemp('e')


@pytest.fixture
def epochs_case(client, monkeypatch):
    monkeypatch.syspath_prepend(str(Path(__file__).resolve().parents[2] / 'converter'))
    monkeypatch.setenv('FOX_RUN_ADAPTER', 'embedded-opaf')
    monkeypatch.delenv('FOX_INSTALLATION_MODE', raising=False)
    monkeypatch.setitem(TARGET, 'active', True)
    monkeypatch.setitem(TARGET, 'scope', {'data_mode': 'synthetic_test_only', 'existing_resources_only': True,
                                      'customer_deployment_authorized': False})
    from forms2apex.target_profile import select_target_profile
    complete = select_target_profile('jsn-native-project-2616-v1')
    for key in ('scope', 'oci', 'database', 'apex', 'sqlcl'):
        monkeypatch.setitem(TARGET, key, deepcopy(complete[key]))
    for key in ('apex', 'sqlcl', 'apexlang_mmd'):
        monkeypatch.setitem(TARGET['tested_versions'], key, complete['tested_versions'][key])
    envelope = {'target_profile': TARGET, 'target_profile_sha256': canonical_hash(TARGET)}
    monkeypatch.setenv('FOX_PROTOTYPE_PROFILE_FILE', 'synthetic-metadata-only')
    monkeypatch.setattr(prototype_job, 'load_prototype_profile', lambda _: deepcopy(envelope))
    c, root, pid = client
    prefix = ''.join(f'<Block Name="B{i}" DatabaseBlock="true"><Item Name="VALUE" ItemType="Text Item" DatabaseItem="true"/>'
                     '<Trigger Name="SAVE" TriggerText="BEGIN NULL; END;"/></Block>' for i in range(5))
    special = '<Block Name="SPECIAL" DatabaseBlock="true" WhereClause="FLAG = 17" OrderByClause="NAME DESC">' + ''.join(
        f'<Item Name="V{i}" ItemType="Text Item" DatabaseItem="true"/>' for i in range(66)) + '</Block>'
    raw = ('<FormModule Name="SYNTHETIC">' + prefix + special +
        '<Block Name="LAST" DatabaseBlock="true"><Item Name="VALUE" ItemType="Text Item" DatabaseItem="true"/></Block></FormModule>').encode()
    upload(c, pid, [('synthetic.xml', raw)])
    assessment = c.get(f'/api/projects/{pid}/prototype-assessment').json()
    body = {key: assessment[key] for key in ('source_hash', 'source_binding', 'target_profile_sha256')}
    body.update(expected_current_source_set_id=assessment['selected_source_set_id'],
        approved_chunk_hashes={row['id']: row['sha256'] for row in assessment['chunks']},
        approved_redacted_source=True, approved_external_ai=True, approved_prototype_scope=True)
    response = c.post(f'/api/projects/{pid}/prototype-runs', json=body)
    assert response.status_code == 202, response.text
    rid = response.json()['id']; job = root / 'jobs' / rid; root.chmod(0o700)
    snapshot = json.loads((job / 'source-snapshot.json').read_bytes())
    model, converter = EpochModel(), EpochConverter()
    @contextmanager
    def db():
        connection = sqlite3.connect(root / 'fox.sqlite3'); connection.row_factory = sqlite3.Row
        try:
            with connection: yield connection
        finally: connection.close()
    def legacy_shape(directory, request, candidate, **kwargs):
        forms_design_review._candidate_shape(candidate, request, {row['id'] for row in request['owned_objects']})
        return candidate, None
    with monkeypatch.context() as old:
        old.setattr(epochs, 'resolved_mapper', legacy_shape)
        with pytest.raises(ValueError):
            run_prototype_pipeline(job, [('synthetic.xml', raw)], project_id=pid, project_name=snapshot['project_name'],
                expected_source_binding=body['source_binding'], approved_chunk_hashes=body['approved_chunk_hashes'],
                approved_policy_id=snapshot['prototype']['approved_policy_id'], opaf_client=model, profile=PROFILE,
                target_profile_loader=lambda: deepcopy(TARGET), processing_approval_check=lambda _: True, focus_schema_version=2)
    with db() as connection: connection.execute("UPDATE runs SET state='ATTENTION' WHERE id=?", (rid,))
    first = c.get(f'/api/projects/{pid}/prototype-runs/{rid}/mapping-continuation')
    assert first.status_code == 200, first.text
    posted = c.post(f'/api/projects/{pid}/prototype-runs/{rid}/continue-mapping',
                    json={**body, 'checkpoint_sha256': first.json()['checkpoint_sha256']})
    assert posted.status_code == 202, posted.text
    monkeypatch.setattr(prototype_job, '_configuration', lambda *args, **kwargs: {'profile': PROFILE,
        'opaf_client': model, 'target_profile_loader': lambda: deepcopy(TARGET), 'converter_adapter': converter})
    with monkeypatch.context() as old:
        # Reproduce the released 0.12 behavior: structural AI review occurred
        # before late whole-blueprint fact validation. No fake fact receipt is
        # persisted or used as current proof by this fixture.
        gate = epochs.source_fact_gate
        old.setattr(epochs, 'source_fact_gate', lambda packet, request, candidate:
            {'legacy_no_early_fact_gate': True} if any(row['kind'] in ('block.where', 'block.order')
                for row in candidate['blueprint']['claims']) else gate(packet, request, candidate))
        worker.process_one(db, root)
    assert len(list(job.glob('prototype-pipeline/focus-*/mapper.json'))) == 8
    assert len(list(job.glob('prototype-pipeline/focus-*/reviewer.json'))) == 7
    assert len(list(job.glob('prototype-pipeline/focus-*/mapper-resolution.json'))) == 1
    with db() as connection: assert connection.execute('SELECT state FROM runs WHERE id=?', (rid,)).fetchone()[0] == 'ATTENTION'
    return c, root, pid, rid, job, snapshot, body, model, converter, db, envelope


def api(case, suffix='mapping-epochs/next'):
    return f'/api/projects/{case[2]}/prototype-runs/{case[3]}/{suffix}'


def submission(case):
    response = case[0].get(api(case)); assert response.status_code == 200, response.text
    plan = response.json()
    return plan, {**case[6], 'checkpoint_sha256': plan['checkpoint_sha256'],
        'expected_epoch_number': plan['epoch_number'], 'expected_predecessor_sha256': plan['predecessor_sha256']}


def test_epoch_two_repairs_once_rechecks_both_versions_and_continues_remaining(epochs_case, monkeypatch):
    c, root, _, rid, job, snapshot, _, model, converter, db, _ = epochs_case
    before = {path.relative_to(job): path.read_bytes() for path in job.rglob('*') if path.is_file()}
    calls = deepcopy(model.calls)
    plan, body = submission(epochs_case)
    assert plan['ai_approved_focuses'] == 7 and plan['source_checked_focuses'] == 6
    assert plan['source_fact_violations'] == 2 and plan['remaining_focus_count'] == 2
    assert plan['continue_remaining_run'] is True and plan['planned_corrective_operations'] == epochs.OPERATIONS
    assert model.calls == calls and converter.calls == []
    result = c.post(api(epochs_case, 'mapping-epochs'), json=body)
    assert result.status_code == 202, result.text
    assert result.json()['id'] == rid and result.json()['epoch_number'] == 2
    assert c.post(api(epochs_case, 'mapping-epochs'), json=body).status_code == 200
    errors = []
    actual = prototype_job.run_prototype_job
    def traced(*args, **kwargs):
        try: return actual(*args, **kwargs)
        except Exception:
            import traceback
            errors.append(traceback.format_exc())
            raise
    monkeypatch.setattr(prototype_job, 'run_prototype_job', traced)
    worker.process_one(db, root)
    with db() as connection:
        row = dict(connection.execute('SELECT * FROM runs WHERE id=?', (rid,)).fetchone())
        assert row['state'] == 'GENERATED', '\n'.join(errors) or row['message']
        assert connection.execute('SELECT COUNT(*) FROM runs').fetchone()[0] == 1
    assert model.calls[:len(calls)] == calls
    newer = model.calls[len(calls):]
    assert newer[0][0] == 'mapper' and 'repair_context' in newer[0][1]
    assert newer[1][1]['review_context']['operation'] == 'repair_review'
    assert newer[2][1]['review_context']['operation'] == 'projection_review'
    assert len([name for name, payload in newer if name == 'mapper' and 'repair_context' in payload]) == 1
    assert len([name for name, payload in newer if name == 'mapper' and 'repair_context' not in payload]) == plan['remaining_focus_count']
    assert all((job / name).read_bytes() == raw for name, raw in before.items())
    assert json.loads((job / 'source-snapshot.json').read_bytes()) == snapshot
    assert len(list((job / 'prototype-pipeline' / epochs.PREFIX).glob('focus-*/projection-receipt.json'))) == 2
    assert converter.calls


@pytest.mark.parametrize('mode', ['unknown', 'invalid', 'reject'])
def test_epoch_has_no_corrective_loop_after_one_bad_or_uncertain_repair(epochs_case, mode):
    c, root, _, rid, _, _, _, model, converter, db, _ = epochs_case
    _, body = submission(epochs_case)
    assert c.post(api(epochs_case, 'mapping-epochs'), json=body).status_code == 202
    model.repair_mode = mode; count = len(model.calls)
    worker.process_one(db, root)
    newer = model.calls[count:]
    assert len([name for name, _ in newer if name == 'mapper']) == 1
    assert len(newer) == (2 if mode == 'reject' else 1)
    assert converter.calls == []
    with db() as connection: assert connection.execute('SELECT state FROM runs WHERE id=?', (rid,)).fetchone()[0] == 'ATTENTION'


@pytest.mark.parametrize('kind', ['absolute', 'parent', 'backslash', 'drive', 'empty-component',
                                'bad-hash', 'boolean-hash', 'not-map', 'over-count'])
def test_staged_technical_descriptors_fail_before_selected_file_reads(epochs_case, tmp_path, monkeypatch, kind):
    c, _, _, _, job, _, _, _, _, _, _ = epochs_case
    _, body = submission(epochs_case)
    assert c.post(api(epochs_case, 'mapping-epochs'), json=body).status_code == 202
    record = epochs.read(job / epochs.RECORD)
    root = tmp_path / 'staged'; directory = root / epochs.PREFIX
    directory.mkdir(parents=True)
    names = {'absolute': '/outside.json', 'parent': 'prototype-pipeline/../outside.json',
             'backslash': 'prototype-pipeline/evil\\outside.json', 'drive': 'C:/outside.json',
             'empty-component': 'prototype-pipeline//outside.json'}
    if kind in names: record['before_files'] = {names[kind]: 'a' * 64}
    elif kind == 'bad-hash': record['before_files'] = {'prototype-pipeline/outside.json': 'not-hash'}
    elif kind == 'boolean-hash': record['before_files'] = {'prototype-pipeline/outside.json': True}
    elif kind == 'not-map': record['before_files'] = []
    else: record['before_files'] = {'prototype-pipeline/f' + str(i): 'a' * 64 for i in range(4097)}
    (directory / 'epoch-record.json').write_text(json.dumps(record))
    reads = []
    original = Path.read_bytes
    def tracked(path):
        reads.append(path)
        if path.name != 'epoch-record.json':
            pytest.fail('Invalid descriptors must fail before any selected proof or predecessor file is read')
        return original(path)
    monkeypatch.setattr(Path, 'read_bytes', tracked)
    with pytest.raises(OpafError): epochs.technical_record(root)
    assert [path.name for path in reads] == ['epoch-record.json']


def test_staged_metadata_and_selected_proof_ancestor_links_are_refused(epochs_case, tmp_path):
    c, _, _, _, job, _, _, _, _, _, _ = epochs_case
    _, body = submission(epochs_case)
    assert c.post(api(epochs_case, 'mapping-epochs'), json=body).status_code == 202
    root = tmp_path / 'linked-staged'; outside = tmp_path / 'outside'; outside.mkdir(); root.mkdir()
    try:
        (root / 'epochs').symlink_to(outside, target_is_directory=True)
    except OSError:
        pytest.skip('Actual symlink creation unavailable under this Windows account')
    with pytest.raises(OpafError): epochs.technical_record(root)
    root2 = tmp_path / 'linked-proof'; directory = root2 / epochs.PREFIX; directory.mkdir(parents=True)
    record = epochs.read(job / epochs.RECORD)
    record['before_files'] = {'prototype-pipeline/alias/retained.json': 'a' * 64}
    (directory / 'epoch-record.json').write_text(json.dumps(record))
    (directory / 'predecessor-record.json').write_bytes((job / FIRST_RECORD).read_bytes())
    (root2 / 'alias').symlink_to(outside, target_is_directory=True)
    with pytest.raises(OpafError): epochs.technical_record(root2)


@pytest.mark.parametrize('injection', ['import-intent', 'epoch-three', 'foreign-focus', 'future-cache'])
def test_postqueue_foreign_work_blocks_worker_before_configuration(epochs_case, monkeypatch, injection):
    c, root, _, rid, job, _, _, model, converter, db, _ = epochs_case
    plan, body = submission(epochs_case)
    assert c.post(api(epochs_case, 'mapping-epochs'), json=body).status_code == 202
    pipeline = job / 'prototype-pipeline'
    if injection == 'import-intent': (pipeline / 'import-intent.json').write_text('{"request_sha256":"' + 'a' * 64 + '"}')
    elif injection == 'epoch-three': (pipeline / 'epochs' / 'epoch-000003').mkdir()
    elif injection == 'foreign-focus': (pipeline / epochs.PREFIX / ('focus-' + 'f' * 24)).mkdir()
    else:
        record = epochs.read(job / epochs.RECORD)
        from fox.forms_focus import build_focus_plan
        from fox.prototype_job import validate_prototype_snapshot
        snapshot = json.loads((job / 'source-snapshot.json').read_bytes()); selected = snapshot['prototype']
        full = build_focus_plan(validate_prototype_snapshot(snapshot), expected_source_binding=selected['source_binding'],
            approved_chunk_hashes=selected['approved_chunk_hashes'], max_owned_objects=32)
        later = pipeline / epochs.PREFIX / full['requests'][-1]['focus_id']; later.mkdir()
        for suffix in ('-request.json', '-target.json', '-intent.json', '.json'): (later / ('mapper' + suffix)).write_text('{}')
    calls = deepcopy((model.calls, converter.calls)); configurations = []
    monkeypatch.setattr(prototype_job, '_configuration', lambda *args, **kwargs: configurations.append(True))
    worker.process_one(db, root)
    assert configurations == [] and (model.calls, converter.calls) == calls
    with db() as connection: assert connection.execute('SELECT state FROM runs WHERE id=?', (rid,)).fetchone()[0] == 'ATTENTION'


def test_injected_foreign_intent_between_corrective_calls_stops_next_operation(epochs_case):
    c, root, _, _, job, _, _, model, converter, db, _ = epochs_case
    _, body = submission(epochs_case)
    assert c.post(api(epochs_case, 'mapping-epochs'), json=body).status_code == 202
    count = len(model.calls); invoke = model.invoke
    def injected(role, request):
        value = invoke(role, request)
        (job / 'prototype-pipeline' / 'import-intent.json').write_text('{"request_sha256":"' + 'b' * 64 + '"}')
        return value
    model.invoke = injected
    worker.process_one(db, root)
    assert len(model.calls) == count + 1 and model.calls[-1][0] == 'mapper'
    assert converter.calls == []


def test_json_phase_dictionary_cannot_exempt_unknown_intent(epochs_case):
    c, _, _, _, job, snapshot, _, _, _, db, _ = epochs_case
    _, body = submission(epochs_case)
    assert c.post(api(epochs_case, 'mapping-epochs'), json=body).status_code == 202
    (job / 'prototype-pipeline' / 'import-intent.json').write_text('{}')
    with db() as connection, pytest.raises(OpafError):
        epochs.validate_epoch_chain(job, snapshot, (job / 'source-snapshot.json').read_bytes(), connection,
            phase={'stage': 'import', 'request_sha256': 'a' * 64})


def test_epoch_authority_callback_staging_and_download_reconstruct_all_versions(epochs_case, monkeypatch):
    from types import SimpleNamespace
    from fox import prototype_authority
    from fox.prototype_download import retained_export_request
    from forms2apex.prototype_gateway import PrototypeGateway
    c, root, _, rid, job, snapshot, _, _, converter, db, envelope = epochs_case
    before = {path.relative_to(job): path.read_bytes() for path in job.rglob('*') if path.is_file()}
    _, body = submission(epochs_case)
    assert c.post(api(epochs_case, 'mapping-epochs'), json=body).status_code == 202
    profile = root / 'public-profile.json'; profile.write_text(json.dumps(envelope)); profile.chmod(0o600)
    stages, errors = [], []
    original_stage = converter.run_stage
    def checked_stage(stage, request):
        # Source-owner DB/event callback runs WHILE the exact current intent is
        # pending, as it does during the real converter HTTP request.
        try:
            result = prototype_authority.authorize_current(root, db, profile, request)
        except Exception:
            import traceback
            errors.append(traceback.format_exc())
            raise
        assert result['request_sha256'] == canonical_hash(request)
        stages.append(stage)
        return original_stage(stage, request)
    converter.run_stage = checked_stage
    worker.process_one(db, root)
    with db() as connection:
        row = dict(connection.execute('SELECT * FROM runs WHERE id=?', (rid,)).fetchone())
        assert row['state'] == 'GENERATED', '\n'.join(errors) or row['message']
    assert stages == ['validate', 'prepare_schema', 'import', 'verify_runtime', 'export']
    assert all((job / name).read_bytes() == raw for name, raw in before.items())
    request, receipt = retained_export_request(job, snapshot, envelope)
    callback = prototype_authority.authorize_current(root, db, profile, request)
    assert callback['request_sha256'] == canonical_hash(request) and receipt['exported'] is True
    bundle = build_authority_bundle(job, request)
    paths = {row['path'] for row in bundle['files']}
    assert epochs.PREFIX + '/epoch-record.json' in paths
    assert len([name for name in paths if name.endswith('projection-receipt.json')]) == 2
    assert len([name for name in paths if name.endswith('/mapper.json')]) == 11  # 8 historic + repair + 2 new
    remote_jobs = root / 'receiver'; remote_jobs.mkdir()
    remote = remote_jobs / rid
    gateway = PrototypeGateway(SimpleNamespace(jobs_root=remote_jobs),
        authorize=lambda value: authorize_prototype_request(remote, value))
    staged = gateway.stage_source_authority(rid, bundle)
    gateway._authorize(request)
    assert gateway.recover_source_authority(rid) == staged
    # A transferred consent claim never replaces the original DB event.
    with db() as connection:
        connection.execute('DELETE FROM events WHERE action=?', (epochs.EVENT,))
    with pytest.raises(OpafError): prototype_authority.authorize_current(root, db, profile, request)


@pytest.mark.parametrize('change', ['owner', 'source', 'selection', 'target', 'consent', 'unit-selection',
                                  'checkpoint', 'predecessor', 'epoch', 'origin', 'epoch-one-event'])
def test_epoch_admission_rejects_stale_scope_and_missing_origin(epochs_case, change):
    c, _, pid, rid, job, _, _, model, converter, db, envelope = epochs_case
    _, body = submission(epochs_case)
    calls = deepcopy((model.calls, converter.calls))
    if change in ('owner', 'source', 'selection', 'origin', 'epoch-one-event'):
        with db() as connection:
            if change == 'owner': connection.execute("UPDATE projects SET owner='foreign' WHERE id=?", (pid,))
            elif change == 'source': connection.execute('UPDATE sources SET text=text||?', (' ',))
            elif change == 'selection': connection.execute('UPDATE project_source_selection SET current_source_set_id=NULL')
            elif change == 'origin': connection.execute('DELETE FROM events WHERE action=? AND object_id=?', ('approved_prototype_conversion', rid))
            else: connection.execute('DELETE FROM events WHERE action=?', ('approved_prototype_mapping_continuation',))
    elif change == 'target': envelope['target_profile_sha256'] = 'a' * 64
    elif change == 'consent': body['approved_external_ai'] = False
    elif change == 'unit-selection': body['approved_chunk_hashes'] = {}
    elif change == 'checkpoint': body['checkpoint_sha256'] = 'b' * 64
    elif change == 'predecessor': body['expected_predecessor_sha256'] = 'c' * 64
    else: body['expected_epoch_number'] = 3
    response = c.post(api(epochs_case, 'mapping-epochs'), json=body)
    assert response.status_code == (404 if change == 'owner' else 409), response.text
    assert not (job / epochs.RECORD).exists() and (model.calls, converter.calls) == calls


def test_epoch_transaction_failure_preserves_orphans_and_refuses_replay(epochs_case):
    c, _, _, rid, job, _, _, model, converter, db, _ = epochs_case
    _, body = submission(epochs_case)
    original = {path.relative_to(job): path.read_bytes() for path in job.rglob('*') if path.is_file()}
    calls = deepcopy((model.calls, converter.calls))
    with db() as connection:
        connection.execute("CREATE TRIGGER epoch_abort BEFORE INSERT ON events WHEN NEW.action='" + epochs.EVENT +
                           "' BEGIN SELECT RAISE(ABORT,'Authored transaction failure'); END")
    assert c.post(api(epochs_case, 'mapping-epochs'), json=body).status_code == 409
    assert (job / epochs.RECORD).is_file()
    assert c.post(api(epochs_case, 'mapping-epochs'), json=body).status_code == 409
    assert c.get(api(epochs_case)).status_code == 409
    with db() as connection: assert connection.execute('SELECT state FROM runs WHERE id=?', (rid,)).fetchone()[0] == 'ATTENTION'
    assert all((job / name).read_bytes() == raw for name, raw in original.items())
    assert (model.calls, converter.calls) == calls


def test_epoch_admission_uses_real_enabled_strict_recovery_callback(epochs_case, monkeypatch):
    from fastapi.testclient import TestClient
    from fox.app import create_app
    from test_source_history_api import ORIGIN, login
    _, root, _, _, _, _, _, model, converter, _, _ = epochs_case
    monkeypatch.setenv('FOX_VERIFICATION_ENABLED', '1')
    monkeypatch.setenv('FOX_VERIFIER_RELEASE_SHA256', 'd' * 64)
    calls = deepcopy((model.calls, converter.calls))
    with TestClient(create_app(root, enable_worker=False), base_url=ORIGIN) as current:
        login(current)
        response = current.get(api(epochs_case)); assert response.status_code == 200, response.text
        plan = response.json()
        body = {**epochs_case[6], 'checkpoint_sha256': plan['checkpoint_sha256'],
            'expected_epoch_number': plan['epoch_number'], 'expected_predecessor_sha256': plan['predecessor_sha256']}
        posted = current.post(api(epochs_case, 'mapping-epochs'), json=body)
        assert posted.status_code == 202, posted.text
    assert (model.calls, converter.calls) == calls
