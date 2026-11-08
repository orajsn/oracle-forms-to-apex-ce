"""Local API/worker scope correction. Provider and Oracle replies are AUTHORED.

No live OPAF call, Oracle operation or business acceptance is claimed.
"""
from concurrent.futures import ThreadPoolExecutor
from copy import deepcopy
import hashlib

import pytest

from fox import prototype_context_screen_epoch as screen, prototype_mapping_epochs as epochs
from fox import prototype_review_correction as correction, prototype_result_publication as publication
from fox.opaf import OpafError, canonical_hash
from test_forms_design_review import sample, changes
from test_prototype_pipeline import PROFILE
from test_prototype_partition_review import inputs, build as partition_task
from test_prototype_context_screen_epoch import (screen_case, next_body as epoch_body, files, process,
    partition_case, container_case, container_source_model, clause_case, epochs_case,
    tmp_path, client, settings, no_external_actions, api)


def _inject_original_review(role, payload, failed_focus_id):
    return (role == PROFILE['reviewer'] and payload.get('scope') != correction.SCOPE
        and payload.get('request', {}).get('focus_id') == failed_focus_id)


@pytest.mark.parametrize('role,scope,focus,expected', [
    (PROFILE['reviewer'], 'original-task', 'saved-nine', True),
    (PROFILE['mapper'], 'original-task', 'saved-nine', False),
    (PROFILE['reviewer'], correction.SCOPE, 'saved-nine', False),
    (PROFILE['reviewer'], 'original-task', 'later-ten', False),
    (PROFILE['reviewer'], 'original-task', None, False)])
def test_invalid_response_fixture_targets_only_original_focus_nine(role, scope, focus, expected):
    assert _inject_original_review(role, {'scope': scope, 'request': {'focus_id': focus}}, 'saved-nine') is expected


def test_future_ledger_is_pure_exact_and_does_not_change_historical_formatter(inputs):
    task, audit = partition_task(inputs)
    before = deepcopy(task)
    future = correction.future_review_task(task)
    assert task == before and partition_task(inputs) == (before, audit)
    assert future['request'] == task['request'] and future['candidate'] == task['candidate']
    assert future['scope'] == task['scope'] and future['task_binding'] != task['task_binding']
    assert future == correction.future_review_task(task)
    ledger = future['ownership_ledger']
    assert ledger['owned_objects'] == [{'id': row['id'], 'kind': row['kind']} for row in task['request']['owned_objects']]
    assert ledger['context_only_objects'] == [{'id': row['id'], 'kind': row['kind']} for row in task['request']['context_objects']]
    assert ledger['inherited_screens']
    ledger['inherited_screens'][0]['declaration']['title'] = 'Changed output copy only'
    assert task == before


def test_source_render_wrapper_cache_is_full_request_local_and_file_fenced(tmp_path, monkeypatch):
    """Cache mechanics only; the connected tests use actual reconstruction."""
    from fox import prototype_pipeline as pipeline, prototype_read_scope as scope
    root = tmp_path / 'prototype-pipeline'
    (root / 'epochs/epoch-000004').mkdir(parents=True)
    path = root / 'one.json'
    original = b'{"unchanged":true}'
    path.write_bytes(original)
    calls = []
    def compute(job, request):
        calls.append(deepcopy(request))
        return {'request': deepcopy(request)}
    monkeypatch.setattr(pipeline, '_authorize_prototype_request', compute)
    request = {'binding': 'original'}
    with scope.epoch_read_scope(root):
        first = pipeline.authorize_prototype_request(root.parent, request)
        first['request']['binding'] = 'mutated-return-value'
        assert pipeline.authorize_prototype_request(root.parent, request)['request'] == request
        pipeline.authorize_prototype_request(root.parent, {'binding': 'different'})
        assert calls == [request, {'binding': 'different'}]
    # Outside a shared operation each call independently reconstructs.
    pipeline.authorize_prototype_request(root.parent, request)
    pipeline.authorize_prototype_request(root.parent, request)
    assert len(calls) == 4
    try:
        with pytest.raises(OpafError):
            with scope.epoch_read_scope(root):
                pipeline.authorize_prototype_request(root.parent, request)
                pipeline.authorize_prototype_request(root.parent, request)
                path.write_bytes(b'{"unchanged":false}')
    finally:
        path.write_bytes(original)


@pytest.mark.parametrize('artifact', ['empty-transport', 'completed-transport', 'future-fact', 'foreign-fact'])
def test_initial_correction_rejects_downstream_namespace_before_reconstruction(tmp_path, monkeypatch, artifact):
    """Early-boundary unit only; API/state preservation is checked below."""
    job = tmp_path / 'disposable-job'
    root = job / 'prototype-pipeline'
    root.mkdir(parents=True)
    (job / 'source-snapshot.json').write_bytes(b'{"preserved":true}')
    if artifact.endswith('transport'):
        directory = job / 'prototype-transport'
        directory.mkdir()
        if artifact == 'completed-transport':
            (directory / 'authority-intent.json').write_bytes(b'{}')
            (directory / 'authority.json').write_bytes(b'{}')
    else:
        directory = root / screen.PREFIX / 'source-facts'
        directory.mkdir(parents=True)
        name = 'focus-' + ('a' if artifact == 'future-fact' else 'f') * 24 + '.json'
        (directory / name).write_bytes(b'{}')
    before = files(job)
    def forbidden(*args, **kwargs): pytest.fail('Downstream artifacts must block before technical reconstruction or adoption.')
    monkeypatch.setattr(screen, 'validate_record', forbidden)
    with pytest.raises(OpafError): correction.inspect(job, None, None, None, object())
    assert files(job) == before and not (root / correction.RECORD).exists()


def test_fact_diagnostic_cache_keys_all_inputs_defensively_copies_and_expires(tmp_path, monkeypatch):
    from fox import prototype_focus_projection as projection, prototype_read_scope as scope
    from test_prototype_focus_projection import example
    _, packet, plan, raw, repaired, _ = example()
    request = plan['requests'][1]
    root = tmp_path / 'fact-proof'
    root.mkdir()
    (root / 'one.json').write_bytes(b'{}')
    actual, calls = projection.source_fact_index, []
    def counted(value): calls.append(True); return actual(value)
    monkeypatch.setattr(projection, 'source_fact_index', counted)
    with scope.readonly_proof_scope(root):
        first = projection.fact_diagnostics(packet, request, raw)
        assert len(first) == 2
        first.clear()
        assert len(projection.fact_diagnostics(packet, request, raw)) == 2 and len(calls) == 1
        assert projection.fact_diagnostics(packet, request, repaired) == [] and len(calls) == 2
        stale_packet = deepcopy(packet); stale_packet['source_binding'] = '0' * 64
        with pytest.raises(ValueError): projection.fact_diagnostics(stale_packet, request, raw)
        assert len(calls) == 3
        stale_request = deepcopy(request); stale_request['source_binding'] = '0' * 64
        with pytest.raises(ValueError): projection.fact_diagnostics(packet, stale_request, raw)
        assert len(calls) == 4
    projection.fact_diagnostics(packet, request, raw)
    projection.fact_diagnostics(packet, request, raw)
    assert len(calls) == 6  # Outside scope there is no cache.
    with scope.readonly_proof_scope(root): projection.fact_diagnostics(packet, request, raw)
    assert len(calls) == 7


def test_fact_cache_keeps_filesystem_exit_fence_and_rejects_inherited_thread(tmp_path):
    from contextvars import copy_context
    from fox import prototype_focus_projection as projection, prototype_read_scope as scope
    from test_prototype_focus_projection import example
    _, packet, plan, raw, _, _ = example()
    root = tmp_path / 'fact-proof'
    root.mkdir()
    path = root / 'one.json'; original = b'{}'; path.write_bytes(original)
    with scope.readonly_proof_scope(root):
        projection.fact_diagnostics(packet, plan['requests'][1], raw)
        context = copy_context()
        with ThreadPoolExecutor(max_workers=1) as pool:
            future = pool.submit(context.run, projection.fact_diagnostics, packet, plan['requests'][1], raw)
            with pytest.raises(OpafError): future.result()
    try:
        with pytest.raises(OpafError):
            with scope.readonly_proof_scope(root):
                projection.fact_diagnostics(packet, plan['requests'][1], raw)
                projection.fact_diagnostics(packet, plan['requests'][1], raw)
                path.write_bytes(b'{"changed":true}')
    finally:
        path.write_bytes(original)


def test_baseline_cache_validates_complete_map_coverage_thread_and_expiry(tmp_path, monkeypatch):
    from contextvars import copy_context
    from fox import prototype_read_scope as scope
    root = tmp_path / 'prototype-pipeline'; root.mkdir()
    first = root / 'binding.json'; first.write_bytes(b'{}')
    second = root / 'packet.json'; second.write_bytes(b'{"second":true}')
    outside = tmp_path / 'uncovered.json'; outside.write_bytes(b'{}')
    digest = hashlib.sha256(first.read_bytes()).hexdigest()
    one = {'binding.json': digest}
    two = {**one, 'packet.json': hashlib.sha256(second.read_bytes()).hexdigest()}
    actual, calls = epochs._check_before_unchanged, []
    def counted(base, descriptors): calls.append((base, descriptors)); return actual(base, descriptors)
    monkeypatch.setattr(epochs, '_check_before_unchanged', counted)
    with scope.readonly_proof_scope(root):
        assert epochs._before_unchanged(root, one) is None
        assert epochs._before_unchanged(root, dict(one)) is None and len(calls) == 1
        epochs._before_unchanged(root, two); assert len(calls) == 2
        with pytest.raises(OpafError): epochs._before_unchanged(root, {'binding.json': '0' * 64})
        with pytest.raises(OpafError): epochs._before_unchanged(root, {'missing.json': digest})
        assert len(calls) == 4
        with pytest.raises(OpafError): epochs._before_unchanged(root, {**one, '../bad': digest})
        assert len(calls) == 4  # All descriptors checked before ANY read/cache lookup.
        context = copy_context()
        with ThreadPoolExecutor(max_workers=1) as pool:
            future = pool.submit(context.run, epochs._before_unchanged, root, one)
            with pytest.raises(OpafError): future.result()
        assert len(calls) == 4
        epochs._before_unchanged(tmp_path, {'uncovered.json': digest})
        outside.write_bytes(b'{"changed":true}')
        try:
            with pytest.raises(OpafError): epochs._before_unchanged(tmp_path, {'uncovered.json': digest})
        finally:
            outside.write_bytes(b'{}')
        assert len(calls) == 6  # Uncovered paths are always reread.
        epochs._before_unchanged(tmp_path, {'prototype-pipeline/binding.json': digest})
        epochs._before_unchanged(tmp_path, {'prototype-pipeline/binding.json': digest})
        assert len(calls) == 7  # Exact owning-job pipeline coverage is supported.
    epochs._before_unchanged(root, one); epochs._before_unchanged(root, one)
    assert len(calls) == 9
    with scope.readonly_proof_scope(root): epochs._before_unchanged(root, one)
    assert len(calls) == 10


@pytest.mark.parametrize('mutation', ['file', 'directory', 'permission'])
def test_baseline_cached_hit_keeps_raw_and_identity_exit_fences(tmp_path, mutation):
    import stat
    from fox import prototype_read_scope as scope
    root = tmp_path / 'proof'; root.mkdir()
    path = root / 'binding.json'; original = b'{}'; path.write_bytes(original)
    mode = stat.S_IMODE(path.stat().st_mode)
    values = {'binding.json': hashlib.sha256(original).hexdigest()}
    try:
        with pytest.raises(OpafError):
            with scope.readonly_proof_scope(root):
                epochs._before_unchanged(root, values)
                if mutation == 'file': path.write_bytes(b'{"changed":true}')
                elif mutation == 'directory': (root / 'extra').mkdir()
                else: path.chmod(0o444)
                assert epochs._before_unchanged(root, values) is None  # Exit fence must still reject.
    finally:
        path.chmod(mode); path.write_bytes(original)
        if (root / 'extra').exists(): (root / 'extra').rmdir()


def test_transport_paths_never_use_baseline_cache_even_if_inventory_fenced(tmp_path, monkeypatch):
    from fox import prototype_read_scope as scope
    root = tmp_path / 'prototype-pipeline'
    directory = root / 'prototype-transport'; directory.mkdir(parents=True)
    (directory / 'authority.json').write_bytes(b'{}')
    values = {'prototype-transport/authority.json': hashlib.sha256(b'{}').hexdigest()}
    actual, calls = epochs._check_before_unchanged, []
    def counted(base, descriptors): calls.append(True); return actual(base, descriptors)
    monkeypatch.setattr(epochs, '_check_before_unchanged', counted)
    with scope.readonly_proof_scope(root):
        assert scope.baseline_read_root(root, values) is None
        assert epochs._before_unchanged(root, values) is None
        assert epochs._before_unchanged(root, values) is None
    assert len(calls) == 2


@pytest.mark.parametrize('mutation', ['owned', 'global', 'unknown', 'mixed', 'bad-binding', 'bad-shape'])
def test_only_context_attribution_is_eligible_and_original_is_unchanged(sample, mutation):
    request, candidate, _ = sample
    output = changes(request, candidate, owner=request['context_objects'][0]['id'])
    before = deepcopy(output)
    assert correction.scope_defect(request, candidate, output)['kind'] == 'CONTEXT_ONLY_FINDING_ATTRIBUTION'
    assert output == before
    if mutation == 'owned': output['findings'][0]['source_object_id'] = request['owned_objects'][0]['id']
    elif mutation == 'global': output['findings'][0]['source_object_id'] = None
    elif mutation == 'unknown': output['findings'][0]['source_object_id'] = 'unknown-id'
    elif mutation == 'mixed': output['findings'].append(changes(request, candidate)['findings'][0])
    elif mutation == 'bad-binding': output['candidate_sha256'] = '0' * 64
    else: output['extra'] = True
    with pytest.raises((OpafError, ValueError)):
        correction.scope_defect(request, candidate, output)


@pytest.fixture
def correction_case(screen_case, monkeypatch):
    case, _ = screen_case
    epoch_plan, body = epoch_body(screen_case)
    assert case[0].post(api(case, 'mapping-epochs'), json=body).status_code == 202
    model = case[7]
    original = model.invoke
    injected = []
    def invalid_scope(role, payload):
        output, invocation = original(role, payload)
        if _inject_original_review(role, payload, epoch_plan['pending_review_focus_id']):
            source = next(row for row in payload['request']['context_objects'] if row['kind'] == 'Block')
            output.update(verdict='CHANGES_REQUIRED', findings=[{'source_object_id': source['id'],
                'code': 'MISSING_SCREEN_DECLARATION', 'detail': 'Authored context Block attribution defect.'}])
            invocation['response_sha256'] = canonical_hash(output)
            assert correction.scope_defect(payload['request'], payload['candidate'], output)['kind'] == 'CONTEXT_ONLY_FINDING_ATTRIBUTION'
            injected.append(deepcopy(output))
        return output, invocation
    monkeypatch.setattr(model, 'invoke', invalid_scope)
    before = files(case[4])
    count = len(model.calls)
    row, errors = process(case, monkeypatch)
    assert len(injected) == 1, 'The invalid review fixture must actually inject exactly one response.'
    assert row['state'] == 'ATTENTION', errors
    assert len(model.calls[count:]) == 1 and model.calls[count:][0][0] == 'reviewer'
    assert not (case[4] / screen.RESULT_BASE / 'publication.json').exists()
    assert all((case[4] / name).read_bytes() == raw for name, raw in before.items())
    return case


def next_body(case):
    response = case[0].get(api(case, 'review-correction'))
    assert response.status_code == 200, response.text
    plan = response.json()
    return plan, {**case[6], 'checkpoint_sha256': plan['checkpoint_sha256'],
        'expected_epoch_record_sha256': plan['epoch_record_sha256'],
        'expected_failed_request_sha256': plan['failed_request_sha256'],
        'expected_failed_response_sha256': plan['failed_response_sha256']}


def test_exact_child_consent_concurrency_preservation_and_complete_reconstruction(correction_case, monkeypatch):
    from fox.prototype_download import retained_export_request
    case = correction_case
    c, _, _, rid, job, snapshot, _, model, _, db, envelope = case
    before, count = files(job), len(model.calls)
    plan, body = next_body(case)
    assert plan['eligible'] is True and plan['correction_recorded'] is False
    assert plan['reason'] == correction.REASON
    assert plan['epoch_number'] == 6 and plan['ai_approved_focuses'] == 8
    assert plan['remaining_focus_count'] == plan['unstarted_focus_count'] + 1
    assert plan['new_reviewer_calls'] == 1 and plan['repeated_mapper_calls'] == 0
    for key, value in [('approved_external_ai', False), ('expected_failed_response_sha256', '0' * 64),
        ('expected_failed_request_sha256', '0' * 64), ('expected_epoch_record_sha256', '0' * 64),
        ('checkpoint_sha256', '0' * 64), ('source_binding', '0' * 64), ('target_profile_sha256', '0' * 64)]:
        assert c.post(api(case, 'review-correction'), json={**body, key: value}).status_code == 409
    assert files(job) == before and len(model.calls) == count
    # Pending/unknown future work, source/prefix/context/role drift all fail closed.
    focus = plan['pending_review_focus_id']
    directory = job / 'prototype-pipeline' / screen.PREFIX / focus
    raw_response = directory / 'reviewer.json'
    mutations = [(directory / 'reviewer-intent.json', None),
        (job / 'prototype-pipeline/validate-intent.json', b'{}'),
        (directory / 'full-audit-context.json', b'{}'),
        (job / 'source-snapshot.json', b'{}'),
        (raw_response, raw_response.read_bytes() + b' ')]
    for path, replacement in mutations:
        existed, raw = path.exists(), path.read_bytes() if path.exists() else None
        try:
            if replacement is None: path.unlink()
            else: path.write_bytes(replacement)
            # Whitespace on an as-yet-unsealed raw envelope is a different exact
            # checkpoint, not an invalid canonical response; old POST must reject.
            if path == raw_response:
                assert c.post(api(case, 'review-correction'), json=body).status_code == 409
            else:
                assert c.get(api(case, 'review-correction')).status_code == 409
        finally:
            if existed: path.write_bytes(raw)
            else: path.unlink(missing_ok=True)
    with db() as connection:
        state_before = tuple(connection.execute('SELECT * FROM runs WHERE id=?', (rid,)).fetchone())
        events_before = connection.execute('SELECT COUNT(*) FROM events').fetchone()[0]
    downstream = [job / 'prototype-transport', job / 'prototype-pipeline' / screen.PREFIX / 'source-facts']
    for path in downstream:
        path.mkdir()
        try:
            variants = [None, 'completed'] if path.name == 'prototype-transport' else ['future', 'foreign']
            for variant in variants:
                added = []
                if variant == 'completed':
                    added = [path / 'authority-intent.json', path / 'authority.json']
                elif variant is not None:
                    all_plan = epochs.reconstruct(job, snapshot, (job / 'source-snapshot.json').read_bytes(), envelope['target_profile'])[1]
                    focus_id = all_plan['requests'][9]['focus_id'] if variant == 'future' else 'focus-' + 'f' * 24
                    added = [path / (focus_id + '.json')]
                for artifact in added: artifact.write_bytes(b'{}')
                try:
                    unchanged = files(job)
                    assert c.get(api(case, 'review-correction')).status_code == 409
                    assert c.post(api(case, 'review-correction'), json=body).status_code == 409
                    assert files(job) == unchanged
                    with db() as connection:
                        assert tuple(connection.execute('SELECT * FROM runs WHERE id=?', (rid,)).fetchone()) == state_before
                        assert connection.execute('SELECT COUNT(*) FROM events').fetchone()[0] == events_before
                finally:
                    for artifact in added: artifact.unlink()
        finally:
            path.rmdir()  # Only this freshly created, empty test namespace.
    assert files(job) == before and len(model.calls) == count
    with ThreadPoolExecutor(max_workers=2) as pool:
        replies = list(pool.map(lambda _: c.post(api(case, 'review-correction'), json=body), range(2)))
    assert sorted(reply.status_code for reply in replies) == [200, 202], [r.text for r in replies]
    child = epochs.read(job / 'prototype-pipeline' / correction.RECORD)
    with db() as connection:
        assert connection.execute('SELECT COUNT(*) FROM events WHERE action=?', (correction.EVENT,)).fetchone()[0] == 1
    assert files(job).keys() - before.keys() == {'prototype-pipeline/' + correction.RECORD}
    # A durable authorization without its exact event may never requeue.
    with db() as connection:
        event = tuple(connection.execute('SELECT owner,action,object_id,created FROM events WHERE action=?', (correction.EVENT,)).fetchone())
        connection.execute('DELETE FROM events WHERE action=?', (correction.EVENT,))
    assert c.post(api(case, 'review-correction'), json=body).status_code == 409
    with db() as connection:
        connection.execute('INSERT INTO events(owner,action,object_id,created) VALUES(?,?,?,?)', event)
    row, errors = process(case, monkeypatch)
    assert row['state'] == 'GENERATED', '\n'.join(errors) or row['message']
    calls = model.calls[count:]
    assert calls[0][0] == 'reviewer' and calls[0][1]['scope'] == correction.SCOPE
    assert calls[0][1]['candidate_sha256'] == plan['candidate_sha256']
    assert all(row['kind'] != 'Block' for row in calls[0][1]['ownership_ledger']['owned_objects'])
    assert calls[0][1]['ownership_ledger']['inherited_screens']
    assert len([role for role, _ in calls if role == 'mapper']) == plan['unstarted_focus_count']
    for role, payload in calls:
        if role != 'reviewer': continue
        assert payload['ownership_ledger']['owned_objects'] == [
            {'id': row['id'], 'kind': row['kind']} for row in payload['request']['owned_objects']]
        assert payload['ownership_ledger']['context_only_objects'] == [
            {'id': row['id'], 'kind': row['kind']} for row in payload['request']['context_objects']]
    assert all((job / name).read_bytes() == raw for name, raw in before.items() if name != 'prototype-result.json')
    assert epochs.read(job / 'prototype-pipeline' / correction.RECORD) == child
    assert publication.validate_publication(job, epochs.read(job / screen.RECORD))['status'] == 'APEX_GENERATED'
    index = epochs.read(job / 'prototype-pipeline/review-index.json')
    assert index['focuses'][8]['kind'] == 'REVIEWED_SCOPE_CORRECTION'
    assert index['focuses'][8]['review_correction_sha256'] == canonical_hash(child)
    retained_export_request(job, snapshot, envelope)
    completed = deepcopy(model.calls)
    assert c.post(api(case, 'review-correction'), json=body).status_code == 200
    assert model.calls == completed
    with db() as connection:
        epochs.validate_epoch_chain(job, snapshot, (job / 'source-snapshot.json').read_bytes(), connection)
        connection.execute('DELETE FROM events WHERE action=?', (correction.EVENT,))
    with pytest.raises((OpafError, ValueError)):
        with db() as connection:
            epochs.validate_epoch_chain(job, snapshot, (job / 'source-snapshot.json').read_bytes(), connection)
    assert model.calls == completed


@pytest.mark.parametrize('outcome', ['semantic-negative', 'second-invalid', 'pending'])
def test_one_attempt_only_and_no_mapper_after_negative_or_uncertain(correction_case, monkeypatch, outcome):
    case = correction_case
    c, _, _, _, job, _, _, model, _, _, _ = case
    plan, body = next_body(case)
    assert c.post(api(case, 'review-correction'), json=body).status_code == 202
    count = len(model.calls)
    original = model.invoke
    def reject(role, payload):
        assert role == PROFILE['reviewer'], 'A negative/uncertain review must stop before any mapper.'
        if outcome == 'pending': raise OSError('Authored unknown provider outcome')
        output, invocation = original(role, payload)
        source_id = (payload['request']['owned_objects'] if outcome == 'semantic-negative'
            else payload['request']['context_objects'])[0]['id']
        output.update(verdict='CHANGES_REQUIRED', findings=[{'source_object_id': source_id,
            'code': 'MISSING_BEHAVIOR', 'detail': 'Authored negative review.'}])
        invocation['response_sha256'] = canonical_hash(output)
        return output, invocation
    monkeypatch.setattr(model, 'invoke', reject)
    row, errors = process(case, monkeypatch)
    assert row['state'] == 'ATTENTION', errors
    calls = model.calls[count:]
    assert len(calls) == (0 if outcome == 'pending' else 1)
    assert all(role == 'reviewer' for role, _ in calls)
    publication_path = job / screen.RESULT_BASE / 'publication.json'
    assert publication_path.exists() is (outcome == 'semantic-negative')
    completed = deepcopy(model.calls)
    duplicate = c.post(api(case, 'review-correction'), json=body)
    assert duplicate.status_code == (200 if outcome == 'semantic-negative' else 409), duplicate.text
    row, errors = process(case, monkeypatch)
    assert model.calls == completed


def test_known_older_run_explicitly_falls_back_without_hiding_drift(screen_case):
    case, _ = screen_case
    response = case[0].get(api(case, 'review-correction'))
    assert response.status_code == 200, response.text
    assert response.json()['eligible'] is False and response.json()['correction_recorded'] is False
