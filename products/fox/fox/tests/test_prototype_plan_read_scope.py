"""Local immutable planning reuse only; external provider records are authored.

No live/model/Oracle/credential call or production adoption is performed.
"""
from copy import deepcopy
import hashlib

import pytest

from fox import prototype_mapping_epochs as epochs, prototype_container_epoch as container
from fox import prototype_partition_review_epoch as partition, prototype_read_scope as scope
from fox import prototype_result_publication as publication
from fox.opaf import OpafError, canonical_hash
from test_prototype_partition_review_epoch import (partition_case, next_body, container_case, container_source_model,
    clause_case, epochs_case, tmp_path, client, settings, no_external_actions, api)


def inventory(case):
    result = {}
    for base in (case[4], partition._stage(case[4])):
        for path in base.rglob('*'):
            if path.is_file(): result[str(path)] = hashlib.sha256(path.read_bytes()).hexdigest()
    return result


def inputs(case):
    job, snapshot, target = case[4], case[5], case[10]['target_profile']
    raw = (job / 'source-snapshot.json').read_bytes()
    packet, plan = epochs.reconstruct(job, snapshot, raw, target)
    return job, snapshot, raw, target, packet, plan


def read_plan(case, function=epochs.inspect_next_epoch):
    with case[9]() as db:
        db.execute('PRAGMA query_only=ON')
        db.execute('BEGIN')
        value = function(case[4], case[5], (case[4] / 'source-snapshot.json').read_bytes(), case[10]['target_profile'], db)
        assert db.total_changes == 0
        return value


def test_complete_four_views_once_and_exact_plan_equivalence(partition_case, monkeypatch, record_property):
    case = partition_case
    before, calls = inventory(case), deepcopy(case[7].calls)
    computed = []
    actual = container.active_focus
    def counted(*args, **kwargs):
        assert kwargs.get('runtime') is None
        if not kwargs.get('preview', False): computed.append(args[3]['focus_id'])
        return actual(*args, **kwargs)
    monkeypatch.setattr(container, 'active_focus', counted)
    # Candidate's unscoped inner planner still has two independent read scopes:
    # publication/model-fence share8; later staged5 predecessor reads compute8.
    baseline = read_plan(case, epochs._inspect_next_epoch)
    unscoped_count = len(computed)
    assert unscoped_count == 16
    computed.clear()
    planned = read_plan(case)
    assert canonical_hash(planned) == canonical_hash(baseline)
    assert len(computed) == 8 and len(set(computed)) == 8
    assert scope._state.get() is None
    assert inventory(case) == before and case[7].calls == calls
    record_property('unscoped_candidate_complete_four_computations', unscoped_count)
    record_property('scoped_complete_four_computations', len(computed))
    record_property('same_complete_plan_checkpoint', True)


def test_same_record_cache_deepcopies_and_expires_between_operations(partition_case, monkeypatch):
    job, _, _, target, packet, plan = inputs(partition_case)
    record = epochs.read(job / container.RECORD)
    root, request = job / 'prototype-pipeline', plan['requests'][0]
    actual, calls = container.active_focus, []
    def counted(*args, **kwargs): calls.append(True); return actual(*args, **kwargs)
    monkeypatch.setattr(container, 'active_focus', counted)
    with scope.epoch_read_scope(root):
        public = epochs.active_focus(root, packet, plan, request, target, [])
        fixed = container._historical_active_focus(root, packet, plan, request, target, [], record)
        assert fixed == public and len(calls) == 1
        public['checked']['approved_structured_design'] = False
        assert container._historical_active_focus(root, packet, plan, request, target, [], record)['checked']['approved_structured_design'] is True
    with scope.epoch_read_scope(root): epochs.active_focus(root, packet, plan, request, target, [])
    assert len(calls) == 2


def test_source_changed_after_cache_hit_fails_scope_exit(partition_case):
    job, _, _, target, packet, plan = inputs(partition_case)
    root, request = job / 'prototype-pipeline', plan['requests'][0]
    path = root / 'sources/source-000.xml'; original = path.read_bytes()
    try:
        with pytest.raises(OpafError):
            with scope.epoch_read_scope(root):
                first = epochs.active_focus(root, packet, plan, request, target, [])
                assert epochs.active_focus(root, packet, plan, request, target, []) == first
                path.write_bytes(original + b' ')
    finally:
        path.write_bytes(original)
    assert scope._state.get() is None


def test_fresh_event_check_is_not_cached_with_complete_views(partition_case):
    case = partition_case
    job = case[4]
    with case[9]() as db:
        row = tuple(db.execute('SELECT owner,action,object_id,created FROM events WHERE object_id LIKE ?',
            (case[3] + ':epoch:000004:%',)).fetchone())
    with scope.epoch_read_scope(job / 'prototype-pipeline'):
        read_plan(case)
        with case[9]() as db: db.execute('DELETE FROM events WHERE object_id=?', (row[2],))
        try:
            with pytest.raises(OpafError): read_plan(case)
        finally:
            with case[9]() as db: db.execute('INSERT INTO events(owner,action,object_id,created) VALUES(?,?,?,?)', row)
    assert scope._state.get() is None


def test_historical_four_rejection_and_current_five_approval_never_share_a_cache_value(partition_case):
    case = partition_case
    _, body = next_body(case)
    assert case[0].post(api(case, 'mapping-epochs'), json=body).status_code == 202
    job, _, _, target, packet, plan = inputs(case)
    old = epochs.read(job / container.RECORD)
    root, current_views, old_views = job / 'prototype-pipeline', [], []
    with scope.epoch_read_scope(root):
        for request in plan['requests'][:8]:
            current_views.append(epochs.active_focus(root, packet, plan, request, target, current_views))
            old_views.append(container._historical_active_focus(root, packet, plan, request, target, old_views, old))
        assert current_views[:7] == old_views[:7]
        assert current_views[7]['checked']['approved_structured_design'] is True
        assert current_views[7]['proof']['kind'] == 'RETAINED_COMPACT_PARTITION_REVIEW'
        assert old_views[7]['checked']['verdict'] == 'CHANGES_REQUIRED'
        assert publication._validate_historical_four_publication(job, old)['status'] == 'CHANGES_REQUIRED'


def test_planning_scope_cannot_execute_runtime_or_span_adoption_writes(partition_case, monkeypatch):
    case = partition_case
    _, _, _, target, packet, plan = inputs(case)
    actual, observed = partition.inspect_next, []
    def inspected(*args, **kwargs):
        assert scope._state.get() is not None
        with pytest.raises(OpafError):
            epochs.active_focus(case[4] / 'prototype-pipeline', packet, plan, plan['requests'][0], target, [], runtime={})
        observed.append('planning')
        return actual(*args, **kwargs)
    monkeypatch.setattr(partition, 'inspect_next', inspected)
    def no_write(*args, **kwargs):
        assert scope._state.get() is None
        observed.append('adoption-outside-scope')
        raise ValueError('Authored stop BEFORE any adoption write')
    monkeypatch.setattr(partition, 'adopt', no_write)
    before, calls = inventory(case), deepcopy(case[7].calls)
    _, body = next_body(case)
    assert case[0].post(api(case, 'mapping-epochs'), json=body).status_code == 409
    assert observed.count('planning') == 2 and observed[-1] == 'adoption-outside-scope'
    assert inventory(case) == before and case[7].calls == calls
    assert not (case[4] / partition.RECORD).exists()
