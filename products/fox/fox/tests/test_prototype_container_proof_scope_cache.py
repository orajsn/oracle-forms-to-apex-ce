"""Complete proof-cache unit acceptance with authored historical view seams.

The actual _proof/_historical/container validator and both byte guards run.
Only clause.active_focus is an authored predecessor-view provider, NOT a claim
of a complete epoch, live authority, OPAF, Oracle or business acceptance.
"""
import asyncio
from concurrent.futures import ThreadPoolExecutor
from contextvars import copy_context
from contextlib import nullcontext
from copy import deepcopy
import json
import os
from pathlib import Path
import sqlite3
import time

import pytest

from fox import prototype_container_epoch as container, prototype_container_proof as proof
from fox import prototype_clause_proof as clause_proof, prototype_read_scope as scope
from fox import forms_blueprint as blueprint
from fox.opaf import OpafError, canonical_hash
from test_prototype_container_proof import case as authored_case
from test_prototype_clause_proof import make_case, write


@pytest.fixture
def case(authored_case, tmp_path, monkeypatch):
    archive, bindings = authored_case
    root = tmp_path / bindings['identity']['job_id'] / 'prototype-pipeline'
    base = root / container.clause.PREFIX
    base.mkdir(parents=True)
    other = tmp_path / 'clause-fixture'; other.mkdir()
    _, clause_bindings = make_case(other)
    write(base, 'clause-proof-descriptor.json', {
        'original_manifest': clause_bindings['approved_manifest'],
        'assembler_sha256': clause_proof.ASSEMBLER_SHA256})
    plan = bindings['full_plan']
    write(base / plan['requests'][7]['focus_id'], 'reviewer.json', {
        'output': bindings['rejected_review'], 'invocation': bindings['rejected_invocation']})
    rejected = {'candidate': bindings['rejected_candidate'],
        'checked': {'approved_structured_design': False}, 'proof': {'authored_unit_seam': True}}
    historical = [*bindings['historical_views'], rejected]
    def authored_history(_root, _packet, _plan, request, _target, previous, _record):
        assert request == _plan['requests'][len(previous)]
        return deepcopy(historical[len(previous)])
    monkeypatch.setattr(container.clause, 'active_focus', authored_history)
    descriptor = {'context_module_sha256': proof.CONTEXT_MODULE_SHA256,
        'original_manifest': bindings['approved_manifest'], 'module_id': bindings['module_id'],
        'original_files': bindings['original_files'],
        'candidate_sha256': canonical_hash(json.loads((archive / 'derived-root-candidate.json').read_bytes())),
        'original_candidate_sha256': canonical_hash(historical[0]['candidate'])}
    predecessor = {'plan': {'repair_focus_id': plan['requests'][6]['focus_id'],
        'projection_focus_id': plan['requests'][7]['focus_id']}}
    members = {name: (archive / name).read_bytes() for name in proof.JSON_FILES}
    args = [root, bindings['packet'], plan, bindings['original_target'], predecessor, descriptor, members]
    return args


@pytest.fixture
def calls(monkeypatch):
    counts = {'historical': 0, 'validate': 0, 'legacy_prefix': 0, 'uncached': 0}
    for module, name, label in ((container, '_historical', 'historical'),
            (proof, '_validate', 'validate'), (proof.context, '_prefix', 'legacy_prefix'),
            (container, '_proof_uncached', 'uncached')):
        original = getattr(module, name)
        def measured(*a, _original=original, _label=label, **kw):
            counts[_label] += 1
            return _original(*a, **kw)
        monkeypatch.setattr(module, name, measured)
    return counts


def outcome(function, args):
    try:
        return ('value', canonical_hash(function(*args)))
    except (ValueError, TypeError, KeyError, RecursionError, OverflowError, OpafError) as error:
        return ('error', type(error), str(error))


def test_complete_uncached_parity_reduction_copies_and_scope_lifetime(case, calls):
    original = deepcopy(case[1:])
    expected = container._proof_uncached(*case)
    calls.update(dict.fromkeys(calls, 0))
    with scope.readonly_proof_scope(case[0]):
        first = container._proof(*case)
        assert first == expected and type(first) is tuple
        first[0]['blueprint']['objects'].clear(); first[2]['file_manifest'].clear()
        assert container._proof(*case) == expected
        with scope.readonly_proof_scope(case[0]):
            assert container._proof(*deepcopy(case)) == expected
        assert calls == {'historical': 1, 'validate': 1, 'legacy_prefix': 1, 'uncached': 1}
    assert case[1:] == original
    with scope.readonly_proof_scope(case[0]): container._proof(*case)
    assert calls['historical'] == calls['validate'] == 2


@pytest.mark.parametrize('index', range(1, 7))
def test_every_actual_argument_change_misses_even_with_unchanged_claimed_hashes(case, calls, index):
    with scope.readonly_proof_scope(case[0]):
        container._proof(*case)
        changed = deepcopy(case)
        if index == 6:
            # Same trusted manifest, different actual member bytes cannot hit.
            changed[index]['result.json'] += b' '
        else:
            changed[index]['authored_extra_key'] = 'changed without changing a caller hash'
        expected = outcome(container._proof_uncached, changed)
        before = calls['uncached']
        assert outcome(container._proof, changed) == expected
        # An invalid exact member is refused by the mandatory pre-hit guard.
        if index != 6: assert calls['uncached'] == before + 1


@pytest.mark.parametrize('which', ['container', 'clause'])
@pytest.mark.parametrize('change', ['tampered', 'missing', 'manifest-length', 'manifest-hash'])
def test_both_installed_module_bytes_and_current_manifests_rechecked_on_hit(case, calls, monkeypatch,
                                                                         tmp_path, which, change):
    module = proof.context if which == 'container' else clause_proof.assembler
    installed = tmp_path / ('installed-' + which + '.py')
    installed.write_bytes(Path(module.__file__).read_bytes())
    monkeypatch.setattr(module, '__file__', str(installed))
    fence = pytest.raises(OpafError) if which == 'clause' and change.startswith('manifest-') else nullcontext()
    with fence, scope.readonly_proof_scope(case[0]):
        container._proof(*case)
        assert container._proof(*case)
        if change == 'tampered': installed.write_bytes(installed.read_bytes() + b'\n# changed')
        elif change == 'missing': installed.unlink()
        elif which == 'container':
            pin = case[5]['original_manifest']['prototype_design_context.py']
            pin['bytes' if change == 'manifest-length' else 'sha256'] = 1 if change == 'manifest-length' else '0' * 64
        else:
            path = case[0] / container.clause.PREFIX / 'clause-proof-descriptor.json'
            value = json.loads(path.read_bytes())
            pin = value['original_manifest']['prototype_clause_analysis.py']
            pin['bytes' if change == 'manifest-length' else 'sha256'] = 1 if change == 'manifest-length' else '0' * 64
            write(path.parent, path.name, value)
        with pytest.raises(ValueError): container._proof(*case)
    assert calls['uncached'] == 1


@pytest.mark.parametrize('name', sorted(proof.JSON_FILES))
def test_each_actual_member_and_each_pin_are_fresh_guards(case, name):
    with scope.readonly_proof_scope(case[0]):
        container._proof(*case)
        changed = deepcopy(case); changed[6][name] += b' '
        with pytest.raises(ValueError): container._proof(*changed)
        changed = deepcopy(case); changed[5]['original_manifest'][name]['sha256'] = '0' * 64
        with pytest.raises(ValueError): container._proof(*changed)


@pytest.mark.parametrize('change', ['tuple', 'dict-subclass', 'scalar-subclass', 'nonstring-key',
                                   'nan', 'cycle', 'huge-int', 'unsafe-focus'])
def test_nonplain_cyclic_overflow_and_unfenced_paths_use_original(case, calls, change):
    class CustomDict(dict): pass
    class CustomStr(str): pass
    with scope.readonly_proof_scope(case[0]):
        container._proof(*case)
        changed = deepcopy(case)
        if change == 'tuple': changed[2]['requests'] = tuple(changed[2]['requests'])
        elif change == 'dict-subclass': changed[1] = CustomDict(changed[1])
        elif change == 'scalar-subclass': changed[1]['scope'] = CustomStr(changed[1]['scope'])
        elif change == 'nonstring-key': changed[1][1] = 'not JSON'
        elif change == 'nan': changed[1]['schema_version'] = float('nan')
        elif change == 'cycle': changed[1]['cycle'] = changed[1]
        elif change == 'huge-int': changed[1]['large'] = 1 << 20_000
        else: changed[2]['requests'][0]['focus_id'] = '../outside'
        expected = outcome(container._proof_uncached, changed)
        before = calls['uncached']
        assert outcome(container._proof, changed) == expected
        assert calls['uncached'] == before + 1


@pytest.mark.parametrize('budget', ['_INDEX_CACHE_MAX_NODES', '_INDEX_CACHE_MAX_DEPTH', '_INDEX_CACHE_MAX_TEXT'])
def test_input_eligibility_limits_fall_back_without_rejecting_valid_proof(case, calls, monkeypatch, budget):
    expected = container._proof_uncached(*case)
    monkeypatch.setattr(blueprint, budget, 0)
    with scope.readonly_proof_scope(case[0]):
        for _ in range(2): assert container._proof(*case) == expected
        assert not scope._state.get()['container_proofs']
    assert calls['uncached'] == 3


@pytest.mark.parametrize('change', ['content', 'replacement', 'extra', 'mode', 'hardlink'])
def test_pipeline_file_changes_after_hit_still_fail_exit(case, change):
    path = case[0] / container.clause.PREFIX / 'clause-proof-descriptor.json'
    with pytest.raises(OpafError):
        with scope.readonly_proof_scope(case[0]):
            expected = container._proof(*case)
            assert container._proof(*case) == expected
            if change == 'content': path.write_bytes(path.read_bytes() + b' ')
            elif change == 'replacement':
                replacement = path.with_name('replacement'); replacement.write_bytes(path.read_bytes())
                os.replace(replacement, path)
            elif change == 'extra': (case[0] / 'extra.json').write_bytes(b'{}')
            elif change == 'mode': path.chmod(0o444)
            else: os.link(path, path.with_name('extra-hardlink'))
    assert scope.current_read_root() is None


def test_directory_absence_checks_run_even_on_a_warm_key(case, calls):
    with pytest.raises(OpafError):
        with scope.readonly_proof_scope(case[0]):
            container._proof(*case)
            (case[0] / container.PREFIX / ('focus-' + 'f' * 24)).mkdir(parents=True)
            with pytest.raises(OpafError): container._proof(*case)
            assert calls['uncached'] == 1


def test_epoch_three_later_focus_absence_on_hit(case, calls, monkeypatch):
    # Authored no-compute result isolates the guard with a >8-focus plan.
    extra = deepcopy(case[2]['requests'][-1]); extra['focus_id'] = 'focus-' + 'f' * 24
    case[2]['requests'].append(extra)
    monkeypatch.setattr(container, '_proof_uncached', lambda *a: ({'unit': 'guard-only'}, {}, {}))
    with pytest.raises(OpafError):
        with scope.readonly_proof_scope(case[0]):
            container._proof(*case)
            (case[0] / container.clause.PREFIX / extra['focus_id']).mkdir()
            with pytest.raises(OpafError): container._proof(*case)


@pytest.mark.parametrize('capacity', ['entries', 'value-bytes', 'aggregate-bytes'])
def test_optional_capacity_falls_back_and_does_not_spend_other_caches(case, calls, monkeypatch, capacity):
    if capacity == 'entries': monkeypatch.setattr(scope, 'MAX_CONTAINER_PROOFS', 1)
    elif capacity == 'value-bytes': monkeypatch.setattr(scope, 'MAX_CONTAINER_PROOF_VALUE_BYTES', 0)
    else: monkeypatch.setattr(scope, 'MAX_CONTAINER_PROOF_BYTES', 0)
    with scope.readonly_proof_scope(case[0]):
        for _ in range(2): container._proof(*case)
        if capacity == 'entries':
            case[4]['another_identity'] = True
            for _ in range(2): container._proof(*case)
            assert calls['uncached'] == 3
        else: assert calls['uncached'] == 2
        state = scope._state.get()
        assert state['document_build_bytes'] == 0 and state['document_builds'] == {}
        mandatory_before = (len(state['cache']), state['bytes'])
        container._proof(*case)
        assert (len(state['cache']), state['bytes']) == mandatory_before


def test_three_cache_budgets_are_independent(case, monkeypatch):
    monkeypatch.setattr(scope, 'MAX_CONTAINER_PROOFS', 1)
    with scope.readonly_proof_scope(case[0]):
        container._proof(*case)
        state = scope._state.get(); before = (len(state['cache']), state['bytes'])
        scope.optional_container_proof(case[0], 'a' * 64, lambda: {'other': True})
        assert (len(state['cache']), state['bytes']) == before
        assert scope.cached_read(case[0], 'technical_record', {'new-mandatory': True}, lambda: {'safe': True}) == {'safe': True}
        assert scope.optional_document_build(case[0], (('authored.xml', 1, 'a' * 64),), lambda: {'safe': True}) == {'safe': True}
        assert len(state['document_builds']) == 1 and len(state['container_proofs']) == 1


def test_no_scope_root_thread_or_task_can_share_complete_proof(case, calls, tmp_path):
    for _ in range(2): container._proof(*case)
    assert calls['uncached'] == 2
    with scope.readonly_proof_scope(case[0]):
        container._proof(*case)
        copied = copy_context()
        with ThreadPoolExecutor(max_workers=1) as pool:
            with pytest.raises(OpafError): pool.submit(copied.run, container._proof, *case).result()
        changed = list(case); changed[0] = tmp_path / 'different'
        with pytest.raises(OpafError): container._proof(*changed)
        with pytest.raises(OpafError): scope.forbid_execution()
    async def owner():
        with scope.readonly_proof_scope(case[0]):
            container._proof(*case)
            async def child(): return container._proof(*case)
            with pytest.raises(OpafError): await asyncio.create_task(child())
    asyncio.run(owner())
    assert calls['uncached'] == 4


def test_arbitrary_subtree_scope_does_not_cache_complete_proof(case, calls):
    original_root = case[0]
    renamed = original_root.with_name('not-a-pipeline')
    original_root.rename(renamed); case[0] = renamed
    with scope.readonly_proof_scope(renamed):
        for _ in range(2): container._proof(*case)
        assert not scope._state.get()['container_proofs']
    assert calls['uncached'] == 2


def test_warm_proof_cannot_cache_fresh_event_query_or_predecessor_owner_gate(case, calls, monkeypatch):
    """Authored record/shape seams; REAL event SQL and normal call ordering.

    This proves the new cache sits below, not around, the current authority
    boundary. It does not attest that these synthetic records authorize work.
    """
    from fox import prototype_result_publication as publication
    root, packet, plan, target, predecessor, descriptor, members = case
    job = root.parent
    first_record = {'owner': 'authored-owner', 'approved_at': 1, 'epoch_number': 2}
    predecessor.update(owner='authored-owner', approved_at=2, epoch_number=3)
    record = {'owner': 'authored-owner', 'approved_at': 3, 'epoch_number': 4, 'before_files': {},
        'plan': {'repair_focus_id': plan['requests'][6]['focus_id']}}
    gate = {'allowed': True, 'checks': 0}
    def current_predecessor(*args, **kwargs):
        gate['checks'] += 1
        if not gate['allowed']: raise OpafError('Authored fresh owner/consent refusal.')
        return predecessor
    monkeypatch.setattr(container.clause, 'validate_record', current_predecessor)
    monkeypatch.setattr(container, 'technical_record', lambda *a: record)
    monkeypatch.setattr(container, '_fresh_descriptor', lambda *a: descriptor)
    monkeypatch.setattr(container, '_shape', lambda *a: None)
    monkeypatch.setattr(publication, 'validate_publication', lambda *a: None)
    monkeypatch.setattr(container.epochs, '_before_unchanged', lambda *a: None)
    monkeypatch.setattr(container.epochs, 'reconstruct', lambda *a: (packet, plan))
    monkeypatch.setattr(container, '_members', lambda *a, **kw: members)
    original_read = container.epochs.read
    authored_reads = {job / container.epochs.RECORD: first_record, job / container.RECORD: record,
        root / container.PREFIX / 'container-proof-descriptor.json': descriptor,
        root / record['plan']['repair_focus_id'] / 'mapper-target.json': target}
    def read(path, *args):
        return deepcopy(authored_reads[path]) if path in authored_reads else original_read(path, *args)
    monkeypatch.setattr(container.epochs, 'read', read)
    with sqlite3.connect(':memory:') as db:
        db.execute('CREATE TABLE events(owner TEXT, action TEXT, object_id TEXT, created REAL)')
        rows = [(entry['owner'], container.epochs.EVENT, container.epochs.event_id(job.name, entry),
                 entry['approved_at']) for entry in (first_record, predecessor, record)]
        db.executemany('INSERT INTO events VALUES(?,?,?,?)', rows)
        with scope.readonly_proof_scope(root):
            assert container.validate_record(job, {}, b'authored only', db) == record
            assert container.validate_record(job, {}, b'authored only', db) == record
            db.execute('DELETE FROM events WHERE object_id=?', (rows[-1][2],))
            with pytest.raises(OpafError): container.validate_record(job, {}, b'authored only', db)
            db.execute('INSERT INTO events VALUES(?,?,?,?)', rows[-1])
            gate['allowed'] = False
            with pytest.raises(OpafError, match='owner/consent'): container.validate_record(job, {}, b'authored only', db)
    assert gate['checks'] == 4 and calls['uncached'] == 1


def test_complete_boundary_synthetic_timing_and_actual_expensive_counts(case, calls, record_property):
    samples = {}
    for name, function in [('uncached', container._proof_uncached), ('cached', container._proof)]:
        calls.update(dict.fromkeys(calls, 0))
        start = time.perf_counter()
        with scope.readonly_proof_scope(case[0]):
            results = [canonical_hash(function(*case)) for _ in range(5)]
        samples[name] = {'wall_seconds': time.perf_counter() - start, 'counts': dict(calls), 'sha256': results[0]}
        assert len(set(results)) == 1
    assert samples['uncached']['sha256'] == samples['cached']['sha256']
    assert samples['uncached']['counts']['historical'] == samples['uncached']['counts']['validate'] == 5
    assert samples['cached']['counts']['historical'] == samples['cached']['counts']['validate'] == 1
    record_property('authored_complete_proof_comparison_not_live', json.dumps(samples, sort_keys=True))
