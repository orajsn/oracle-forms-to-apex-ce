"""Final DSC-view cache units, NOT a complete epoch/live authority claim.

Only _derive's historical material is authored. Actual record/file/role/env/
review/source-fact checks, frozen module/member guards and SQLite event SQL run.
"""
import asyncio
from concurrent.futures import ThreadPoolExecutor
from contextvars import copy_context
from copy import deepcopy
import hashlib
import json
from pathlib import Path
import sqlite3
import time

import pytest

from fox import prototype_dsc_identity_repair as dsc, prototype_read_scope as scope
from fox import prototype_container_epoch as container, prototype_clause_epoch as clause
from fox import prototype_container_proof as container_proof, prototype_clause_proof as clause_proof
from fox import forms_blueprint as blueprint
from fox.forms_design_review import validate_design_review
from fox.opaf import OpafError, canonical_hash
from test_forms_dsc_identity import example
from test_prototype_container_proof import case as container_bundle
from test_prototype_clause_proof import make_case, sealed_role, write


@pytest.fixture
def case(tmp_path_factory, monkeypatch):
    tmp_path = tmp_path_factory.mktemp('d')  # Fixed epoch paths need a short Windows root.
    docs, packet, plan, request, original = example()
    job = tmp_path / ('fox-' + '1' * 20); root = job / 'prototype-pipeline'; root.mkdir(parents=True)
    marker = b'{"authored":"DSC-view-unit-only"}'; (root / 'marker.json').write_bytes(marker)
    container_base = tmp_path / 'container-fixture'; container_base.mkdir()
    archive, bindings = container_bundle.__wrapped__(container_base)
    write(root / container.PREFIX, 'container-proof-descriptor.json', {
        'context_module_sha256': container_proof.CONTEXT_MODULE_SHA256,
        'original_manifest': bindings['approved_manifest']})
    for name in container_proof.JSON_FILES:
        path = root / container.PREFIX / 'container-proof' / name
        path.parent.mkdir(parents=True, exist_ok=True); path.write_bytes((archive / name).read_bytes())
    clause_base = tmp_path / 'clause-fixture'; clause_base.mkdir()
    archive, clause_bindings = make_case(clause_base)
    write(root / clause.PREFIX, 'clause-proof-descriptor.json', {
        'original_manifest': clause_bindings['approved_manifest'], 'assembler_sha256': clause_proof.ASSEMBLER_SHA256})
    for name in clause_proof.JSON_FILES:
        path = root / clause.PREFIX / 'clause-proof' / name
        path.parent.mkdir(parents=True, exist_ok=True); path.write_bytes((archive / name).read_bytes())
    target = bindings['original_target']
    supplement = dsc.identity.build_identity_supplement(docs)
    candidate, receipt = dsc.identity.project_candidate_reasons(docs, request, original, supplement)
    original_task = {'request': request, 'candidate': original, 'candidate_sha256': canonical_hash(original)}
    task = dsc._review_task(request, candidate, receipt, supplement, original_task)
    index = next(i for i, row in enumerate(plan['requests']) if row['focus_id'] == request['focus_id'])
    history = []
    for number, req in enumerate(plan['requests'][:index + 1]):
        old = original if number == index else {'focus_id': req['focus_id'], 'focus_binding': req['focus_binding'],
            'blueprint': {'schema_version': 1, 'scope': blueprint.BLUEPRINT_SCOPE, 'source_binding': packet['source_binding'],
                'objects': [{'source_object_id': obj['id'], 'disposition': 'unresolved', 'reason': 'Authored retained metadata.'}
                    for obj in req['owned_objects']], **{key: [] for key in ('screens','claims','actions','relationships','questions','assumptions')}}}
        review = {'source_binding': packet['source_binding'], 'focus_binding': req['focus_binding'],
            'candidate_sha256': canonical_hash(old), 'verdict': 'CHANGES_REQUIRED' if number == index else 'APPROVED',
            'findings': [{'source_object_id': None, 'code': 'AUTHORED_REJECTION', 'detail': 'Authored terminal only.'}] if number == index else []}
        checked = validate_design_review(req, old, review)
        history.append({'candidate': deepcopy(old), 'checked': checked, 'proof': {
            'focus_id': req['focus_id'], 'reviewer_invocation': {'room_id': 'historical-' + str(number)},
            'authored_historical_material_not_live_proof': True}})
    selected = {'index': index, 'focus_id': request['focus_id'], 'candidate': candidate, 'receipt': receipt, 'task': task,
        'projection_receipt_sha256': canonical_hash(receipt), 'original_candidate_sha256': canonical_hash(original),
        'projected_candidate_sha256': canonical_hash(candidate), 'review_task_sha256': canonical_hash(task)}
    proposed = {'metadata_task_policy': dsc.TASK_POLICY, 'projections': [{key: selected[key] for key in
        ('index','focus_id','projection_receipt_sha256','original_candidate_sha256','projected_candidate_sha256','review_task_sha256')}],
        'authored_historical_material_not_live_proof': True}
    epoch = {'epoch_number': 6, 'job_id': job.name, 'project_id': 'authored-project', 'snapshot_sha256': 'c' * 64,
        'source_hash': 'd' * 64, 'source_binding': packet['source_binding'], 'target_profile_sha256': canonical_hash(target),
        'owner': 'authored-owner', 'approved_at': 1.0}
    before = {'prototype-pipeline/marker.json': hashlib.sha256(marker).hexdigest()}
    record = {'schema_version': 1, 'scope': dsc.SCOPE, 'epoch_number': 6,
        'epoch_record_sha256': canonical_hash(epoch), **{key: epoch[key] for key in
            ('job_id','project_id','snapshot_sha256','source_hash','source_binding','target_profile_sha256','owner')},
        'approvals': {'redacted_source': True,'external_ai': True,'synthetic_prototype': True},
        'approved_at': 2.0, 'before_files': before, 'plan': proposed,
        'checkpoint_sha256': dsc.checkpoint(epoch, before, proposed)}
    write(root, 'binding.json', {'source_binding': packet['source_binding']})
    write(root, dsc.RECORD, record); write(root / dsc.PREFIX, 'supplement.json', supplement)
    write(root / dsc.PREFIX, 'historical-publication.json', {'authored': 'not live proof'})
    directory = root / dsc.PREFIX / request['focus_id']
    for name, value in [('projection-candidate.json', candidate), ('projection-receipt.json', receipt), ('reviewer-request.json', task)]:
        write(directory, name, value)
    output = {'source_binding': packet['source_binding'], 'focus_binding': request['focus_binding'],
        'candidate_sha256': canonical_hash(candidate), 'verdict': 'APPROVED', 'findings': []}
    sealed_role(root / dsc.PREFIX, request['focus_id'], 'reviewer', target, task, output,
        {'job_id': job.name, 'source_hash': packet['source_binding']})
    write(directory, 'review-receipt.json', validate_design_review(request, candidate, output))
    material = proposed, supplement, [selected], history
    monkeypatch.setattr(dsc, '_derive', lambda *a: deepcopy(material))
    args = [root, packet, plan, request, target, deepcopy(history[:index]), epoch]
    return args, record, directory


@pytest.fixture
def calls(monkeypatch):
    counts = {'uncached': 0, 'authorization': 0, 'container_guard': 0, 'clause_guard': 0}
    for module, name, label in [(dsc, '_active_focus_uncached', 'uncached'), (dsc, 'validate_authorization', 'authorization'),
        (container_proof, '_guard_members', 'container_guard'), (clause_proof, '_guard_installed_module', 'clause_guard')]:
        original = getattr(module, name)
        def measured(*a, _original=original, _label=label, **kw):
            counts[_label] += 1; return _original(*a, **kw)
        monkeypatch.setattr(module, name, measured)
    return counts


def outcome(function, args, **kw):
    try: return ('value', canonical_hash(function(*args, **kw)))
    except (ValueError, TypeError, KeyError, AttributeError, RecursionError, OverflowError, UnicodeError, StopIteration, OpafError) as error:
        return ('error', type(error), str(error))


@pytest.mark.parametrize('kind', ['projected', 'historical', 'preview'])
def test_final_view_uncached_parity_detached_graph_and_fresh_guards(case, calls, kind):
    args, record, _ = case; preview = kind == 'preview'
    if kind == 'historical': args[3] = args[2]['requests'][0]; args[5] = []
    expected = dsc._active_focus_uncached(*args, preview=preview); calls.update(dict.fromkeys(calls, 0))
    before = deepcopy(args[1:])
    with scope.epoch_read_scope(args[0]):
        first = dsc.active_focus(*args, preview=preview)
        assert first == expected
        if preview:
            first['review_request']['candidate']['blueprint']['objects'][0]['reason'] = 'Detached nested task'
        else:
            assert first['checked']['business_behavior_accepted'] is False
            first['candidate']['blueprint']['objects'][0]['reason'] = 'Detached nested candidate'
            first['proof']['reviewer_invocation']['room_id'] = 'Detached nested proof'
        first.clear()
        assert dsc.active_focus(*deepcopy(args), preview=preview) == expected
        assert dsc.active_focus(*args, preview=preview) == expected
        assert calls == {'uncached': 1, 'authorization': 1, 'container_guard': 3, 'clause_guard': 3}
        assert len(scope._state.get()['dsc_views']) == 1
    assert args[1:] == before


@pytest.mark.parametrize('index', range(1, 8))
def test_every_actual_argument_source_reference_and_preview_is_bound(case, calls, index):
    args, _, _ = case
    with scope.epoch_read_scope(args[0]):
        dsc.active_focus(*args); changed = deepcopy(args); kw = {}
        if index == 1: changed[1]['sources'][0]['facts']['objects'][0]['name'] = 'Changed actual source'
        elif index == 2: changed[2]['authored_changed_plan'] = True
        elif index == 3: changed[3]['focus_binding'] = 'e' * 64
        elif index == 4: changed[4]['opaf']['roles']['reviewer']['model'] = 'Changed actual target'
        elif index == 5: changed[5][0]['proof']['reviewer_invocation']['room_id'] = 'Changed actual prior proof'
        elif index == 6: changed[6]['approved_at'] = 0.5
        else: kw['preview'] = True
        expected = outcome(dsc._active_focus_uncached, changed, **kw); before = calls['uncached']
        assert outcome(dsc.active_focus, changed, **kw) == expected
        assert calls['uncached'] == before + 1


def test_preview_unknown_result_never_reused_as_completed_review(case, calls):
    args, _, directory = case; (directory / 'reviewer.json').unlink()
    with scope.epoch_read_scope(args[0]):
        preview = dsc.active_focus(*args, preview=True)
        assert set(preview) == {'review_request'}
        assert dsc.active_focus(*args, preview=True) == preview
        with pytest.raises(OpafError): dsc.active_focus(*args)
        assert len(scope._state.get()['dsc_views']) == 1
    assert calls['uncached'] == 2


def test_runtime_provided_cannot_reuse_view_and_execution_remains_forbidden(case, calls):
    args, _, _ = case; callbacks = []
    runtime = {'opaf_client': object(), 'target_profile_loader': lambda: callbacks.append('profile'),
        'processing_approval_check': lambda value: callbacks.append('consent'), 'approval_context': {}}
    with scope.epoch_read_scope(args[0]):
        dsc.active_focus(*args)
        with pytest.raises(OpafError): dsc.active_focus(*args, runtime=runtime)
        assert calls['uncached'] == 2 and callbacks == []


@pytest.mark.parametrize('module_name', ['context', 'assembler'])
@pytest.mark.parametrize('change', ['missing', 'tampered'])
def test_both_installed_byte_guards_run_after_warm_hit(case, calls, monkeypatch, tmp_path, module_name, change):
    args, _, _ = case
    module = container_proof.context if module_name == 'context' else clause_proof.assembler
    installed = tmp_path / ('installed-' + module_name + '.py'); installed.write_bytes(Path(module.__file__).read_bytes())
    monkeypatch.setattr(module, '__file__', str(installed))
    with scope.epoch_read_scope(args[0]):
        dsc.active_focus(*args); dsc.active_focus(*args)
        if change == 'missing': installed.unlink()
        else: installed.write_bytes(installed.read_bytes() + b'\n# changed')
        with pytest.raises(ValueError): dsc.active_focus(*args)
    assert calls['uncached'] == 1


@pytest.mark.parametrize('which', ['container-member', 'clause-member', 'container-manifest', 'clause-manifest'])
def test_exact_member_and_current_manifest_guards_are_fresh(case, calls, which):
    args, _, _ = case; root = args[0]
    with pytest.raises(OpafError):
        with scope.epoch_read_scope(root):
            dsc.active_focus(*args)
            if which.endswith('member'):
                prefix = container.PREFIX + '/container-proof' if which.startswith('container') else clause.PREFIX + '/clause-proof'
                path = root / prefix / 'result.json'; path.write_bytes(path.read_bytes() + b' ')
            else:
                prefix = container.PREFIX if which.startswith('container') else clause.PREFIX
                filename = 'container-proof-descriptor.json' if which.startswith('container') else 'clause-proof-descriptor.json'
                path = root / prefix / filename; value = json.loads(path.read_bytes())
                name = 'prototype_design_context.py' if which.startswith('container') else 'prototype_clause_analysis.py'
                value['original_manifest'][name]['bytes'] += 1; write(path.parent, path.name, value)
            with pytest.raises(ValueError): dsc.active_focus(*args)
            assert calls['uncached'] == 1


@pytest.mark.parametrize('where', ['container-extra-focus', 'clause-later-focus', 'dsc-unknown-file'])
def test_directory_absence_and_unknown_names_checked_on_hit(case, calls, where):
    args, _, directory = case
    if where == 'clause-later-focus':
        # Guard-only authored future request; no extra runtime/history is implied.
        while len(args[2]['requests']) < 9:
            req = deepcopy(args[3]); req['focus_id'] = 'focus-' + f'{len(args[2]["requests"]):024x}'
            args[2]['requests'].append(req)
    with pytest.raises(OpafError):
        with scope.epoch_read_scope(args[0]):
            dsc.active_focus(*args)
            if where == 'container-extra-focus': (args[0] / container.PREFIX / ('focus-' + 'f' * 24)).mkdir()
            elif where == 'clause-later-focus': (args[0] / clause.PREFIX / args[2]['requests'][8]['focus_id']).mkdir()
            else: (directory / 'unexpected.json').write_bytes(b'{}')
            with pytest.raises(OpafError): dsc.active_focus(*args)
            assert calls['uncached'] == 1


def test_current_event_owner_sql_is_fresh_after_view_hit(case, calls):
    args, record, _ = case; root = args[0]
    with sqlite3.connect(':memory:') as db:
        db.execute('CREATE TABLE events(owner TEXT,action TEXT,object_id TEXT,created REAL)')
        row = record['owner'], dsc.EVENT, dsc.event_id(root.parent.name, record), record['approved_at']
        db.execute('INSERT INTO events VALUES(?,?,?,?)', row)
        with scope.epoch_read_scope(root):
            dsc.active_focus(*args); dsc.validate_event(root, record, db)
            dsc.active_focus(*args)
            db.execute('DELETE FROM events')
            with pytest.raises(OpafError): dsc.validate_event(root, record, db)
            db.execute('INSERT INTO events VALUES(?,?,?,?)', ('wrong-owner', *row[1:]))
            with pytest.raises(OpafError): dsc.validate_event(root, record, db)
            with pytest.raises(OpafError): scope.forbid_execution()
    assert calls['uncached'] == 1


@pytest.mark.parametrize('change', ['tuple', 'subclass', 'cycle', 'unsafe-focus', 'nonbool-preview'])
def test_unsupported_inputs_take_original_path_and_errors(case, calls, change):
    class Custom(dict): pass
    args, _, _ = case
    with scope.epoch_read_scope(args[0]):
        dsc.active_focus(*args); changed = deepcopy(args); kw = {}
        if change == 'tuple': changed[2]['requests'] = tuple(changed[2]['requests'])
        elif change == 'subclass': changed[1] = Custom(changed[1])
        elif change == 'cycle': changed[1]['cycle'] = changed[1]
        elif change == 'unsafe-focus': changed[3]['focus_id'] = '../outside'
        else: kw['preview'] = 1
        expected = outcome(dsc._active_focus_uncached, changed, **kw); before = calls['uncached']
        assert outcome(dsc.active_focus, changed, **kw) == expected
        assert calls['uncached'] == before + 1


@pytest.mark.parametrize('limit', ['MAX_DSC_VIEWS', 'MAX_DSC_VIEW_VALUE_BYTES', 'MAX_DSC_VIEW_BYTES'])
def test_optional_capacity_falls_back_without_other_budget_changes(case, calls, monkeypatch, limit):
    args, _, _ = case
    monkeypatch.setattr(scope, limit, 0)
    with scope.epoch_read_scope(args[0]):
        expected = dsc.active_focus(*args); mandatory = (len(scope._state.get()['cache']), scope._state.get()['bytes'])
        assert dsc.active_focus(*args) == expected
        assert calls['uncached'] == 2 and not scope._state.get()['dsc_views']
        assert (len(scope._state.get()['cache']), scope._state.get()['bytes']) == mandatory


def test_scope_expiry_root_thread_and_task_boundaries(case, calls, tmp_path):
    args, _, _ = case
    for _ in range(2): dsc.active_focus(*args)
    assert calls['uncached'] == 2
    with scope.epoch_read_scope(args[0]):
        dsc.active_focus(*args)
        with ThreadPoolExecutor(max_workers=1) as pool:
            with pytest.raises(OpafError): pool.submit(copy_context().run, dsc.active_focus, *args).result()
        different = list(args); different[0] = tmp_path / 'different'
        with pytest.raises(OpafError): dsc.active_focus(*different)
    async def owner():
        with scope.epoch_read_scope(args[0]):
            dsc.active_focus(*args)
            async def child(): return dsc.active_focus(*args)
            with pytest.raises(OpafError): await asyncio.create_task(child())
    asyncio.run(owner())
    assert calls['uncached'] == 4


@pytest.mark.parametrize('change', ['content', 'mode', 'replace', 'hardlink'])
def test_cached_view_still_fails_enclosing_marker_fence(case, change):
    args, _, _ = case; marker = args[0] / 'marker.json'
    with pytest.raises(OpafError):
        with scope.epoch_read_scope(args[0]):
            expected = dsc.active_focus(*args)
            if change == 'content': marker.write_bytes(b'{"changed":true}')
            elif change == 'mode': marker.chmod(0o444)
            elif change == 'replace':
                replacement = marker.with_name('replacement'); replacement.write_bytes(marker.read_bytes())
                replacement.replace(marker)
            else:
                import os
                os.link(marker, marker.with_name('hardlink.json'))
            assert dsc.active_focus(*args) == expected  # Technical data, not a grant; exit MUST fail.
            with pytest.raises(OpafError): scope.forbid_execution()
    assert scope.current_read_root() is None


def test_separate_view_budget_cannot_exhaust_mandatory_or_other_optional_stores(case, calls, monkeypatch):
    args, _, _ = case
    with scope.epoch_read_scope(args[0]):
        dsc.active_focus(*args); state = scope._state.get()
        mandatory = len(state['cache']), state['bytes']
        monkeypatch.setattr(scope, 'MAX_CACHED_VALUES', 0); monkeypatch.setattr(scope, 'MAX_CACHE_BYTES', 0)
        changed = deepcopy(args); changed[5][0]['proof']['reviewer_invocation']['room_id'] = 'different-prior'
        dsc.active_focus(*changed)
        assert calls['uncached'] == 2 and len(state['dsc_views']) == 2
        assert (len(state['cache']), state['bytes']) == mandatory
        assert not state['document_builds'] and not state['container_proofs'] and not state['screen_projections'] and not state['context_prefixes']
        scope.optional_document_build(args[0], (('authored.xml', 1, 'a' * 64),), lambda: {'safe': True})
        scope.optional_container_proof(args[0], 'b' * 64, lambda: {'safe': True})
        scope.optional_screen_projection(args[0], 'c' * 64, lambda: {'safe': True})
        scope.optional_context_prefix(args[0], 'd' * 64, lambda: {'safe': True})
        assert len(state['document_builds']) == len(state['container_proofs']) == len(state['screen_projections']) == len(state['context_prefixes']) == 1


def test_actual_final_view_build_count_and_authored_bounded_timing(case, calls, record_property):
    args, _, _ = case; samples = {}
    for name, function in [('uncached', dsc._active_focus_uncached), ('cached', dsc.active_focus)]:
        calls.update(dict.fromkeys(calls, 0)); start = time.perf_counter()
        with scope.epoch_read_scope(args[0]):
            hashes = [canonical_hash(function(*args)) for _ in range(5)]
            state = scope._state.get()
            retained = {'entries': len(state['dsc_views']), 'serialized_bytes': state['dsc_view_bytes']}
        samples[name] = {'wall_seconds': time.perf_counter() - start, 'calls': dict(calls), 'sha256': hashes[0], **retained}
        assert len(set(hashes)) == 1
    assert samples['uncached']['sha256'] == samples['cached']['sha256']
    assert samples['uncached']['calls']['authorization'] == 5 and samples['cached']['calls']['authorization'] == 1
    assert samples['cached']['calls']['container_guard'] == samples['cached']['calls']['clause_guard'] == 5
    record_property('authored_dsc_final_view_not_full_epoch_or_live', json.dumps(samples, sort_keys=True))
