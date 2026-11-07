"""Synthetic pure context checks only; no executed model/review/Oracle proof."""
from copy import deepcopy

import pytest

from fox.forms_focus import build_focus_plan
from fox.forms_understanding_packet import local_packet
from fox.forms_blueprint import source_fact_index, _stable_id
from fox.opaf import canonical_hash
from fox.prototype_design_context import (PROPOSAL_SCOPE, REFERENCE_SCOPE, RETENTION_REASON,
    propose_container_retention, validate_prefix_context, build_review_context)

TARGET = 'a' * 64


def mapping_candidate(request, screen, *, omit_module=False):
    rows, screens, claims, actions = [], [], [], []
    for source in request['owned_objects']:
        row = {'source_object_id': source['id'], 'disposition': 'unresolved',
               'reason': 'Synthetic retained source metadata, not implemented business behavior.'}
        if source['kind'] == 'FormModule' and omit_module:
            row.update(disposition='omitted', reason='ordinary legacy visual container; web-recomposition')
        if source['kind'] in ('Block', 'Item', 'Trigger', 'ProgramUnit'):
            row.update(disposition='proposed', screen_id=screen)
            if source['kind'] == 'Block':
                row['native_component'] = 'form'
                screens.append({'id': screen, 'title': 'Synthetic shared screen'})
        rows.append(row)
        if source['kind'] in ('Trigger', 'ProgramUnit'):
            for unit in request['code_units']:
                if unit['owner_id'] != source['id']:
                    continue
                ref = request['focus_id'] + '-claim-' + str(len(claims))
                claims.append({'id': ref, 'source_object_id': source['id'], 'kind': 'behavior.intent',
                    'value': 'Synthetic authored interpretation of the selected complete body.',
                    'status': 'proposal', 'evidence_refs': [source['id'], unit['id']],
                    'reason': 'Synthetic structural coverage only; semantics unverified.'})
                actions.append({'id': request['focus_id'] + '-action-' + str(len(actions)), 'claim_ids': [ref]})
    return {'focus_id': request['focus_id'], 'focus_binding': request['focus_binding'],
        'blueprint': {'schema_version': 1, 'scope': 'fox-forms-blueprint-v1',
            'source_binding': request['source_binding'], 'objects': rows, 'screens': screens,
            'claims': claims, 'relationships': [], 'actions': actions, 'questions': [], 'assumptions': []}}


def references(plan, candidates):
    return {candidate['focus_id']: {'scope': REFERENCE_SCOPE, 'focus_id': candidate['focus_id'],
        'source_binding': plan['source_binding'], 'focus_request_sha256': canonical_hash(request),
        'candidate_sha256': canonical_hash(candidate), 'target_profile_sha256': TARGET,
        'proof_sha256': canonical_hash(['authored synthetic reference; not executed review', candidate['focus_id']])}
        for request, candidate in zip(plan['requests'], candidates, strict=False)}


def example(*, unknown_block=False):
    # Block + 31 Items in its owning chunk; next chunk has exactly29 Items/3Triggers.
    items = ''.join(f'<Item Name="V{i}" ItemType="Text Item" DatabaseItem="true"/>' for i in range(60))
    triggers = ''.join(f'<Trigger Name="T{i}" TriggerText="BEGIN NULL; END;"/>' for i in range(3))
    docs = [('synthetic.xml', ('<FormModule Name="SYNTHETIC"><Window Name="W"/><Canvas Name="C"/><Block Name="MAIN"'
                              + ('' if unknown_block else ' DatabaseBlock="true"') + '>'
                              + items + triggers + '</Block></FormModule>').encode())]
    packet = local_packet(docs)
    plan = build_focus_plan(docs, expected_source_binding=packet['source_binding'],
        approved_chunk_hashes={row['id']: row['sha256'] for row in packet['chunks']}, max_owned_objects=32)
    assert len(plan['requests']) == 3
    block = next(row for entry in packet['sources'] for row in entry['facts']['objects'] if row['kind'] == 'Block')
    candidates = [mapping_candidate(request, 'screen-' + block['id'], omit_module=True) for request in plan['requests']]
    module = next(row for row in plan['requests'][0]['owned_objects'] if row['kind'] == 'FormModule')
    bp = candidates[0]['blueprint']
    ref = plan['requests'][0]['focus_id'] + '-metadata-claim'
    bp['claims'] = [{'id': ref, 'source_object_id': module['id'], 'kind': 'design.metadata', 'status': 'proposal',
        'value': 'Synthetic proposal to retain source metadata, not working behavior.', 'evidence_refs': [module['id']],
        'reason': 'Synthetic unrelated metadata proposal retained exactly.'}]
    bp['actions'] = [{'id': ref + '-action', 'claim_ids': [ref]}]
    bp['relationships'] = [{'id': ref + '-relation', 'claim_ids': [ref]}]
    bp['questions'] = [{'id': ref + '-question', 'source_object_id': module['id'], 'text': 'Retain this unrelated synthetic question.'}]
    bp['assumptions'] = [{'id': ref + '-assumption', 'scope': 'prototype-only', 'text': 'Synthetic metadata only, not acceptance.'}]
    proposed, receipt = propose_container_retention(packet, plan['requests'][0], candidates[0], module['id'], canonical_hash(candidates[0]))
    return packet, plan, candidates, proposed, receipt


def structural(packet, plan, candidates, proposal):
    amended = [deepcopy(proposal), *deepcopy(candidates[1:])]
    return amended, references(plan, amended)


def reseal(plan, candidates):
    for request, candidate in zip(plan['requests'], candidates, strict=True):
        request['focus_binding'] = canonical_hash({key: value for key, value in request.items() if key != 'focus_binding'})
        candidate['focus_binding'] = request['focus_binding']
    plan['plan_binding'] = canonical_hash({key: value for key, value in plan.items() if key != 'plan_binding'})


def test_proposal_is_explicit_precise_unreviewed_and_preserves_every_other_byte_value():
    packet, plan, originals, candidate, receipt = example()
    before = deepcopy((packet, plan, originals))
    original = originals[0]
    expected = deepcopy(original)
    index = receipt['object_index']
    expected['blueprint']['objects'][index].update(disposition='unresolved', reason=RETENTION_REASON)
    assert candidate == expected and receipt['before'] == original['blueprint']['objects'][index]
    assert receipt['after'] == expected['blueprint']['objects'][index]
    assert receipt['scope'] == PROPOSAL_SCOPE and receipt['proposal_status'] == 'UNREVIEWED'
    assert receipt['independent_review_required'] is True and receipt['raw_model_output'] is False
    assert receipt['semantic_equivalence_asserted'] is False
    for key in ('authority_granted', 'generation_ready', 'native_apex_generated', 'import_verified', 'business_behavior_accepted'):
        assert receipt[key] is False
    assert (packet, plan, originals) == before
    assert receipt['candidate_sha256'] == canonical_hash(candidate)


def test_original_omitted_root_prefix_rejected_even_with_wellformed_proof_refs():
    packet, plan, originals, _, _ = example()
    with pytest.raises(ValueError):
        validate_prefix_context(packet, plan, originals, references(plan, originals), expected_target_sha256=TARGET)
    assert originals[0]['blueprint']['objects'][0]['disposition'] == 'omitted'


def test_explicit_unreviewed_root_and_last_rejected_candidate_are_structural_inputs_not_approval():
    packet, plan, originals, proposed, receipt = example()
    candidates, refs = structural(packet, plan, originals, proposed)
    root, current = candidates[0]['focus_id'], candidates[-1]['focus_id']
    refs.pop(root)
    refs.pop(current)
    before = deepcopy((packet, plan, candidates, refs, receipt))
    checked = validate_prefix_context(packet, plan, candidates, refs, expected_target_sha256=TARGET,
        container_proposals={root: receipt}, unreviewed_focus_id=current)
    assert checked['structural_prefix_valid'] is True
    assert checked['unreviewed_container_proposal_focus_ids'] == [root]
    assert checked['reference_bindings'][root]['kind'] == 'UNREVIEWED_CONTAINER_RETENTION_PROPOSAL'
    assert checked['current_unreviewed_focus_id'] == current
    assert checked['historical_review_provenance_verified'] is False and checked['authority_granted'] is False
    assert (packet, plan, candidates, refs, receipt) == before
    with pytest.raises(ValueError):
        build_review_context(packet, plan, candidates, refs, expected_target_sha256=TARGET, focus_id=current)


def test_actual_shape29_items3_triggers_with_complete_explicit_shared_context_and_no_acceptance():
    packet, plan, originals, proposed, _ = example()
    candidates, refs = structural(packet, plan, originals, proposed)
    current = candidates[-1]['focus_id']
    refs.pop(current)
    before = deepcopy((packet, plan, candidates, refs))
    context = build_review_context(packet, plan, candidates, refs, expected_target_sha256=TARGET, focus_id=current)
    rows = context['owned_rows']
    assert len(rows) == 32
    assert sum(row['source']['kind'] == 'Item' for row in rows) == 29
    assert sum(row['source']['kind'] == 'Trigger' for row in rows) == 3
    assert candidates[-1]['blueprint']['screens'] == []
    for row in rows:
        screen = row['screen_context']
        assert screen['borrowed_from_prior_focus'] is True
        assert screen['declaration']['id'] == row['mapping']['screen_id']
        assert screen['source_block']['kind'] == 'Block' and screen['owner_mapping']['native_component'] == 'form'
        assert screen['owner_binding']['proof_sha256'] == refs[candidates[1]['focus_id']]['proof_sha256']
        assert row['ancestors'][-1]['source']['kind'] == 'FormModule'
        assert row['ancestors'][-1]['mapping']['disposition'] == 'unresolved'
        if row['source']['kind'] == 'Trigger':
            assert len(row['unit_coverage']) == 1 and row['unit_coverage'][0]['claim_ids'] and row['unit_coverage'][0]['action_ids']
    for key in ('historical_review_provenance_verified', 'processing_consent_verified', 'full_application_validated',
                'generation_ready', 'import_verified', 'business_behavior_accepted', 'authority_granted'):
        assert context[key] is False
    assert (packet, plan, candidates, refs) == before
    context['owned_rows'][0]['mapping']['reason'] = 'Caller mutation.'
    assert (packet, plan, candidates, refs) == before


@pytest.mark.parametrize('mutation', ['stale-pin', 'wrong-module', 'not-root', 'wrong-kind', 'not-owned',
    'not-omitted', 'screen', 'native', 'stale-focus', 'changed-source'])
def test_retention_proposal_preconditions_fail_closed(mutation):
    packet, plan, originals, _, receipt = example()
    request, original, module = plan['requests'][0], originals[0], receipt['module_id']
    pin = canonical_hash(original)
    if mutation == 'stale-pin': pin = '0' * 64
    elif mutation == 'wrong-module': module = 'unknown-module'
    elif mutation in ('not-root', 'wrong-kind', 'not-owned'):
        block = next(row for row in plan['requests'][1]['owned_objects'] if row['kind'] == 'Block')
        module = block['id']
        if mutation != 'not-owned': request, original = plan['requests'][1], originals[1]; pin = canonical_hash(original)
    elif mutation == 'not-omitted': original['blueprint']['objects'][0]['disposition'] = 'unresolved'; pin = canonical_hash(original)
    elif mutation == 'screen': original['blueprint']['objects'][0]['screen_id'] = 'screen-forbidden'; pin = canonical_hash(original)
    elif mutation == 'native': original['blueprint']['objects'][0]['native_component'] = 'form'; pin = canonical_hash(original)
    elif mutation == 'stale-focus': request['focus_binding'] = '0' * 64
    else: packet['source_binding'] = '0' * 64
    with pytest.raises(ValueError):
        propose_container_retention(packet, request, original, module, pin)


def test_no_reason_regex_is_permission_or_a_precondition():
    packet, plan, originals, _, receipt = example()
    originals[0]['blueprint']['objects'][0]['reason'] = 'Synthetic unrelated wording; no scope consent is inferred.'
    result, proof = propose_container_retention(packet, plan['requests'][0], originals[0], receipt['module_id'], canonical_hash(originals[0]))
    assert result['blueprint']['objects'][0]['disposition'] == 'unresolved'
    assert proof['processing_consent_verified'] is False and proof['authority_granted'] is False


def test_root_owned_code_unit_refused_even_when_packet_and_focus_are_internally_bound():
    packet, plan, originals, _, receipt = example()
    request, original, module = deepcopy(plan['requests'][0]), deepcopy(originals[0]), receipt['module_id']
    entry = packet['sources'][0]
    root = next(row for row in entry['facts']['objects'] if row['id'] == module)
    unit = deepcopy(entry['facts']['code_units'][0])
    unit.update(owner_id=module, kind='FormModule', location=deepcopy(root['location']))
    unit['id'] = _stable_id(entry['source'], unit['location'], unit['source_attribute'])
    entry['facts']['code_units'].append(unit)
    entry['facts']['totals']['code_units'] += 1
    descriptors = []
    for value in entry['facts']['code_units']:
        descriptors.append({'id': 'fup1-' + canonical_hash([entry['source']['name'], entry['source']['sha256'], value['id']]),
            'source_sha256': entry['source']['sha256'], 'code_unit_id': value['id'], 'sha256': value['sha256'], 'bytes': value['bytes']})
    packet['chunks'] = descriptors
    packet['selectable_code_unit_ids'] = [row['code_unit_id'] for row in descriptors]
    packet['source_binding'] = canonical_hash({'sources': packet['sources'], 'chunks': descriptors})
    request.update(source_binding=packet['source_binding'], code_units=[unit],
                   chunks=[{**descriptors[-1], 'text': 'BEGIN NULL; END;'}], unselected_code_unit_ids=[])
    request['focus_id'] = 'focus-' + canonical_hash([packet['source_binding'], [row['id'] for row in request['owned_objects']]])[:24]
    request['focus_binding'] = canonical_hash({key: value for key, value in request.items() if key != 'focus_binding'})
    original.update(focus_id=request['focus_id'], focus_binding=request['focus_binding'])
    original['blueprint']['source_binding'] = packet['source_binding']
    source_fact_index(packet)  # Synthetic bound metadata is otherwise valid, not an original-XML claim.
    with pytest.raises(ValueError):
        propose_container_retention(packet, request, original, module, canonical_hash(original))


@pytest.mark.parametrize('mutation', ['foreign-screen', 'wrong-block', 'duplicate-screen', 'missing-screen',
    'omitted-root', 'unresolved-block', 'proposed-missing-screen', 'native-on-item', 'classification-component',
    'extra-context-owner', 'empty-context', 'future-owner', 'unknown-owner', 'wrong-focus'])
def test_prefix_mapping_and_ownership_failures(mutation):
    packet, plan, originals, proposed, _ = example()
    candidates, refs = structural(packet, plan, originals, proposed)
    if mutation == 'foreign-screen': candidates[-1]['blueprint']['objects'][0]['screen_id'] = 'screen-foreign'
    elif mutation == 'wrong-block': candidates[-1]['blueprint']['objects'][0]['screen_id'] = 'screen-' + next(iter(packet['sources'][0]['facts']['objects']))['id']
    elif mutation == 'duplicate-screen': candidates[-1]['blueprint']['screens'] = deepcopy(candidates[1]['blueprint']['screens'])
    elif mutation == 'missing-screen': candidates[1]['blueprint']['screens'] = []
    elif mutation == 'omitted-root': candidates[0] = deepcopy(originals[0])
    elif mutation == 'unresolved-block': candidates[1]['blueprint']['objects'][0].update(disposition='unresolved'); candidates[1]['blueprint']['objects'][0].pop('screen_id'); candidates[1]['blueprint']['objects'][0].pop('native_component'); candidates[1]['blueprint']['screens'] = []
    elif mutation == 'proposed-missing-screen': candidates[-1]['blueprint']['objects'][0].pop('screen_id')
    elif mutation == 'native-on-item': candidates[-1]['blueprint']['objects'][0]['native_component'] = 'form'
    elif mutation == 'classification-component':
        candidates[1]['blueprint']['objects'][0]['native_component'] = 'page-items'
    elif mutation == 'extra-context-owner': candidates[-1]['blueprint']['objects'].append(deepcopy(candidates[1]['blueprint']['objects'][0]))
    elif mutation == 'empty-context': plan['requests'][-1]['context_objects'] = []; reseal(plan, candidates)
    elif mutation == 'future-owner': candidates[1], candidates[2] = candidates[2], candidates[1]
    elif mutation == 'unknown-owner': candidates[-1]['blueprint']['objects'][0]['source_object_id'] = 'unknown-source'
    else: candidates[-1]['focus_id'] = 'focus-' + '0' * 24
    refs = references(plan, candidates)
    with pytest.raises(ValueError):
        validate_prefix_context(packet, plan, candidates, refs, expected_target_sha256=TARGET)


@pytest.mark.parametrize('mutation', ['missing-chunk', 'partial-body', 'unit-sha', 'missing-unit',
    'missing-claim', 'wrong-kind', 'claim-no-unit', 'scalar-behavior', 'missing-action', 'wrong-action', 'duplicate-action'])
def test_trigger_whole_unit_and_behavior_action_structure_failures(mutation):
    packet, plan, originals, proposed, _ = example()
    candidates, _ = structural(packet, plan, originals, proposed)
    request, bp = plan['requests'][-1], candidates[-1]['blueprint']
    if mutation == 'missing-chunk':
        removed = request['chunks'].pop()
        del plan['selected_chunk_hashes'][removed['id']]
        request['unselected_code_unit_ids'] = [removed['code_unit_id']]
    elif mutation == 'partial-body': request['chunks'][0]['text'] = 'BEGIN'
    elif mutation == 'unit-sha': request['code_units'][0]['sha256'] = '0' * 64
    elif mutation == 'missing-unit': request['code_units'].pop()
    elif mutation == 'missing-claim': bp['claims'].pop()
    elif mutation == 'wrong-kind': bp['claims'][0]['kind'] = 'unrelated.intent'
    elif mutation == 'claim-no-unit': bp['claims'][0]['evidence_refs'] = [bp['claims'][0]['source_object_id']]
    elif mutation == 'scalar-behavior': bp['claims'][0]['value'] = True
    elif mutation == 'missing-action': bp['actions'].pop()
    elif mutation == 'wrong-action': bp['actions'][0]['claim_ids'] = [bp['claims'][1]['id']]
    else: bp['actions'].append(deepcopy(bp['actions'][0]))
    reseal(plan, candidates)
    with pytest.raises(ValueError):
        validate_prefix_context(packet, plan, candidates, references(plan, candidates), expected_target_sha256=TARGET)


@pytest.mark.parametrize('mutation', ['missing', 'extra', 'approved-bool', 'proof-sha', 'candidate-sha',
    'request-sha', 'target', 'source', 'unknown-focus', 'proposal-as-proof'])
def test_reference_bindings_not_approval_booleans(mutation):
    packet, plan, originals, proposed, receipt = example()
    candidates, refs = structural(packet, plan, originals, proposed)
    current = candidates[-1]['focus_id']
    refs.pop(current)
    root = candidates[0]['focus_id']
    if mutation == 'missing': refs.pop(root)
    elif mutation == 'extra': refs[current] = deepcopy(refs[root])
    elif mutation == 'approved-bool': refs[root]['approved'] = True
    elif mutation == 'proof-sha': refs[root]['proof_sha256'] = True
    elif mutation == 'candidate-sha': refs[root]['candidate_sha256'] = canonical_hash(originals[0])
    elif mutation == 'request-sha': refs[root]['focus_request_sha256'] = '0' * 64
    elif mutation == 'target': refs[root]['target_profile_sha256'] = '0' * 64
    elif mutation == 'source': refs[root]['source_binding'] = '0' * 64
    elif mutation == 'unknown-focus': refs[root]['focus_id'] = current
    else: refs[root] = receipt
    with pytest.raises(ValueError):
        build_review_context(packet, plan, candidates, refs, expected_target_sha256=TARGET, focus_id=current)


@pytest.mark.parametrize('mutation', ['empty', 'none-focus', 'wrong-current', 'stale-plan', 'stale-source',
    'stale-target', 'duplicate-focus', 'partial-plan', 'proposal-receipt-tamper'])
def test_no_blanket_empty_or_stale_context(mutation):
    packet, plan, originals, proposed, receipt = example()
    candidates, refs = structural(packet, plan, originals, proposed)
    current, target = candidates[-1]['focus_id'], TARGET
    refs.pop(current)
    if mutation == 'empty': candidates = []
    elif mutation == 'none-focus': current = None
    elif mutation == 'wrong-current': current = candidates[0]['focus_id']
    elif mutation == 'stale-plan': plan['plan_binding'] = '0' * 64
    elif mutation == 'stale-source': packet['source_binding'] = '0' * 64
    elif mutation == 'stale-target': target = '0' * 64
    elif mutation == 'duplicate-focus': plan['requests'][1] = deepcopy(plan['requests'][0]); reseal(plan, candidates)
    elif mutation == 'partial-plan': plan['requests'].pop(); plan['plan_binding'] = canonical_hash({k: v for k, v in plan.items() if k != 'plan_binding'})
    else:
        root = candidates[0]['focus_id']; refs.pop(root); receipt['after']['reason'] = 'Forged new reason.'
        with pytest.raises(ValueError):
            validate_prefix_context(packet, plan, candidates, refs, expected_target_sha256=target,
                container_proposals={root: receipt}, unreviewed_focus_id=current)
        return
    with pytest.raises(ValueError):
        build_review_context(packet, plan, candidates, refs, expected_target_sha256=target, focus_id=current)


def test_genuine_unknown_block_classification_cannot_own_a_proposed_screen():
    packet, plan, originals, proposed, _ = example(unknown_block=True)
    candidates, refs = structural(packet, plan, originals, proposed)
    block = next(row for row in plan['requests'][1]['owned_objects'] if row['kind'] == 'Block')
    assert block['classification'] == 'unknown'
    with pytest.raises(ValueError):
        validate_prefix_context(packet, plan, candidates, refs, expected_target_sha256=TARGET)


def test_resealed_plan_cannot_guess_a_future_owner_even_if_its_candidate_is_supplied_later():
    packet, plan, originals, proposed, _ = example()
    candidates, _ = structural(packet, plan, originals, proposed)
    plan['requests'][1], plan['requests'][2] = plan['requests'][2], plan['requests'][1]
    candidates[1], candidates[2] = candidates[2], candidates[1]
    reseal(plan, candidates)
    with pytest.raises(ValueError):
        validate_prefix_context(packet, plan, candidates, references(plan, candidates), expected_target_sha256=TARGET)


def test_program_unit_uses_whole_unit_and_behavior_action_checks_without_becoming_an_item():
    # Two supplied modules are one synthetic project. Page placement here is an
    # authored design proposal, not inferred semantics or execution authority.
    docs = [('a.xml', b'<FormModule Name="A"><Block Name="B" DatabaseBlock="true"><Item Name="I" ItemType="Text Item"/></Block></FormModule>'),
            ('b.xml', b'<FormModule Name="B"><ProgramUnit Name="P" ProgramUnitText="BEGIN NULL; END;"/></FormModule>')]
    packet = local_packet(docs)
    plan = build_focus_plan(docs, expected_source_binding=packet['source_binding'],
        approved_chunk_hashes={row['id']: row['sha256'] for row in packet['chunks']}, max_owned_objects=32)
    block = next(row for entry in packet['sources'] for row in entry['facts']['objects'] if row['kind'] == 'Block')
    candidates = [mapping_candidate(request, 'screen-' + block['id']) for request in plan['requests']]
    assert len(candidates) == 3
    refs = references(plan, candidates)
    current = candidates[-1]['focus_id']; refs.pop(current)
    context = build_review_context(packet, plan, candidates, refs, expected_target_sha256=TARGET, focus_id=current)
    unit_row = next(row for row in context['owned_rows'] if row['source']['kind'] == 'ProgramUnit')
    assert unit_row['unit_coverage'] and unit_row['source']['kind'] != 'Item'
    candidates[-1]['blueprint']['actions'] = []
    with pytest.raises(ValueError):
        build_review_context(packet, plan, candidates, refs, expected_target_sha256=TARGET, focus_id=current)


def test_nonroot_formmodule_is_not_a_retention_proposal_target():
    docs = [('nested.xml', b'<FormModule Name="OUTER"><FormModule Name="INNER"/></FormModule>')]
    packet = local_packet(docs)
    plan = build_focus_plan(docs, expected_source_binding=packet['source_binding'], approved_chunk_hashes={})
    request = next(row for row in plan['requests'] if any(obj['kind'] == 'FormModule' and obj['parent_id'] is not None for obj in row['owned_objects']))
    source = next(row for row in request['owned_objects'] if row['kind'] == 'FormModule')
    assert source['parent_id'] is not None
    candidate = mapping_candidate(request, 'unused', omit_module=True)
    with pytest.raises(ValueError):
        propose_container_retention(packet, request, candidate, source['id'], canonical_hash(candidate))
