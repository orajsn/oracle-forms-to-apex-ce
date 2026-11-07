"""Pure synthetic source facts/projection; no provider or business acceptance."""
from copy import deepcopy
import pytest

from fox.forms_focus import build_focus_plan
from fox.forms_understanding_packet import local_packet
from fox.prototype_focus_projection import (fact_diagnostics, source_fact_gate, repair_requirements,
                                            validate_repair, project_context)
from test_prototype_pipeline import SyntheticOpaf, PROFILE


def example():
    raw = ('<FormModule Name="SYNTHETIC"><Block Name="MAIN" DatabaseBlock="true" '
        'WhereClause="FLAG = 17" OrderByClause="NAME DESC">' +
        ''.join(f'<Item Name="V{i}" ItemType="Text Item" DatabaseItem="true"/>' for i in range(4)) +
        '</Block></FormModule>').encode()
    docs = [('synthetic.xml', raw)]
    packet = local_packet(docs)
    plan = build_focus_plan(docs, expected_source_binding=packet['source_binding'],
        approved_chunk_hashes={row['id']: row['sha256'] for row in packet['chunks']}, max_owned_objects=3)
    previous, request = plan['requests'][1:3]
    candidate, _ = SyntheticOpaf().invoke(PROFILE['mapper'], previous)
    for i, unit in enumerate(previous['code_units']):
        candidate['blueprint']['claims'].append({'id': 'bad-' + str(i), 'source_object_id': unit['owner_id'],
            'kind': 'block.where' if unit['source_attribute'] == 'WhereClause' else 'block.order',
            'status': 'source_fact', 'value': 'Invented metadata', 'evidence_refs': [unit['id']],
            'reason': 'Authored invalid observation; must be repaired, not downgraded.'})
    repaired = deepcopy(candidate)
    for i, row in enumerate(repaired['blueprint']['claims']):
        row.update(kind='behavior.intent', status='proposal', value='Filter matching rows' if i == 0 else 'Sort names descending')
        repaired['blueprint']['actions'].append({'id': 'action-' + str(i), 'claim_ids': [row['id']]})
    projected, _ = SyntheticOpaf().invoke(PROFILE['mapper'], request)
    block = next(row for row in candidate['blueprint']['objects'] if 'native_component' in row)
    for row in projected['blueprint']['objects']: row['screen_id'] = block['screen_id']
    projected['blueprint']['screens'] = deepcopy(candidate['blueprint']['screens'])
    extra = deepcopy(block); extra['reason'] = 'Context layout description differs; reviewer must inspect both.'
    projected['blueprint']['objects'].append(extra)
    projected['blueprint']['claims'].append({'id': 'context-kind', 'source_object_id': block['source_object_id'],
        'kind': 'object.kind', 'status': 'source_fact', 'value': 'Block',
        'evidence_refs': [block['source_object_id']], 'reason': 'Exact context-only metadata.'})
    for i, obj in enumerate(request['owned_objects']):
        projected['blueprint']['claims'].append({'id': 'alias-' + str(i), 'source_object_id': obj['id'],
            'kind': 'object.item_type', 'status': 'source_fact', 'value': obj['item_type'],
            'evidence_refs': [obj['id']], 'reason': 'Exact Item metadata with noncanonical kind alias.'})
    return docs, packet, plan, candidate, repaired, projected


def test_early_gate_refuses_ai_approved_unsupported_facts_and_repair_requires_real_coverage():
    _, packet, plan, raw, repaired, _ = example()
    request = plan['requests'][1]
    before = deepcopy(raw)
    assert len(fact_diagnostics(packet, request, raw)) == 2
    with pytest.raises(ValueError): source_fact_gate(packet, request, raw)
    requirements = repair_requirements(packet, request, raw)
    assert validate_repair(packet, request, raw, repaired, requirements)['source_facts_checked'] is True
    assert raw == before
    relabeled = deepcopy(raw)
    for row in relabeled['blueprint']['claims']: row['status'] = 'proposal'
    with pytest.raises(ValueError): validate_repair(packet, request, raw, relabeled, requirements)


@pytest.mark.parametrize('change', ['mapping', 'screen', 'claim-value', 'missing-action', 'unrelated-claim', 'invented-fact'])
def test_one_repair_cannot_change_unrelated_choices_or_invent_new_facts(change):
    _, packet, plan, raw, repaired, _ = example()
    requirements = repair_requirements(packet, plan['requests'][1], raw)
    if change == 'mapping': repaired['blueprint']['objects'][0]['reason'] = 'Changed unrelated reason'
    elif change == 'screen': repaired['blueprint']['screens'][0]['title'] = 'Different title'
    elif change == 'claim-value': repaired['blueprint']['claims'][0]['value'] = raw['blueprint']['claims'][0]['value']
    elif change == 'missing-action': repaired['blueprint']['actions'] = []
    elif change == 'unrelated-claim':
        row = deepcopy(repaired['blueprint']['claims'][0]); row['id'] = 'extra'; row['kind'] = 'unrelated'; repaired['blueprint']['claims'].append(row)
    else: repaired['blueprint']['claims'][0].update(kind='block.where', status='source_fact')
    with pytest.raises(ValueError): validate_repair(packet, plan['requests'][1], raw, repaired, requirements)


def test_projection_retains_all_excluded_metadata_and_different_rationales():
    _, packet, plan, _, repaired, raw = example()
    before = deepcopy(raw)
    candidate, receipt = project_context(packet, plan['requests'][2], raw, repaired, 'a' * 64, [repaired])
    assert len(candidate['blueprint']['objects']) == len(plan['requests'][2]['owned_objects'])
    assert candidate['blueprint']['screens'] == []
    assert all(row['kind'] == 'item.item_type' for row in candidate['blueprint']['claims'])
    assert receipt['excluded_objects'][0]['reason'] != receipt['prior_objects'][0]['reason']
    assert receipt['rationale_semantic_equivalence_asserted'] is False
    assert receipt['excluded_claims'][0] == raw['blueprint']['claims'][0]
    assert len(receipt['aliases']) == 2 and raw == before


@pytest.mark.parametrize('value', [True, 17, None, ['Generic scalar']])
def test_clause_coverage_requires_prose_not_scalar_placeholder(value):
    _, packet, plan, raw, repaired, _ = example()
    requirements = repair_requirements(packet, plan['requests'][1], raw)
    repaired['blueprint']['claims'][0]['value'] = value
    with pytest.raises(ValueError): validate_repair(packet, plan['requests'][1], raw, repaired, requirements)


@pytest.mark.parametrize('index', [0, 1])
def test_new_claim_and_action_ids_cannot_launder_unsupported_literal(index):
    _, packet, plan, raw, repaired, _ = example()
    requirements = repair_requirements(packet, plan['requests'][1], raw)
    repaired['blueprint']['claims'][index].update(id='renamed-claim', value=raw['blueprint']['claims'][index]['value'])
    repaired['blueprint']['actions'][index] = {'id': 'renamed-action', 'claim_ids': ['renamed-claim']}
    with pytest.raises(ValueError): validate_repair(packet, plan['requests'][1], raw, repaired, requirements)


@pytest.mark.parametrize('change', ['mapping', 'title', 'referenced', 'behavior', 'alias-value', 'extra-context'])
def test_projection_refuses_nonexact_or_behavioral_omissions(change):
    _, packet, plan, _, repaired, raw = example()
    if change == 'mapping': raw['blueprint']['objects'][-1]['native_component'] = 'report'
    elif change == 'title': raw['blueprint']['screens'][0]['title'] = 'Other'
    elif change == 'referenced': raw['blueprint']['actions'].append({'id': 'keep', 'claim_ids': ['context-kind']})
    elif change == 'behavior': raw['blueprint']['claims'][0].update(kind='behavior.intent', status='proposal')
    elif change == 'alias-value': raw['blueprint']['claims'][1]['value'] = 'Invented widget'
    else: raw['blueprint']['objects'].append(deepcopy(raw['blueprint']['objects'][-1]))
    with pytest.raises(ValueError): project_context(packet, plan['requests'][2], raw, repaired, 'a' * 64, [repaired])


def test_alias_only_projection_preserves_unvalidated_screen_and_shape_rejects_it():
    _, packet, plan, _, repaired, raw = example()
    raw['blueprint']['objects'] = [row for row in raw['blueprint']['objects'] if row['source_object_id'] in
                                  {obj['id'] for obj in plan['requests'][2]['owned_objects']}]
    raw['blueprint']['claims'] = [row for row in raw['blueprint']['claims'] if row['kind'] == 'object.item_type']
    raw['blueprint']['screens'] = [{'id': None, 'title': 'Must not silently disappear'}]
    before = deepcopy(raw)
    with pytest.raises(ValueError):
        project_context(packet, plan['requests'][2], raw, None, None, [repaired], strict_known_case=False)
    assert raw == before
