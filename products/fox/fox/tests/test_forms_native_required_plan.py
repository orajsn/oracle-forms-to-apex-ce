"""Source-bound synthetic required UI planning; no live conversion claims."""
from copy import deepcopy
import hashlib
import json

import pytest

from fox.forms_native_plan import POLICY_ID, build_native_prototype_plan
from fox.forms_native_required_plan import (
    INPUT_POLICY_ID, PROFILE_ID, bound_native_input_policy,
    build_native_plan, build_native_required_prototype_plan,
)
from test_forms_native_plan import design, item, source


def build(documents, blueprint=None, **kwargs):
    return build_native_required_prototype_plan(documents, blueprint or design(documents),
        project_id="project-1", project_name="Synthetic prototype", approved_policy_id=POLICY_ID, **kwargs)


def required_item(name="VALUE", attribute='Required="true"', **kwargs):
    return item(name, **kwargs).replace('/>', ' ' + attribute + '/>')


@pytest.mark.parametrize("attribute, expected", [
    ('Required="true"', True), ('Required="TRUE"', True), ('Required="TrUe"', True),
    ('Required="false"', False), ('Required="FALSE"', False), ('', False),
    ('Required="yes"', False), ('Required="1"', False), ('Required="default"', False),
    ('Required="inherited"', False), ('Required=""', False),
    ('x:Required="true" xmlns:x="urn:synthetic"', False),
    ('required="true"', False),
])
def test_only_direct_unqualified_boolean_true_enables_required(attribute, expected):
    docs = [("demo.xml", source([required_item(attribute=attribute)]))]
    original = deepcopy(docs)
    blueprint = design(docs)
    original_blueprint = deepcopy(blueprint)
    plan = build(docs, blueprint)
    spec = plan['rendering_spec']
    field = spec['blocks'][0]['fields'][0]
    assert field['value_required'] is expected
    assert field['nullable'] is True
    assert spec['schema_version'] == 2 and spec['profile_id'] == PROFILE_ID
    assert spec['input_validation_policy'] == INPUT_POLICY_ID
    coverage = next(row for row in plan['coverage']['objects'] if row['kind'] == 'Item')
    proof = coverage['input_validation']['source_proof']
    assert proof['source_object_id'] == field['source_item_id']
    assert proof['source_name'] == field['source_name'] == 'VALUE'
    assert proof['source_file'] == 'demo.xml'
    assert proof['source_sha256'] == hashlib.sha256(docs[0][1]).hexdigest()
    assert proof['location'] == coverage['location']
    assert coverage['input_validation']['native_required_ui'] is expected
    assert coverage['input_validation']['original_event_timing_preserved'] is False
    assert coverage['input_validation']['database_constraint_inferred'] is False
    if 'x:Required' in attribute:
        assert proof['attributes'] == {'{urn:synthetic}Required': 'true'}
        assert any(row['code'] == 'required_input_unknown' for row in plan['remediation'])
    if expected:
        assert any(row['code'] == 'native_required_ui_submit_time' for row in plan['assumptions'])
    assert docs == original and blueprint == original_blueprint
    assert plan == build(docs, blueprint)
    unsigned = {key: value for key, value in plan.items() if key != 'plan_sha256'}
    canonical = json.dumps(unsigned, ensure_ascii=False, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()
    assert plan['plan_sha256'] == hashlib.sha256(canonical).hexdigest()


@pytest.mark.parametrize('component', ['report', 'interactive-grid'])
def test_readonly_component_required_is_remediation_not_claimed_enforced(component):
    docs = [('demo.xml', source([required_item()]))]
    blueprint = design(docs)
    next(row for row in blueprint['objects'] if 'native_component' in row)['native_component'] = component
    plan = build(docs, blueprint)
    block = plan['rendering_spec']['blocks'][0]
    assert block['native_component'] == 'report'
    assert block['fields'][0]['in_edit_form'] is False
    assert block['fields'][0]['value_required'] is False
    assert any(row['code'] == 'required_input_not_implemented' for row in plan['remediation'])


def test_control_display_non_database_unsupported_and_omitted_required_have_remediation():
    docs = [('data.xml', source([
        required_item('EDITABLE'), required_item('DISPLAY', kind='Display Item'),
        required_item('COMPUTED', flag='false'), required_item('UNKNOWN', flag=''),
        required_item('ACTION', kind='Push Button'), required_item('OMITTED'),
    ])), ('control.xml', source([required_item('CONTROL', flag='false')], database=False))]
    blueprint = design(docs)
    from fox.forms_understanding_packet import local_packet
    objects = [obj for entry in local_packet(docs)['sources'] for obj in entry['facts']['objects']]
    omitted_id = next(obj['id'] for obj in objects if obj['name'] == 'OMITTED')
    proposal = next(row for row in blueprint['objects'] if row['source_object_id'] == omitted_id)
    proposal.update(disposition='omitted', reason='Explicit synthetic omission.')
    proposal.pop('screen_id')
    plan = build(docs, blueprint)
    fields = {field['source_name']: field for block in plan['rendering_spec']['blocks'] for field in block['fields']}
    assert fields['EDITABLE']['value_required'] is True
    assert all(field['value_required'] is False for name, field in fields.items() if name != 'EDITABLE')
    assert 'OMITTED' not in fields and 'ACTION' not in fields
    unimplemented = {row['source_object_id'] for row in plan['remediation']
                     if row['code'] == 'required_input_not_implemented'}
    expected = {obj['id'] for obj in objects if obj['kind'] == 'Item' and obj['name'] != 'EDITABLE'}
    assert unimplemented == expected
    assert all(field['nullable'] is True for field in fields.values())
    assert plan['coverage']['accounted_objects'] == plan['coverage']['source_objects']


def test_required_does_not_inherit_from_block_or_child_property():
    raw = source([required_item(attribute='')]).replace(b'DatabaseBlock="true"', b'DatabaseBlock="true" Required="true"')
    raw = raw.replace(b'ColumnName="CUSTOMER_COLUMN" />',
                      b'ColumnName="CUSTOMER_COLUMN"><Property Name="Required" Value="true"/></Item>')
    plan = build([('demo.xml', raw)])
    assert plan['rendering_spec']['blocks'][0]['fields'][0]['value_required'] is False
    assert any(row['code'] == 'required_input_unknown' for row in plan['remediation'])


def test_qualified_property_does_not_override_direct_false_and_is_explicit_remediation():
    docs = [('demo.xml', source([required_item(attribute='Required="false" x:Required="true" xmlns:x="urn:synthetic"')]))]
    plan = build(docs)
    assert plan['rendering_spec']['blocks'][0]['fields'][0]['value_required'] is False
    assert any(row['code'] == 'qualified_required_not_interpreted' for row in plan['remediation'])


def test_source_name_or_id_rebinding_is_rejected():
    docs = [('demo.xml', source([required_item()]))]
    blueprint = design(docs)
    changed = [('demo.xml', docs[0][1].replace(b'Name="VALUE"', b'Name="OTHER"'))]
    with pytest.raises(ValueError):
        build(changed, blueprint)
    blueprint['objects'][-1]['source_object_id'] = 'invented'
    with pytest.raises(ValueError):
        build(docs, blueprint)


def test_default_dispatch_is_exact_legacy_even_with_required_source():
    docs = [('demo.xml', source([required_item()]))]
    kwargs = dict(project_id='project-1', project_name='Synthetic prototype', approved_policy_id=POLICY_ID)
    legacy = build_native_prototype_plan(docs, design(docs), **kwargs)
    assert build_native_plan(docs, design(docs), **kwargs) == legacy
    assert build_native_plan(docs, design(docs), native_input_policy=None, **kwargs) == legacy
    assert 'value_required' not in legacy['rendering_spec']['blocks'][0]['fields'][0]
    assert build_native_plan(docs, design(docs), native_input_policy=INPUT_POLICY_ID, **kwargs) == build(docs)


@pytest.mark.parametrize('policy', [None, '', True, 1, [], {}, 'forms-required-inputs-v2'])
def test_present_invalid_policy_is_never_legacy(policy):
    with pytest.raises(ValueError, match='native input policy'):
        bound_native_input_policy({'native_input_policy': policy})
    assert bound_native_input_policy({}) is None
