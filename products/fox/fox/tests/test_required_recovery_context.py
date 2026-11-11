"""Pure selected renderer context, not live recovery or retry permission."""
from copy import deepcopy
import hashlib

import pytest

from fox.verification_recovery import claimed_validation_snapshot, RecoveryError
from forms2apex import native_blueprint, native_blueprint_required


def request_for(renderer):
    source_id = 'ff1-' + 'a' * 24
    item_id = 'ff1-' + 'b' * 24
    project = 'synthetic-required-recovery'
    binding = 'c' * 64
    field = {'source_item_id': item_id, 'source_name': 'VALUE',
             'name': native_blueprint._field_name(item_id), 'label': 'Value',
             'data_type': 'VARCHAR2', 'widget': 'text', 'length': 80,
             'nullable': True, 'in_edit_form': True}
    spec = {'schema_version': 1, 'profile_id': native_blueprint.PROFILE_ID,
            'data_mode': 'synthetic_test_only', 'project_id': project,
            'project_name': 'Synthetic recovery', 'source_binding': binding,
            'blocks': [{'source_block_id': source_id, 'name': 'EXAMPLE', 'sequence': 1,
                        'classification': 'database', 'native_component': 'form',
                        'table_name': native_blueprint._table(project, binding, source_id),
                        'fields': [field]}]}
    if renderer is native_blueprint_required:
        spec.update(schema_version=2, profile_id=renderer.PROFILE_ID,
                    input_validation_policy=renderer.INPUT_VALIDATION_POLICY)
        field['value_required'] = True
    return {'job_id': 'fox-' + '1' * 20, 'project_id': project,
            'source_binding': binding, 'plan_sha256': 'd' * 64,
            'source_authority': {'synthetic': True}, 'rendering_spec': spec,
            'rendered_zip_sha256': hashlib.sha256(renderer.deterministic_prototype_zip(spec)).hexdigest()}


@pytest.mark.parametrize('renderer', [native_blueprint, native_blueprint_required])
def test_claimed_snapshot_uses_exact_selected_context(renderer):
    request = request_for(renderer)
    original = deepcopy(request)
    snapshot = claimed_validation_snapshot(request)
    assert snapshot['template'] == renderer.context()
    assert snapshot['draft_zip_sha256'] == request['rendered_zip_sha256']
    assert request == original


@pytest.mark.parametrize('renderer', [native_blueprint, native_blueprint_required])
def test_changed_saved_zip_cannot_gain_snapshot(renderer):
    request = request_for(renderer)
    request['rendered_zip_sha256'] = '0' * 64
    with pytest.raises(RecoveryError, match='CLAIMED_VALIDATION_RENDERED_ZIP_CHANGED'):
        claimed_validation_snapshot(request)


def test_unknown_profile_cannot_fall_back_to_legacy():
    request = request_for(native_blueprint_required)
    request['rendering_spec']['profile_id'] = 'unknown'
    with pytest.raises(ValueError, match='PROTOTYPE_PROFILE_UNSUPPORTED'):
        claimed_validation_snapshot(request)
