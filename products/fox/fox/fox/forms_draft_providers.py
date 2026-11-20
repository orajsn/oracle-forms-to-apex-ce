"""Rebuild the installed draft layout before another adapter reads its slots."""
import json

from forms2apex import native_buffer
from .forms_draft_policy import apply_draft_policies
from .forms_synthetic_save import apply_synthetic_saves
from .forms_item_validation import apply_item_validations


def rebuild_draft_providers(documents, packet, chunks, trace, files):
    plan = json.loads(files['fox-package/buffer-plan.json'])
    targets = (json.loads(files['fox-package/buffer-receipt.json'])['generated_operations']
               if plan['operations'] else [])
    buffers = {op['operation_id']: op for op in plan['operations']}
    base = dict(files)
    for target in targets:
        base[target['page_file']] = native_buffer._page(buffers[target['operation_id']], target['page_id']).encode()
    guarded, policy = apply_draft_policies(documents, packet, chunks, trace, base)
    if policy != json.loads(files['fox-package/draft-policy-receipt.json']):
        raise ValueError('DRAFT_PROVIDER_POLICY_CHANGED')
    proved, save = apply_synthetic_saves(documents, packet, chunks, trace, guarded)
    if save != json.loads(files['fox-package/synthetic-save-receipt.json']):
        raise ValueError('DRAFT_PROVIDER_SAVE_CHANGED')
    validations = {}
    if 'fox-package/item-validation-receipt.json' in files:
        proved, item = apply_item_validations(documents, packet, chunks, trace, proved)
        if item != json.loads(files['fox-package/item-validation-receipt.json']):
            raise ValueError('DRAFT_PROVIDER_ITEM_VALIDATION_CHANGED')
        for operation in [*item['generated_operations'], *item.get('adapted_operations', [])]:
            contract = operation['contract']
            key = contract['buffer_operation_id']
            if key in validations:
                raise ValueError('DRAFT_PROVIDER_MULTIPLE_ITEM_LAYOUTS')
            validations[key] = contract
    return plan, targets, proved, save, validations
