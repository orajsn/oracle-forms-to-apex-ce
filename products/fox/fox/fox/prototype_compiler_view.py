"""Separate deterministic compiler derivation; original AI reviews stay intact."""
from pathlib import Path

from .opaf import OpafError, canonical_hash
from . import prototype_compiler_continuation as protocol
from .prototype_item_screen_inheritance import project
from .forms_focus_merge import merge_focus_blueprints


def present(root):
    location = protocol.path(Path(root).parent)
    return location.exists() or location.is_symlink()


def retained_views(root, packet, plan, target):
    """Return every ORIGINAL reviewed view, never a completed candidate review."""
    state = protocol.reconstruction(root)
    if state is None:
        return None
    boundary, receipt = state['record']['plan'], state['receipt']
    if (canonical_hash(plan) != boundary['focus_plan_sha256']
            or canonical_hash(packet) != receipt['packet_sha256']
            or canonical_hash(target) != boundary['target_profile_sha256']
            or len(state['views']) != len(plan['requests'])
            or any(view['checked']['approved_structured_design'] is not True for view in state['views'])):
        raise OpafError('Compiler continuation differs from its exact original reviewed design.')
    return state['views']


def merge(root, documents, plan, responses):
    """Compile the original reviewed inputs with a separately pinned derivation."""
    state = protocol.reconstruction(root)
    if state is None:
        return merge_focus_blueprints(documents, plan, responses)
    originals = [view['candidate'] for view in state['views']]
    if (canonical_hash(responses) != canonical_hash(originals)
            or canonical_hash(plan) != state['record']['plan']['focus_plan_sha256']):
        raise OpafError('Compiler inputs differ from the original reviewed candidates.')
    completed, receipt = project(documents, plan, responses)
    merged = merge_focus_blueprints(documents, plan, completed)
    if (receipt is None or canonical_hash(completed) != canonical_hash(state['responses'])
            or canonical_hash(receipt) != canonical_hash(state['receipt'])
            or canonical_hash(merged) != canonical_hash(state['merged'])):
        raise OpafError('Compiler derivation differs from its exact source-bound completion.')
    return merged
