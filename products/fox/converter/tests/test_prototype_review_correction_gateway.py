"""Actual local HTTP/ZIP authority with AUTHORED provider/SQL/browser outcomes."""
from pathlib import Path
import importlib.util
from copy import deepcopy
import json
import sys
import time

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'fox/tests'))
# Converter-only collection does not discover the FOX sibling conftest.
# Execute its canonical import-time isolation BEFORE importing fox.app fixtures.
_bootstrap_path = Path(__file__).resolve().parents[2] / 'fox/tests/conftest.py'
_bootstrap_spec = importlib.util.spec_from_file_location('review_correction_fox_test_bootstrap', _bootstrap_path)
_bootstrap_spec.loader.exec_module(importlib.util.module_from_spec(_bootstrap_spec))
from test_prototype_review_correction import (correction_case, next_body, screen_case, partition_case,
    container_case, container_source_model, clause_case, epochs_case, tmp_path, client,
    settings, no_external_actions)
from test_prototype_context_screen_http import _http_roundtrip
from forms2apex.prototype_authority_client import DEFAULT_AUTHORITY_TIMEOUT_SECONDS

# The runtime constant is a socket-operation timeout, not a total deadline.
# Total elapsed below is a separate measured acceptance budget at the same 30s.
AUTHORITY_CALLBACK_BUDGET_SECONDS = DEFAULT_AUTHORITY_TIMEOUT_SECONDS
OUTPUT_REQUEST_BUDGET_SECONDS = 30  # Main-owned viewOutput GET policy: 30000ms.


@pytest.mark.parametrize('tail,allowed', [
    ('authorization.json', True), ('attempt-000001/reviewer-request.json', True),
    ('attempt-000001/reviewer-target.json', True), ('attempt-000001/reviewer-intent.json', True),
    ('attempt-000001/reviewer.json', True), ('attempt-000001/review-receipt.json', True),
    ('attempt-000001/mapper.json', False), ('attempt-000002/reviewer.json', False),
    ('extra.json', False), ('../reviewer.json', False)])
def test_fixed_child_paths_sender_receiver_parity(tail, allowed):
    from fox.prototype_transport import _epoch_authority_member
    from forms2apex.prototype_gateway import _SCREEN_FIXED_PATHS, _SCREEN_FOCUS_PATH
    path = 'epochs/epoch-000006/review-correction/' + tail
    assert _epoch_authority_member(path, clause_epoch=True, container_epoch=True,
        partition_epoch=True, screen_epoch=True) is allowed
    assert bool(path in _SCREEN_FIXED_PATHS or _SCREEN_FOCUS_PATH.fullmatch(path)) is allowed
    assert not _epoch_authority_member(path, clause_epoch=True, container_epoch=True, partition_epoch=True)


def test_actual_public_profile_file_mutation_is_visible_before_connected_fixture(tmp_path):
    from fox import prototype_authority
    from fox.opaf import canonical_hash
    from forms2apex.target_profile import select_target_profile
    from test_prototype_pipeline import TARGET
    target = deepcopy(TARGET)
    complete = select_target_profile('jsn-native-project-2616-v1')
    for key in ('active', 'scope', 'oci', 'database', 'apex', 'sqlcl'):
        target[key] = deepcopy(complete[key])
    for key in ('apex', 'sqlcl', 'apexlang_mmd'):
        target['tested_versions'][key] = complete['tested_versions'][key]
    profile = tmp_path / 'authored-public-profile.json'
    profile.write_text(json.dumps({'target_profile': target, 'target_profile_sha256': canonical_hash(target)}))
    profile.chmod(0o600)
    original = profile.read_bytes()
    first = prototype_authority._profile(profile)
    changed = deepcopy(first)
    changed['target_profile']['opaf']['roles']['mapper']['graph_sha256'] = '0' * 64
    changed['target_profile_sha256'] = canonical_hash(changed['target_profile'])
    try:
        profile.write_text(json.dumps(changed))
        assert prototype_authority._profile(profile) == changed
        assert changed['target_profile_sha256'] != first['target_profile_sha256']
    finally:
        profile.write_bytes(original)
    assert prototype_authority._profile(profile) == first


def test_corrected_review_survives_real_local_http_gateway_output_and_download(correction_case, monkeypatch, tmp_path_factory, record_property):
    case = correction_case
    from fox import prototype_authority
    record_property('authority_declared_budget_seconds', AUTHORITY_CALLBACK_BUDGET_SECONDS)
    record_property('output_declared_budget_seconds', OUTPUT_REQUEST_BUDGET_SECONDS)
    record_property('package_transport_budget_seconds', 600)
    actual_authority = prototype_authority.authorize_current
    authority_samples = []
    def timed_authority(*args, **kwargs):
        started = time.perf_counter()
        try:
            return actual_authority(*args, **kwargs)
        finally:
            elapsed = time.perf_counter() - started
            authority_samples.append(elapsed)
            record_property(f'authority_callback_{len(authority_samples):03d}_seconds', elapsed)
            assert elapsed < AUTHORITY_CALLBACK_BUDGET_SECONDS, (
                f'Current-authority callback exceeded its declared {AUTHORITY_CALLBACK_BUDGET_SECONDS}s budget: {elapsed:.6f}s')
    monkeypatch.setattr(prototype_authority, 'authorize_current', timed_authority)
    handlers = {'output': [], 'download': []}
    # Reuse the existing real HTTP/ZIP harness, selecting this new authenticated
    # admission route; responses and queue execution remain the actual handlers.
    class Client:
        def post(self, url, **kwargs):
            return case[0].post(url.removesuffix('mapping-epochs') + 'review-correction', **kwargs)
        def get(self, url, **kwargs):
            started = time.perf_counter()
            response = case[0].get(url, **kwargs)
            name = url.rsplit('/', 1)[-1]
            if name in handlers:
                elapsed = time.perf_counter() - started
                handlers[name].append(elapsed)
                record_property(f'{name}_handler_{len(handlers[name]):03d}_seconds', elapsed)
                if name == 'output':
                    assert elapsed < OUTPUT_REQUEST_BUDGET_SECONDS, (
                        f'Output handler exceeded its declared {OUTPUT_REQUEST_BUDGET_SECONDS}s UI budget: {elapsed:.6f}s')
            return response
    wrapped = (Client(), *case[1:])
    result = _http_roundtrip(wrapped, monkeypatch, tmp_path_factory, next_epoch_body=lambda _: next_body(case))
    for key, value in result.items(): record_property(key, value)
    for name, timings in handlers.items():
        assert timings
        record_property('maximum_' + name + '_handler_seconds', max(timings))
    assert result['maximum_authority_seconds'] < AUTHORITY_CALLBACK_BUDGET_SECONDS, result
    assert max(handlers['output']) < OUTPUT_REQUEST_BUDGET_SECONDS, handlers
    # Native browser attachment; its converter package GET has a separate 600s
    # transport budget. Keep download latency visible, never invent a 15s limit.
    assert result['stage_posts'] == 5 and result['package_bytes'] > 0
    # Warm technical caches must never retain DB consent/current selection or
    # current target facts. This is the real callback over the generated fixture.
    from fox import prototype_authority, prototype_read_scope, prototype_download
    from fox.prototype_download import retained_export_request
    from fox import prototype_review_correction as correction
    from fox.opaf import OpafError, canonical_hash
    c, root, pid, rid, job, snapshot, _, model, _, db, envelope = case
    export, _ = retained_export_request(job, snapshot, envelope)
    profile = root / 'public-profile.json'
    with db() as connection:
        event = tuple(connection.execute('SELECT owner,action,object_id,created FROM events WHERE action=?', (correction.EVENT,)).fetchone())
        selection = connection.execute('SELECT current_source_set_id FROM project_source_selection WHERE project=?', (pid,)).fetchone()[0]
    completed_calls = deepcopy(model.calls)
    with prototype_read_scope.epoch_read_scope(job / 'prototype-pipeline'):
        prototype_authority.authorize_current(root, db, profile, export)
        with db() as connection: connection.execute('DELETE FROM events WHERE action=?', (correction.EVENT,))
        try:
            with pytest.raises((OpafError, ValueError)): prototype_authority.authorize_current(root, db, profile, export)
        finally:
            with db() as connection: connection.execute('INSERT INTO events(owner,action,object_id,created) VALUES(?,?,?,?)', event)
        with db() as connection: connection.execute('UPDATE project_source_selection SET current_source_set_id=NULL WHERE project=?', (pid,))
        try:
            with pytest.raises((OpafError, ValueError)): prototype_authority.authorize_current(root, db, profile, export)
        finally:
            with db() as connection: connection.execute('UPDATE project_source_selection SET current_source_set_id=? WHERE project=?', (selection, pid))
        original_profile = profile.read_bytes()
        try:
            changed_profile = json.loads(original_profile)
            changed_profile['target_profile']['opaf']['roles']['mapper']['graph_sha256'] = '0' * 64
            changed_profile['target_profile_sha256'] = canonical_hash(changed_profile['target_profile'])
            profile.write_text(json.dumps(changed_profile))
            with pytest.raises((OpafError, ValueError)): prototype_authority.authorize_current(root, db, profile, export)
        finally:
            profile.write_bytes(original_profile)
        prototype_authority.authorize_current(root, db, profile, export)
    assert model.calls == completed_calls
