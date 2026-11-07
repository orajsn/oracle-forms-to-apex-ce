"""Real current FOX authority connected to retained gateway package reads.

Only model/SQLcl/browser execution uses authored synthetic adapters. Current
owner/source/profile policy, historical proof checks and ZIP validation are real.
"""
from copy import deepcopy
import hashlib
import importlib
import json
from pathlib import Path
import sys
from types import SimpleNamespace

import pytest

from fox import prototype_authority as authority
from fox.opaf import canonical_hash
from test_prototype_authority import prepared
from test_prototype_job import queued


@pytest.fixture
def connected(prepared, tmp_path_factory, monkeypatch):
    from forms2apex import native_blueprint
    from forms2apex.project_reviews import canonical, digest
    from forms2apex.security import alias_for_job
    from forms2apex.target_profile import select_target_profile
    root, job, db, _, saved_export, profile, _, model = prepared
    fixture_dir = str(Path(__file__).resolve().parents[2] / 'converter/tests')
    sys.path.insert(0, fixture_dir)
    try:
        gateway_fixture = importlib.import_module('test_prototype_gateway')
        release_fixture = importlib.import_module('test_prototype_release')
    finally:
        sys.path.remove(fixture_dir)
    spec = deepcopy(saved_export['rendering_spec'])
    monkeypatch.setattr(gateway_fixture, 'spec', lambda _: deepcopy(spec))
    item = gateway_fixture.case.__wrapped__(tmp_path_factory)
    item.settings.jobs_root = root / 'jobs'
    item.request.clear()
    item.request.update({**deepcopy(saved_export), 'prior_receipts': {}})
    callback_requests = []
    def real_current_authority(request):
        result = authority.authorize_current(root, db, profile, request)
        assert result['request_sha256'] == canonical_hash(request)
        callback_requests.append(deepcopy(request))
        return request
    item.adapter.authorize = real_current_authority
    with db() as c:
        c.execute("UPDATE runs SET state='PROCESSING' WHERE id=?", (job.name,))
    files = native_blueprint.render_native_blueprint(spec)
    compiled = digest({name: hashlib.sha256(text.encode()).hexdigest() for name, text in files.items()})
    original_import = item.adapter.importer
    def synthetic_import(*args, **kwargs):
        return {**original_import(*args, **kwargs), 'application_alias': alias_for_job(job.name),
                'workspace': 'FORMS2APEX_POC', 'compiled_metadata_sha256': compiled}
    item.adapter.importer = synthetic_import
    item.adapter.runtime_verifier = release_fixture.browser_receipt
    item.adapter.target_profile_loader = lambda _: select_target_profile('jsn-native-project-2616-v1')
    original_runner = item.adapter.runner
    def synthetic_export(sql, args, commands, directory, **kwargs):
        if not any('apex export' in command for command in commands):
            return original_runner(sql, args, commands, directory, **kwargs)
        item.calls.append('export')
        app_id = item.request['prior_receipts']['import']['application_id']
        (directory / f'f{app_id}.sql').write_bytes(b'-- Synthetic SQLcl output; not a live export\n' * 100)
        app = directory / alias_for_job(job.name).lower()
        for name, text in files.items():
            path = app / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(text, encoding='utf-8', newline='\n')
        return SimpleNamespace(returncode=0, stdout='FOX_PROTO_EXPORT_BEFORE=1\nFOX_PROTO_EXPORT_AFTER=1\n', stderr='')
    item.adapter.runner = synthetic_export
    pipeline = job / 'prototype-pipeline'
    for stage in ('validate', 'prepare_schema', 'import', 'verify_runtime', 'export'):
        request = deepcopy(item.request)
        # Replace the initial synthetic-stage fixture with actual gateway proof
        # while PROCESSING. No permissive authorizer is used for any stage.
        (pipeline / (stage + '-intent.json')).write_bytes(canonical({'request_sha256': digest(request)}))
        receipt = gateway_fixture.advance(item, stage)
        (pipeline / (stage + '.json')).write_bytes(canonical(receipt))
    result_path = job / 'prototype-result.json'
    result = json.loads(result_path.read_bytes())
    result['converter_receipts'] = item.request['prior_receipts']
    result_path.write_bytes(canonical(result))
    with db() as c:
        c.execute("UPDATE runs SET state='GENERATED' WHERE id=?", (job.name,))
    export_request = {**deepcopy(item.request), 'prior_receipts': {
        key: deepcopy(value) for key, value in item.request['prior_receipts'].items() if key != 'export'}}
    return root, job, db, profile, item, export_request, callback_requests, model


def test_generated_package_get_authorizes_only_exact_export(connected):
    root, job, db, profile, item, request, callbacks, model = connected
    assert authority.authorize_current(root, db, profile, request)['job_id'] == job.name
    earlier = {**deepcopy(request), 'prior_receipts': {}}
    with pytest.raises(ValueError, match='only authorizes its retained export'):
        authority.authorize_current(root, db, profile, earlier)
    # Normal earlier-stage recovery is still forbidden by the real GENERATED
    # policy. The package read must inspect its history without invoking it.
    with pytest.raises(ValueError, match='only authorizes its retained export'):
        item.adapter.recover_stage_for_job(job.name, 'validate')
    before = {path.relative_to(job): path.read_bytes() for path in job.rglob('*') if path.is_file()}
    operations = deepcopy((item.calls, model.calls, model.observations))
    callbacks.clear()
    for _ in range(2):
        raw = item.adapter.read_package(job.name)
        assert hashlib.sha256(raw).hexdigest() == item.request['prior_receipts']['export']['package_sha256']
    assert callbacks == [request] * 4  # Initial + final freshness check, both export only.
    assert (item.calls, model.calls, model.observations) == operations
    assert {path.relative_to(job): path.read_bytes() for path in job.rglob('*') if path.is_file()} == before
    with db() as c:
        assert tuple(c.execute('SELECT state,artifact FROM runs WHERE id=?', (job.name,)).fetchone()) == ('GENERATED', None)
        assert c.execute('SELECT COUNT(*) FROM acceptances').fetchone()[0] == 0


@pytest.mark.parametrize('stage', ['validate', 'prepare_schema', 'import', 'verify_runtime', 'export'])
def test_authorized_export_still_rejects_tampered_historical_request(connected, stage):
    _, job, _, _, item, _, _, _ = connected
    path = job / 'prototype-converter' / (stage + '-request.json')
    value = json.loads(path.read_bytes()); value['project_id'] = 'tampered'
    path.write_text(json.dumps(value), encoding='utf-8')
    before = deepcopy(item.calls)
    with pytest.raises(RuntimeError, match='STAGE_REQUEST_CHANGED|SOURCE_BINDING_MISMATCH'):
        item.adapter.read_package(job.name)
    assert item.calls == before
