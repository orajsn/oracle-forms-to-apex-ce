"""Real local epoch-four HTTP/ZIP/current-authority wiring only.

Provider replies, SQLcl output and authenticated browser evidence are AUTHORED
synthetic adapters. No actual OPAF/Oracle/browser/business acceptance is claimed.
No sealed history/stage receipt is replaced to fabricate the connected result.
"""
from copy import deepcopy
import hashlib
import importlib
import json
from pathlib import Path
import sys
from types import SimpleNamespace

from starlette.applications import Starlette
from starlette.routing import Route
from starlette.testclient import TestClient

from fox import prototype_authority, prototype_download, prototype_mapping_epochs as epochs
from fox import prototype_container_epoch as container, prototype_job
from fox.opaf import ConverterClient, OpafError, canonical_hash
from fox.prototype_transport import PrototypeHttpConverterAdapter
from test_prototype_container_epoch import (container_case, container_source_model, next_body, process,
    clause_case, epochs_case, tmp_path, client, settings, no_external_actions, api)


class MCP:
    def __init__(self): self.routes = []
    def custom_route(self, path, methods, include_in_schema=False):
        def register(function):
            self.routes.append(Route(path, function, methods=methods))
            return function
        return register


def test_four_exact_http_receiver_full_zip_and_current_output_race_guards(container_case, monkeypatch, tmp_path_factory):
    from forms2apex.prototype_routes import attach_prototype_routes
    from forms2apex import native_blueprint
    from forms2apex.project_reviews import digest
    from forms2apex.security import alias_for_job
    from forms2apex.target_profile import select_target_profile
    case = container_case
    c, root, pid, rid, job, snapshot, _, model, _, db, envelope = case
    plan, body = next_body(case)
    assert c.post(api(case, 'mapping-epochs'), json=body).status_code == 202
    profile = root / 'public-profile.json'
    profile.write_text(json.dumps(envelope)); profile.chmod(0o600)
    fixtures = str(Path(__file__).resolve().parents[2] / 'converter/tests')
    sys.path.insert(0, fixtures)
    try:
        gateway_fixture = importlib.import_module('test_prototype_gateway')
        release_fixture = importlib.import_module('test_prototype_release')
    finally:
        sys.path.remove(fixtures)
    token = 'AUTHORED-SYNTHETIC-LOCAL-HTTP-ONLY'
    http_calls, callbacks, private_factories, package_races = [], [], [], []
    holder = {}
    stage_source = model.calls[:]

    def prepare(request):
        if holder:
            return holder['gateway']
        spec = deepcopy(request['rendering_spec'])
        monkeypatch.setattr(gateway_fixture, 'spec', lambda _: deepcopy(spec))
        item = gateway_fixture.case.__wrapped__(tmp_path_factory)
        def authorize(value):
            result = prototype_authority.authorize_current(root, db, profile, value)
            callbacks.append((len(value['prior_receipts']), result['request_sha256']))
            return value
        item.adapter.authorize = authorize
        files = native_blueprint.render_native_blueprint(spec)
        compiled = digest({name: hashlib.sha256(text.encode()).hexdigest() for name, text in files.items()})
        old_import = item.adapter.importer
        def imported(*args, **kwargs):
            return {**old_import(*args, **kwargs), 'application_alias': alias_for_job(rid),
                'workspace': 'FORMS2APEX_POC', 'compiled_metadata_sha256': compiled}
        item.adapter.importer = imported
        item.adapter.runtime_verifier = release_fixture.browser_receipt
        item.adapter.target_profile_loader = lambda _: select_target_profile('jsn-native-project-2616-v1')
        old_runner = item.adapter.runner
        def exported(sql, args, commands, directory, **kwargs):
            if not any('apex export' in command for command in commands):
                return old_runner(sql, args, commands, directory, **kwargs)
            app_id = item.request['prior_receipts']['import']['application_id']
            (directory / f'f{app_id}.sql').write_bytes(b'-- Authored synthetic SQLcl export; NOT a live Oracle export\n' * 100)
            app = directory / alias_for_job(rid).lower()
            for name, text in files.items():
                path = app / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(text, encoding='utf-8', newline='\n')
            return SimpleNamespace(returncode=0, stdout='FOX_PROTO_EXPORT_BEFORE=1\nFOX_PROTO_EXPORT_AFTER=1\n', stderr='')
        item.adapter.runner = exported
        item.request.clear(); item.request.update(deepcopy(request))
        holder.update(gateway=item.adapter, item=item)
        return item.adapter

    class LazyGateway:
        def supports(self, stage): return stage in ('validate', 'prepare_schema', 'import', 'verify_runtime', 'export')
        def recover_source_authority(self, job_id):
            return holder['gateway'].recover_source_authority(job_id) if holder else None
        def stage_source_authority(self, job_id, bundle):
            # The real transport has already produced native-plan.json; no
            # fake source-authority request/receipt is introduced here.
            rendering = epochs.read(job / 'prototype-pipeline/native-plan.json')
            request = {'rendering_spec': rendering['rendering_spec'], 'prior_receipts': {}}
            return prepare(request).stage_source_authority(job_id, bundle)
        def recover_stage_for_job(self, job_id, stage):
            return holder['gateway'].recover_stage_for_job(job_id, stage) if holder else None
        def run_stage(self, stage, request):
            item = holder['item']
            item.request.clear(); item.request.update(deepcopy(request))
            return holder['gateway'].run_stage(stage, request)
        def read_package(self, job_id): return holder['gateway'].read_package(job_id)

    mcp = MCP()
    attach_prototype_routes(mcp, LazyGateway(), SimpleNamespace(bearer_token=token))
    with TestClient(Starlette(routes=mcp.routes)) as receiver:
        sender = ConverterClient('http://127.0.0.1:8091', token)
        def request(method, path, payload=None, binary=False):
            # Actual Starlette HTTP routes, bearer check, JSON body decoder,
            # receiver whitelist and real gateway—not an endpoint simulator.
            http_calls.append((method, path))
            response = receiver.request(method, path, json=payload if payload is not None else None,
                headers={'Authorization': 'Bearer ' + token})
            if response.status_code >= 400:
                raise OpafError('Local HTTP receiver refused the request.', response.status_code)
            if path.endswith('/package') and package_races:
                package_races.pop(0)()
            return response.content if binary else response.json()
        monkeypatch.setattr(sender, 'request', request)
        adapter = PrototypeHttpConverterAdapter(job, sender)
        runtime = {'profile': deepcopy(envelope['target_profile']['opaf']['roles']), 'opaf_client': model,
            'target_profile_loader': lambda: deepcopy(envelope['target_profile']), 'converter_adapter': adapter}
        monkeypatch.setattr(prototype_job, '_configuration', lambda *args, **kwargs: runtime)
        row, errors = process(case, monkeypatch)
        assert row['state'] == 'GENERATED', '\n'.join(errors) or row['message']
        new = model.calls[len(stage_source):]
        assert new[0][0] == 'reviewer' and new[0][1]['request']['focus_id'] == plan['projection_focus_id']
        assert len([role for role, _ in new if role == 'mapper']) == plan['remaining_focus_count']
        assert sum(method == 'POST' and path.endswith('/authority') for method, path in http_calls) == 1
        assert [path.rsplit('/', 1)[-1] for method, path in http_calls if method == 'POST' and '/stages/' in path] == [
            'validate', 'prepare_schema', 'import', 'verify_runtime', 'export']
        assert callbacks
        def factory(*args, **kwargs): private_factories.append(True); return sender
        monkeypatch.setattr(prototype_download, 'configured_download_client', factory)
        base = f'/api/projects/{pid}/prototype-runs/{rid}'
        metadata = c.get(base + '/output')
        assert metadata.status_code == 200, metadata.text
        assert metadata.json()['status'] == 'APEX_GENERATED' and metadata.json()['business_behavior_accepted'] is False
        package = c.get(base + '/download')
        assert package.status_code == 200, package.text
        assert package.headers['content-type'] == 'application/zip'
        assert package.headers['x-content-sha256'] == hashlib.sha256(package.content).hexdigest()
        from fox.prototype_download import retained_export_request, validate_generated_package
        export, receipt = retained_export_request(job, snapshot, envelope)
        validate_generated_package(package.content, request=export, export_receipt=receipt)
        completed = deepcopy(model.calls)
        previous_history = job / epochs.read(job / container.RECORD)['plan']['previous_result']['history_path']
        old_history_raw = previous_history.read_bytes()
        with db() as connection:
            event = tuple(connection.execute('SELECT owner,action,object_id,created FROM events WHERE object_id LIKE ?',
                (rid + ':epoch:000004:%',)).fetchone())

        for mutation in ('missing-event', 'old-history'):
            if mutation == 'missing-event':
                with db() as connection: connection.execute('DELETE FROM events WHERE object_id=?', (event[2],))
            else: previous_history.write_bytes(old_history_raw + b' ')
            private_factories.clear(); before_http = len(http_calls)
            try:
                for tail in ('/output', '/download'):
                    denied = c.get(base + tail)
                    assert denied.status_code == 409, denied.text
                assert private_factories == [] and len(http_calls) == before_http
            finally:
                if mutation == 'missing-event':
                    with db() as connection: connection.execute('INSERT INTO events(owner,action,object_id,created) VALUES(?,?,?,?)', event)
                else: previous_history.write_bytes(old_history_raw)

        # Mutate AFTER successful real package GET, outside any proof-read scope.
        # Fresh post-package DB/history validation must refuse delivery.
        for mutation in ('event-after-read', 'history-after-read'):
            def race(kind=mutation):
                if kind == 'event-after-read':
                    with db() as connection: connection.execute('DELETE FROM events WHERE object_id=?', (event[2],))
                else: previous_history.write_bytes(old_history_raw + b' ')
            package_races.append(race)
            try:
                denied = c.get(base + '/download')
                assert denied.status_code == 409, denied.text
                assert not package_races
            finally:
                if mutation == 'event-after-read':
                    with db() as connection: connection.execute('INSERT INTO events(owner,action,object_id,created) VALUES(?,?,?,?)', event)
                else: previous_history.write_bytes(old_history_raw)
        assert model.calls == completed
        assert sum(method == 'POST' and '/stages/' in path for method, path in http_calls) == 5
