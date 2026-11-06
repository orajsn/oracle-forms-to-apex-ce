"""Fake HTTP over actual retained synthetic pipeline jobs; no live-flow proof."""
import base64
from copy import deepcopy
import hashlib
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from fox.opaf import ConverterClient, OpafError, canonical_hash
from fox.prototype_pipeline import run_prototype_pipeline
from fox.prototype_transport import (PrototypeHttpConverterAdapter, authority_manifest,
                                     build_authority_bundle)
from fox import prototype_transport

# Reuse authored synthetic provider fixtures, not forged saved source/reviews.
from test_prototype_pipeline import PROFILE, TARGET, SyntheticConverter, SyntheticOpaf, documents
from fox.forms_native_plan import POLICY_ID
from fox.forms_understanding_packet import local_packet


class FakeConverterHttp:
    """Endpoint simulator behind the real guarded ConverterClient instance."""

    def __init__(self):
        self.calls, self.authority, self.receipts = [], None, {}
        self.fail_authority = self.lose_authority = self.bad_authority = False
        self.fail_stage = self.bad_stage = None

    def request(self, method, path, payload=None, binary=False):
        self.calls.append((method, path, deepcopy(payload)))
        if path.endswith('/authority'):
            if method == 'GET':
                if self.authority is None:
                    raise OpafError('Synthetic not found', 404)
                return deepcopy(self.authority)
            assert method == 'POST'
            receipt = {'schema_version': 1, 'scope': 'fox-prototype-authority-staging-receipt-v1',
                       **{key: payload[key] for key in ('job_id', 'source_binding', 'source_authority', 'manifest_sha256')},
                       'staged': True, 'source_review_authorized': False}
            if self.bad_authority:
                receipt['manifest_sha256'] = '0' * 64
            if not self.lose_authority:
                self.authority = receipt
            if self.fail_authority:
                raise OpafError('SENSITIVE_HTTP_ERROR')
            return deepcopy(receipt)
        stage = path.rsplit('/', 1)[-1]
        if method == 'GET':
            if stage not in self.receipts:
                raise OpafError('Synthetic not found', 404)
            return deepcopy(self.receipts[stage])
        assert method == 'POST' and self.authority is not None
        receipt = {'stage': stage, 'request_sha256': canonical_hash(payload),
                   'source_binding': payload['source_binding'], 'plan_sha256': payload['plan_sha256'],
                   'business_behavior_accepted': False}
        receipt.update({'validate': {'passed': True}, 'prepare_schema': {'ready_for_import': True},
                        'import': {'imported': True, 'application_id': 123}}[stage])
        if self.bad_stage == stage:
            receipt['request_sha256'] = '0' * 64
        self.receipts[stage] = receipt
        if self.fail_stage == stage:
            raise OpafError('SENSITIVE_HTTP_ERROR')
        return deepcopy(receipt)


def test_runtime_capability_is_negotiated_without_writes(tmp_path, monkeypatch):
    calls=[]
    client=ConverterClient('http://127.0.0.1:8091','SYNTHETIC-NOT-A-REAL-TOKEN')
    def request(method,path,payload=None):
        calls.append((method,path,payload))
        return {'schema_version':1,'scope':'fox-prototype-capabilities-v1',
                'stages':['validate','prepare_schema','import','verify_runtime','export']}
    monkeypatch.setattr(client,'request',request)
    adapter=PrototypeHttpConverterAdapter(tmp_path/('fox-'+'a'*20),client)
    assert adapter.supports('verify_runtime') and adapter.supports('export')
    assert calls==[('GET','/fox/prototype/capabilities',None)]*2
    assert not list(tmp_path.iterdir())


def test_malformed_runtime_capabilities_cannot_enable_stage(tmp_path, monkeypatch):
    client=ConverterClient('http://127.0.0.1:8091','SYNTHETIC-NOT-A-REAL-TOKEN')
    monkeypatch.setattr(client,'request',lambda *args: {'stages':['export']})
    adapter=PrototypeHttpConverterAdapter(tmp_path/('fox-'+'a'*20),client)
    with pytest.raises(OpafError,match='capabilities'):
        adapter.supports('export')


@pytest.fixture
def retained(tmp_path, monkeypatch):
    monkeypatch.syspath_prepend(str(Path(__file__).resolve().parents[2] / 'converter'))
    docs = documents()
    job = tmp_path / ('fox-' + '2' * 20)
    recorder = SyntheticConverter(supported=('validate',))
    kwargs = {'project_id': 'synthetic-project', 'project_name': 'Synthetic prototype',
              'expected_source_binding': local_packet(docs)['source_binding'], 'approved_chunk_hashes': {},
              'approved_policy_id': POLICY_ID, 'opaf_client': SyntheticOpaf(), 'profile': deepcopy(PROFILE),
              'target_profile_loader': lambda: deepcopy(TARGET), 'processing_approval_check': lambda _: True}
    run_prototype_pipeline(job, docs, converter_adapter=recorder, **kwargs)
    http = FakeConverterHttp()
    client = ConverterClient('http://127.0.0.1:8091', 'SYNTHETIC-NOT-A-REAL-TOKEN')
    monkeypatch.setattr(client, 'request', http.request)
    return job, docs, recorder.requests[0], http, PrototypeHttpConverterAdapter(job, client), kwargs


def test_bundle_is_exact_allowlist_canonical_and_body_bound(retained):
    job, _, request, _, _, _ = retained
    # Adjacent original/config/intent files are never walked or transferred.
    (job / 'private-original.xml').write_text('DO_NOT_EXPORT_ORIGINAL')
    root = job / 'prototype-pipeline'
    (root / 'operator-secrets.json').write_text('{"password":"DO_NOT_EXPORT"}')
    bundle = build_authority_bundle(job, request)
    assert bundle == build_authority_bundle(job, request)
    assert bundle['manifest_sha256'] == canonical_hash(authority_manifest(bundle))
    paths = [row['path'] for row in bundle['files']]
    assert paths == sorted(paths) and len(paths) == len(set(paths))
    assert all(not path.startswith('/') and '\\' not in path and ':' not in path and '..' not in path for path in paths)
    assert not any('intent' in path or 'operator-' in path or 'private-original' in path for path in paths)
    assert sum(path.endswith('/mapper.json') for path in paths) == len(json.loads((root / 'review-index.json').read_text())['focuses'])
    assert sum(path.startswith('sources/') for path in paths) == 2
    for row in bundle['files']:
        raw = base64.b64decode(row['content_base64'], validate=True)
        assert row['bytes'] == len(raw)
        assert row['sha256'] == hashlib.sha256(raw).hexdigest()
        assert raw == (root / row['path']).read_bytes()
    encoded = json.dumps(bundle)
    assert 'DO_NOT_EXPORT' not in encoded and str(job) not in encoded


def test_real_guarded_client_required_and_original_endpoint_guards_preserved(retained):
    job, *_ = retained
    with pytest.raises(OpafError, match='guarded ConverterClient'):
        PrototypeHttpConverterAdapter(job, FakeConverterHttp())
    for url in ('http://example.com:8091', 'http://127.0.0.1:8092', 'http://user:secret@127.0.0.1:8091'):
        with pytest.raises(OpafError):
            ConverterClient(url, 'SYNTHETIC')


def test_stage_uses_concrete_http_endpoints_and_posts_authority_once(retained):
    job, _, request, http, adapter, _ = retained
    result = adapter.run_stage('validate', request)
    assert result['passed'] is True
    assert [(method, path.rsplit('/', 1)[-1]) for method, path, _ in http.calls] == [
        ('GET', 'authority'), ('POST', 'authority'), ('POST', 'validate')]
    assert all(path.startswith('/fox/prototype/jobs/' + job.name + '/') for _, path, _ in http.calls)
    assert (job / 'prototype-transport' / 'authority-intent.json').is_file()
    assert (job / 'prototype-transport' / 'authority.json').is_file()
    # Explicit second call checks authority read-only rather than reposting it.
    adapter.run_stage('validate', request)
    assert sum(method == 'POST' and path.endswith('/authority') for method, path, _ in http.calls) == 1
    assert not adapter.supports('verify_runtime') and not adapter.supports('export')


def test_recover_stage_is_get_only_without_local_mutation(retained):
    job, _, request, http, adapter, _ = retained
    assert adapter.recover_stage('validate', request) is None
    assert not (job / 'prototype-transport').exists()
    adapter.run_stage('validate', request)
    before = {path.relative_to(job): path.read_bytes() for path in job.rglob('*') if path.is_file()}
    http.calls.clear()
    assert adapter.recover_stage('validate', request)['passed'] is True
    assert [method for method, _, _ in http.calls] == ['GET']
    after = {path.relative_to(job): path.read_bytes() for path in job.rglob('*') if path.is_file()}
    assert before == after


def test_lost_authority_post_response_reconciles_get_without_repost(retained):
    _, _, request, http, adapter, _ = retained
    http.fail_authority = True
    with pytest.raises(OpafError, match='uncertain') as error:
        adapter.run_stage('validate', request)
    assert 'SENSITIVE' not in str(error.value)
    http.fail_authority = False
    adapter.run_stage('validate', request)
    assert sum(method == 'POST' and path.endswith('/authority') for method, path, _ in http.calls) == 1
    assert sum(method == 'POST' and path.endswith('/validate') for method, path, _ in http.calls) == 1


def test_uncertain_authority_without_remote_confirmation_never_reposts(retained):
    _, _, request, http, adapter, _ = retained
    http.fail_authority = http.lose_authority = True
    with pytest.raises(OpafError, match='uncertain'):
        adapter.run_stage('validate', request)
    http.fail_authority = False
    with pytest.raises(OpafError, match='without replay'):
        adapter.run_stage('validate', request)
    assert [method for method, _, _ in http.calls] == ['GET', 'POST', 'GET']


@pytest.mark.parametrize('kind', ['authority', 'stage'])
def test_unbound_http_receipts_do_not_become_success(retained, kind):
    _, _, request, http, adapter, _ = retained
    if kind == 'authority':
        http.bad_authority = True
    else:
        http.bad_stage = 'validate'
    with pytest.raises(OpafError):
        adapter.run_stage('validate', request)
    if kind == 'authority':
        assert not any(path.endswith('/validate') for _, path, _ in http.calls)
    else:
        with pytest.raises(OpafError, match='stale or unbound'):
            adapter.recover_stage('validate', request)


def test_missing_member_or_changed_source_blocks_before_any_http(retained):
    job, _, request, http, adapter, _ = retained
    (job / 'prototype-pipeline' / 'sources' / 'source-000.xml').write_bytes(b'<FormModule Name="CHANGED"/>')
    with pytest.raises(OpafError):
        adapter.run_stage('validate', request)
    assert http.calls == []


def test_private_absolute_path_in_allowlisted_artifact_is_not_transferred(retained):
    job, _, request, http, adapter, _ = retained
    # Non-authoritative rendered trace can carry diagnostics. Even this
    # allowlisted file must not leak an absolute workstation path.
    path = job / 'prototype-pipeline' / 'rendered.json'
    value = json.loads(path.read_text())
    value['trace']['private_diagnostic'] = 'C:\\Users\\Private\\original.xml'
    path.write_text(json.dumps(value))
    with pytest.raises(OpafError, match='absolute path'):
        adapter.run_stage('validate', request)
    assert http.calls == []


def test_credential_field_in_allowlisted_artifact_is_not_transferred(retained):
    job, _, request, http, adapter, _ = retained
    path = job / 'prototype-pipeline' / 'rendered.json'
    value = json.loads(path.read_text())
    value['trace']['password'] = 'SYNTHETIC-MUST-NOT-TRANSFER'
    path.write_text(json.dumps(value))
    with pytest.raises(OpafError, match='credential field'):
        adapter.run_stage('validate', request)
    assert http.calls == []


def test_pending_staging_binding_change_blocks_without_remote_call(retained):
    job, _, request, http, adapter, _ = retained
    http.fail_authority = True
    with pytest.raises(OpafError):
        adapter.run_stage('validate', request)
    path = job / 'prototype-transport' / 'authority-intent.json'
    value = json.loads(path.read_text())
    value['manifest_sha256'] = '0' * 64
    path.write_text(json.dumps(value))
    before = deepcopy(http.calls)
    with pytest.raises(OpafError, match='intent changed'):
        adapter.run_stage('validate', request)
    assert http.calls == before


def test_http_lost_import_response_pipeline_recovers_get_only_without_replay(retained):
    job, docs, _, http, adapter, kwargs = retained
    # The fixture's authored validation receipt already exists. The remaining
    # real pipeline checkpoints are reused; the HTTP simulator loses import.
    http.fail_stage = 'import'
    with pytest.raises(OpafError, match='reconcile without replay'):
        run_prototype_pipeline(job, docs, converter_adapter=adapter, **kwargs)
    assert sum(method == 'POST' and path.endswith('/import') for method, path, _ in http.calls) == 1
    http.fail_stage = None
    result = run_prototype_pipeline(job, docs, converter_adapter=adapter, **kwargs)
    assert result['status'] == 'BLOCKED_ADAPTER' and result['stage'] == 'verify_runtime'
    assert result['facts']['import_verified'] is True
    assert result['facts']['download_ready'] is False
    assert sum(method == 'POST' and path.endswith('/import') for method, path, _ in http.calls) == 1


@pytest.mark.parametrize('bound', ['MAX_AUTHORITY_BYTES', 'MAX_AUTHORITY_MEMBER_BYTES',
                                 'MAX_AUTHORITY_FILES', 'MAX_AUTHORITY_WIRE_BYTES'])
def test_bundle_limits_fail_before_http(retained, monkeypatch, bound):
    _, _, request, http, adapter, _ = retained
    monkeypatch.setattr(prototype_transport, bound, 1)
    with pytest.raises(OpafError, match='bound|oversized'):
        adapter.run_stage('validate', request)
    assert not http.calls


def test_sender_bundle_stages_in_actual_receiver_and_revalidates_source_authority(retained, tmp_path):
    from forms2apex.prototype_gateway import PrototypeGateway
    from fox.prototype_pipeline import authorize_prototype_request

    job, _, request, _, _, _ = retained
    remote_jobs = tmp_path / 'receiver'
    remote_jobs.mkdir()
    receiver = PrototypeGateway(SimpleNamespace(jobs_root=remote_jobs))
    bundle = build_authority_bundle(job, request)
    assert receiver.recover_source_authority(job.name) is None
    receipt = receiver.stage_source_authority(job.name, bundle)
    assert receipt['manifest_sha256'] == bundle['manifest_sha256']
    assert receipt['source_review_authorized'] is False
    remote_job = remote_jobs / job.name
    # Validate the actual received artifact closure, not a mocked boolean.
    assert authorize_prototype_request(remote_job, request) is request
    before = {path.relative_to(remote_job): path.read_bytes() for path in remote_job.rglob('*') if path.is_file()}
    assert receiver.recover_source_authority(job.name) == receipt
    assert receiver.stage_source_authority(job.name, bundle) == receipt
    after = {path.relative_to(remote_job): path.read_bytes() for path in remote_job.rglob('*') if path.is_file()}
    assert before == after
