"""Synthetic retained export/read tests; no live SQLcl, Oracle or browser proof."""
from copy import deepcopy
import hashlib

import pytest

from forms2apex.project_reviews import canonical, read_object
from test_prototype_gateway import case, advance
from test_prototype_release import imported_case


@pytest.fixture
def exported_case(imported_case):
    item = imported_case
    advance(item, 'verify_runtime')
    request = deepcopy(item.request)
    receipt = advance(item, 'export')
    return item, request, receipt


def test_repeated_package_get_revalidates_without_writes_or_external_calls(exported_case):
    item, request, receipt = exported_case
    before_calls = deepcopy(item.calls)
    before = {p.relative_to(item.root): p.read_bytes() for p in item.root.rglob('*') if p.is_file()}
    authorized = []
    # Explicitly synthetic authorizer. Production always uses its trusted callback.
    item.adapter.authorize = lambda value: authorized.append(deepcopy(value)) or value
    for _ in range(2):
        raw = item.adapter.read_package(request['job_id'])
        assert hashlib.sha256(raw).hexdigest() == receipt['package_sha256']
    assert authorized and item.calls == before_calls
    assert {p.relative_to(item.root): p.read_bytes() for p in item.root.rglob('*') if p.is_file()} == before


@pytest.mark.parametrize('stage', ['validate', 'prepare_schema', 'import', 'verify_runtime', 'export'])
@pytest.mark.parametrize('status', ['FAILED', 'UNKNOWN', 'UNAVAILABLE'])
def test_noncomplete_stage_is_not_downloadable(exported_case, stage, status):
    item, request, _ = exported_case
    path = item.root / (stage + '.json')
    receipt = read_object(path); receipt['status'] = status
    path.write_bytes(canonical(receipt))
    before = deepcopy(item.calls)
    with pytest.raises(RuntimeError):
        item.adapter.read_package(request['job_id'])
    assert item.calls == before


@pytest.mark.parametrize('target', ['prototype-package.zip', 'runtime-evidence/browser-report.json',
                                  'verify_runtime.json', 'import-intent.json'])
def test_missing_or_tampered_export_proof_blocks_get(exported_case, target):
    item, request, _ = exported_case
    (item.root / target).write_bytes(b'tampered')
    before = deepcopy(item.calls)
    with pytest.raises((RuntimeError, ValueError)):
        item.adapter.read_package(request['job_id'])
    assert item.calls == before


def test_authorization_revocation_blocks_retained_package(exported_case):
    item, request, _ = exported_case
    item.adapter.authorize = None
    with pytest.raises(RuntimeError, match='AUTHORIZATION_UNAVAILABLE'):
        item.adapter.read_package(request['job_id'])


def test_fox_exact_package_validator_accepts_only_retained_proof(exported_case):
    from fox.prototype_download import validate_generated_package
    item, request, receipt = exported_case
    raw = item.adapter.read_package(request['job_id'])
    assert validate_generated_package(raw, request=request, export_receipt=receipt) == raw
    with pytest.raises((RuntimeError, ValueError)):
        validate_generated_package(raw + b'tamper', request=request, export_receipt=receipt)
    request['prior_receipts']['verify_runtime']['runtime_receipt']['authenticated'] = False
    with pytest.raises(RuntimeError):
        validate_generated_package(raw, request=request, export_receipt=receipt)


def test_http_adapter_uses_only_configured_client_fixed_get_and_exact_hash(exported_case, monkeypatch):
    from fox.opaf import ConverterClient, OpafError
    from fox.prototype_transport import PrototypeHttpConverterAdapter
    item, request, receipt = exported_case
    raw = item.adapter.read_package(request['job_id'])
    calls, authorizations = [], []
    # This fixture authors synthetic gateway proof, so isolate HTTP byte transfer
    # from source-authority reconstruction, exercised in API/pipeline tests.
    monkeypatch.setattr('fox.prototype_transport.authorize_prototype_request',
                        lambda job, value: authorizations.append(deepcopy(value)) or value)
    client = ConverterClient('http://127.0.0.1:8091', 'SYNTHETIC-TEST-ONLY')
    def get(method, path, payload=None, binary=False):
        calls.append((method, path, payload, binary))
        return raw
    monkeypatch.setattr(client, 'request', get)
    adapter = PrototypeHttpConverterAdapter(item.root.parent, client)
    for _ in range(2):
        assert adapter.read_package(request, receipt) == raw
    assert calls == [('GET', '/fox/prototype/jobs/' + request['job_id'] + '/package', None, True)] * 2
    assert len(authorizations) == 4
    bad = deepcopy(receipt); bad['package_sha256'] = 'f' * 64
    with pytest.raises(RuntimeError):
        adapter.read_package(request, bad)
    monkeypatch.setattr(client, 'request', lambda *args, **kwargs: b'x' * 8_000_001)
    with pytest.raises(OpafError):
        adapter.read_package(request, receipt)
    changed = deepcopy(request); changed['job_id'] = 'fox-' + 'f' * 20
    with pytest.raises(OpafError):
        adapter.read_package(changed, receipt)
