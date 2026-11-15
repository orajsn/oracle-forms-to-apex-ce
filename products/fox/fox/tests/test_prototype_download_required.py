"""Synthetic typed runtime receipts and exact ZIPs; no live execution proof."""
from copy import deepcopy
import builtins
import hashlib
import importlib
from pathlib import Path
import sys

import pytest

from fox.opaf import OpafError, canonical_hash
from fox.prototype_download import validate_generated_package


@pytest.fixture(scope='module', params=['v1', 'required-v1', 'required-no-extra', 'required-mixed'])
def package_case(request, tmp_path_factory):
    fixture_dir = str(Path(__file__).resolve().parents[2] / 'converter/tests')
    sys.path.insert(0, fixture_dir)
    try:
        gateway = importlib.import_module('test_prototype_gateway')
        release = importlib.import_module('test_prototype_release')
    finally:
        sys.path.remove(fixture_dir)
    profile = 'v1' if request.param == 'v1' else 'required-v1'
    case = gateway._case(tmp_path_factory, profile)
    if request.param in ('required-no-extra', 'required-mixed'):
        blocks = case.request['rendering_spec']['blocks']
        for block in (blocks if request.param == 'required-no-extra' else blocks[:1]):
            for field in block['fields']:
                field['value_required'] = False
        case.request['rendered_zip_sha256'] = hashlib.sha256(
            case.renderer.deterministic_prototype_zip(case.request['rendering_spec'])).hexdigest()
    case = release.imported_case.__wrapped__(case)
    gateway.advance(case, 'verify_runtime')
    proof = case.request['prior_receipts']['verify_runtime']['runtime_receipt']
    extra_checks = [page['checks']['additional_required_input_validation'] for page in proof['pages']
                    if 'additional_required_input_validation' in page['checks']]
    assert extra_checks == ({'v1': [], 'required-v1': ['PASSED', 'PASSED'],
        'required-no-extra': ['NOT_EXERCISED_NO_ADDITIONAL_REQUIRED_FIELDS'] * 2,
        'required-mixed': ['NOT_EXERCISED_NO_ADDITIONAL_REQUIRED_FIELDS', 'PASSED']}[request.param])
    export_request = deepcopy(case.request)
    exported = gateway.advance(case, 'export')
    return Path(exported['package_path']).read_bytes(), export_request, exported


def test_typed_runtime_download_preserves_exact_package_and_receipts(package_case, monkeypatch):
    raw, request, exported = package_case
    before = deepcopy((request, exported))
    original_import = builtins.__import__
    forbidden = {'prototype_release', 'sqlcl', 'runtime_preflight', 'native_target',
                 'project_reviews', 'review_receipts', 'security', 'subprocess', 'http', 'socket'}
    def pure_import(name, globals=None, locals=None, fromlist=(), level=0):
        assert name.rsplit('.', 1)[-1] not in forbidden
        assert not forbidden.intersection(fromlist or ())
        return original_import(name, globals, locals, fromlist, level)
    monkeypatch.setattr(builtins, '__import__', pure_import)
    assert validate_generated_package(raw, request=request, export_receipt=exported) is raw
    assert (request, exported) == before


@pytest.mark.parametrize('change', [
    'ordinary-false', 'ordinary-int', 'ordinary-string', 'ordinary-missing', 'check-extra',
    'passed-int', 'authenticated-int', 'page-id-bool', 'page-id-float', 'page-id-string',
    'page-missing', 'page-extra', 'page-order', 'pages-tuple', 'page-key-extra',
    'page-key-missing', 'checks-list', 'page-list',
    'additional-true', 'additional-false', 'additional-int', 'additional-wrong-state',
    'additional-missing',
])
def test_runtime_download_rejects_inexact_page_evidence(package_case, change):
    raw, original_request, original_exported = package_case
    request, exported = deepcopy((original_request, original_exported))
    proof = request['prior_receipts']['verify_runtime']['runtime_receipt']
    page = proof['pages'][0]
    checks = page['checks']
    if change.startswith('additional-'):
        forms = [row for row in proof['pages'] if 'additional_required_input_validation' in row['checks']]
        if not forms:
            pytest.skip('Historical profile has no additional-required-input check.')
        checks = forms[0]['checks']
        key = 'additional_required_input_validation'
        if change == 'additional-missing':
            checks.pop(key)
        else:
            checks[key] = {'additional-true': True, 'additional-false': False, 'additional-int': 1,
                'additional-wrong-state': ('PASSED' if checks[key] != 'PASSED'
                    else 'NOT_EXERCISED_NO_ADDITIONAL_REQUIRED_FIELDS')}[change]
    elif change.startswith('ordinary-'):
        if change == 'ordinary-missing':
            checks.pop('render')
        else:
            checks['render'] = {'ordinary-false': False, 'ordinary-int': 1, 'ordinary-string': 'PASSED'}[change]
    elif change == 'check-extra':
        checks['unexpected'] = True
    elif change in ('passed-int', 'authenticated-int'):
        page[change.removesuffix('-int')] = 1
    elif change.startswith('page-id-'):
        page['page_id'] = {'page-id-bool': True, 'page-id-float': float(page['page_id']),
                           'page-id-string': str(page['page_id'])}[change]
    elif change == 'page-missing':
        proof['pages'].pop()
    elif change == 'page-extra':
        proof['pages'].append(deepcopy(page))
    elif change == 'page-order':
        proof['pages'].reverse()
    elif change == 'pages-tuple':
        proof['pages'] = tuple(proof['pages'])
    elif change == 'page-key-missing':
        page.pop('authenticated')
    elif change == 'checks-list':
        page['checks'] = list(checks)
    elif change == 'page-list':
        proof['pages'][0] = []
    else:
        page['unexpected'] = True
    # Keep the outer digest bindings current so the typed page gate, not a
    # stale-hash failure, is what rejects this authored negative receipt.
    request['prior_receipts']['verify_runtime']['runtime_receipt_sha256'] = canonical_hash(proof)
    exported['runtime_receipt_sha256'] = canonical_hash(proof)
    with pytest.raises(OpafError, match='runtime page coverage is incomplete'):
        validate_generated_package(raw, request=request, export_receipt=exported)
