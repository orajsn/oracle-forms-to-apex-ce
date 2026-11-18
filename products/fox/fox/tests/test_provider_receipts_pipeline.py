"""Explicit opt-in synthetic pipeline; no installed service or real inference."""
import hashlib
import json
from types import SimpleNamespace
import zipfile

import pytest

from fox.opaf import OpafError
from fox.prototype_pipeline import run_prototype_pipeline
from fox.provider_receipts import LocalProviderReceiptStore
from test_oci_genai import direct_setup
from test_prototype_export_only import authored_validator


@pytest.fixture
def tmp_path(tmp_path_factory):
    return tmp_path_factory.mktemp('p')


def configured(case):
    job, _, client, _, _, _, options = case
    store = LocalProviderReceiptStore(job.parent / 'receipts', sealed_job_root=job)
    def prepared(*args, **kwargs):
        return client.invoke_prepared(*args, **kwargs, receipt_store=store)
    return store, {**options, 'opaf_client': SimpleNamespace(invoke_prepared=prepared),
                   'delivery_mode': 'apexlang_package', 'offline_validator': authored_validator}


def retained(job):
    return {str(p.relative_to(job)): hashlib.sha256(p.read_bytes()).hexdigest()
            for p in job.rglob('*') if p.is_file()}


def test_opt_in_receipts_reach_synthetic_package_without_changing_legacy_shapes(direct_setup):
    job, docs, _, service, _, _, _ = direct_setup
    store, options = configured(direct_setup)
    result = run_prototype_pipeline(job, docs, **options)
    assert result['status'] == 'APEX_GENERATED'
    assert result['format_validated'] is True
    assert result['facts']['business_behavior_accepted'] is False
    assert len(list(store.root.glob('*.intent.json'))) == len(service.calls)
    assert len(list(store.root.glob('*.response.json'))) == len(service.calls)
    assert len(service.calls) == 2 * result['assessment']['focus_count']
    with zipfile.ZipFile(job / 'prototype-pipeline/apexlang-package.zip') as package:
        assert 'application.apx' in package.namelist()
        metadata = json.loads(package.read('fox-package/metadata.json'))
        assert metadata['validation']['sqlcl_version'] == 'synthetic-test'
    before, calls = retained(job), len(service.calls)
    service.failure = AssertionError('Completed provider calls must not repeat')
    assert run_prototype_pipeline(job, docs, **options) == result
    assert retained(job) == before and len(service.calls) == calls


def test_bad_reply_is_retained_but_pending_pipeline_gate_is_not_bypassed(direct_setup):
    job, docs, _, service, _, _, _ = direct_setup
    store, options = configured(direct_setup)
    service.alter = lambda body: body['chat_response']['choices'][0]['message']['content'][0].update(text='not valid JSON')
    with pytest.raises(OpafError, match='without replay'):
        run_prototype_pipeline(job, docs, **options)
    response = json.loads(next(store.root.glob('*.response.json')).read_text())['payload']
    assert response['body']['chat_response']['choices'][0]['message']['content'][0]['text'] == 'not valid JSON'
    assert not (job / 'prototype-pipeline/apexlang-package.zip').exists()
    before = retained(job)
    with pytest.raises(OpafError, match='uncertain'):
        run_prototype_pipeline(job, docs, **options)
    assert len(service.calls) == 1 and retained(job) == before
