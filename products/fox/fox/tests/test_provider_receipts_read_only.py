"""Read-only evidence opening must not initialize or rewrite a receipt store."""
import hashlib

import pytest

from fox.provider_receipts import LocalProviderReceiptStore, ProviderReceiptError
from test_oci_genai_receipts import case, invoke, payload, recover


def inventory(root):
    return {p.name: (hashlib.sha256(p.read_bytes()).hexdigest(), p.stat().st_mtime_ns)
            for p in root.iterdir() if p.is_file()}


def test_open_missing_receipts_never_creates_directory(tmp_path, monkeypatch):
    def forbidden(*args, **kwargs):
        pytest.fail('Read-only open must not fsync storage')
    monkeypatch.setattr('fox.provider_receipts._sync_directory', forbidden)
    job = tmp_path / 'job'
    job.mkdir()
    missing = tmp_path / 'missing'
    with pytest.raises(ProviderReceiptError):
        LocalProviderReceiptStore.read_only(missing, sealed_job_root=job)
    assert not missing.exists()


def test_read_only_recovery_preserves_receipts_and_never_authenticates_or_calls(case, monkeypatch):
    expected = invoke(case)[:3]
    client, service, current, identity, request, store = case
    intent = payload(store, 'intent')
    pending_binding = dict(intent['binding'], request_sha256='e'*64)
    pending_key = store.begin(pending_binding, client_request_id='fox-'+'e'*32,
        started_at_utc=intent['started_at_utc'], environment=intent['environment'])
    before = inventory(store.root)
    def forbidden(*args, **kwargs):
        pytest.fail('Read-only recovery must not initialize, fsync or submit')
    monkeypatch.setattr('fox.provider_receipts._sync_directory', forbidden)
    monkeypatch.setattr(client, '_client', forbidden)
    readonly = LocalProviderReceiptStore.read_only(store.root, sealed_job_root=store.sealed_job_root)
    assert recover((client, service, current, identity, request, readonly)) == expected
    assert inventory(store.root) == before and len(service.calls) == 1
    with pytest.raises(ProviderReceiptError):
        readonly.begin(dict(intent['binding'], request_sha256='f'*64), client_request_id='fox-'+'f'*32,
                       started_at_utc=intent['started_at_utc'], environment=intent['environment'])
    with pytest.raises(ProviderReceiptError):
        readonly.capture(pending_key, body={}, status=200,
                         request_id='synthetic', completed_at_utc=intent['started_at_utc'])
    assert inventory(store.root) == before
