"""Bounded local proof reuse, never execution or persisted approval caching."""
import asyncio
from concurrent.futures import ThreadPoolExecutor
from contextvars import copy_context
import os

import pytest

from fox import prototype_read_scope as scope, prototype_pipeline, prototype_job
from fox.opaf import OpafError, ConverterClient
from fox.prototype_transport import PrototypeHttpConverterAdapter


@pytest.fixture
def root(tmp_path):
    path = tmp_path / 'proof'; path.mkdir()
    (path / 'one.json').write_bytes(b'{"safe":true}')
    return path


def test_nested_scope_deepcopy_and_complete_value_identity(root):
    calls = []
    def compute(): calls.append(True); return {'candidate': {'value': 'original'}}
    with scope.readonly_proof_scope(root):
        first = scope.cached_read(root, 'active_focus', {'previous': {'checked': True}}, compute)
        first['candidate']['value'] = 'mutated'
        with scope.readonly_proof_scope(root):
            assert scope.cached_read(root, 'active_focus', {'previous': {'checked': True}}, compute)['candidate']['value'] == 'original'
        scope.cached_read(root, 'active_focus', {'previous': {'checked': False}}, compute)
    with scope.readonly_proof_scope(root): scope.cached_read(root, 'active_focus', {'previous': {'checked': True}}, compute)
    assert len(calls) == 3


@pytest.mark.parametrize('mutation', ['content', 'same-bytes-replacement', 'extra', 'permission'])
def test_mutation_after_cached_hit_is_detected(root, mutation):
    with pytest.raises(OpafError):
        with scope.readonly_proof_scope(root):
            scope.cached_read(root, 'technical_record', {}, lambda: {'safe': True})
            assert scope.cached_read(root, 'technical_record', {}, lambda: None) == {'safe': True}
            path = root / 'one.json'
            if mutation == 'content': path.write_bytes(b'{"safe":false}')
            elif mutation == 'same-bytes-replacement':
                temporary = root / 'replacement'
                temporary.write_bytes(path.read_bytes())
                os.replace(temporary, path)
            elif mutation == 'permission': path.chmod(0o444)
            else: (root / 'extra.json').write_bytes(b'{}')


def test_cross_root_and_runtime_any_root_are_refused(root):
    with scope.readonly_proof_scope(root):
        with pytest.raises(OpafError):
            with scope.readonly_proof_scope(root.parent): pass
        with pytest.raises(OpafError): scope.cached_read(root.parent, 'technical_record', {}, lambda: {})
        with pytest.raises(OpafError): scope.forbid_execution()
    scope.forbid_execution()


def test_thread_context_inheritance_cannot_reuse_scope(root):
    with scope.readonly_proof_scope(root):
        context = copy_context()
        with ThreadPoolExecutor(max_workers=1) as pool:
            result = pool.submit(context.run, scope.cached_read, root, 'technical_record', {}, lambda: {})
            with pytest.raises(OpafError): result.result()


def test_async_child_context_cannot_reuse_scope(root):
    async def run():
        with scope.readonly_proof_scope(root):
            async def child():
                with pytest.raises(OpafError): scope.cached_read(root, 'technical_record', {}, lambda: {})
            await asyncio.create_task(child())
    asyncio.run(run())


def test_entry_and_aggregate_byte_budgets(root, monkeypatch):
    monkeypatch.setattr(scope, 'MAX_CACHED_VALUE_BYTES', 100)
    monkeypatch.setattr(scope, 'MAX_CACHE_BYTES', 110)
    with scope.readonly_proof_scope(root):
        with pytest.raises(OpafError): scope.cached_read(root, 'active_focus', {'key': 'huge'}, lambda: {'v': 'x' * 101})
        scope.cached_read(root, 'active_focus', {'key': 'one'}, lambda: {'v': 'x' * 60})
        with pytest.raises(OpafError): scope.cached_read(root, 'active_focus', {'key': 'two'}, lambda: {'v': 'x' * 60})


def test_model_runtime_configuration_and_package_http_cannot_enter_scope(root, monkeypatch):
    calls = []
    client = ConverterClient('http://127.0.0.1:8091', 'SYNTHETIC-ONLY-TOKEN')
    monkeypatch.setattr(client, 'request', lambda *args, **kwargs: calls.append(args))
    adapter = PrototypeHttpConverterAdapter(root / ('fox-' + 'a' * 20), client)
    with scope.readonly_proof_scope(root):
        with pytest.raises(OpafError):
            prototype_pipeline._role(root, 'mapper', object(), {}, {}, {}, None, None, None)
        with pytest.raises(OpafError): prototype_job._configuration('a' * 64)
        with pytest.raises(OpafError): adapter.read_package({}, {})
        with pytest.raises(OpafError): adapter.run_stage('validate', {})
        with pytest.raises(OpafError): adapter._get('/fox/prototype/capabilities')
    assert calls == []
