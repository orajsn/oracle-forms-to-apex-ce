"""Mandatory detached-copy fidelity only; no cached grants or live operations."""
import asyncio
from collections import OrderedDict
from concurrent.futures import ThreadPoolExecutor
from contextvars import copy_context
from copy import deepcopy
import json
import math
import os
from pathlib import Path
import struct
import sys
import time

import pytest

from fox import prototype_read_scope as scope
from fox.opaf import canonical_hash, OpafError


@pytest.fixture
def root(tmp_path):
    path = tmp_path / 'proof'; path.mkdir()
    (path / 'marker.json').write_bytes(b'{"authored":"copy-fence-only"}')
    return path


@pytest.fixture
def clones(monkeypatch):
    counts = {'deepcopy': 0, 'loads': 0}
    original_copy, original_loads = scope.deepcopy, scope.json.loads
    def copied(value): counts['deepcopy'] += 1; return original_copy(value)
    def loaded(*a, **kw): counts['loads'] += 1; return original_loads(*a, **kw)
    monkeypatch.setattr(scope, 'deepcopy', copied)
    monkeypatch.setattr(scope.json, 'loads', loaded)
    return counts


def ordered_shape(value):
    if isinstance(value, dict): return type(value), [(type(k), k, ordered_shape(v)) for k, v in value.items()]
    if isinstance(value, (list, tuple)): return type(value), [ordered_shape(v) for v in value]
    if type(value) is float: return float, struct.pack('!d', value)
    return type(value), value


def read(root, value, identity=None):
    return scope.cached_read(root, 'active_focus', {} if identity is None else identity, lambda: value)


def test_fast_tree_exact_types_order_unicode_floats_bigint_flags_and_detachment(root, clones):
    value = {'z': [{'b': False, 'a': True, 'one': 1, 'float-one': 1.0, 'negative-zero': -0.0,
        'subnormal': 5e-324, 'largest': sys.float_info.max, 'tiny': sys.float_info.min,
        'none': None, 'bigint': 1 << 1000, 'negative-bigint': -(1 << 1000)}],
        '1': 'é漢字😀\x00\n\t\\"', 'é': {'decomposed': 'e\u0301', 'bom': '\ufeff'}, 'a': []}
    expected = ordered_shape(deepcopy(value))
    with scope.readonly_proof_scope(root):
        first = read(root, value)
        assert ordered_shape(first) == expected
        first['z'][0]['b'] = 'Changed result'; first['a'].append('Changed result')
        value['z'][0]['none'] = 'Changed original after fill'
        second = read(root, value); third = read(root, value)
        assert ordered_shape(second) == ordered_shape(third) == expected
        assert second['z'] is not third['z'] and second['z'][0] is not third['z'][0]
        tag, raw = next(iter(scope._state.get()['cache'].values()))
        assert tag is True and type(raw) is bytes and raw.startswith(b'{"z":')
    assert clones == {'deepcopy': 0, 'loads': 3}


class DictSubclass(dict): pass
class ListSubclass(list): pass
class StrSubclass(str): pass
class IntSubclass(int): pass
class FloatSubclass(float): pass


@pytest.mark.parametrize('value', [({'nested': [1]},), {'tuple': ([1], 2)},
    DictSubclass(z=[1], a=False), ListSubclass([{'a': 1}]), {'s': StrSubclass('text')},
    {'i': IntSubclass(17)}, {'f': FloatSubclass(-0.0)}, OrderedDict([('z', [1]), ('a', True)]),
    {1: ['integer key']}, {True: ['boolean key']}, {1.5: ['float key']}, {None: ['null key']}])
def test_nonplain_tuple_and_nonstring_keys_keep_deepcopy_types_and_order(root, clones, value):
    expected = ordered_shape(deepcopy(value))
    with scope.readonly_proof_scope(root):
        assert ordered_shape(read(root, value)) == expected
        assert ordered_shape(read(root, value)) == expected
        assert next(iter(scope._state.get()['cache'].values()))[0] is False
    assert clones == {'deepcopy': 3, 'loads': 0}


@pytest.mark.parametrize('kind', ['list', 'dict', 'empty-list', 'nested'])
def test_shared_mutable_aliases_keep_original_memo_semantics(root, clones, kind):
    shared = {'nested': [1]} if kind == 'dict' else [] if kind == 'empty-list' else [1]
    value = {'left': shared, 'right': shared}
    if kind == 'nested': value = {'left': {'child': shared}, 'right': {'child': shared}}
    with scope.readonly_proof_scope(root):
        first, second = read(root, value), read(root, value)
        a, b = (first['left']['child'], first['right']['child']) if kind == 'nested' else (first['left'], first['right'])
        assert a is b and a is not shared
        if type(a) is list: a.append('Changed one alias')
        else: a['new'] = True
        assert ordered_shape(second) == ordered_shape(deepcopy(value))
        assert next(iter(scope._state.get()['cache'].values()))[0] is False
    assert clones == {'deepcopy': 3, 'loads': 0}


@pytest.mark.parametrize('returned', [b'not JSON', (True, b'{"not":"a private tag"}')])
def test_custom_copy_arbitrary_return_cannot_be_confused_with_fast_representation(root, clones, returned):
    seen = []
    class Custom(list):
        def __deepcopy__(self, memo): seen.append(True); return returned
    value = Custom([1])
    with scope.readonly_proof_scope(root):
        assert read(root, value) == read(root, value) == returned
    assert clones == {'deepcopy': 3, 'loads': 0} and len(seen) == 1


def test_original_custom_deepcopy_failure_is_not_suppressed_or_stored(root, clones):
    class Custom(list):
        def __deepcopy__(self, memo): raise RuntimeError('Authored original copy failure')
    with scope.readonly_proof_scope(root):
        for _ in range(2):
            with pytest.raises(RuntimeError, match='Authored original copy failure'): read(root, Custom([1]))
        assert not scope._state.get()['cache'] and scope._state.get()['bytes'] == 0
    assert clones == {'deepcopy': 2, 'loads': 0}


@pytest.mark.parametrize('value', [None, True, False, 17, 1.0, 'immutable root'])
def test_scalar_roots_keep_original_cheap_deepcopy_path(root, clones, value):
    with scope.readonly_proof_scope(root):
        assert ordered_shape(read(root, value)) == ordered_shape(value)
        assert ordered_shape(read(root, value)) == ordered_shape(value)
    assert clones == {'deepcopy': 3, 'loads': 0}


@pytest.mark.parametrize('limit', ['_JSON_COPY_MAX_DEPTH', '_JSON_COPY_MAX_NODES', '_JSON_COPY_MAX_INT_BITS'])
def test_fast_eligibility_bounds_decline_only_optimization(root, clones, monkeypatch, limit):
    value = {'z': [{'a': 17, 'b': False}]}
    monkeypatch.setattr(scope, limit, 0)
    with scope.readonly_proof_scope(root):
        assert read(root, value) == read(root, value) == value
    assert clones == {'deepcopy': 3, 'loads': 0}


@pytest.mark.parametrize('bits,fast', [(2047, True), (3072, False)])
def test_bigint_roundtrip_survives_lowered_python_digit_limit(root, clones, bits, fast):
    value = {'number': 1 << bits, 'approved': False}
    original_limit = sys.get_int_max_str_digits()
    try:
        sys.set_int_max_str_digits(4300)
        with scope.readonly_proof_scope(root):
            assert read(root, value) == value
            sys.set_int_max_str_digits(640)
            assert read(root, value) == value
    finally:
        sys.set_int_max_str_digits(original_limit)
    assert clones == ({'deepcopy': 0, 'loads': 2} if fast else {'deepcopy': 3, 'loads': 0})


@pytest.mark.parametrize('change', ['cycle', 'nan', 'inf', 'negative-inf', 'surrogate', 'mixed-keys', 'bytes'])
def test_original_serialization_failures_precede_copy_eligibility(root, clones, monkeypatch, change):
    value = {'safe': True}
    if change == 'cycle': value['self'] = value
    elif change == 'surrogate': value['s'] = '\ud800'
    elif change == 'mixed-keys': value[1] = 'unorderable mixed key types'
    elif change == 'bytes': value['raw'] = b'not JSON'
    else: value['number'] = {'nan': float('nan'), 'inf': float('inf'), 'negative-inf': float('-inf')}[change]
    try: json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False, allow_nan=False).encode('utf-8')
    except (ValueError, TypeError, UnicodeError) as error: expected = type(error), str(error)
    else: pytest.fail('Authored malformed value unexpectedly serialized.')
    def forbidden(*a): pytest.fail('Original serialization failure reached copy eligibility.')
    monkeypatch.setattr(scope, '_json_tree_copy_bytes', forbidden)
    with scope.readonly_proof_scope(root):
        for _ in range(2):
            with pytest.raises(expected[0]) as caught: read(root, value)
            assert str(caught.value) == expected[1]
        assert not scope._state.get()['cache'] and scope._state.get()['bytes'] == 0
    assert clones == {'deepcopy': 0, 'loads': 0}


def test_original_entry_value_aggregate_budgets_and_accounting_unchanged(root, monkeypatch):
    value = {'z': [True, False], 'a': 'é'}
    size = len(json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False, allow_nan=False).encode())
    monkeypatch.setattr(scope, 'MAX_CACHED_VALUE_BYTES', size)
    monkeypatch.setattr(scope, 'MAX_CACHE_BYTES', size)
    monkeypatch.setattr(scope, 'MAX_CACHED_VALUES', 2)
    with scope.readonly_proof_scope(root):
        assert read(root, value) == value
        assert scope._state.get()['bytes'] == size
        with pytest.raises(OpafError): read(root, value, {'new': True})
        assert len(scope._state.get()['cache']) == 1 and scope._state.get()['bytes'] == size
        assert read(root, value) == value  # Capacity cannot invalidate an existing hit.
        monkeypatch.setattr(scope, 'MAX_CACHED_VALUES', 1)
        calls = []
        with pytest.raises(OpafError): scope.cached_read(root, 'active_focus', {'other': True}, lambda: calls.append(True))
        assert calls == []
    monkeypatch.setattr(scope, 'MAX_CACHED_VALUE_BYTES', size - 1)
    with scope.readonly_proof_scope(root), pytest.raises(OpafError): read(root, value)


def test_no_scope_execution_root_thread_task_and_new_scope_behavior_unchanged(root, clones, tmp_path):
    value = {'z': [False]}; computed = []
    def compute(): computed.append(True); return value
    assert scope.cached_read(root, 'active_focus', {}, compute) is value
    assert clones == {'deepcopy': 0, 'loads': 0}
    with scope.readonly_proof_scope(root):
        scope.cached_read(root, 'active_focus', {}, compute)
        before = dict(clones)
        with ThreadPoolExecutor(max_workers=1) as pool:
            with pytest.raises(OpafError): pool.submit(copy_context().run, read, root, value).result()
        with pytest.raises(OpafError): read(tmp_path, value)
        with pytest.raises(OpafError): scope.cached_read(root, 'unapproved-kind', {}, compute)
        with pytest.raises(OpafError): scope.forbid_execution()
        assert clones == before
    async def owner():
        with scope.readonly_proof_scope(root):
            read(root, value)
            async def child(): return read(root, value)
            with pytest.raises(OpafError): await asyncio.create_task(child())
    asyncio.run(owner())
    with scope.readonly_proof_scope(root): scope.cached_read(root, 'active_focus', {}, compute)
    assert len(computed) == 3 and clones == {'deepcopy': 0, 'loads': 3}


@pytest.mark.parametrize('change', ['content', 'replace', 'extra', 'missing', 'mode', 'hardlink'])
def test_fast_copy_never_suppresses_file_fences(root, change):
    path = root / 'marker.json'
    with pytest.raises(OpafError):
        with scope.readonly_proof_scope(root):
            assert read(root, {'safe': [True]}) == read(root, {'safe': [True]})
            if change == 'content': path.write_bytes(b'{"changed":true}')
            elif change == 'replace':
                replacement = root / 'replacement'; replacement.write_bytes(path.read_bytes()); os.replace(replacement, path)
            elif change == 'extra': (root / 'extra.json').write_bytes(b'{}')
            elif change == 'missing': path.unlink()
            elif change == 'mode': path.chmod(0o444)
            else: os.link(path, root / 'hardlink.json')
    assert scope.current_read_root() is None


def test_optional_stores_retain_original_deepcopy_and_independent_budgets(root, clones):
    with scope.readonly_proof_scope(root):
        for _ in range(2):
            scope.optional_document_build(root, (('authored.xml', 1, 'a' * 64),), lambda: {'z': [True]})
            scope.optional_container_proof(root, 'b' * 64, lambda: {'z': [True]})
            scope.optional_screen_projection(root, 'c' * 64, lambda: {'z': [True]})
            scope.optional_context_prefix(root, 'd' * 64, lambda: {'z': [True]})
        assert scope._state.get()['bytes'] == 0 and not scope._state.get()['cache']
    assert clones == {'deepcopy': 12, 'loads': 0}


def test_modest_actual_cached_clone_counts_and_synthetic_timing(root, clones, monkeypatch, record_property):
    value = {'z': [{'id': number, 'approved': False, 'claims': [{'kind': 'authored', 'text': 'α synthetic only'}],
        'proof': {'original': True, 'rows': [number, number + 1]}} for number in range(600)], 'a': True}
    results = {}
    for label in ('original-deepcopy-path', 'strict-json-path'):
        clones.update(dict.fromkeys(clones, 0)); computed = []; start = time.perf_counter()
        with monkeypatch.context() as copy_mode:
            if label == 'original-deepcopy-path': copy_mode.setattr(scope, '_json_tree_copy_bytes', lambda value: None)
            with scope.readonly_proof_scope(root):
                hashes = []
                def compute(): computed.append(True); return value
                for _ in range(8): hashes.append(canonical_hash(scope.cached_read(root, 'active_focus', {}, compute)))
                size = scope._state.get()['bytes']
        results[label] = {'wall_seconds': time.perf_counter() - start, 'clones': dict(clones),
            'computations': len(computed), 'result_sha256': hashes[0], 'logical_serialized_bytes': size}
        assert len(set(hashes)) == 1 and len(computed) == 1
    assert results['original-deepcopy-path']['result_sha256'] == results['strict-json-path']['result_sha256']
    assert results['original-deepcopy-path']['clones'] == {'deepcopy': 9, 'loads': 0}
    assert results['strict-json-path']['clones'] == {'deepcopy': 0, 'loads': 8}
    assert results['original-deepcopy-path']['logical_serialized_bytes'] == results['strict-json-path']['logical_serialized_bytes']
    record_property('authored_mandatory_copy_not_live', json.dumps(results, sort_keys=True))
