"""Deterministic parser tests; authored responses are not live OPAF proof."""
import json
import hashlib
from copy import deepcopy

import pytest

from fox.opaf import OpafClient, OpafError, canonical_hash, parse_model_message


@pytest.mark.parametrize('wrap', [lambda s: s, lambda s: '\n' + s + '\t',
    lambda s: '```json\n' + s + '\n```', lambda s: '```\n' + s + '\n```',
    lambda s: ' \n```json\r\n' + s + '\r\n```\n '])
def test_single_object_and_exact_fences(wrap):
    expected = {'focus_id': 'synthetic', 'blueprint': {'objects': [], 'literal': '```'}}
    assert parse_model_message(wrap(json.dumps(expected))) == expected


def test_existing_dictionary_is_unchanged():
    message = {'objects': [], 'nested': {'value': 1.25}}
    original = deepcopy(message)
    assert parse_model_message(message) is message
    assert message == original


@pytest.mark.parametrize('message', [
    'Here is the result: {"a":1}', '{"a":1} done', '{}{}', '{}\n{}',
    '```json\n{}\n```\ntrailing', 'prefix\n```json\n{}\n```',
    '```json\n{}\n```\n```json\n{}\n```', '```JSON\n{}\n```',
    '```python\n{}\n```', '```json {} ```', '```json\n{}',
    '[]', 'true', 'null', '1', '"{}"', '{"a":1,"a":2}',
    '{"nested":{"a":1,"a":2}}', '{"a":NaN}', '{"a":Infinity}',
    '{"a":-Infinity}', '{"a":1e999}', '```json\n{"a":NaN}\n```',
    [], None, {1: 'not-json-key'}, {'a': float('nan')}, {'a': [float('inf')]},
    '{"nested":' + '[' * 1500 + '0' + ']' * 1500 + '}',
])
def test_ambiguous_or_nonfinite_output_is_rejected(message):
    with pytest.raises(ValueError):
        parse_model_message(message)


def test_invocation_keeps_hash_of_original_fenced_api_response(monkeypatch):
    role = {'workflow_id': 'A' * 32, 'model': 'synthetic',
            'graph_sha256': canonical_hash({'nodes': []})}
    response = {'roomId': 'synthetic-room', 'message': '```json\n{"objects": []}\n```'}
    original = deepcopy(response)
    calls = []
    def request(self, method, path, payload=None, login=False):
        calls.append(method)
        if login:
            return {}
        if method == 'GET':
            return {'data': {'published': True, 'data': {'nodes': []}}}
        return response
    monkeypatch.setattr(OpafClient, '_request', request)
    output, invocation = OpafClient('https://localhost/agentFactory', '', '').invoke(role, {})
    assert output == {'objects': []}
    assert invocation['response_sha256'] == canonical_hash(original)
    assert response == original and calls.count('POST') == 1


@pytest.mark.parametrize('raw', [b'{"roomId":"synthetic","message":{"a":1,"a":2}}',
    b'{"roomId":"synthetic","message":{"nested":{"a":1,"a":2}}}',
    b'{"roomId":"synthetic","message":{"value":NaN}}'])
def test_raw_api_object_cannot_erase_duplicate_or_nonfinite_model_properties(monkeypatch, raw):
    class Connection:
        status = 200
        def __init__(self, *args, **kwargs): self.sock = self
        def connect(self): pass
        def getpeercert(self, **kwargs): return b'synthetic-certificate'
        def request(self, *args, **kwargs): pass
        def getresponse(self): return self
        def read(self, *args): return raw
        def close(self): pass
    monkeypatch.setattr('fox.opaf.http.client.HTTPSConnection', Connection)
    client = OpafClient('https://localhost/agentFactory', '', '',
                        hashlib.sha256(b'synthetic-certificate').hexdigest())
    with pytest.raises(OpafError, match='unsupported response format'):
        client._request('POST', '/v1/synthetic', {})
