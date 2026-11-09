"""Trusted validation wait selection, not a live latency or total-time guarantee."""
import json
from types import SimpleNamespace

import pytest

from fox import opaf

JOB = 'fox-0123456789abcdefabcd'
BASE = '/fox/prototype/jobs/' + JOB


@pytest.fixture
def transport(monkeypatch):
    calls = []

    class Connection:
        def __init__(self, host, port, *, timeout):
            self.entry = {'host': host, 'port': port, 'timeout': timeout, 'closed': False}
            calls.append(self.entry)

        def request(self, method, path, body, headers):
            self.entry.update(method=method, path=path, body=body, headers=headers)

        def getresponse(self):
            if failure[0]:
                raise TimeoutError('authored response loss')
            return SimpleNamespace(status=200, read=lambda limit: b'{"retained":true}')

        def close(self):
            self.entry['closed'] = True

    failure = [False]
    monkeypatch.setattr(opaf.http.client, 'HTTPConnection', Connection)
    return opaf.ConverterClient('http://127.0.0.1:8091', 'synthetic-token'), calls, failure


@pytest.mark.parametrize('method,path,expected', [
    ('POST', BASE + '/stages/validate', 1080),
    ('POST', BASE + '/continue-validation', 1080),
    ('GET', BASE + '/stages/validate', 600),
    ('GET', BASE + '/continue-validation', 600),
    ('POST', BASE + '/validate-preclaim-witness', 600),
    ('POST', BASE + '/stages/import', 600),
    ('POST', BASE + '/stages/export', 600),
    ('POST', BASE + '/stages/validate?timeout=9999', 600),
    ('POST', BASE + '/stages/validate/', 600),
    ('POST', BASE.replace(JOB, 'fox-not-a-job') + '/stages/validate', 600),
    ('POST', '/fox/jobs/' + JOB, 600),
])
def test_exact_trusted_validation_paths_only(transport, method, path, expected):
    client, calls, _ = transport
    payload = {'timeout': 1, 'untrusted_wait_seconds': 99999}
    assert client.request(method, path, payload) == {'retained': True}
    assert len(calls) == 1
    assert calls[0]['timeout'] == expected
    assert calls[0]['host'] == '127.0.0.1' and calls[0]['port'] == 8091
    assert json.loads(calls[0]['body']) == payload
    assert calls[0]['headers']['Authorization'] == 'Bearer synthetic-token'
    assert calls[0]['closed'] is True


@pytest.mark.parametrize('suffix', ['/stages/validate', '/continue-validation'])
def test_response_loss_closes_once_without_replay(transport, suffix):
    client, calls, failure = transport
    failure[0] = True
    with pytest.raises(opaf.OpafError, match='Reconcile the existing job before retrying'):
        client.request('POST', BASE + suffix, {'request': 'synthetic'})
    assert len(calls) == 1 and calls[0]['timeout'] == 1080
    assert calls[0]['closed'] is True
