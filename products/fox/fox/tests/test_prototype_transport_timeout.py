"""Trusted stage wait selection, not a live latency or total-time guarantee."""
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
    ('GET', BASE + '/stages/validate', 1080),
    ('GET', BASE + '/continue-validation', 600),
    ('POST', BASE + '/validate-preclaim-witness', 600),
    ('POST', BASE + '/stages/import', 4800),
    ('POST', BASE + '/stages/export', 3600),
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


@pytest.mark.parametrize('stage,seconds', [('validate', 1080), ('prepare_schema', 2400),
    ('import', 4800), ('verify_runtime', 3600), ('export', 3600)])
@pytest.mark.parametrize('method', ['POST', 'GET'])
def test_all_exact_stage_paths_have_matching_post_get_waits(transport, stage, seconds, method):
    client, calls, _ = transport
    payload = {'stage': 'other', 'timeout': 0, 'timeout_seconds': 999999,
               'deadline_at_utc': '2099-01-01T00:00:00Z', 'untrusted_wait_seconds': 1}
    assert client.request(method, BASE + '/stages/' + stage, payload) == {'retained': True}
    assert len(calls) == 1 and calls[0]['timeout'] == seconds
    assert json.loads(calls[0]['body']) == payload and calls[0]['closed'] is True


@pytest.mark.parametrize('method', ['POST', 'GET'])
@pytest.mark.parametrize('path', [
    BASE + '/stages/unknown', BASE + '/stages/IMPORT', BASE + '/stages/import/',
    BASE + '/stages/import?timeout=9999', BASE + '/stages/import#fragment',
    BASE + '/stages/import/extra', BASE + '/stages/%69mport',
    BASE.replace(JOB, JOB.upper()) + '/stages/import',
    BASE.replace(JOB, JOB[:-1]) + '/stages/import',
    BASE.replace(JOB, JOB + 'a') + '/stages/import',
    '/prefix' + BASE + '/stages/import', BASE + '/stages/import\n',
    BASE + '/authority', BASE + '/validate-preclaim-witness',
    '/fox/prototype/capabilities', '/fox/jobs/' + JOB, None,
])
def test_malformed_or_unrelated_paths_keep_default_wait(transport, method, path):
    client, calls, _ = transport
    client.request(method, path, {'timeout': 99999, 'stage': 'import'})
    assert len(calls) == 1 and calls[0]['timeout'] == 600 and calls[0]['closed'] is True


@pytest.mark.parametrize('method', ['PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS', 'post', 'get'])
def test_other_methods_cannot_select_stage_or_continuation_budget(transport, method):
    client, calls, _ = transport
    for suffix in ('/stages/import', '/continue-validation'):
        client.request(method, BASE + suffix, {'timeout_seconds': 4800})
    assert len(calls) == 2 and all(row['timeout'] == 600 and row['closed'] is True for row in calls)


@pytest.mark.parametrize('stage,seconds', [('validate', 1080), ('prepare_schema', 2400),
    ('import', 4800), ('verify_runtime', 3600), ('export', 3600)])
@pytest.mark.parametrize('method', ['POST', 'GET'])
def test_each_stage_observation_loss_never_posts_retries_or_polls(transport, stage, seconds, method):
    client, calls, failure = transport
    failure[0] = True
    with pytest.raises(opaf.OpafError, match='Reconcile the existing job before retrying'):
        client.request(method, BASE + '/stages/' + stage, {'timeout_seconds': 1})
    assert len(calls) == 1 and calls[0]['timeout'] == seconds
    assert calls[0]['method'] == method and calls[0]['closed'] is True
