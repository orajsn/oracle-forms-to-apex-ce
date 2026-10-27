"""Real loopback transport only; synthetic requests are not conversion evidence."""
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, HTTPServer
import json
from pathlib import Path
import socket
import subprocess
import sys
import threading

import pytest

from fox.opaf import ConverterClient, OpafError


TOKEN = 'synthetic-loopback-test-token-not-a-credential'


def test_legacy_import_and_construction_do_not_load_fresh_projection_module():
    repository = Path(__file__).resolve().parents[1]
    program = r'''
import importlib.abc, json, sys
sys.path.insert(0, sys.argv[1])
class DenyFreshImport(importlib.abc.MetaPathFinder):
    def find_spec(self, fullname, path=None, target=None):
        if fullname == 'fox.installation':
            raise AssertionError('Legacy mode must not load an unmeasured fresh module')
sys.meta_path.insert(0, DenyFreshImport())
from fox.opaf import ConverterClient
client = ConverterClient('http://127.0.0.1:8091', 'synthetic-only-token')
assert client._port == 8091 and 'fox.installation' not in sys.modules
print(json.dumps({'legacy_port': client._port, 'fresh_module_loaded': False}))
'''
    result = subprocess.run([sys.executable, '-I', '-B', '-c', program, str(repository)],
                            capture_output=True, timeout=20, check=False)
    assert result.returncode == 0 and result.stderr == b''
    assert json.loads(result.stdout) == {'legacy_port': 8091, 'fresh_module_loaded': False}


def projection(endpoint):
    return {
        'schema_version': 1,
        'scope': 'fox-fresh-app-projection-v1',
        'installation_mode': 'fresh',
        'installation_id': 'fst-' + '1' * 32,
        'storage_plan_sha256': 'a' * 64,
        'storage_completion_sha256': 'b' * 64,
        'converter_endpoint': endpoint,
    }


@contextmanager
def loopback_server(*, status=200, body=b'{"ok":true}', disconnect=False):
    received = []

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            self.respond()

        def do_POST(self):
            self.respond()

        def respond(self):
            raw = self.rfile.read(int(self.headers.get('Content-Length', '0')))
            received.append({'method': self.command, 'path': self.path,
                             'headers': dict(self.headers), 'body': raw})
            if disconnect:
                self.close_connection = True
                self.connection.shutdown(socket.SHUT_RDWR)
                self.connection.close()
                return
            self.send_response(status)
            self.send_header('Content-Type', 'application/octet-stream')
            self.send_header('Content-Length', str(len(body)))
            self.end_headers()
            try:
                self.wfile.write(body)
            except (BrokenPipeError, ConnectionResetError, ConnectionAbortedError):
                # The bounded-response test deliberately closes before EOF.
                pass

        def log_message(self, *args):
            pass

    server = HTTPServer(('127.0.0.1', 0), Handler)
    thread = threading.Thread(target=server.serve_forever, kwargs={'poll_interval': 0.01}, daemon=True)
    thread.start()
    endpoint = f'http://127.0.0.1:{server.server_port}'
    try:
        yield endpoint, received
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
        assert not thread.is_alive(), 'Isolated loopback server did not terminate.'


@pytest.mark.parametrize('status', [200, 201])
def test_fresh_client_dials_projected_port_and_sends_exact_request(status):
    with loopback_server(status=status) as (endpoint, received):
        payload = {'job_id': 'synthetic-only', 'text': 'local fixture', 'count': 2}
        client = ConverterClient(endpoint, TOKEN, projection=projection(endpoint))
        assert client.request('POST', '/synthetic/jobs', payload) == {'ok': True}
        assert len(received) == 1
        request = received[0]
        assert request['method'] == 'POST'
        assert request['path'] == '/synthetic/jobs'
        assert request['headers']['Host'] == endpoint.removeprefix('http://')
        assert request['headers']['Authorization'] == 'Bearer ' + TOKEN
        assert request['headers']['Content-Type'] == 'application/json'
        assert request['body'] == json.dumps(payload).encode()


def test_binary_response_is_returned_exactly_without_json_parsing():
    raw = b'PK\x03\x04\x00\xff\xfe\r\nsynthetic-not-an-apex-package'
    with loopback_server(body=raw) as (endpoint, received):
        client = ConverterClient(endpoint, TOKEN, projection=projection(endpoint))
        assert client.request('GET', '/synthetic/package', binary=True) == raw
        assert len(received) == 1
        assert received[0]['body'] == b''
        assert received[0]['headers']['Authorization'] == 'Bearer ' + TOKEN


def test_binary_response_at_exact_size_limit_remains_accepted():
    raw = b'x' * 8_000_000
    with loopback_server(body=raw) as (endpoint, received):
        client = ConverterClient(endpoint, TOKEN, projection=projection(endpoint))
        assert client.request('GET', '/synthetic/size-boundary', binary=True) == raw
        assert len(received) == 1


@pytest.mark.parametrize('status', [301, 400, 401, 409, 500, 503])
@pytest.mark.parametrize('binary', [False, True])
def test_http_error_retains_status_and_never_replays(status, binary):
    with loopback_server(status=status, body=b'not json') as (endpoint, received):
        client = ConverterClient(endpoint, TOKEN, projection=projection(endpoint))
        with pytest.raises(OpafError, match='No automatic replay') as caught:
            client.request('POST', '/synthetic/no-replay', {'synthetic': True}, binary=binary)
        assert caught.value.status_code == status
        assert TOKEN not in str(caught.value)
        assert len(received) == 1


@pytest.mark.parametrize('binary', [False, True])
def test_oversized_response_fails_without_replay(binary):
    with loopback_server(body=b'x' * 8_000_001) as (endpoint, received):
        client = ConverterClient(endpoint, TOKEN, projection=projection(endpoint))
        with pytest.raises(OpafError, match='No automatic replay'):
            client.request('GET', '/synthetic/oversize', binary=binary)
        assert len(received) == 1


def test_transport_disconnect_is_not_retried():
    with loopback_server(disconnect=True) as (endpoint, received):
        client = ConverterClient(endpoint, TOKEN, projection=projection(endpoint))
        with pytest.raises(OpafError, match='Reconcile the existing job') as caught:
            client.request('POST', '/synthetic/uncertain', {'synthetic': True})
        assert caught.value.status_code is None
        assert TOKEN not in str(caught.value)
        assert len(received) == 1


def test_invalid_json_response_is_not_retried_or_silently_accepted():
    with loopback_server(body=b'not-json') as (endpoint, received):
        client = ConverterClient(endpoint, TOKEN, projection=projection(endpoint))
        # Existing transport contract surfaces JSON decoding errors directly.
        with pytest.raises(ValueError):
            client.request('GET', '/synthetic/invalid-json')
        assert len(received) == 1


def test_projection_is_snapshotted_and_not_reconsulted_after_client_construction():
    with loopback_server() as (endpoint, received):
        value = projection(endpoint)
        client = ConverterClient(endpoint, TOKEN, projection=value)
        value['converter_endpoint'] = 'http://127.0.0.1:65535'
        value['ready'] = True
        assert client.request('GET', '/synthetic/snapshot') == {'ok': True}
        assert len(received) == 1


@pytest.mark.parametrize('value', [None, {}, False, [], 'not-a-projection'])
def test_explicit_invalid_projection_cannot_fall_back_to_legacy(value):
    with pytest.raises(OpafError):
        ConverterClient('http://127.0.0.1:8091', TOKEN, projection=value)


@pytest.mark.parametrize('changes', [
    {'schema_version': True}, {'installation_mode': 'legacy'},
    {'storage_plan_sha256': 'A' * 64}, {'storage_completion_sha256': None},
    {'installation_id': 'fst-' + '1' * 31}, {'ready': True},
    {'credential_file': '/synthetic/forbidden'}, {'release_sha256': 'c' * 64},
])
def test_invalid_projection_rejects_before_any_local_request(changes):
    with loopback_server() as (endpoint, received):
        with pytest.raises(OpafError):
            ConverterClient(endpoint, TOKEN, projection={**projection(endpoint), **changes})
        assert received == []


def test_projected_url_must_match_exactly_without_url_normalization():
    with loopback_server() as (endpoint, received):
        value = projection(endpoint)
        candidates = [endpoint + '/', endpoint + '?', endpoint + '#',
                      endpoint.replace('127.0.0.1', 'localhost'),
                      endpoint.replace('http:', 'HTTP:'),
                      endpoint + '\n', 'http://127.0.0.1:8091']
        for candidate in candidates:
            if candidate == endpoint:
                continue
            with pytest.raises(OpafError):
                ConverterClient(candidate, TOKEN, projection=value)
        assert received == []


@pytest.mark.parametrize('url', ['http://127.0.0.1:8091', 'http://127.0.0.1:8091/'])
def test_omitted_projection_keeps_legacy_constructor_contract(url):
    # Constructor only: never bind to or contact a possibly live 8091 service.
    assert isinstance(ConverterClient(url, TOKEN), ConverterClient)


@pytest.mark.parametrize('url', [
    'http://127.0.0.1:8092', 'http://127.0.0.1:19091',
    'http://localhost:8091', 'https://127.0.0.1:8091',
    'http://u:p@127.0.0.1:8091', 'http://127.0.0.1:8091/path',
])
def test_omitted_projection_still_rejects_alternate_ports_and_origins(url):
    with pytest.raises(OpafError):
        ConverterClient(url, TOKEN)


def test_legacy_constructor_rejects_the_real_ephemeral_server_without_a_request():
    with loopback_server() as (endpoint, received):
        assert not endpoint.endswith(':8091')
        with pytest.raises(OpafError):
            ConverterClient(endpoint, TOKEN)
        assert received == []
