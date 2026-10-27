"""Local-only preparation contract: synthetic bytes, fake native tools, no listener."""
import asyncio
from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import threading
import unittest
from unittest.mock import patch

from fastapi import FastAPI, HTTPException
from fastapi.testclient import TestClient

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from fox import local_preparation as local
from fox.prepared_source import UPLOAD_MANIFEST_NAME, verify_upload_manifest
from fox.intake import checked_source


ORIGIN = 'http://127.0.0.1:8100'
XML = b'<Module><FormModule Name="SYNTHETIC"/></Module>'


class FakeNative:
    """Not real binary extraction or Oracle compatibility evidence."""
    name = 'FAKE-UNIT-TEST-ONLY'

    def __init__(self):
        self.calls = []

    def check(self):
        return {'formats': sorted(local.extractor.BINARY), 'private_path': '/must-not-leak'}

    def extract(self, source, destination):
        self.calls.append((source.suffix.lower(), source.read_bytes()))
        output = destination / (source.stem + '_' + source.suffix[1:] + '.xml')
        output.write_bytes(XML)
        return output


@contextmanager
def application(backend=None, *, root_units=None, private=False):
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        if root_units is not None:
            padding = root_units - len(str(root).encode('utf-16-le')) // 2 - 1
            assert 0 < padding < 240
            root = root / ('r' * padding)
            root.mkdir()
        if private:
            from fox.local_security import protect_new_directory
            protect_new_directory(root)
        app = FastAPI()
        calls = []

        def owner(request):
            calls.append('auth')
            value = request.cookies.get('synthetic-session')
            if value not in {'alice', 'bob'}:
                raise HTTPException(401, 'Secret callback diagnostic must not leak.')
            return value

        service = local.register_local_preparation(app, root, owner, backend, origin=ORIGIN)
        with TestClient(app, base_url=ORIGIN, client=('127.0.0.1', 50000),
                        cookies={'synthetic-session': 'alice'}) as client:
            yield client, service, root, calls


def upload(client, files=None, **kwargs):
    return client.post(local.PREFIX + '/jobs', headers={'Origin': ORIGIN},
                       files=files or [('files', ('demo.xml', XML, 'application/octet-stream'))], **kwargs)


def completed(client, service, response):
    if response.status_code != 202:
        raise AssertionError(response.text)
    service._future.result(timeout=5)
    result = client.get(local.PREFIX + '/jobs/' + response.json()['job_id'])
    if result.status_code != 200:
        raise AssertionError(result.text)
    return result.json()


class LocalPreparationTests(unittest.TestCase):
    @unittest.skipUnless(os.name == 'nt', 'Actual Windows shallow layout and DACL regression')
    def test_actual_default_length_private_layout_readable_fake_native_and_malformed(self):
        from fox.local_security import verify_private
        backend = FakeNative()
        with application(backend, root_units=153, private=True) as (client, service, root, _):
            old = root / 'local-preparation' / 'retained-old-evidence'
            old.mkdir(parents=True)
            (old / 'sentinel.txt').write_bytes(b'old-failed-proof-remains')
            readable = completed(client, service, upload(client, [('files', ('notes.txt', b'\xef\xbb\xbfSynthetic\r\n'))]))
            self.assertEqual(readable['state'], 'PREPARED_REVIEW_REQUIRED')
            job = service._jobs[readable['job_id']]
            self.assertEqual(job.directory, root / 'i' / job.identifier)
            self.assertEqual(job.prepared, root / 'p' / job.identifier)
            self.assertEqual(len(str(job.prepared / 'ready' / UPLOAD_MANIFEST_NAME)), 224)
            public = json.loads((job.prepared / 'ready' / UPLOAD_MANIFEST_NAME).read_bytes())
            self.assertEqual(public['extraction_job_id'], job.identifier)
            self.assertEqual((job.directory / 's/notes.txt').read_bytes(), b'\xef\xbb\xbfSynthetic\r\n')
            self.assertEqual((job.prepared / 'ready/notes.txt').read_bytes(), b'\xef\xbb\xbfSynthetic\r\n')
            selected = [('files', ('module' + ext, b'FAKE ONLY')) for ext in ('.fmb', '.mmb', '.olb', '.pll')]
            native = completed(client, service, upload(client, selected))
            self.assertEqual(native['state'], 'PREPARED_REVIEW_REQUIRED')
            self.assertEqual(len(backend.calls), 4)
            malformed = completed(client, service, upload(client, [('files', ('bad.xml', b'<bad'))]))
            self.assertEqual(malformed['state'], 'BLOCKED')
            self.assertEqual(malformed['code'], 'LOCAL_PREPARATION_FAILED')
            self.assertTrue((root / 'p' / malformed['job_id'] / 'status.json').is_file())
            self.assertEqual((old / 'sentinel.txt').read_bytes(), b'old-failed-proof-remains')
            verify_private(root)

    @unittest.skipUnless(os.name == 'nt', 'Windows path budget boundary')
    def test_path_budget_returns_fixed_422_before_staging_and_allows_correction(self):
        backend = FakeNative()
        with application(backend, root_units=153) as (client, service, root, _):
            for name in ('r' * 37 + '.txt', 'b' * 33 + '.fmb'):
                response = upload(client, [('files', (name, b'Synthetic'))])
                self.assertEqual(response.status_code, 422)
                self.assertEqual(response.json(), {'detail': {'code': 'LOCAL_PATH_BUDGET_EXCEEDED',
                    'message': local.extractor.PATH_BUDGET_MESSAGE}})
                self.assertFalse(any((root / name).exists() for name in ('i', 'p')))
                self.assertEqual(service._jobs, {})
                self.assertIsNone(service._future)
                self.assertEqual(backend.calls, [])
                self.assertFalse(service._busy)
            boundary = completed(client, service, upload(client, [('files', ('r' * 36 + '.txt', b'Synthetic'))]))
            self.assertEqual(boundary['state'], 'PREPARED_REVIEW_REQUIRED')
            native = completed(client, service, upload(client, [('files', ('b' * 32 + '.fmb', b'FAKE ONLY'))]))
            self.assertEqual(native['state'], 'PREPARED_REVIEW_REQUIRED')

    def test_feature_is_absent_unless_explicitly_registered(self):
        with TestClient(FastAPI(), base_url=ORIGIN) as client:
            self.assertEqual(client.get(local.PREFIX + '/capabilities').status_code, 404)
        for origin in ('http://0.0.0.0:8100', 'https://127.0.0.1:8100', 'http://localhost:8100',
                       ORIGIN + '/path', 'http://u:p@127.0.0.1:8100', ORIGIN + '?token=secret'):
            with self.subTest(origin=origin), self.assertRaises(ValueError):
                local.register_local_preparation(FastAPI(), Path('.'), lambda _: 'alice', origin=origin)

    def test_capabilities_are_presence_only_and_do_not_expose_paths(self):
        with application(FakeNative()) as (client, service, root, _):
            value = client.get(local.PREFIX + '/capabilities').json()
            self.assertEqual(value['native_formats'], ['.fmb', '.mmb', '.olb', '.pll'])
            self.assertFalse(value['native_extraction_verified'])
            self.assertFalse(value['automatic_upload'])
            self.assertFalse(value['conversion_available'])
            self.assertNotIn('/must-not-leak', json.dumps(value))
            self.assertFalse(any((root / name).exists() for name in ('i', 'p')))

    def test_auth_origin_host_and_peer_fail_before_body_consumption_or_staging(self):
        with application() as (client, service, root, calls):
            client.cookies.clear()
            denied = upload(client)
            self.assertEqual(denied.status_code, 401)
            self.assertNotIn('Secret callback diagnostic', denied.text)
            client.cookies.set('synthetic-session', 'alice')
            for headers in ({'Origin': 'https://foreign.invalid'}, {'Origin': ORIGIN, 'Host': 'foreign.invalid'}, {}):
                response = client.post(local.PREFIX + '/jobs', headers=headers,
                                       files=[('files', ('demo.xml', XML))])
                self.assertEqual(response.status_code, 403)
            self.assertEqual(client.get(local.PREFIX + '/capabilities', headers={'Origin': 'https://foreign.invalid'}).status_code, 403)
            self.assertFalse(any((root / name).exists() for name in ('i', 'p')))

            async def attempt(peer, headers):
                received = []
                async def receive():
                    raise AssertionError('Denied request must not consume a body')
                async def send(message):
                    received.append(message)
                scope = {'type': 'http', 'http_version': '1.1', 'method': 'POST',
                         'scheme': 'http', 'path': local.PREFIX + '/jobs', 'raw_path': b'/api/local-preparation/jobs',
                         'root_path': '', 'query_string': b'', 'headers': headers,
                         'client': (peer, 50000), 'server': ('127.0.0.1', 8100)}
                await client.app(scope, receive, send)
                return received[0]['status']
            good = [(b'host', b'127.0.0.1:8100'), (b'origin', ORIGIN.encode()), (b'cookie', b'synthetic-session=alice')]
            self.assertEqual(asyncio.run(attempt('192.0.2.1', good)), 403)
            self.assertEqual(asyncio.run(attempt('127.0.0.1', good + [(b'host', b'127.0.0.1:8100')])), 403)
            self.assertEqual(asyncio.run(attempt('127.0.0.1', good[:-1])), 401)

    def test_readable_bom_crlf_exact_files_and_review_required_no_side_effects(self):
        raw = b'\xef\xbb\xbfSynthetic note\r\nSecond line\r\n'
        with application() as (client, service, root, _), \
             patch.object(socket, 'create_connection', side_effect=AssertionError('no network')), \
             patch.object(subprocess, 'Popen', side_effect=AssertionError('no process')):
            result = completed(client, service, upload(client, [('files', ('notes.txt', raw))]))
            self.assertEqual(result['state'], 'PREPARED_REVIEW_REQUIRED')
            self.assertFalse(result['approved_for_upload'])
            self.assertFalse(result['automatic_upload'])
            self.assertFalse(result['conversion_started'])
            self.assertNotIn(str(root), json.dumps(result))
            returned = {}
            for item in result['files']:
                response = client.get(f"{local.PREFIX}/jobs/{result['job_id']}/files/{item['file_id']}")
                self.assertEqual(response.status_code, 200)
                self.assertEqual(response.headers['cache-control'], 'no-store')
                self.assertEqual(hashlib.sha256(response.content).hexdigest(), item['sha256'])
                returned[item['name']] = response.content
            self.assertEqual(returned['notes.txt'], raw)
            verify_upload_manifest(returned[UPLOAD_MANIFEST_NAME], [checked_source('notes.txt', raw)])
            self.assertFalse((root / 'fox.sqlite3').exists())
            self.assertEqual(set(returned), {'notes.txt', UPLOAD_MANIFEST_NAME})

    def test_all_four_fake_native_formats_use_existing_extractor(self):
        backend = FakeNative()
        selected = [('files', ('module' + ext, b'FAKE ONLY ' + ext.encode())) for ext in ('.fmb', '.mmb', '.olb', '.pll')]
        with application(backend) as (client, service, _, _), \
             patch.object(subprocess, 'Popen', side_effect=AssertionError('no real Oracle execution')):
            result = completed(client, service, upload(client, selected))
            self.assertEqual(result['state'], 'PREPARED_REVIEW_REQUIRED')
            self.assertEqual({call[0] for call in backend.calls}, local.extractor.BINARY)
            self.assertEqual({item['name'] for item in result['files']},
                             {'module_fmb.xml', 'module_mmb.xml', 'module_olb.xml', 'module_pll.xml', UPLOAD_MANIFEST_NAME})

    def test_missing_native_tools_block_before_staging_but_readable_still_works(self):
        with application() as (client, service, root, _):
            self.assertEqual(upload(client, [('files', ('module.fmb', b'fake'))]).status_code, 409)
            self.assertFalse(any((root / name).exists() for name in ('i', 'p')))
            self.assertEqual(completed(client, service, upload(client))['state'], 'PREPARED_REVIEW_REQUIRED')

    def test_rejects_paths_archives_fields_empty_and_case_collisions_before_staging(self):
        cases = [[('files', ('../sentinel.txt', b'bytes'))], [('files', ('C:\\sentinel.txt', b'bytes'))],
                 [('files', ('source.zip', b'archive'))], [('files', ('CON.txt', b'bytes'))],
                 [('files', ('empty.xml', b''))], [('files', ('A.xml', XML)), ('files', ('a.xml', XML))],
                 [('files', ('demo.xml', XML)), ('oracle_home', (None, 'C:/secret'))]]
        with application() as (client, _, root, _):
            for selection in cases:
                with self.subTest(names=[item[1][0] for item in selection]):
                    self.assertIn(upload(client, selection).status_code, (400, 413, 422))
                    self.assertFalse(any((root / name).exists() for name in ('i', 'p')))

    def test_declared_and_actual_streamed_envelope_are_bounded_before_staging(self):
        with application() as (client, _, root, _), patch.object(local, 'MAX_REQUEST_BYTES', 100):
            response = client.post(local.PREFIX + '/jobs', headers={'Origin': ORIGIN,
                'Content-Type': 'multipart/form-data; boundary=x', 'Content-Length': '101'}, content=b'x')
            self.assertEqual(response.status_code, 413)
            response = client.post(local.PREFIX + '/jobs', headers={'Origin': ORIGIN,
                'Content-Type': 'multipart/form-data; boundary=x', 'Content-Length': '1'},
                content=iter([b'x' * 60, b'y' * 60]))
            self.assertEqual(response.status_code, 413)
            response = client.post(local.PREFIX + '/jobs', headers={'Origin': ORIGIN,
                'Content-Type': 'multipart/form-data; boundary=x'}, content=iter([b'x' * 60, b'y' * 60]))
            self.assertEqual(response.status_code, 413)
            self.assertFalse(any((root / name).exists() for name in ('i', 'p')))

    def test_file_count_per_file_and_selected_total_limits(self):
        with application() as (client, _, root, _):
            with patch.object(local, 'MAX_FILES', 1):
                self.assertIn(upload(client, [('files', ('a.txt', b'a')), ('files', ('b.txt', b'b'))]).status_code, (400, 413, 422))
            with patch.object(local, 'MAX_FILE_BYTES', 3):
                self.assertEqual(upload(client, [('files', ('a.txt', b'abcd'))]).status_code, 413)
            with patch.object(local, 'MAX_SELECTED_BYTES', 3):
                self.assertEqual(upload(client, [('files', ('a.txt', b'ab')), ('files', ('b.txt', b'cd'))]).status_code, 413)
            self.assertFalse(any((root / name).exists() for name in ('i', 'p')))

    def test_owner_isolation_private_files_and_arbitrary_paths_are_not_served(self):
        with application() as (client, service, root, _):
            sentinel = root / 'unrelated.txt'
            sentinel.write_bytes(b'never-serve-secret')
            result = completed(client, service, upload(client))
            route = f"{local.PREFIX}/jobs/{result['job_id']}"
            client.cookies.set('synthetic-session', 'bob')
            self.assertEqual(client.get(route).status_code, 404)
            self.assertEqual(client.get(route + '/files/' + result['files'][0]['file_id']).status_code, 404)
            client.cookies.set('synthetic-session', 'alice')
            for name in ('manifest.json', 'local-status.json', 'demo.xml', 'inputs', 'file-' + '0' * 32):
                response = client.get(route + '/files/' + name)
                self.assertIn(response.status_code, (404, 409))
                self.assertNotIn('never-serve-secret', response.text)
            self.assertEqual(sentinel.read_bytes(), b'never-serve-secret')
            self.assertFalse(client.get('/api/projects').status_code == 200)

    def test_failure_is_sanitized_and_partial_native_output_is_unavailable(self):
        class Failing(FakeNative):
            def extract(self, source, destination):
                (destination / 'partial.xml').write_bytes(XML)
                raise RuntimeError('sensitive source or Oracle diagnostic never-echo')
        with application(Failing()) as (client, service, _, _):
            result = completed(client, service, upload(client, [('files', ('module.fmb', b'fake'))]))
            self.assertEqual(result['state'], 'BLOCKED')
            self.assertEqual(result['files'], [])
            self.assertNotIn('never-echo', json.dumps(result))
            self.assertEqual(client.get(f"{local.PREFIX}/jobs/{result['job_id']}/files/file-{'0' * 32}").status_code, 409)

    def test_changed_outputs_and_added_private_members_block_release(self):
        with application() as (client, service, _, _):
            first = completed(client, service, upload(client))
            job = service._jobs[first['job_id']]
            (job.prepared / 'ready' / 'demo.xml').write_bytes(b'changed')
            response = client.get(f"{local.PREFIX}/jobs/{first['job_id']}/files/{first['files'][0]['file_id']}")
            self.assertEqual(response.status_code, 409)
            self.assertNotIn('changed', response.content.decode().replace('Prepared output changed or is unavailable; do not reuse it.', ''))
            second = completed(client, service, upload(client))
            job2 = service._jobs[second['job_id']]
            (job2.prepared / 'ready' / 'private.txt').write_bytes(b'never-serve')
            self.assertEqual(client.get(f"{local.PREFIX}/jobs/{second['job_id']}").status_code, 409)

    def test_one_active_worker_no_duplicate_dispatch_and_no_automatic_retry(self):
        started, finish = threading.Event(), threading.Event()
        class Waiting(FakeNative):
            def extract(self, source, destination):
                started.set()
                if not finish.wait(5):
                    raise RuntimeError('test wait timed out')
                return super().extract(source, destination)
        backend = Waiting()
        with application(backend) as (client, service, _, _):
            first = upload(client, [('files', ('module.fmb', b'fake'))])
            try:
                self.assertTrue(started.wait(2))
                self.assertEqual(first.status_code, 202)
                self.assertEqual(upload(client).status_code, 409)
                self.assertEqual(client.get(f"{local.PREFIX}/jobs/{first.json()['job_id']}").json()['state'], 'RUNNING')
            finally:
                finish.set()
            self.assertEqual(completed(client, service, first)['state'], 'PREPARED_REVIEW_REQUIRED')
            self.assertEqual(len(backend.calls), 1)
            self.assertEqual(len(service._jobs), 1)

    def test_duplicate_registration_and_closed_service_reject_without_more_work(self):
        with application() as (client, service, root, _):
            with self.assertRaises(ValueError):
                local.register_local_preparation(client.app, root, lambda _: 'alice')
            service.close()
            self.assertEqual(upload(client).status_code, 503)
            self.assertFalse(any((root / name).exists() for name in ('i', 'p')))


if __name__ == '__main__':
    unittest.main()
