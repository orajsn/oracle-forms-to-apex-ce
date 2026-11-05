"""Real local API/extractor integration; synthetic sources and fake native tools only.

Not Oracle binary extraction, provider execution or native APEX proof. Tests share
the existing authenticated localhost fixture, not a fabricated service result.
"""
import asyncio
import hashlib
import json
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import threading
import unittest
from unittest.mock import patch
from xml.sax.saxutils import quoteattr

from fastapi import FastAPI
from fastapi.testclient import TestClient

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parent))
from fox import extractor, local_preparation as local
from fox.prepared_source import UPLOAD_MANIFEST_NAME
from test_local_preparation import ORIGIN, FakeNative, application, completed


def synthetic_xml(blocks):
    code = ("UPDATE SYN_ORDERS SET AMOUNT = 42, STATUS = 'OPEN' WHERE ID = :B0.ID; "
            "INSERT INTO SYN_AUDIT (ID, NOTE) VALUES (:B0.ID, 'DELETE FROM NOT_REAL is text'); "
            "SYN_API.SAVE(:B0.ID);")
    body = ''.join(f'<Block Name="B{i}" DatabaseBlock="{str(i % 2 == 0).lower()}">'
                   f'<Item Name="ID" DatabaseItem="true" ItemType="Text Item"/>'
                   f'<Trigger Name="SAVE" TriggerText={quoteattr(code)}/></Block>'
                   for i in range(blocks))
    return f'<Module><FormModule Name="SYNTHETIC">{body}</FormModule></Module>'.encode()


class SyntheticNative(FakeNative):
    def __init__(self, raw):
        super().__init__()
        self.raw = raw

    def extract(self, source, destination):
        self.calls.append((source.suffix.lower(), source.read_bytes()))
        output = destination / (source.stem + '_' + source.suffix[1:] + '.xml')
        output.write_bytes(self.raw)
        return output


def assess(client, selected=None, headers=None):
    return client.post(local.PREFIX + '/assessments', headers={'Origin': ORIGIN} if headers is None else headers,
                       files=selected if selected is not None else [('files', ('synthetic.xml', synthetic_xml(9)))])


def fetch(client, job_id):
    return client.get(f'{local.PREFIX}/jobs/{job_id}/assessment')


class LocalFormsAssessmentTests(unittest.TestCase):
    def assert_local_only(self, result):
        self.assertEqual(result['state'], 'ASSESSED_LOCAL_ONLY')
        self.assertEqual(result['code'], 'LOCAL_FACTS_AVAILABLE')
        self.assertTrue(result['assessment_available'])
        self.assertEqual(result['files'], [])
        for key in ('approved_for_upload', 'automatic_upload', 'conversion_started'):
            self.assertFalse(result[key], key)

    def assert_envelope(self, payload, job_id):
        self.assertEqual(payload['schema_version'], 1)
        self.assertEqual(payload['scope'], 'fox-local-forms-assessment-v1')
        self.assertEqual(payload['job_id'], job_id)
        self.assertEqual(payload['status'], 'ASSESSED_LOCAL_ONLY')
        for key in ('raw_files_uploaded', 'network_calls', 'model_calls', 'conversion_started'):
            self.assertIs(payload[key], False, key)

    def test_route_is_absent_without_explicit_local_registration(self):
        with TestClient(FastAPI(), base_url=ORIGIN) as client:
            self.assertEqual(assess(client).status_code, 404)

    def test_real_local_api_inventories_9_and_51_blocks_and_dml_without_inference(self):
        for count in (9, 51):
            with self.subTest(blocks=count), application() as (client, service, root, _), \
                 patch.object(socket, 'create_connection', side_effect=AssertionError('no network')), \
                 patch.object(subprocess, 'Popen', side_effect=AssertionError('no native/provider process')):
                raw = synthetic_xml(count)
                result = completed(client, service, assess(client, [('files', ('synthetic.xml', raw))]))
                self.assert_local_only(result)
                response = fetch(client, result['job_id'])
                self.assertEqual(response.status_code, 200, response.text)
                self.assertEqual(response.headers['cache-control'], 'no-store')
                self.assertEqual(hashlib.sha256(response.content).hexdigest(), result['assessment_sha256'])
                payload = response.json()
                self.assert_envelope(payload, result['job_id'])
                facts = payload['files'][0]['facts']
                self.assertEqual(facts['totals']['blocks'], count)
                self.assertEqual(facts['totals']['items'], count)
                self.assertEqual(facts['totals']['triggers'], count)
                self.assertEqual({block['classification'] for block in facts['blocks']}, {'database', 'control'})
                names = {row['name'] for row in facts['dependencies']}
                self.assertTrue({'SYN_ORDERS', 'SYN_AUDIT', 'SYN_API.SAVE'} <= names)
                self.assertNotIn('NOT_REAL', names)
                self.assertEqual(facts['assessment_status'], 'LOCAL_FACTS_ONLY')
                self.assertFalse(facts['safety']['model_submission_allowed'])
                self.assertFalse(facts['safety']['native_generation_allowed'])
                self.assertFalse(facts['safety']['code_executed'])
                self.assertTrue(facts['findings'])
                self.assertEqual(payload['files'][0]['source']['sha256'], hashlib.sha256(raw).hexdigest())
                self.assertEqual(payload['files'][0]['readable']['sha256'], hashlib.sha256(raw).hexdigest())
                artifact = service._jobs[result['job_id']].prepared / 'assessment.json'
                self.assertEqual(response.content, artifact.read_bytes())
                self.assertFalse(list(root.rglob(UPLOAD_MANIFEST_NAME)))
                self.assertFalse(list(root.rglob('ready')))
                self.assertFalse((root / 'fox.sqlite3').exists())
                self.assertNotIn(str(root), response.text)
                self.assertNotIn("STATUS = 'OPEN'", response.text)

    def test_fake_fmb_extracts_once_and_supporting_sources_are_retained_not_assumed_understood(self):
        raw = synthetic_xml(9)
        backend = SyntheticNative(raw)
        selected = [('files', ('module.fmb', b'SYNTHETIC FMB NOT ORACLE BINARY')),
                    ('files', ('schema.sql', b'CREATE TABLE SYN_ORDERS (ID NUMBER);')),
                    ('files', ('library.pld', b'PROCEDURE synthetic_only IS BEGIN NULL; END;'))]
        with application(backend) as (client, service, root, _):
            result = completed(client, service, assess(client, selected))
            self.assert_local_only(result)
            self.assertEqual(len(backend.calls), 1)
            payload = fetch(client, result['job_id']).json()
            self.assertEqual(len(payload['files']), 1)
            self.assertEqual(payload['files'][0]['facts']['totals']['blocks'], 9)
            self.assertEqual(payload['files'][0]['source']['name'], 'module.fmb')
            self.assertEqual(payload['files'][0]['readable']['sha256'], hashlib.sha256(raw).hexdigest())
            unassessed = {row['name']: row for row in payload['unassessed_sources']}
            self.assertEqual(set(unassessed), {'schema.sql', 'library.pld'})
            self.assertTrue(all(row['reason'] for row in unassessed.values()))
            staged = service._jobs[result['job_id']].directory / 's'
            for _, (name, content) in selected:
                self.assertEqual((staged / name).read_bytes(), content)
            self.assertFalse(list(root.rglob(UPLOAD_MANIFEST_NAME)))
            # Local facts cannot be fetched through the old approved-readable route.
            response = client.get(f"{local.PREFIX}/jobs/{result['job_id']}/files/file-{'a' * 32}")
            self.assertNotEqual(response.status_code, 200)

    def test_authentication_origin_host_and_peer_gate_assessment_before_body_or_staging(self):
        with application() as (client, service, root, _):
            client.cookies.clear()
            denied = assess(client)
            self.assertEqual(denied.status_code, 401)
            self.assertNotIn('Secret callback', denied.text)
            client.cookies.set('synthetic-session', 'alice')
            for headers in ({}, {'Origin': 'https://foreign.invalid'}, {'Origin': ORIGIN, 'Host': 'foreign.invalid'}):
                self.assertEqual(assess(client, headers=headers).status_code, 403)
            async def attempt():
                sent = []
                async def receive():
                    raise AssertionError('Forbidden request must not consume source bytes')
                async def send(message):
                    sent.append(message)
                path = local.PREFIX + '/assessments'
                scope = {'type': 'http', 'http_version': '1.1', 'method': 'POST', 'scheme': 'http',
                         'path': path, 'raw_path': path.encode(), 'root_path': '', 'query_string': b'',
                         'headers': [(b'host', b'127.0.0.1:8100'), (b'origin', ORIGIN.encode()),
                                     (b'cookie', b'synthetic-session=alice')],
                         'client': ('192.0.2.1', 50000), 'server': ('127.0.0.1', 8100)}
                await client.app(scope, receive, send)
                return sent[0]['status']
            self.assertEqual(asyncio.run(attempt()), 403)
            self.assertEqual(service._jobs, {})
            self.assertFalse(any((root / name).exists() for name in ('i', 'p')))

    def test_owner_isolation_for_status_and_exact_assessment(self):
        with application() as (client, service, _, _):
            result = completed(client, service, assess(client))
            client.cookies.set('synthetic-session', 'bob')
            self.assertEqual(fetch(client, result['job_id']).status_code, 404)
            self.assertEqual(client.get(f"{local.PREFIX}/jobs/{result['job_id']}").status_code, 404)
            client.cookies.clear()
            self.assertEqual(fetch(client, result['job_id']).status_code, 401)

    def test_native_capability_and_file_parser_fail_before_staging(self):
        cases = [[('files', ('../bad.xml', synthetic_xml(9)))], [('files', ('bad.zip', b'archive'))],
                 [('files', ('empty.xml', b''))], [('files', ('A.xml', synthetic_xml(9))), ('files', ('a.xml', synthetic_xml(9)))],
                 [('files', ('demo.xml', synthetic_xml(9))), ('oracle_home', (None, 'C:/private'))]]
        with application() as (client, service, root, _):
            self.assertEqual(assess(client, [('files', ('module.fmb', b'fake'))]).status_code, 409)
            capabilities = client.get(local.PREFIX + '/capabilities').json()
            self.assertTrue(capabilities['forms_assessment_available'])
            self.assertFalse(capabilities['conversion_available'])
            self.assertFalse(capabilities['automatic_upload'])
            self.assertFalse(capabilities['native_extraction_verified'])
            for selected in cases:
                self.assertIn(assess(client, selected).status_code, (400, 413, 422))
            self.assertEqual(service._jobs, {})
            self.assertFalse(any((root / name).exists() for name in ('i', 'p')))

    def test_malformed_unsafe_and_secret_sources_block_with_safe_fixed_diagnostic(self):
        for raw in (b'<bad', b'<!DOCTYPE Module [<!ENTITY x "bad">]><Module>&x;</Module>',
                    b'<Module><FormModule Name="SYN"><Trigger Name="T" TriggerText="pwd := \'SENSITIVE-SYNTHETIC\';"/></FormModule></Module>'):
            with self.subTest(raw=raw[:10]), application() as (client, service, root, _):
                result = completed(client, service, assess(client, [('files', ('bad.xml', raw))]))
                self.assertEqual(result['state'], 'BLOCKED')
                self.assertEqual(result['code'], 'LOCAL_ASSESSMENT_FAILED')
                self.assertFalse(result['assessment_available'])
                self.assertEqual(result['files'], [])
                self.assertNotIn('SENSITIVE-SYNTHETIC', json.dumps(result))
                self.assertNotIn(str(root), json.dumps(result))
                self.assertNotEqual(fetch(client, result['job_id']).status_code, 200)
                self.assertFalse(list(root.rglob(UPLOAD_MANIFEST_NAME)))

    def test_source_readable_and_assessment_tamper_block_status_and_download(self):
        for target_kind in ('source', 'readable', 'assessment', 'input-bindings'):
            with self.subTest(target=target_kind), application(SyntheticNative(synthetic_xml(9))) as (client, service, _, _):
                result = completed(client, service, assess(client, [('files', ('module.fmb', b'SYNTHETIC'))]))
                job = service._jobs[result['job_id']]
                if target_kind == 'assessment':
                    target = job.prepared / 'assessment.json'
                elif target_kind == 'input-bindings':
                    target = job.prepared / 'assessment-inputs.json'
                elif target_kind == 'source':
                    target = job.directory / 's' / 'module.fmb'
                else:
                    candidates = list(job.prepared.rglob('module_fmb.xml'))
                    self.assertEqual(len(candidates), 1)
                    target = candidates[0]
                target.write_bytes(target.read_bytes() + b' ')
                status = client.get(f"{local.PREFIX}/jobs/{result['job_id']}")
                self.assertEqual(status.status_code, 409)
                self.assertNotEqual(fetch(client, result['job_id']).status_code, 200)
                later = client.get(f"{local.PREFIX}/jobs/{result['job_id']}")
                self.assertEqual(later.json()['state'], 'BLOCKED')
                self.assertFalse(later.json()['assessment_available'])

    def test_shared_reservation_running_status_and_no_automatic_replay(self):
        started, finish = threading.Event(), threading.Event()
        class Waiting(SyntheticNative):
            def extract(self, source, destination):
                started.set()
                if not finish.wait(5):
                    raise RuntimeError('synthetic test wait timed out')
                return super().extract(source, destination)
        backend = Waiting(synthetic_xml(9))
        with application(backend) as (client, service, _, _):
            first = assess(client, [('files', ('module.fmb', b'SYNTHETIC'))])
            try:
                self.assertEqual(first.status_code, 202, first.text)
                self.assertTrue(started.wait(2))
                self.assertEqual(client.get(f"{local.PREFIX}/jobs/{first.json()['job_id']}").json()['state'], 'RUNNING')
                self.assertEqual(assess(client).status_code, 409)
                self.assertEqual(client.post(local.PREFIX + '/jobs', headers={'Origin': ORIGIN},
                                            files=[('files', ('x.xml', synthetic_xml(9)))]).status_code, 409)
                self.assertNotEqual(fetch(client, first.json()['job_id']).status_code, 200)
            finally:
                finish.set()
            result = completed(client, service, first)
            self.assert_local_only(result)
            for _ in range(2):
                self.assertEqual(fetch(client, result['job_id']).status_code, 200)
            self.assertEqual(len(backend.calls), 1)
            self.assertEqual(len(service._jobs), 1)

    def test_related_unassessed_source_tamper_also_invalidates_assessment(self):
        selected = [('files', ('synthetic.xml', synthetic_xml(9))),
                    ('files', ('schema.sql', b'CREATE TABLE SYN_ORDERS (ID NUMBER);'))]
        with application() as (client, service, _, _):
            result = completed(client, service, assess(client, selected))
            job = service._jobs[result['job_id']]
            (job.directory / 's' / 'schema.sql').write_bytes(b'CHANGED SYNTHETIC RELATED SOURCE')
            response = fetch(client, result['job_id'])
            self.assertEqual(response.status_code, 409)
            later = client.get(f"{local.PREFIX}/jobs/{result['job_id']}").json()
            self.assertEqual(later['state'], 'BLOCKED')
            self.assertEqual(later['code'], 'ASSESSMENT_OUTPUT_CHANGED')
            self.assertFalse(later['assessment_available'])

    def test_original_change_between_extractor_and_service_binding_is_not_rebound_as_current(self):
        actual_assess = extractor.assess
        def change_after_assessment(source, *args, **kwargs):
            job = actual_assess(source, *args, **kwargs)
            # Exercise the real extraction result followed by a source race,
            # not a fake assessment JSON or mocked fact-reader success.
            (source / 'synthetic.xml').write_bytes(synthetic_xml(51))
            return job
        with application() as (client, service, root, _), \
             patch.object(extractor, 'assess', side_effect=change_after_assessment):
            result = completed(client, service, assess(client))
            self.assertEqual(result['state'], 'BLOCKED')
            self.assertEqual(result['code'], 'LOCAL_ASSESSMENT_FAILED')
            self.assertFalse(result['assessment_available'])
            self.assertNotEqual(fetch(client, result['job_id']).status_code, 200)
            self.assertFalse(list(root.rglob(UPLOAD_MANIFEST_NAME)))

    def test_extractor_direct_assessment_is_create_only_and_not_prepare_or_ready(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / 's'
            source.mkdir()
            raw = synthetic_xml(9)
            (source / 'synthetic.xml').write_bytes(raw)
            with patch.object(extractor, 'prepare', side_effect=AssertionError('assessment is not preparation')):
                job = extractor.assess(source, root / 'p')
            payload = json.loads((job / 'assessment.json').read_bytes())
            self.assertEqual(payload['files'][0]['facts']['totals']['blocks'], 9)
            self.assert_envelope(payload, payload['job_id'])
            self.assertEqual((source / 'synthetic.xml').read_bytes(), raw)
            self.assertFalse(list(job.rglob(UPLOAD_MANIFEST_NAME)))
            self.assertFalse((job / 'ready').exists())
            before = (job / 'assessment.json').read_bytes()
            with self.assertRaises((ValueError, FileExistsError)):
                extractor.assess(source, root / 'p', job_id=payload['job_id'])
            self.assertEqual((job / 'assessment.json').read_bytes(), before)


if __name__ == '__main__':
    unittest.main()
