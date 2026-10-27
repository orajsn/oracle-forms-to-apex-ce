"""Local-only recovery bridge tests: fake observer/executor, temporary SQLite.

Real frozen backend validators run against independently built synthetic failed
evidence. No live journal, application import, subprocess, network or credential
reader is used. Reader capability checks are compatibility, not deployment proof.
"""
from contextlib import ExitStack, closing
from copy import deepcopy
from dataclasses import replace
from datetime import timedelta
from functools import partial
import gc
import importlib
import io
import json
from pathlib import Path
import socket
import sqlite3
import subprocess
import sys
import tempfile
import types
import unittest
from unittest.mock import Mock, patch

import pytest

ROOT = Path(__file__).resolve().parents[3]
for path in (ROOT, ROOT / 'fox', ROOT / 'fox/tests'):
    sys.path.insert(0, str(path))
from qa.operator import failure_recovery_transport as transport
from qa.operator import product_verifier as product
from qa.operator.failed_verification import FailureResolver, HeldOperatorLock
from fox import verification_recovery as recovery
from fox.verification_queue import Claim

SECRET = 'DoNotReturnCredentialsProviderOutputOrClaimTokens'
ClosedFailure = recovery.ClosedFailure


def incompatible_reader(run, legacy, closed=None, retry=None):
    return {'blocks_admission': False, 'recovery_state': 'failed_closed', 'retry_eligible': True}


class RecoveryTransportTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='fr-', dir=ROOT / 'work')
        self.addCleanup(self.temp.cleanup); self.addCleanup(gc.collect)
        self.root = Path(self.temp.name).resolve()
        self.mp = pytest.MonkeyPatch(); self.addCleanup(self.mp.undo)
        # The shared package fixtures need symbols from test_fox, not its app.
        # Forbid that transitive import from constructing fox.app/create_app.
        stub = types.ModuleType('test_fox')
        def forbidden(*args, **kwargs): raise AssertionError('LIVE_APP_FIXTURE_FORBIDDEN')
        stub.client = stub.signed_in = stub.project = forbidden
        self.modules = patch.dict(sys.modules, {'test_fox': stub}); self.modules.start(); self.addCleanup(self.modules.stop)
        self.fixture = importlib.import_module('test_verification_recovery')
        self.addCleanup(self.fixture._IMPORT.cleanup)
        self.fixture.no_external_actions.__wrapped__(self.mp)
        self.mp.setattr(socket, 'create_connection', forbidden)
        self.mp.setattr(socket.socket, 'connect', forbidden)
        self.mp.setattr(subprocess, 'run', forbidden)
        self.mp.setattr(subprocess, 'Popen', forbidden)
        self.manifest = product.build_manifest(product.read_config(ROOT / 'deployment/product-verifier-20261018a.json'))
        self.mp.setattr(self.fixture, 'OLD_RELEASE', transport.ACTIVE_RELEASE)
        self.mp.setattr(self.fixture, 'QA_SOURCE', self.manifest['qa_source_sha256'])
        harness = self.fixture.harness.__wrapped__(self.root, self.mp)
        package = self.fixture.valid_package.__wrapped__(harness)
        proof = self.fixture.proof_case.__wrapped__(package, harness)
        case = self.fixture.v2_case.__wrapped__(proof)
        self.bundle = self.fixture.failed_bundle(case)
        self.database, self.queue, self.claim = self.fixture.seed(self.root / 's', self.bundle)
        self.source = transport.backend_source()
        self.identity = transport.PinnedIdentity(transport.INSTANCE, transport.COMPARTMENT, transport.REGION,
            transport.FOX_CONTAINER, transport.FOX_IMAGE, transport.ACTIVE_RELEASE, tuple(sorted(self.manifest['modules'].items())))
        self.observed = []
        self.observer = self.host_observer
        self.reader = transport.NextReaderCapability('e' * 64, transport.BACKEND_SHA256, recovery.admission_status)
        self.approved = ()
        self.apply_allowed = False
        self.executor_calls = []
        self.lock_stack = ExitStack(); self.addCleanup(self.lock_stack.close)
        self.resolver = self.lock_resolver(self.manifest, 'operator')
        self.operator_lease = self.lock_stack.enter_context(self.resolver._lock())

    def lock_resolver(self, manifest, folder):
        release = transport._digest(transport._canonical(manifest))
        private = self.root / folder
        owner = private / 'product-verifier' / release[:16]
        session = owner / ('session-' + '1' * 24)
        session.mkdir(parents=True)
        (owner / 'worker.lock').write_bytes(b'0')
        (owner / 'release.json').write_bytes(transport._canonical({
            'scope': 'fox-product-verifier-journal-v1', 'release_sha256': release}))
        return FailureResolver(manifest=manifest, expected_release_sha256=release, session=session,
            expected_collection_sha256='a' * 64, private_root=private, privacy_check=lambda _: None)

    def host_observer(self, probe):
        self.observed.append(probe)
        return {key: value for key, value in deepcopy(self.bundle['producer']).items()
                if key not in {'technical_proof_count', 'human_acceptance_count'}}

    def evidence(self, disposition=False):
        value = {'binding': self.claim.binding, **{key: self.bundle[key] for key in
            ('package', 'plan_raw', 'collection_raw', 'files', 'journal_summary')}}
        if 'wrapper_raw' in self.bundle:
            value['wrapper_raw'] = self.bundle['wrapper_raw']
        if disposition:
            document = recovery.validate_failed_evidence(**self.fixture.arguments(self.bundle))
            value.update(disposition=document, disposition_sha256=recovery.disposition_sha256(document))
        return value

    def executor(self, packet, *, source, operator_lease):
        self.assertIs(operator_lease, self.operator_lease)
        operator_lease.require_active(transport.ACTIVE_RELEASE)
        self.assertNotIn('operator_lease', packet)
        self.executor_calls.append(packet['operation'])
        return transport.execute_injected(packet, source=source, root=self.database.parent,
            identity=self.identity, observer=self.observer, approved_synchronous_launches=self.approved,
            next_reader=self.reader, allow_apply=self.apply_allowed, now=self.bundle['now'])

    def client(self, *, apply=False, executor=None):
        client = transport.FailureRecoveryTransport(self.manifest, transport.ACTIVE_RELEASE,
            executor=self.executor if executor is None else executor, allow_apply=apply)
        return partial(client, operator_lease=self.operator_lease)

    def logical(self):
        with closing(sqlite3.connect(self.database)) as db:
            schema = db.execute('SELECT type,name,tbl_name,sql FROM sqlite_master ORDER BY type,name').fetchall()
            rows = {name: db.execute('SELECT * FROM ' + name).fetchall() for name in
                    ('runs', 'verification_queue', 'acceptances', 'technical_verifications', 'events')}
        files = {str(path.relative_to(self.database.parent)): path.read_bytes()
                 for path in (self.database.parent / 'jobs').rglob('*') if path.is_file()}
        return schema, rows, files

    def packet(self, operation, evidence=None):
        return transport._wire(operation, self.claim, evidence or self.evidence(operation != 'observe'),
                               self.manifest, transport.ACTIVE_RELEASE, operation == 'resolve_failure')

    def direct(self, operation, **kwargs):
        defaults = dict(source=self.source, root=self.database.parent, identity=self.identity,
            observer=self.observer, approved_synchronous_launches=self.approved,
            next_reader=self.reader, allow_apply=self.apply_allowed, now=self.bundle['now'])
        defaults.update(kwargs)
        return transport.execute_injected(self.packet(operation), **defaults)

    def sync(self):
        self.bundle = self.fixture.synchronous_bundle((self.bundle,))
        self.approved = (self.bundle['reviewed_synchronous_launch'],)

    def test_default_and_real_dispatch_are_unavailable_before_any_backend_or_io(self):
        client = transport.FailureRecoveryTransport(self.manifest, transport.ACTIVE_RELEASE)
        with patch.object(transport, 'backend_source', side_effect=AssertionError('NO_SOURCE_READ')), \
             patch.object(transport, '_wire', side_effect=AssertionError('NO_PACKET_BUILD')):
            for operation in transport.OPS:
                with self.assertRaisesRegex(transport.RecoveryTransportError, 'LIVE_RECOVERY_TRANSPORT_UNAVAILABLE'):
                    client(operation, claim=self.claim, evidence=self.evidence(operation != 'observe'), operator_lease=self.operator_lease)
            with self.assertRaisesRegex(transport.RecoveryTransportError, 'LIVE_RECOVERY_TRANSPORT_UNAVAILABLE'):
                transport.dispatch('apply', observer={'forged': True})

    def test_non_pinned_manifest_and_backend_source_are_rejected(self):
        value = deepcopy(self.manifest); value['images']['fox'] = 'sha256:' + 'a' * 64
        with self.assertRaises(transport.RecoveryTransportError):
            transport.FailureRecoveryTransport(value, transport.ACTIVE_RELEASE)
        with self.assertRaisesRegex(transport.RecoveryTransportError, 'RECOVERY_BACKEND_SOURCE_CHANGED'):
            self.direct('observe', source=self.source + b'\n')

    def test_exact_identity_and_installed_module_hashes_precede_backend_execution(self):
        changed = [replace(self.identity, container_id='a' * 64), replace(self.identity, image_id='sha256:' + 'a' * 64),
                   replace(self.identity, instance_id='other'), replace(self.identity, release_sha256='a' * 64),
                   replace(self.identity, module_sha256=()),
                   replace(self.identity, module_sha256=((self.identity.module_sha256[0][0], 'a' * 64), *self.identity.module_sha256[1:]))]
        for identity in changed:
            with patch.object(transport, '_load_backend', side_effect=AssertionError('NO_BACKEND')), \
                 self.assertRaises(transport.RecoveryTransportError):
                self.direct('observe', identity=identity)
        self.assertEqual(self.observed, [])

    def test_observe_is_read_only_with_no_recovery_schema(self):
        before = self.logical(); raw = self.database.read_bytes(); members = set(self.database.parent.iterdir())
        with patch.object(recovery.VerificationRecovery, 'initialize', side_effect=AssertionError('NO_INIT')):
            result = self.client()('observe', claim=self.claim, evidence=self.evidence())
        self.assertEqual(result, self.bundle['producer'])
        self.assertEqual(before, self.logical()); self.assertEqual(raw, self.database.read_bytes())
        self.assertEqual(members, set(self.database.parent.iterdir()))
        self.assertNotIn('verification_failed_dispositions', repr(before[0]))

    def test_host_input_has_exact_bytes_and_no_caller_producer_or_counts(self):
        self.sync(); self.direct('observe')
        observed = self.observed[0]
        self.assertIs(type(observed), transport.HostProbeInput)
        self.assertEqual(observed.binding, self.claim.binding)
        expected = tuple((name, self.bundle['files'][name]) for name in transport.PROBE_FILES)
        self.assertEqual(observed.raw_evidence, expected + (('wrapper_raw', self.bundle['wrapper_raw']),))
        self.assertEqual(observed.journal_summary_raw, recovery.canonical_bytes(self.bundle['journal_summary']))
        self.assertNotIn(self.claim.attempt_token, repr(observed))
        self.assertNotIn('technical_proof_count', observed.__dict__)

    def test_missing_observer_and_caller_assertion_keys_cannot_grant_authority(self):
        for key in ('producer', 'technical_proof_count', 'human_acceptance_count', 'trusted_contract', 'approved_synchronous_launches'):
            evidence = self.evidence(); evidence[key] = {'forged': True}
            with self.assertRaises(transport.RecoveryTransportError): self.client()('observe', claim=self.claim, evidence=evidence)
        with self.assertRaisesRegex(transport.RecoveryTransportError, 'TRUSTED_HOST_OBSERVER_UNAVAILABLE'):
            self.direct('observe', observer=None)
        self.assertEqual(self.observed, [])

    def test_host_observer_may_not_claim_database_counts(self):
        with self.assertRaisesRegex(transport.RecoveryTransportError, 'HOST_OBSERVER_MUST_NOT_SUPPLY_DATABASE_COUNTS'):
            self.direct('observe', observer=lambda _: deepcopy(self.bundle['producer']))

    def test_stale_private_claim_with_same_public_binding_is_rejected(self):
        other = Claim(self.claim.binding, 'f' * 32)
        altered = self.evidence(); altered['journal_summary'] = deepcopy(altered['journal_summary'])
        altered['journal_summary']['claim_sha256'] = recovery.claim_sha256(other)
        with self.assertRaises(transport.RecoveryTransportError): self.client()('observe', claim=other, evidence=altered)
        self.assertEqual(self.observed, [])

    def test_actual_acceptance_and_proof_rows_block_reported_zero_counts(self):
        for table in ('acceptances', 'technical_verifications'):
            with closing(sqlite3.connect(self.database)) as db, db:
                if table == 'acceptances': db.execute('INSERT INTO acceptances VALUES(?,?,?)', (self.claim.binding.job_id, 'synthetic-owner', 'existing'))
                else: db.execute('INSERT INTO technical_verifications(run) VALUES(?)', (self.claim.binding.job_id,))
            with self.assertRaisesRegex(transport.RecoveryTransportError, 'RECOVERY_EXISTING_OUTCOME_BLOCKS_RESOLUTION'):
                self.direct('observe')
            with closing(sqlite3.connect(self.database)) as db, db: db.execute('DELETE FROM ' + table)
        self.assertEqual(self.observed, [])

    def test_missing_lazy_proof_table_is_zero_but_missing_acceptances_blocks(self):
        with closing(sqlite3.connect(self.database)) as db, db: db.execute('DROP TABLE technical_verifications')
        self.assertEqual(self.direct('observe')['technical_proof_count'], 0)
        with closing(sqlite3.connect(self.database)) as db, db: db.execute('DROP TABLE acceptances')
        with self.assertRaises(transport.RecoveryTransportError): self.direct('observe')

    def test_malformed_existing_proof_schema_blocks(self):
        with closing(sqlite3.connect(self.database)) as db, db:
            db.execute('DROP TABLE technical_verifications'); db.execute('CREATE TABLE technical_verifications(unrelated TEXT)')
        with self.assertRaises(transport.RecoveryTransportError): self.direct('observe')
        self.assertEqual(self.observed, [])

    def test_changed_retained_server_package_or_source_blocks_readiness_without_writes(self):
        job = self.database.parent / 'jobs' / self.claim.binding.job_id
        for filename in ('apex-package.zip', 'source-snapshot.json'):
            with self.subTest(filename=filename):
                path = job / filename; original = path.read_bytes()
                if filename == 'apex-package.zip':
                    changed = original + b'changed server package'
                else:
                    value = json.loads(original)
                    value['files'][0]['text'] += '\nchanged server source'
                    changed = recovery.canonical_bytes(value)
                path.write_bytes(changed)
                before = self.logical(); database_bytes = self.database.read_bytes()
                with self.assertRaises(transport.RecoveryTransportError): self.direct('observe')
                self.assertEqual(self.observed, [])
                self.assertEqual(before, self.logical())
                self.assertEqual(database_bytes, self.database.read_bytes())
                path.write_bytes(original)

    def test_mutation_during_host_observation_is_rechecked(self):
        def race(probe):
            value = self.host_observer(probe)
            with closing(sqlite3.connect(self.database)) as db, db:
                db.execute('INSERT INTO acceptances VALUES(?,?,?)', (self.claim.binding.job_id, 'synthetic-owner', 'race'))
            return value
        with self.assertRaises(transport.RecoveryTransportError): self.direct('observe', observer=race)

    def test_observer_requires_fresh_complete_zero_producer_inventory(self):
        self.sync()
        changes = [{'observed_at_utc': (self.bundle['now'] - timedelta(seconds=301)).isoformat()},
                   {'live_producer_count': 1}, {'unknown_producer_count': 1}, {'producer_inventory_complete': False},
                   {'timed_out': True}, {'detached': True}, {'qa_report_sha256': 'f' * 64}, {'wrapper_sha256': 'f' * 64}]
        for changed in changes:
            with self.subTest(changed=changed), self.assertRaises(transport.RecoveryTransportError):
                self.direct('observe', observer=lambda p: {**self.host_observer(p), **changed})

    def test_synchronous_contract_is_configured_separately_not_in_evidence(self):
        self.sync()
        with self.assertRaises(transport.RecoveryTransportError): self.direct('observe', approved_synchronous_launches=())
        with self.assertRaises(transport.RecoveryTransportError):
            self.direct('observe', approved_synchronous_launches=(self.approved[0].__dict__,))
        self.assertEqual(self.direct('observe')['scope'], recovery.SYNCHRONOUS_SCOPE)

    def test_bare_and_prefixed_report_image_representations_keep_exact_bytes(self):
        for bare in (False, True):
            bundle = deepcopy(self.bundle)
            if bare:
                for name in ('qa-result.json', 'stage-receipt.json', 'launch-receipt.json', 'launch-intent.json', 'dispatch-receipt.json'):
                    value = json.loads(bundle['files'][name])
                    target = value['runtime'] if name == 'qa-result.json' else value
                    target['image_id'] = target['image_id'][7:]
                    bundle['files'][name] = recovery.canonical_bytes(value)
                self.fixture.reseal_collection(bundle)
            prior = self.bundle; self.bundle = bundle
            self.sync()
            before = deepcopy(self.bundle['files'])
            result = self.direct('observe')
            self.assertEqual(result['image_id'], self.fixture.IMAGE)
            self.assertEqual(before, self.bundle['files'])
            self.bundle = prior; self.approved = ()

    def test_default_apply_and_missing_reader_cannot_bootstrap_schema(self):
        original = self.logical()
        with self.assertRaises(transport.RecoveryTransportError):
            self.client()('resolve_failure', claim=self.claim, evidence=self.evidence(True))
        with self.assertRaisesRegex(transport.RecoveryTransportError, 'EXPLICIT_RECOVERY_APPLY_REQUIRED'):
            self.direct('resolve_failure')
        with self.assertRaisesRegex(transport.RecoveryTransportError, 'NEXT_READER_CAPABILITY_REQUIRED'):
            self.direct('resolve_failure', allow_apply=True, next_reader=None)
        self.assertEqual(original, self.logical())

    def test_reader_digest_must_match_actual_module_bytes_and_function_code(self):
        self.reader.check()
        changed = replace(self.reader, reader_sha256='a' * 64)
        with self.assertRaisesRegex(transport.RecoveryTransportError, 'NEXT_READER_SOURCE_CHANGED'): changed.check()
        fake = types.FunctionType((lambda *args: {}). __code__, recovery.admission_status.__globals__, 'admission_status')
        changed = replace(self.reader, reader=fake)
        with self.assertRaises(transport.RecoveryTransportError): changed.check()

    def test_incompatible_reader_blocks_before_any_schema_write(self):
        before = self.logical()
        capability = transport.NextReaderCapability('e' * 64, transport._digest(Path(__file__).read_bytes()), incompatible_reader)
        with self.assertRaisesRegex(transport.RecoveryTransportError, 'NEXT_READER_COMPATIBILITY_UNPROVEN'):
            self.direct('resolve_failure', allow_apply=True, next_reader=capability)
        self.assertEqual(before, self.logical())

    def test_valid_resolution_appends_only_schema_and_one_disposition(self):
        self.sync(); before = self.logical(); self.apply_allowed = True
        reply = self.client(apply=True)('resolve_failure', claim=self.claim, evidence=self.evidence(True))
        self.assertEqual(reply, {'status': 'FAILED_QA_RECORDED', 'disposition_sha256': self.evidence(True)['disposition_sha256'],
                                'disposition': self.evidence(True)['disposition']})
        after = self.logical()
        self.assertEqual(before[1:], after[1:])
        self.assertGreater(len(after[0]), len(before[0]))
        with closing(sqlite3.connect(self.database)) as db:
            self.assertEqual(db.execute('SELECT COUNT(*) FROM verification_failed_dispositions').fetchone()[0], 1)
            self.assertEqual(db.execute('SELECT COUNT(*) FROM verification_retry_attempts').fetchone()[0], 0)
        self.assertEqual(len(self.observed), 2)

    def test_second_probe_change_prevents_disposition_record(self):
        def change(probe):
            value = self.host_observer(probe)
            if len(self.observed) == 2: value['live_producer_count'] = 1
            return value
        before = self.logical()
        with self.assertRaises(transport.RecoveryTransportError):
            self.direct('resolve_failure', allow_apply=True, observer=change)
        self.assertEqual(before[1:], self.logical()[1:])
        with closing(sqlite3.connect(self.database)) as db:
            self.assertEqual(db.execute('SELECT COUNT(*) FROM verification_failed_dispositions').fetchone()[0], 0)

    def test_lookup_missing_is_read_only_and_never_observes_or_initializes(self):
        before = self.logical(); raw = self.database.read_bytes()
        result = self.direct('lookup_resolution', observer=lambda _: self.fail('LOOKUP_MUST_NOT_OBSERVE'), next_reader=None)
        self.assertIsNone(result); self.assertEqual(before, self.logical()); self.assertEqual(raw, self.database.read_bytes())
        self.assertEqual(self.observed, [])

    def test_lost_reply_only_allows_lookup_and_preserves_one_record(self):
        self.apply_allowed = True
        def lost(packet, *, source, operator_lease):
            result = self.executor(packet, source=source, operator_lease=operator_lease)
            if packet['operation'] == 'resolve_failure': raise RuntimeError(SECRET)
            return result
        client = self.client(apply=True, executor=lost); evidence = self.evidence(True)
        with self.assertRaisesRegex(transport.RecoveryTransportError, 'LOOKUP_ONLY'):
            client('resolve_failure', claim=self.claim, evidence=evidence)
        with self.assertRaisesRegex(transport.RecoveryTransportError, 'RECOVERY_LOOKUP_ONLY_AFTER_ATTEMPT'):
            client('resolve_failure', claim=self.claim, evidence=evidence)
        seen = len(self.observed)
        result = client('lookup_resolution', claim=self.claim, evidence=evidence)
        self.assertEqual(result['status'], 'FAILED_QA_RECORDED'); self.assertEqual(seen, len(self.observed))
        self.assertEqual(self.executor_calls, ['resolve_failure', 'lookup_resolution'])

    def test_lookup_preserves_later_genuine_acceptance_and_does_not_require_zero_counts(self):
        self.direct('resolve_failure', allow_apply=True)
        with closing(sqlite3.connect(self.database)) as db, db:
            db.execute("UPDATE runs SET state='ACCEPTED' WHERE id=?", (self.claim.binding.job_id,))
            db.execute('INSERT INTO acceptances VALUES(?,?,?)', (self.claim.binding.job_id, 'synthetic-owner', 'later review'))
        before = self.logical()
        reply = self.direct('lookup_resolution', observer=None, next_reader=None)
        self.assertEqual(reply['status'], 'FAILED_QA_RECORDED'); self.assertEqual(before, self.logical())

    def test_unknown_operation_raw_fields_and_bad_ack_never_escape(self):
        for op in ('retry', 'initialize', 'complete', 'promote', SECRET):
            with self.assertRaises(transport.RecoveryTransportError): self.client()(op, claim=self.claim, evidence=self.evidence())
        for extra in ({'provider_text': SECRET}, {'attempt_token': self.claim.attempt_token}):
            client = self.client(executor=lambda *args, **kwargs: {**self.bundle['producer'], **extra})
            with self.assertRaises(transport.RecoveryTransportError) as caught:
                client('observe', claim=self.claim, evidence=self.evidence())
            self.assertNotIn(SECRET, str(caught.exception)); self.assertNotIn(self.claim.attempt_token, str(caught.exception))
        client = self.client(executor=lambda *args, **kwargs: {'status': 'FAILED_QA_RECORDED', 'secret': SECRET})
        with self.assertRaises(transport.RecoveryTransportError): client('lookup_resolution', claim=self.claim, evidence=self.evidence(True))

    def test_arbitrary_observer_exception_is_bounded_and_no_acceptance_or_token_output(self):
        client = self.client(executor=lambda *args, **kwargs: (_ for _ in ()).throw(RuntimeError(SECRET)))
        with self.assertRaises(transport.RecoveryTransportError) as caught: client('observe', claim=self.claim, evidence=self.evidence())
        self.assertEqual(str(caught.exception), 'RECOVERY_TRANSPORT_OUTCOME_UNCONFIRMED_LOOKUP_ONLY')

    def test_generated_source_is_inert_and_carries_only_exact_pinned_backend(self):
        before = self.logical(); program = transport.container_source()
        namespace = {'__name__': '_generated_recovery_test'}
        module = types.ModuleType(namespace['__name__']); namespace = module.__dict__
        with patch.dict(sys.modules, {module.__name__: module}), \
             patch.object(sqlite3, 'connect', side_effect=AssertionError('NO_DATABASE_ON_SOURCE_LOAD')), \
             patch.object(Path, 'read_bytes', side_effect=AssertionError('NO_FILES_ON_SOURCE_LOAD')):
            exec(compile(program, '<inert-recovery-source>', 'exec'), namespace)
            with self.assertRaisesRegex(namespace['RecoveryTransportError'], 'LIVE_RECOVERY_TRANSPORT_UNAVAILABLE'):
                namespace['dispatch']('resolve_failure')
        import base64
        self.assertEqual(base64.b64decode(namespace['PINNED_BACKEND_B64']), self.source)
        self.assertEqual(before, self.logical())
        self.assertNotIn('ssh', program.lower()); self.assertNotIn('admin_secret', program)

    def test_generated_library_runs_only_the_explicit_injected_read_only_seam(self):
        module = types.ModuleType('_generated_recovery_execution_test')
        with patch.dict(sys.modules, {module.__name__: module}):
            exec(compile(transport.container_source(), '<inert-recovery-source>', 'exec'), module.__dict__)
            identity = module.PinnedIdentity(**self.identity.__dict__)
            before = self.logical()
            result = module.execute_injected(self.packet('observe'), source=self.source, root=self.database.parent,
                identity=identity, observer=self.observer, now=self.bundle['now'])
            self.assertEqual(result, self.bundle['producer']); self.assertEqual(before, self.logical())

    def test_generated_library_closed_state_is_one_readonly_snapshot(self):
        recorded = self.direct('resolve_failure', allow_apply=True)
        module = types.ModuleType('_generated_closed_snapshot_test')
        with patch.dict(sys.modules, {module.__name__: module}):
            exec(compile(transport.container_source(), '<inert-recovery-source>', 'exec'), module.__dict__)
            identity = module.PinnedIdentity(**self.identity.__dict__)
            before = self.logical(); connects = []
            real_connect = sqlite3.connect
            def read_only_connect(*args, **kwargs):
                connects.append(args[0]); self.assertTrue(args[0].endswith('?mode=ro'))
                return real_connect(*args, **kwargs)
            with patch.object(sqlite3, 'connect', side_effect=read_only_connect):
                result = module.execute_injected(self.packet('read_closed_state'), source=self.source,
                    root=self.database.parent, identity=identity, observer=None, next_reader=None)
            self.assertEqual(result['acknowledgement'], recorded); self.assertTrue(result['union_ready'])
            self.assertEqual(len(connects), 1); self.assertEqual(before, self.logical())

    def test_frontend_requires_exact_active_lease_before_packet_source_or_executor(self):
        client = transport.FailureRecoveryTransport(self.manifest, transport.ACTIVE_RELEASE, executor=Mock())
        altered = deepcopy(self.manifest); altered['enabled'] = False
        with self.lock_resolver(altered, 'wrong-release')._lock() as wrong_release:
            for lease in (None, {'locked': True}, object(), wrong_release):
                with self.subTest(lease=type(lease).__name__), \
                     patch.object(transport, '_wire', side_effect=AssertionError('NO_PACKET_ACCESS')), \
                     patch.object(transport, 'backend_source', side_effect=AssertionError('NO_BACKEND_READ')), \
                     self.assertRaisesRegex(transport.RecoveryTransportError, 'ACTIVE_OPERATOR_LEASE_REQUIRED'):
                    client('observe', claim=object(), evidence=object(), operator_lease=lease)
        self.lock_stack.close()
        with patch.object(transport, '_wire', side_effect=AssertionError('NO_PACKET_ACCESS')), \
             patch.object(transport, 'backend_source', side_effect=AssertionError('NO_BACKEND_READ')), \
             self.assertRaisesRegex(transport.RecoveryTransportError, 'ACTIVE_OPERATOR_LEASE_REQUIRED'):
            client('observe', claim=object(), evidence=object(), operator_lease=self.operator_lease)
        client.executor.assert_not_called()

    def test_frontend_passes_real_fd_lease_out_of_band_and_never_serializes_it(self):
        self.assertIs(type(self.operator_lease), HeldOperatorLock)
        self.operator_lease.require_active(transport.ACTIVE_RELEASE)
        seen = []
        def inspect_executor(packet, *, source, operator_lease):
            seen.append(operator_lease)
            self.assertIs(operator_lease, self.operator_lease)
            self.assertNotIn('operator_lease', packet)
            self.assertNotIn('operator_lease', packet['evidence'])
            return self.executor(packet, source=source, operator_lease=operator_lease)
        result = self.client(executor=inspect_executor)('observe', claim=self.claim, evidence=self.evidence())
        self.assertEqual(result, self.bundle['producer']); self.assertEqual(seen, [self.operator_lease])

    def test_frontend_rejects_lease_closed_by_executor_before_returning_result(self):
        def closes(packet, *, source, operator_lease):
            result = self.executor(packet, source=source, operator_lease=operator_lease)
            self.lock_stack.close()
            return result
        with self.assertRaisesRegex(transport.RecoveryTransportError, 'OUTCOME_UNCONFIRMED_LOOKUP_ONLY'):
            self.client(executor=closes)('observe', claim=self.claim, evidence=self.evidence())

    def test_atomic_closed_read_has_one_readonly_snapshot_and_no_other_operation(self):
        recorded = self.direct('resolve_failure', allow_apply=True)
        before = self.logical(); observed = len(self.observed)
        connects, trace = [], []
        real_connect = sqlite3.connect
        def traced(*args, **kwargs):
            connects.append((args, kwargs))
            connection = real_connect(*args, **kwargs)
            connection.set_trace_callback(trace.append)
            return connection
        with patch.object(sqlite3, 'connect', side_effect=traced):
            value = self.direct('read_closed_state', observer=None, next_reader=None)
        self.assertEqual(value, {'acknowledgement': recorded,
            'eligibility': {'blocks_admission': False, 'recovery_state': 'failed_closed', 'retry_eligible': True},
            'union_ready': True})
        self.assertEqual(len(connects), 1)
        self.assertTrue(connects[0][0][0].endswith('?mode=ro'))
        self.assertEqual([sql for sql in trace if sql == 'BEGIN'], ['BEGIN'])
        self.assertTrue(all(sql.startswith(('SELECT ', 'PRAGMA foreign_keys=', 'PRAGMA table_info(', 'BEGIN', 'ROLLBACK')) for sql in trace))
        self.assertEqual(len(self.observed), observed); self.assertEqual(before, self.logical())

    def test_atomic_closed_read_missing_schema_or_closure_never_means_ready(self):
        before = self.logical()
        value = self.direct('read_closed_state', observer=None, next_reader=None)
        blocked = {'acknowledgement': None,
            'eligibility': {'blocks_admission': True, 'recovery_state': 'unavailable', 'retry_eligible': False}, 'union_ready': False}
        self.assertEqual(value, blocked); self.assertEqual(before, self.logical())
        self.direct('resolve_failure', allow_apply=True)
        evidence = self.evidence(True)
        evidence['disposition'] = deepcopy(evidence['disposition'])
        evidence['disposition']['journal_summary_sha256'] = '0' * 64
        evidence['disposition_sha256'] = recovery.disposition_sha256(evidence['disposition'])
        packet = self.packet('read_closed_state', evidence=evidence)
        before = self.logical()
        value = transport.execute_injected(packet, source=self.source, root=self.database.parent, identity=self.identity)
        self.assertEqual(value, blocked); self.assertEqual(before, self.logical())

    def test_atomic_union_rejects_active_unknown_and_orphan_identities(self):
        recorded = self.direct('resolve_failure', allow_apply=True)
        other = 'fox-' + '9' * 20
        for state in ('QUEUED', 'PROCESSING', 'QA_REQUIRED', 'ATTENTION', 'UNKNOWN'):
            with closing(sqlite3.connect(self.database)) as db, db:
                db.execute('INSERT INTO runs VALUES(?,?,?,?,?,?,?,?)', (other, 'other-project', '9' * 64,
                    state, 'synthetic other row', 1, 1, None))
            before = self.logical()
            value = self.direct('read_closed_state', observer=None)
            self.assertEqual(value['acknowledgement'], recorded)
            self.assertFalse(value['union_ready']); self.assertFalse(value['eligibility']['blocks_admission'])
            self.assertEqual(before, self.logical())
            with closing(sqlite3.connect(self.database)) as db, db: db.execute('DELETE FROM runs WHERE id=?', (other,))
        # A queue-only orphan is still in the union; it must not disappear from
        # readiness just because no corresponding run is present.
        with closing(sqlite3.connect(self.database)) as db, db:
            db.row_factory = sqlite3.Row
            legacy = dict(db.execute('SELECT * FROM verification_queue WHERE job_id=?', (self.claim.binding.job_id,)).fetchone())
            legacy['job_id'] = other
            backend = transport._load_backend(self.source)
            binding = backend.VerificationBinding.from_payload({key: legacy[key] for key in self.claim.binding.payload()})
            legacy['binding_sha256'] = backend.VerificationQueue._save.__globals__['_digest'](binding.payload())
            backend.VerificationQueue._save(db, legacy, insert=True)
        value = self.direct('read_closed_state', observer=None)
        self.assertEqual(value['acknowledgement'], recorded); self.assertFalse(value['union_ready'])
        with closing(sqlite3.connect(self.database)) as db, db:
            db.execute('DELETE FROM verification_queue WHERE job_id=?', (other,))
            # Deliberately malformed retry-only orphan. Its ID must be checked
            # even though neither runs nor verification_queue contains it.
            db.execute('INSERT INTO verification_retry_attempts VALUES(?,?,?,?,?,?,?,?)',
                ('attempt-' + '8' * 32, 'request-' + '8' * 32, recorded['disposition_sha256'], other,
                 b'{}', '8' * 64, self.bundle['now'].isoformat(), '8' * 64))
        value = self.direct('read_closed_state', observer=None)
        self.assertFalse(value['union_ready'])

    def test_atomic_read_tampered_current_retained_bytes_or_ledger_is_blocked(self):
        self.direct('resolve_failure', allow_apply=True)
        path = self.database.parent / 'jobs' / self.claim.binding.job_id / 'apex-package.zip'
        original = path.read_bytes(); path.write_bytes(original + b'tampered')
        before = self.logical()
        result = self.direct('read_closed_state', observer=None)
        self.assertIsNone(result['acknowledgement']); self.assertTrue(result['eligibility']['blocks_admission'])
        self.assertFalse(result['union_ready']); self.assertEqual(before, self.logical())
        path.write_bytes(original)
        with closing(sqlite3.connect(self.database)) as db, db:
            db.execute('DROP TRIGGER verification_failed_dispositions_no_update')
            db.execute("UPDATE verification_failed_dispositions SET record_sha256=?", ('f' * 64,))
        before = self.logical()
        result = self.direct('read_closed_state', observer=None)
        self.assertIsNone(result['acknowledgement']); self.assertFalse(result['union_ready'])
        self.assertEqual(before, self.logical())

    def test_atomic_frontend_rejects_extra_fields_unbound_ack_and_inconsistent_flags(self):
        recorded = self.direct('resolve_failure', allow_apply=True)
        valid = {'acknowledgement': recorded,
            'eligibility': {'blocks_admission': False, 'recovery_state': 'failed_closed', 'retry_eligible': True}, 'union_ready': True}
        edits = [lambda v: v.update(extra=SECRET), lambda v: v['acknowledgement'].update(disposition_sha256='0' * 64),
                 lambda v: v.update(acknowledgement=None), lambda v: v.update(union_ready=1),
                 lambda v: v['eligibility'].update(extra=SECRET),
                 lambda v: v['eligibility'].update(blocks_admission=True)]
        for change in edits:
            result = deepcopy(valid); change(result)
            with self.assertRaises(transport.RecoveryTransportError):
                self.client(executor=lambda *args, **kwargs: result)('read_closed_state', claim=self.claim, evidence=self.evidence(True))

    def test_atomic_read_missing_fences_or_changed_recovery_schema_stays_blocked(self):
        self.direct('resolve_failure', allow_apply=True)
        with closing(sqlite3.connect(self.database)) as db:
            fences = db.execute("SELECT name,sql FROM sqlite_master WHERE type='trigger' AND name LIKE 'verification_%'").fetchall()
        self.assertEqual(len(fences), 8)
        for name, definition in fences:
            with closing(sqlite3.connect(self.database)) as db, db: db.execute('DROP TRIGGER ' + name)
            before = self.logical()
            value = self.direct('read_closed_state', observer=None)
            self.assertIsNone(value['acknowledgement']); self.assertFalse(value['union_ready'])
            self.assertEqual(before, self.logical())
            with closing(sqlite3.connect(self.database)) as db, db: db.execute(definition)
        with closing(sqlite3.connect(self.database)) as db, db:
            db.execute('ALTER TABLE verification_retry_events ADD COLUMN unexpected TEXT')
        before = self.logical()
        value = self.direct('read_closed_state', observer=None)
        self.assertIsNone(value['acknowledgement']); self.assertFalse(value['union_ready'])
        self.assertEqual(before, self.logical())

    def test_adapter_exact_types_and_local_closed_binding_precede_transport(self):
        real_transport = transport.FailureRecoveryTransport(self.manifest, transport.ACTIVE_RELEASE, executor=self.executor)
        class TransportSubclass(transport.FailureRecoveryTransport): pass
        class ResolverSubclass(FailureResolver): pass
        for resolver, backend_transport in ((object(), real_transport),
                (object.__new__(ResolverSubclass), real_transport), (self.resolver, object()),
                (self.resolver, TransportSubclass(self.manifest, transport.ACTIVE_RELEASE))):
            with self.assertRaises(transport.RecoveryTransportError): transport.ClosedFailureReadAdapter(resolver, backend_transport)
        adapter = transport.ClosedFailureReadAdapter(self.resolver, real_transport)
        self.assertIs(adapter.resolver, self.resolver)
        with self.assertRaises(transport.RecoveryTransportError):
            adapter.read_closed_state('a' * 64, self.claim.binding.job_id, {'locked': True})
        with patch.object(self.resolver, '_validated_closed_under_lock', side_effect=RuntimeError(SECRET)), \
             self.assertRaises(transport.RecoveryTransportError):
            adapter.read_closed_state('a' * 64, self.claim.binding.job_id, self.operator_lease)
        self.assertEqual(self.executor_calls, [])

    def test_adapter_validated_local_seam_forwards_one_atomic_call_under_same_real_lock(self):
        recorded = self.direct('resolve_failure', allow_apply=True)
        backend_transport = transport.FailureRecoveryTransport(self.manifest, transport.ACTIVE_RELEASE, executor=self.executor)
        adapter = transport.ClosedFailureReadAdapter(self.resolver, backend_transport)
        # These three local-only validator seams isolate the adapter call
        # protocol. Backend closure/evidence validation above is real; the
        # resolver's complete private-journal checks have their own suite.
        with patch.object(self.resolver, '_validated_closed_under_lock', return_value=deepcopy(recorded)) as closed, \
             patch.object(self.resolver, '_local', return_value=(self.claim, self.evidence())) as local, \
             patch.object(self.resolver, '_validate', return_value=deepcopy(recorded['disposition'])) as validate:
            before = self.logical(); observed = len(self.observed)
            value = adapter.read_closed_state(recorded['disposition_sha256'], self.claim.binding.job_id, self.operator_lease)
            self.assertEqual(value['acknowledgement'], recorded); self.assertTrue(value['union_ready'])
            self.assertEqual(self.executor_calls, ['read_closed_state']); self.assertEqual(observed, len(self.observed))
            self.assertEqual(before, self.logical())
            closed.assert_called_once_with(self.operator_lease); local.assert_called_once(); validate.assert_called_once()
            for sha, job in (('f' * 64, self.claim.binding.job_id), (recorded['disposition_sha256'], 'fox-' + '8' * 20)):
                with self.assertRaises(transport.RecoveryTransportError): adapter.read_closed_state(sha, job, self.operator_lease)
        self.assertEqual(self.executor_calls, ['read_closed_state'])


if __name__ == '__main__':
    unittest.main()
