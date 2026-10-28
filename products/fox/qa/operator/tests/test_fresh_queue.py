"""Actual S0/F/SQLite queue adapter, not a live R4 admission/host proof.

The normal-state tests use an explicitly synthetic A record bound to genuine
local S0/F. This exercises the application-side fence, not a real lease/image
attestation. The production provider and supervisor still reject R4 execution.
"""
from contextlib import closing
from copy import deepcopy
import json
import os
from pathlib import Path
import runpy
import shlex
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[3]
POSIX = os.name == 'posix' and hasattr(os, 'geteuid') and os.geteuid() > 0


def scenario(name, original):
    support = runpy.run_path(str(original / 'qa/operator/tests/test_fresh_backend.py'))
    with tempfile.TemporaryDirectory(prefix='fq-') as temporary:
        parent = Path(temporary);parent.chmod(0o700);source = parent / 'release'
        support['copy_source_closure'](original, source)
        fixture = support['Fixture'](parent, source)
        if name == 'alternate':
            projection = deepcopy(fixture.values['projection']);projection['converter_endpoint'] = 'http://127.0.0.1:18291'
            fixture.put('projection', Path(fixture.refs['projection']['path']), projection)
            config = deepcopy(fixture.values['provider']);config['app_projection'] = fixture.refs['projection']
            config['runtime']['converter_endpoint'] = projection['converter_endpoint']
            config['runtime']['settings']['fox_origin'] = 'http://127.0.0.1:18110'
            config['runtime']['roles']['fox'].update(name='fox-fresh-second', user=str(os.geteuid())+':'+str(os.getegid()))
            config['runtime']['roles']['converter']['name'] = 'forms2apex-fresh-second'
            fixture.put('provider', Path(fixture.refs['provider']['path']), config)
            release = deepcopy(fixture.values['release']);release['hosted_runtime_configuration_sha256'] = fixture.refs['provider']['sha256']
            fixture.put('release', Path(fixture.refs['release']['path']), release)
        backend_result = fixture.call();backend_ref = backend_result['backend_initialization']
        from qa.operator import runtime_provider as runtime, fresh_queue as q
        from qa.operator import product_queue_transport as legacy
        from fox import fresh_startup, verification_queue, verification_runtime, technical_release
        config = fixture.values['provider'];release = fixture.values['release'];release_sha = fixture.refs['release']['sha256']
        secret_parent = Path(config['admin_secret_file']).parent
        secret_parent.mkdir(mode=0o700, exist_ok=True)
        runtime.configure_fresh(fixture.refs['provider'], fixture.refs['release'], backend_ref, layout=fixture.layout)
        provider = runtime.selected_hosted()
        request = {'operation':'claim', 'apply':True, 'manifest':release, 'release_sha256':release_sha,
                   'binding':None, 'claim':None, 'code':None, 'proof_sha256':None}
        value = q.packet(provider, request)
        env = {'FOX_INSTALLATION_MODE':'fresh', 'FOX_DATA_DIR':str(fixture.roots['fox_data']),
            'FOX_FRESH_PUBLIC_CONFIG_DIR':str(fixture.public), 'FOX_VERIFICATION_ENABLED':'1',
            'FOX_VERIFIER_RELEASE_SHA256':release_sha,
            'FOX_FRESH_PROVIDER_SHA256':fixture.refs['provider']['sha256'],
            'FOX_FRESH_PROJECTION_SHA256':fixture.refs['projection']['sha256'],
            'FOX_FRESH_BACKEND_SHA256':backend_ref['sha256']}
        # Execute the exact serialized shared dispatcher and fresh functions.
        # Only production container mount/loader scaffolding is excluded here;
        # no passing startup/queue validator is mocked or replaced.
        generated = q.container_source();compile(generated,'<fresh-container>','exec')
        namespace = {};exec(compile(generated[:-len(q.CONTAINER_BODY)],'<serialized-fresh>','exec'),namespace)
        def execute(packet=value):
            with patch.dict(os.environ,env,clear=True):
                return namespace['execute_container'](packet, verification_queue, technical_release,
                    verification_runtime, fresh_startup, root=fixture.roots['fox_data'], environ=env)
        if name == 'fenced':
            before = support['snapshot'](parent)
            try:execute()
            except namespace['FreshQueueError'] as error:assert str(error)=='FRESH_QUEUE_LIVE_ADMISSION_REQUIRED'
            else:raise AssertionError('PRE_ADMISSION_QUEUE_EXECUTED')
            assert support['snapshot'](parent) == before
        elif name == 'invalid_packet':
            before = support['snapshot'](parent)
            for field in ('installation_id','provider_configuration_sha256','app_projection_sha256','backend_initialization_sha256'):
                bad = deepcopy(value);bad[field] = 'changed'
                try:execute(bad)
                except namespace['FreshQueueError']:pass
                else:raise AssertionError('INVALID_PACKET_ACCEPTED')
            assert support['snapshot'](parent) == before
        elif name == 'legacy_fenced':
            with patch.object(legacy.clean,'oci_scope',side_effect=AssertionError('NO_OCI')), \
                 patch.object(legacy.clean,'ssh_json',side_effect=AssertionError('NO_LEGACY_EXECUTION')):
                try:legacy.dispatch('claim',release,expected_release_sha256=release_sha,apply=True)
                except legacy.QueueTransportError:pass
                else:raise AssertionError('LEGACY_DISPATCH_ACCEPTED_R4')
            for call in (lambda:provider.execute_host(generated,b'{}',timeout=1), provider.admin_secret):
                try:call()
                except runtime.ProviderError as error:assert str(error)=='FRESH_BOUND_TRANSPORT_AND_ADMISSION_REQUIRED'
                else:raise AssertionError('FRESH_GENERAL_EXECUTION_UNFENCED')
        else:
            # This is NOT a genuine operator A or independent runtime evidence.
            # It is deliberately produced only inside this isolated test.
            admission = {'schema_version':1,'scope':'fox-fresh-live-admission-v1',
                'installation_id':fixture.identity,'storage_completion_sha256':fixture.refs['completion']['sha256'],
                'app_projection_sha256':fixture.refs['projection']['sha256'],
                'provider_configuration_sha256':fixture.refs['provider']['sha256'],'release_sha256':release_sha,
                'backend_initialization_sha256':backend_ref['sha256'],'admission_sha256':'a'*64,
                'installation_sha256':'b'*64,'live_observation_sha256':'c'*64,
                'observed_at_utc':'2027-01-01T00:00:00Z','transition':'INITIAL_TO_NORMAL',
                'automatic_replay_permitted':False}
            admitted = fixture.public/'live-admission.json'
            admitted.write_bytes(support['canonical'](admission));admitted.chmod(0o600)
            if name == 'environment':
                before = support['snapshot'](parent)
                env['FOX_FRESH_PROVIDER_SHA256'] = 'f'*64
                try:execute()
                except namespace['FreshQueueError'] as error:assert str(error)=='FRESH_QUEUE_ENVIRONMENT_CHANGED'
                else:raise AssertionError('ENVIRONMENT_DRIFT_ACCEPTED')
                assert support['snapshot'](parent)==before
                return {'status':'PASSED'}
            if name == 'identity':
                before = support['snapshot'](parent)
                other = deepcopy(value);other['installation_id']='fst-'+'f'*32
                try:execute(other)
                except namespace['FreshQueueError'] as error:assert str(error)=='FRESH_QUEUE_LIVE_ADMISSION_REQUIRED'
                else:raise AssertionError('ANOTHER_INSTALLATION_ID_ACCEPTED')
                assert support['snapshot'](parent)==before
                return {'status':'PASSED'}
            assert execute()['status']=='IDLE'
            heartbeat=deepcopy(value);heartbeat['request']['operation']='heartbeat'
            assert execute(heartbeat)['status']=='CONTACT_RECORDED'
            with closing(sqlite3.connect(fixture.database)) as db,db:
                for index in (1,2):
                    project='synthetic-project-'+str(index);job='fox-'+str(index)*20
                    db.execute('INSERT INTO projects VALUES(?,?,?,?,?,?)',(project,'synthetic-owner','test',project,'',1.0))
                    db.execute('INSERT INTO runs VALUES(?,?,?,?,?,?,?,?)',(job,project,str(index)*64,'QA_REQUIRED','',1.0,1.0,'jobs/'+job+'/apex-package.zip'))
            queue_store=verification_queue.VerificationQueue(fixture.database, enabled=True, verifier_release_sha256=release_sha)
            for index in (1,2):
                queue_store.enqueue(verification_queue.VerificationBinding('fox-'+str(index)*20,str(index)*64,str(index+2)*64,release_sha))
            claimed=execute();assert claimed['status']=='CLAIMED'
            assert claimed['claim']['binding']['job_id']=='fox-'+'1'*20
            assert execute()['status']=='IDLE'  # no second concurrent claim
            status=deepcopy(value);status['request'].update(operation='status',apply=False,binding=claimed['claim']['binding'])
            checked=execute(status);assert checked['queue']['state']=='running'
            assert claimed['claim']['attempt_token'] not in json.dumps(checked)
            attention=deepcopy(value);attention['request'].update(operation='attention',binding=claimed['claim']['binding'],
                claim=claimed['claim'],code='BACKEND_OUTCOME_UNCONFIRMED')
            assert execute(attention)['queue']['state']=='attention'
            # Unknown proof cannot become completion/acceptance, even with the
            # exact retained claim. The real technical reader is still used.
            complete=deepcopy(value);complete['request'].update(operation='complete',binding=claimed['claim']['binding'],
                claim=claimed['claim'],proof_sha256='e'*64)
            try:execute(complete)
            except verification_queue.QueueError:pass
            else:raise AssertionError('FABRICATED_PROOF_COMPLETED')
            assert queue_store.get('fox-'+'1'*20)['state']=='attention'
            with closing(sqlite3.connect(fixture.database)) as db:
                assert db.execute('SELECT count(*) FROM acceptances').fetchone()[0]==0
                assert db.execute('SELECT count(*) FROM projects').fetchone()[0]==2
            if name == 'removed_admission':
                admitted.rename(fixture.private/'retained-synthetic-admission.json')
                before=support['snapshot'](parent)
                try:execute()
                except fresh_startup.FreshStartupError:pass
                else:raise AssertionError('MISSING_ADMISSION_REBOOTSTRAPPED')
                assert support['snapshot'](parent)==before
        return {'status':'PASSED'}


class FreshQueueTests(unittest.TestCase):
    def run_case(self,name):
        if not POSIX:self.skipTest('actual nonroot POSIX storage/locks required')
        program='import json,runpy,sys\nm=runpy.run_path(sys.argv[1]);print(json.dumps(m["scenario"](sys.argv[2],m["ROOT"])))'
        result=subprocess.run([sys.executable,'-I','-B','-c',program,str(Path(__file__).resolve()),name],
            stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=120)
        self.assertEqual(result.returncode,0,result.stdout.decode()+result.stderr.decode())
        self.assertEqual(json.loads(result.stdout),{'status':'PASSED'})


class FreshQueueWireTests(unittest.TestCase):
    def setUp(self):
        for path in (ROOT,ROOT/'fox',ROOT/'converter'):
            if str(path) not in sys.path:sys.path.insert(0,str(path))
        from qa.operator import fresh_queue
        self.q=fresh_queue
        fixture=runpy.run_path(str(ROOT/'qa/operator/tests/test_fresh_contracts.py'))['chain']()
        self.manifest=fixture.values['release']
        self.value={'schema_version':1,'scope':self.q.SCOPE,'installation_id':fixture.values['provider']['storage']['installation_id'],
            'provider_configuration_sha256':fixture.refs['provider']['sha256'],
            'app_projection_sha256':fixture.refs['projection']['sha256'],
            'backend_initialization_sha256':fixture.refs['backend']['sha256'],'fox_user':'1001:1002',
            'request':{'operation':'claim','apply':True,'manifest':self.manifest,'release_sha256':fixture.refs['release']['sha256'],
                       'binding':None,'claim':None,'code':None,'proof_sha256':None}}

    def test_exact_r4_wire_does_not_convert_or_enable_legacy_release(self):
        self.assertEqual(self.q.validate_packet(self.value),self.value)
        with self.assertRaises(self.q.queue.QueueTransportError):self.q.queue.validate_release(self.manifest)
        selected=self.q.validate_release(self.manifest);selected['images']['fox']='changed'
        self.assertNotEqual(selected,self.manifest)

    def test_invalid_headers_scope_images_targets_and_source_sets_are_closed(self):
        changes=[lambda x:x.update(schema_version=True),lambda x:x.update(installation_mode='legacy'),
            lambda x:x.update(enabled=False),lambda x:x.update(scope=self.q.queue.HOSTED_SCOPE),
            lambda x:x['images'].update(fox=self.q.H_FOX_IMAGE),lambda x:x['target'].update(region='other-region'),
            lambda x:x['modules'].pop('fresh_startup.py'),lambda x:x['code'].pop('fresh_queue.py'),
            lambda x:x['project']['queue_modules'].update(unreviewed='a'*64),
            lambda x:x['project']['modules'].update(storage='b'*64),
            lambda x:x['opaf_profile'].update(path='/../synthetic-private')]
        for change in changes:
            value=deepcopy(self.manifest);change(value)
            with self.subTest(change=changes.index(change)),self.assertRaises(self.q.FreshQueueError):
                self.q.validate_release(value)

    def test_packet_environment_identity_and_claim_shapes_are_strict(self):
        changes=[lambda x:x.update(schema_version=True),lambda x:x.update(scope='legacy'),
            lambda x:x.update(installation_id='fst-'+'a'*31),lambda x:x.update(fox_user='0:0'),
            lambda x:x.update(fox_user='1001:2147483648'),lambda x:x.update(extra='synthetic-secret'),
            lambda x:x.update(provider_configuration_sha256='f'*64),
            lambda x:x['request'].update(release_sha256='f'*64),
            lambda x:x['request'].update(apply=False),lambda x:x['request'].update(claim={'attempt_token':'a'*32})]
        for change in changes:
            value=deepcopy(self.value);change(value)
            with self.subTest(change=changes.index(change)),self.assertRaises((self.q.FreshQueueError,self.q.queue.QueueTransportError)):
                self.q.validate_packet(value)

    def test_duplicate_unbounded_and_non_json_wire_is_not_accepted(self):
        for raw in (b'{}',b'[]',b'{"a":1,"a":2}',b'{"a":NaN}',b'synthetic-private-not-json',b'x'*65537):
            with self.subTest(size=len(raw)),self.assertRaises(self.q.FreshQueueError):self.q.parse_packet(raw)

    def test_full_generated_program_refuses_bad_wire_without_echo(self):
        program=self.q.container_source()
        with tempfile.TemporaryDirectory(prefix='fq-wire-') as temporary:
            path=Path(temporary)/'generated.py';path.write_text(program)
            result=subprocess.run([sys.executable,'-I','-B',str(path)],input=b'synthetic-private-not-json',
                stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=30)
        self.assertEqual(result.returncode,0)
        value=json.loads(result.stdout)
        self.assertEqual(value,{'status':'STOPPED','code':'FRESH_QUEUE_JSON_INVALID','automatic_replay_permitted':False})
        self.assertNotIn(b'synthetic-private',result.stdout);self.assertFalse(result.stderr)

    def test_published_vm_guard_keeps_target_checks_under_python_optimization(self):
        line=next(x for x in (ROOT/'qa/lib/assert-jsn-vm.sh').read_text().splitlines() if '| python3 ' in x)
        arguments=shlex.split(line.split('| python3 ',1)[1]);program=arguments[arguments.index('-c')+1]
        good={'id':'synthetic-instance','compartmentId':'synthetic-compartment',
              'canonicalRegionName':'us-ashburn-1','region':'iad'}
        for field in (None,'id','compartmentId','canonicalRegionName','region'):
            value=dict(good)
            if field:value[field]='not-authorized'
            result=subprocess.run([sys.executable,'-I','-B','-O','-c',program,'synthetic-instance','synthetic-compartment'],
                input=json.dumps(value).encode(),stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=10)
            self.assertEqual(result.returncode,0 if field is None else 1)


for _name in ('normal','alternate','fenced','invalid_packet','environment','identity','legacy_fenced','removed_admission'):
    setattr(FreshQueueTests,'test_'+_name,lambda self,name=_name:self.run_case(name))
