"""Real fresh bootstrap/backend, synthetic only at external host/Podman I/O."""
from contextlib import closing, contextmanager
from copy import deepcopy
from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path
import runpy
import socket
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[3]
POSIX = os.name == 'posix' and hasattr(os, 'geteuid') and os.geteuid() > 0


def fake_containers(remote, config, release_ref, backend_ref):
    now = datetime.now(timezone.utc)
    rows = []
    for index, (role, wanted) in enumerate(config['runtime']['roles'].items(), 1):
        created = now - timedelta(days=1) if role == 'opaf' else now
        running = role == 'opaf'
        environment = (remote.fox_environment(config, release_ref, backend_ref) if role == 'fox' else
                       remote.converter_environment(config, release_ref, backend_ref) if role == 'converter' else {})
        if role == 'fox':
            environment.update(FOX_ADMIN_USERNAME='synthetic-user', FOX_PASSWORD_HASH='a'*32+':'+'b'*128)
        rows.append({'Id': str(index)*64, 'Name': wanted['name'], 'Image': wanted['image'],
            'Created': created.isoformat(),
            'Config': {'User': wanted['user'], 'Env': [key+'='+value for key, value in sorted(environment.items())],
                       'Cmd': ['SYNTHETIC_IMAGE_ONLY'], 'Entrypoint': None},
            'HostConfig': {'ReadonlyRootfs': wanted['read_only_rootfs'],
                'Tmpfs': {'/tmp': 'rw,noexec,nosuid,nodev,size=64m,mode=1777'} if role == 'fox' else {}},
            'Mounts': [{'Type': 'bind', 'Source': row['source'], 'Destination': row['destination'],
                        'RW': not row['read_only']} for row in wanted['mounts']],
            'State': {'Running': running, 'Pid': 100+index if running else 0, 'ExitCode': 0,
                'Status': 'running' if running else 'configured',
                'StartedAt': (created+timedelta(seconds=1)).isoformat() if running else '0001-01-01T00:00:00Z',
                'FinishedAt': '0001-01-01T00:00:00Z'}})
    rows[0]['Mounts'].append({'Type': 'tmpfs', 'Source': '', 'Destination': '/tmp', 'RW': True})
    return rows


@contextmanager
def external_boundary(runtime, remote, provider, config, containers, *, alter=None, image_fault=None):
    calls, sample = [], [0]
    target = config['target_profile']['oci']
    def scope(instance, program, raw, *, timeout):
        assert instance is provider and program == runtime._OCI_PROGRAM and timeout == 240
        packet = json.loads(raw)
        assert packet['profile'] == config['target_profile'] and packet['require_database_available'] is False
        for name, encoded in packet['sources'].items():
            import base64
            assert hashlib.sha256(base64.b64decode(encoded, validate=True)).hexdigest() == config['converter_sources'][name]
        calls.append('scope')
        return json.dumps({'database_id': target['database_id'], 'database_compartment_id': target['compartment_id'],
            'instance_id': target['instance_id'], 'instance_compartment_id': target['compartment_id'],
            'region': target['region'], 'database_lifecycle_state': 'AVAILABLE',
            'instance_lifecycle_state': 'RUNNING', 'database_db_name': 'JSNF2APEX'}).encode()
    def podman(args, **options):
        assert calls and calls[0] == 'scope'
        assert args[:2] == ['/usr/bin/podman', '--remote=false']
        if args[2:4] == ['exec', '-i']:
            from qa.operator import fresh_image
            assert args[4:12] == ['--env','LD_PRELOAD=','--env','LD_AUDIT=',
                                 '--env','LD_LIBRARY_PATH=','--env','PYTHONDONTWRITEBYTECODE=1']
            packet = json.loads(options['input']); role = packet['role']
            actual_id = next(row['Id'] for row in containers if row['Name'] == config['runtime']['roles'][role]['name'])
            assert args[12] == actual_id and args[13:] == [fresh_image.PYTHON[role],'-I','-S','-B','-c',fresh_image.reader_program()]
            assert options == {'input':options['input'],'cwd':'/','env':provider._environment(),
                               'stdout':subprocess.PIPE,'stderr':subprocess.PIPE,'timeout':120}
            calls.append('read-image-'+role)
            value = {'schema_version':1,'scope':'fox-fresh-image-payload-observation-v1',
                'status':'MEASURED_NOT_ADMITTED','role':role,'request_sha256':remote.digest(options['input']),
                'read_only':True,'file_count':len(packet['files']),
                'measured_sha256':remote.digest(remote.canonical(packet['files'])), 'total_bytes':packet['expected_bytes']}
            if image_fault:
                image_fault(role, value)
            return subprocess.CompletedProcess(args,0,json.dumps(value).encode(),b'')
        assert options == {'cwd': '/', 'env': provider._environment(), 'stdout': subprocess.PIPE,
                           'stderr': subprocess.PIPE, 'timeout': 60}
        assert 'CONTAINER_HOST' not in options['env']
        if args[2:] == ['ps', '-aq', '--no-trunc']:
            calls.append('list')
            return subprocess.CompletedProcess(args, 0, ('\n'.join(row['Id'] for row in containers)+'\n').encode(), b'')
        assert args[2:4] == ['inspect', '--'] and args[4:] == sorted(row['Id'] for row in containers)
        calls.append('inspect'); sample[0] += 1
        measured = deepcopy(containers)
        if alter:
            alter(sample[0], measured)
        return subprocess.CompletedProcess(args, 0, json.dumps(measured).encode(), b'')
    with patch.object(runtime.HostedProvider, 'execute_host', scope), patch.object(subprocess, 'run', podman), \
         patch.object(socket.socket, 'connect', side_effect=AssertionError('NO_NETWORK')):
        yield calls


def scenario(name, original):
    support = runpy.run_path(str(original / 'qa/operator/tests/test_fresh_backend.py'))
    with tempfile.TemporaryDirectory(prefix='fro-') as temporary:
        parent = Path(temporary); parent.chmod(0o700)
        source = parent / 'release'
        support['copy_source_closure'](original, source)
        # Real reviewed template/mirror bytes plus explicitly synthetic built
        # UI: these fixtures test the measurement protocol, not a released app.
        template_root = original/'converter/forms2apex/templates'
        for path in template_root.rglob('*'):
            if path.is_file():
                target = source/path.relative_to(original)
                target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
                target.write_bytes(path.read_bytes()); target.chmod(0o600)
        mirror = source/'converter/fox_source_contract/source-manifest.json'
        mirror.write_bytes((original/'converter/fox_source_contract/source-manifest.json').read_bytes()); mirror.chmod(0o600)
        dist = source/'fox/dist'; (dist/'assets').mkdir(mode=0o700,parents=True)
        (dist/'index.html').write_bytes(b'<!-- SYNTHETIC UI, NOT A RELEASE --><script src="assets/unit.js"></script>')
        (dist/'assets/unit.js').write_bytes(b'/* synthetic image fixture */')
        (dist/'index.html').chmod(0o600); (dist/'assets/unit.js').chmod(0o600)
        fixture = support['Fixture'](parent, source)
        backend_ref = fixture.call()['backend_initialization']
        from qa.operator import runtime_provider as runtime, fresh_remote as remote
        config, release_ref = fixture.values['provider'], fixture.refs['release']
        Path(config['admin_secret_file']).parent.mkdir(mode=0o700)
        for role in config['runtime']['roles'].values():
            for mount in role['mounts']:
                path = Path(mount['source'])
                if not path.exists():
                    path.mkdir(mode=0o700, parents=True)
        runtime.configure_fresh(fixture.refs['provider'], release_ref, backend_ref, layout=fixture.layout)
        provider = runtime.hosted()
        containers = fake_containers(remote, config, release_ref, backend_ref)
        if name in ('old_staged_role', 'previously_started_role'):
            if name == 'old_staged_role':
                containers[0]['Created'] = (datetime.now(timezone.utc)-timedelta(days=1)).isoformat()
            else:
                containers[0]['State'].update(Status='stopped',
                    StartedAt=datetime.now(timezone.utc).isoformat(), FinishedAt=datetime.now(timezone.utc).isoformat())
            before = support['snapshot'](parent)
            with external_boundary(runtime, remote, provider, config, containers):
                try:
                    remote.measure_deployment(provider)
                except remote.FreshRemoteError:
                    pass
                else:
                    raise AssertionError('EXISTING_ROLE_ADOPTED')
            assert support['snapshot'](parent) == before
            return {'status': 'PASSED'}
        before = support['snapshot'](parent)
        with external_boundary(runtime, remote, provider, config, containers):
            result = remote.measure_deployment(provider)
        assert result['status'] == 'MEASURED_NOT_PUBLISHED'
        assert result['backend']['mode'] == 'FENCED' and result['backend']['run_count'] == 0
        assert result['connected_admission'] is result['automatic_replay_permitted'] is result['image_contents_checked'] is False
        assert ('a'*32+':'+'b'*128) not in json.dumps(result)
        assert support['snapshot'](parent) == before
        if name == 'staged':
            assert not (fixture.public/'live-admission.json').exists()
            return {'status': 'PASSED'}
        fixture.put('deployment', fixture.private/'D2.json', result['deployment_document'])
        if name in ('secret_reference', 'secret_bind_alias'):
            admin = Path(config['admin_secret_file'])
            secret = b'SYNTHETIC_ADMIN_MUST_NOT_BE_READ'
            admin.write_bytes(secret); admin.chmod(0o600)
            reference = ({'path': str(admin), 'sha256': remote.digest(secret)}
                         if name == 'secret_reference' else fixture.refs['deployment'])
            attempted = []
            original_read, original_identity = runtime._read, remote.filesystem_identity
            def refuse_secret_read(path, *args, **kwargs):
                if Path(path) == admin or (name == 'secret_bind_alias' and str(path) == reference['path']):
                    attempted.append(str(path)); raise AssertionError('SECRET_VALUE_READ')
                return original_read(path, *args, **kwargs)
            def alias_identity(path):
                return original_identity(admin) if str(path) == reference['path'] else original_identity(path)
            with patch.object(runtime, '_read', refuse_secret_read), \
                 patch.object(remote, 'filesystem_identity', alias_identity if name == 'secret_bind_alias' else original_identity), \
                 external_boundary(runtime, remote, provider, config, containers) as calls:
                try:
                    remote.observe_host_state(provider, reference)
                except remote.FreshRemoteError as error:
                    assert str(error) == 'FRESH_DEPLOYMENT_REFERENCE_IS_SECRET'
                else:
                    raise AssertionError('SECRET_REFERENCE_ACCEPTED')
            assert not attempted and not calls
            return {'status': 'PASSED'}
        for row in containers:
            row['State'].update(Running=True, Pid=200, Status='running', StartedAt=datetime.now(timezone.utc).isoformat())
        if name in ('normal', 'busy', 'live_wal', 'unknown_run'):
            # Synthetic unit A only: no actual admission, I2 or image proof.
            p = fixture.values['projection']
            admission = {'schema_version': 1, 'scope': 'fox-fresh-live-admission-v1',
                'installation_id': fixture.identity, 'storage_completion_sha256': fixture.refs['completion']['sha256'],
                'app_projection_sha256': fixture.refs['projection']['sha256'], 'provider_configuration_sha256': provider.sha256,
                'release_sha256': release_ref['sha256'], 'backend_initialization_sha256': backend_ref['sha256'],
                'admission_sha256': fixture.refs['deployment']['sha256'], 'installation_sha256': '7'*64,
                'live_observation_sha256': '8'*64, 'observed_at_utc': datetime.now(timezone.utc).isoformat(),
                'transition': 'INITIAL_TO_NORMAL', 'automatic_replay_permitted': False}
            (fixture.public/'live-admission.json').write_bytes(remote.canonical(admission))
            with closing(sqlite3.connect(fixture.database)) as db, db:
                db.execute('INSERT INTO projects VALUES(?,?,?,?,?,?)', ('p','synthetic-owner','Synthetic','P','',1))
                state = 'UNKNOWN' if name == 'unknown_run' else 'QUEUED' if name == 'busy' else 'ATTENTION'
                db.execute('INSERT INTO runs VALUES(?,?,?,?,?,?,?,?)', ('fox-'+'a'*20,'p','b'*64,state,'Synthetic',1,1,None))
        alter, image_fault = None, None
        if name == 'static_drift':
            containers[0]['Config']['Cmd'] = ['CHANGED_SYNTHETIC_COMMAND']
        elif name == 'id_drift':
            containers[0]['Id'] = '9'*64
        elif name == 'environment_drift':
            containers[0]['Config']['Env'] = [value for value in containers[0]['Config']['Env'] if not value.startswith('FOX_INSTALLATION_MODE=')]
        elif name == 'converter_environment_drift':
            containers[1]['Config']['Env'] = [value for value in containers[1]['Config']['Env'] if not value.startswith('F2A_FRESH_PROVIDER_SHA256=')]
        elif name == 'converter_loader_environment':
            containers[1]['Config']['Env'].append('LD_PRELOAD=SYNTHETIC_UNSAFE_VALUE')
        elif name == 'inventory_race':
            alter = lambda sample, rows: rows[0]['State'].update(Pid=999) if sample == 2 else None
        elif name == 'incomplete_inventory':
            alter = lambda sample, rows: rows.pop() if sample == 1 else None
        elif name == 'backend_race':
            def change_backend(sample, rows):
                if sample == 2:
                    with closing(sqlite3.connect(fixture.database)) as db, db:
                        db.execute('INSERT INTO projects VALUES(?,?,?,?,?,?)', ('race','synthetic','Synthetic','Race','',2))
            alter = change_backend
        elif name == 'root_replaced':
            old = fixture.roots['converter_jobs']; old.rename(parent/'retained-original-jobs'); old.mkdir(mode=0o700)
        elif name == 'failed_initialization':
            path = fixture.attempt/'failure.json'; path.write_bytes(b'{}'); path.chmod(0o600)
        elif name == 'private_observation_extra':
            path = fixture.attempt/'observed.json'
            value = json.loads(path.read_bytes()); value['unexpected'] = 'not an initializer field'
            path.write_bytes(remote.canonical(value))
        elif name == 'image_digest_forged':
            image_fault = lambda role, value: value.update(measured_sha256='0'*64) if role == 'fox' else None
        elif name == 'image_role_forged':
            image_fault = lambda role, value: value.update(role='opaf') if role == 'converter' else None
        elif name == 'image_count_forged':
            image_fault = lambda role, value: value.update(file_count=True) if role == 'fox' else None
        elif name in ('extra_live', 'extra_created', 'extra_unknown', 'extra_stopped'):
            extra = deepcopy(containers[0]); extra.update(Id='9'*64, Name='fox-unrelated-producer')
            extra['State'].update(Running=name=='extra_live', Pid=444 if name=='extra_live' else 0,
                Status='running' if name=='extra_live' else 'created' if name=='extra_created' else 'configured',
                StartedAt=datetime.now(timezone.utc).isoformat() if name=='extra_live' else '0001-01-01T00:00:00Z')
            containers.append(extra)
            if name == 'extra_stopped':
                moment = datetime.now(timezone.utc)
                extra['Created'] = (moment-timedelta(minutes=10)).isoformat()
                extra['State'].update(Status='stopped', StartedAt=(moment-timedelta(minutes=9)).isoformat(),
                                      FinishedAt=(moment-timedelta(minutes=8)).isoformat())
        expected_failure = name in ('static_drift','id_drift','environment_drift','converter_environment_drift',
                                    'converter_loader_environment','inventory_race','backend_race',
                                    'root_replaced','failed_initialization','unknown_run','incomplete_inventory','private_observation_extra',
                                    'image_digest_forged','image_role_forged','image_count_forged')
        writer = sqlite3.connect(fixture.database) if name == 'live_wal' else None
        wal_before = None
        if writer:
            writer.execute('PRAGMA journal_mode=WAL'); writer.execute('PRAGMA wal_autocheckpoint=0')
            writer.execute("UPDATE runs SET state='QUEUED',updated=3 WHERE id=?", ('fox-'+'a'*20,)); writer.commit()
            wal_before = Path(str(fixture.database)+'-wal').read_bytes()
        logical_before = support['base_rows'](fixture.database) if not writer else None
        try:
            with external_boundary(runtime, remote, provider, config, containers, alter=alter, image_fault=image_fault):
                if expected_failure:
                    try:
                        remote.observe_host_state(provider, fixture.refs['deployment'])
                    except remote.FreshRemoteError:
                        pass
                    else:
                        raise AssertionError('UNCONFIRMED_STATE_ACCEPTED')
                else:
                    observed = remote.observe_host_state(provider, fixture.refs['deployment'])
                    assert observed['status'] == 'OBSERVED_NOT_ADMITTED' and observed['connected_admission'] is False
                    if name in ('normal','busy','live_wal'):
                        assert observed['backend']['mode'] == 'NORMAL' and observed['backend']['run_count'] == 1
                        assert observed['backend']['busy_conversion_count'] == (1 if name in ('busy','live_wal') else 0)
                    else:
                        assert observed['backend']['mode'] == 'FENCED'
                    for kind, key in (('extra_live','live_producer_count'), ('extra_created','never_started_producer_count'),
                                      ('extra_unknown','unknown_producer_count'), ('extra_stopped','stopped_non_live_producer_count')):
                        if name == kind:
                            assert observed['producer_counts'][key] == 1
                    assert observed['image_contents_checked'] is True
                    assert observed['image_contents_scope'] == 'fox-converter-application-payload-v1'
                    assert set(observed['image_measurements']) == {'fox','converter'}
                    assert observed['full_installation_chain_checked'] is observed['operator_admission_lease_checked'] is False
                    if writer:
                        assert Path(str(fixture.database)+'-wal').read_bytes() == wal_before
        finally:
            if writer:
                writer.close()
        if not writer and name != 'backend_race':
            assert support['base_rows'](fixture.database) == logical_before
        return {'status': 'PASSED'}


class PureObserverTests(unittest.TestCase):
    def test_recovery_blobs_are_bounded_hashes_not_plaintext_in_fingerprint(self):
        for directory in (ROOT, ROOT/'fox', ROOT/'converter'):
            sys.path.insert(0, str(directory))
        from qa.operator import fresh_remote as remote
        payload = b'SYNTHETIC_PRIVATE_RECOVERY_RECORD'
        ledger = {'verification_retry_events': [{'sequence': 1, 'payload_raw': payload}]}
        expected = {'runs': [], 'ledger': {'verification_retry_events': [{'sequence': 1,
            'payload_raw': {'blob_bytes': len(payload), 'sha256': hashlib.sha256(payload).hexdigest()}}]}}
        self.assertEqual(remote.scheduling_digest([], ledger), hashlib.sha256(remote.canonical(expected)).hexdigest())
        changed = {'verification_retry_events': [{'sequence': 1, 'payload_raw': payload+b' changed'}]}
        self.assertNotEqual(remote.scheduling_digest([], ledger), remote.scheduling_digest([], changed))
        with patch.object(remote, 'MAX_WIRE', 8), self.assertRaises(remote.FreshRemoteError):
            remote.scheduling_digest([], ledger)

    def test_wrong_provider_rejected_before_process_or_sql(self):
        for directory in (ROOT, ROOT/'fox', ROOT/'converter'):
            sys.path.insert(0, str(directory))
        from qa.operator import fresh_remote as remote
        for value in (None, {}, object()):
            with self.subTest(value=type(value).__name__), patch.object(subprocess,'run',side_effect=AssertionError('NO_PROCESS')), \
                 patch.object(sqlite3,'connect',side_effect=AssertionError('NO_SQL')), self.assertRaises(remote.FreshRemoteError):
                remote.measure_deployment(value)

    def test_missing_deployment_reference_never_observes_unbound_live_state(self):
        for directory in (ROOT, ROOT/'fox', ROOT/'converter'):
            sys.path.insert(0, str(directory))
        from qa.operator import fresh_remote as remote
        with patch.object(subprocess, 'run', side_effect=AssertionError('NO_PROCESS')), self.assertRaisesRegex(
                remote.FreshRemoteError, 'DEPLOYMENT_REFERENCE_REQUIRED'):
            remote.observe_host_state(None, None)


@unittest.skipUnless(POSIX, 'Genuine nonroot POSIX fresh source/backend execution required')
class PosixObserverTests(unittest.TestCase):
    def run_scenario(self, name):
        result = subprocess.run([sys.executable,'-I','-B',str(Path(__file__).resolve()),'--scenario',name,str(ROOT)],
                                capture_output=True,text=True,timeout=90)
        self.assertEqual(result.returncode,0,result.stderr+result.stdout)
        self.assertEqual(json.loads(result.stdout)['status'],'PASSED')


for _case in ('staged','old_staged_role','previously_started_role','fenced_live','normal','busy','live_wal','unknown_run','static_drift','id_drift',
              'environment_drift','converter_environment_drift','converter_loader_environment',
              'inventory_race','backend_race','root_replaced','failed_initialization',
              'private_observation_extra','incomplete_inventory','secret_reference','secret_bind_alias',
              'extra_live','extra_created','extra_unknown','extra_stopped',
              'image_digest_forged','image_role_forged','image_count_forged'):
    def _test(self, name=_case):
        self.run_scenario(name)
    setattr(PosixObserverTests,'test_'+_case,_test)


if __name__=='__main__':
    if len(sys.argv)==4 and sys.argv[1]=='--scenario':
        print(json.dumps(scenario(sys.argv[2],Path(sys.argv[3])),sort_keys=True))
    else:
        unittest.main()
