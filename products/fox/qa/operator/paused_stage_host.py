"""Read-only host metadata for an explicit inert-startup baseline.

The peer probe may use only the audited configuration-only constructor in a
fresh pinned interpreter. No execution-authority or credential-content call is
permitted. This collector must run under the existing maintenance lease and
current installation/host guards.
It fails closed if effective units, process attribution or roots are unavailable.
"""
from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import subprocess


def need(value, code='INERT_HOST_UNCONFIRMED'):
    if not value:
        raise RuntimeError(code)


def hashed(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':'),
        ensure_ascii=False, allow_nan=False).encode()).hexdigest()


def safe(path):
    path = Path(path)
    need(path.is_absolute() and '..' not in path.parts and path.resolve() == path)
    need(all(not parent.is_symlink() for parent in (path, *path.parents)))
    return path


def read_ref(ref):
    need(type(ref) is dict and set(ref) == {'path', 'sha256'}
         and type(ref['sha256']) is str and re.fullmatch('[a-f0-9]{64}', ref['sha256']))
    path = safe(ref['path']); before = path.stat()
    need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and before.st_uid == os.getuid()
         and not before.st_mode & 0o022 and 0 < before.st_size <= 2_000_000)
    raw = path.read_bytes(); after = path.stat()
    need(len(raw) == before.st_size and hashlib.sha256(raw).hexdigest() == ref['sha256']
         and (before.st_dev, before.st_ino, before.st_mtime_ns, before.st_ctime_ns) ==
             (after.st_dev, after.st_ino, after.st_mtime_ns, after.st_ctime_ns))
    return raw


def parse(raw):
    def unique(rows):
        out = {}
        for key, value in rows:
            need(key not in out); out[key] = value
        return out
    return json.loads(raw, object_pairs_hook=unique, parse_constant=lambda _: need(False))


def command(argv):
    result = subprocess.run(argv, capture_output=True, timeout=60, check=False)
    need(result.returncode == 0 and not result.stderr.strip() and len(result.stdout) <= 16_000_000)
    return result.stdout


def verifier_binding(plan):
    """Only the reviewed transition references, not request-selected identities."""
    return {'helper':plan['helper'],'support':plan['support'],'installation':plan['new_installation'],
            'unit':{'path':plan['old_unit']['path'],'sha256':plan['new_unit']['sha256']}}


VERIFIER_PROBE = r'''
import hashlib,importlib.util,json,pathlib,sys,os,time
from datetime import datetime,timezone
p=json.load(sys.stdin)
def need(ok,code):
 if not ok:raise RuntimeError(code)
def load(name,ref):
 path=pathlib.Path(ref['path']);raw=path.read_bytes()
 need(hashlib.sha256(raw).hexdigest()==ref['sha256'],'INERT_VERIFIER_HELPER_CHANGED')
 spec=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(spec);sys.modules[name]=m
 exec(compile(raw,str(path),'exec'),m.__dict__);return m
A=load('_inert_verifier_helper',p['helper']);M=load('_inert_verifier_support',p['support'])
unit=pathlib.Path(p['unit']['path']);state=M.service_state(A,unit.name)
if state['MainPID']=='0' and state['ActiveState'] in ('inactive','failed'):
 print('null');raise SystemExit(0)
need(state['LoadState']=='loaded' and state['ActiveState']=='active' and state['SubState']=='running'
 and state['MainPID'].isdigit() and state['FragmentPath']==str(unit),'INERT_VERIFIER_UNIT_CHANGED')
unit_raw=A.read(unit,private=True)
need(hashlib.sha256(unit_raw).hexdigest()==p['unit']['sha256'],'INERT_VERIFIER_UNIT_CHANGED')
need(A.command(['/usr/bin/systemctl','--user','show',unit.name,'--property=DropInPaths']).strip()==b'DropInPaths=',
 'INERT_VERIFIER_UNIT_DROPINS')
raw=A.read(pathlib.Path(p['installation']['path']),private=True)
need(hashlib.sha256(raw).hexdigest()==p['installation']['sha256'],'INERT_VERIFIER_INSTALLATION_CHANGED')
i=A.parse(raw)
root,runtime,bridge,product=A.source_namespace(i['layout']['release_root'],i['layout']['inventory']['sha256'])
from qa.operator import hosted_service as service
admission=service.HostedAdmission(p['installation']['path'],expected_sha256=p['installation']['sha256'])
python=admission.provider.configuration['python']['path']
argv=[python,'-I','-B',str(admission.source_root/'qa/operator/hosted_service.py'),'run','--installation',
 p['installation']['path'],'--installation-sha256',p['installation']['sha256'],'--apply']
identity=M.runtime_identity(int(state['MainPID']),python,argv)
now=datetime.now(timezone.utc);uptime=float(pathlib.Path('/proc/uptime').read_text().split()[0])
birth=now.timestamp()-uptime+identity['start_ticks']/os.sysconf('SC_CLK_TCK')
journal=product.PrivateJournal(admission.release)
need(journal.root.is_dir(),'INERT_VERIFIER_IDLE_WITNESS_MISSING')
pending_before={d.name for d in journal.pending()}
directories=list(journal.root.glob('session-*'));need(len(directories)<=10000,'INERT_VERIFIER_JOURNAL_BOUNDS')
if p.get('session') is not None:
 directories=[d for d in directories if d.name==p['session']]
else:
 directories=sorted(directories,key=lambda d:(d/'p0001-claim.complete.json').stat().st_mtime_ns
  if (d/'p0001-claim.complete.json').exists() else 0,reverse=True)
result=None
for directory in directories:
 need(not (directory/'attention.json').exists(),'INERT_VERIFIER_ATTENTION')
 path=directory/'p0001-claim.complete.json'
 if not path.exists():continue
 header=journal.read(directory,'session.json');intent=journal.raw(directory,'p0001-claim.intent.json')
 raw_outcome=journal.raw(directory,path.name);outcome=A.parse(raw_outcome)
 need(header['release_sha256']==admission.release and header['startup_authorized'] is True
  and header['bounds']==admission.document['bounds'],'INERT_VERIFIER_IDLE_HEADER_CHANGED')
 need(A.parse(intent)=={'scope':'fox-product-verifier-step-v1','release_sha256':admission.release,
  'step':'p0001-claim','binding_sha256':None},'INERT_VERIFIER_IDLE_INTENT_CHANGED')
 need(outcome=={'scope':'fox-product-verifier-step-result-v1','release_sha256':admission.release,
  'intent_sha256':hashlib.sha256(intent).hexdigest(),'result':{'status':'IDLE'}},'INERT_VERIFIER_NOT_IDLE')
 started=datetime.fromisoformat(header['started_at_utc'].replace('Z','+00:00'));stamp=path.stat()
 need(started.tzinfo is not None and birth-5<=started.timestamp()<=now.timestamp()+5
  and -5<=now.timestamp()-stamp.st_mtime<=120 and stamp.st_mtime>=started.timestamp()-5,
  'INERT_VERIFIER_IDLE_WITNESS_STALE')
 selected_names={f.name for f in directory.iterdir()}
 need(selected_names<={'session.json','p0001-claim.intent.json',path.name,'complete.json'},
  'INERT_VERIFIER_NONIDLE_WORK_PRESENT')
 need(pending_before<={directory.name},'INERT_VERIFIER_OTHER_PENDING_SESSION')
 if (directory/'complete.json').exists():
  complete=journal.read(directory,'complete.json')
  need(complete['status']=='SESSION_COMPLETE' and complete['release_sha256']==admission.release
   and complete['completed_jobs']==[],'INERT_VERIFIER_NOT_IDLE')
  journal._check_seal(directory,complete)
 selected_files={name:hashlib.sha256(journal.raw(directory,name)).hexdigest() for name in selected_names}
 result={'identity':identity,'argv_sha256':hashlib.sha256(b'\0'.join(v.encode() for v in argv)+b'\0').hexdigest(),
  'unit_sha256':p['unit']['sha256'],'source_sha256':i['layout']['inventory']['sha256'],
  'release_sha256':admission.release,'witness':{'status':'GENUINE_NEW_VERIFIER_IDLE_CLAIM','session':directory.name,
   'claim_complete_sha256':hashlib.sha256(raw_outcome).hexdigest(),'claim_mtime_ns':stamp.st_mtime_ns}}
 need(journal.raw(directory,path.name)==raw_outcome,'INERT_VERIFIER_IDLE_WITNESS_CHANGED')
 break
need(result is not None,'INERT_VERIFIER_IDLE_WITNESS_MISSING')
pending_after={d.name for d in journal.pending()}
need(pending_after==pending_before and pending_after<={directory.name},'INERT_VERIFIER_PENDING_SET_CHANGED')
need({f.name for f in directory.iterdir()}==set(selected_files)
 and all(hashlib.sha256(journal.raw(directory,name)).hexdigest()==pin for name,pin in selected_files.items()),
 'INERT_VERIFIER_SELECTED_IDLE_SESSION_CHANGED')
need(M.runtime_identity(identity['pid'],python,argv)==identity and M.service_state(A,unit.name)==state
 and A.read(unit,private=True)==unit_raw,'INERT_VERIFIER_IDENTITY_CHANGED_DURING_READ')
print(json.dumps(result,sort_keys=True))
'''


def verifier_observation(binding):
    """Fresh protected process+idle read; never admission.check()/pump()/auth."""
    need(type(binding) is dict and set(binding) in ({'helper','support','installation','unit'},
         {'helper','support','installation','unit','session'}),'INERT_VERIFIER_BINDING_REQUIRED')
    raw=command(['systemctl','--user','show',Path(binding['unit']['path']).name,'--property=MainPID'])
    match=re.fullmatch(rb'MainPID=([0-9]+)\s*',raw)
    need(match is not None,'INERT_VERIFIER_UNIT_PID_UNKNOWN')
    pid=int(match[1])
    # Preserve the pre-existing ACTUAL caller-ancestor exclusion during its own
    # admission-before-first-claim. Only a peer gets a new exception, and that
    # requires the independently bound genuine fresh idle proof below.
    if pid==0 or pid in ancestor_pids():return None
    installation=parse(read_ref(binding['installation']))
    provider=parse(read_ref(installation['provider']))
    result=subprocess.run([provider['python']['path'],'-I','-B','-c',VERIFIER_PROBE],
        input=json.dumps(binding).encode(),capture_output=True,timeout=120,check=False)
    need(result.returncode==0 and not result.stderr.strip() and 0<len(result.stdout)<=131072,
         'INERT_PROTECTED_VERIFIER_PROBE_FAILED')
    proof=parse(result.stdout)
    if proof is not None:
        need(proof['release_sha256']==installation['release']['sha256']
             and proof['source_sha256']==installation['layout']['inventory']['sha256']
             and proof['unit_sha256']==binding['unit']['sha256'],'INERT_VERIFIER_PROOF_BINDING_CHANGED')
    return proof


def startup_baseline(value, infrastructure, source_sha256):
    """Load only this current installation's explicit private transition binding."""
    release = value['release_sha256']
    need(re.fullmatch('[a-f0-9]{64}', release))
    # Same installation-owned transition location as the existing reader.
    root = Path.home() / '.local/share/fox-project-transitions' / release
    path = safe(root / 'plan.json')
    if not path.exists():
        return None
    info = path.stat(); need(info.st_uid == os.getuid() and not info.st_mode & 0o077)
    plan = parse(path.read_bytes())
    reference = plan.get('preclaim_preservation')
    if reference is None:
        return None
    baseline = parse(read_ref(reference))
    if baseline.get('scope') not in ('fox-inert-startup-baseline-v1', 'fox-inert-startup-baseline-v2'):
        return None
    need(value['for_startup'] is True and plan['scope'] == 'fox-current-pair-transition-v2'
         and plan['schema_version'] == 2)
    installation = parse(read_ref(plan['new_installation']))
    need(installation['release']['sha256'] == release
         and installation['admission']['sha256'] == value['configuration_sha256']
         and installation['provider']['sha256'] == value['provider_configuration_sha256'])
    manifest = parse(read_ref(installation['release'])); admission = parse(read_ref(installation['admission']))
    need(manifest == value['manifest'] and admission['infrastructure'] == infrastructure)
    inventory = parse(read_ref(installation['layout']['inventory']))
    need(inventory['files']['qa/operator/paused_stage_host.py'] == source_sha256)
    profile={'path':str(safe(installation['layout']['release_root'])/'deployment/target-profile.jsn-project-v2.json'),
             'sha256':inventory['files']['deployment/target-profile.jsn-project-v2.json']}
    provider=parse(read_ref(installation['provider']))
    need(parse(read_ref(profile))==provider['target_profile'],'INERT_INSTALLED_PROVIDER_PROFILE_CHANGED')
    result = baseline, inventory['files']['fox/fox/paused_stage_preservation.py'],profile,verifier_binding(plan)
    if baseline['scope'] == 'fox-inert-startup-baseline-v2':
        return (*result, semantic_sources(inventory))
    return result


# Exact Python COPY projection of prepare_project_release.APP_RENDERER_FILES.
# The materialized-image regression enforces equality; execution-side converter
# modules are deliberately NOT installed or demanded in the FOX image.
APP_RENDERER_PY = (
    'forms2apex/__init__.py', 'forms2apex/native_blueprint.py', 'forms2apex/native.py',
    'forms2apex/native_contract.py', 'forms2apex/native_project.py', 'forms2apex/native_schema.py',
    'forms2apex/prototype_package.py', 'forms2apex/native_blueprint_required.py', 'forms2apex/blueprint_profiles.py',
    'fox_source_contract/__init__.py', 'fox_source_contract/intake.py', 'fox_source_contract/native_source.py',
    'fox_source_contract/project_conversion.py', 'defusedxml/__init__.py', 'defusedxml/common.py',
    'defusedxml/ElementTree.py')
APP_RENDERER_TEMPLATE_ROOTS = ('forms2apex/templates/native-table-v1/',
                               'forms2apex/templates/blueprint-prototype-v1/')


def semantic_sources(inventory):
    """Pin only the measured FOX package and its exact renderer COPY closure."""
    modules, templates = {}, {}
    for name, pin in inventory['files'].items():
        for prefix, package in (('fox/fox/', 'fox'), ('converter/forms2apex/', 'forms2apex'),
                                ('converter/fox_source_contract/', 'fox_source_contract'),
                                ('converter/defusedxml/', 'defusedxml')):
            if not name.startswith(prefix):continue
            relative = name[len(prefix):]
            renderer = package + '/' + relative
            if relative.endswith('.py') and (package == 'fox' or renderer in APP_RENDERER_PY):
                tail = relative[:-3]
                need('/' not in tail and tail.isidentifier(), 'INERT_SEMANTIC_NAMESPACE_INVALID')
                modules[package if tail == '__init__' else package + '.' + tail] = pin
            elif renderer.startswith(APP_RENDERER_TEMPLATE_ROOTS):
                need('..' not in PurePosixPath(relative).parts and str(PurePosixPath(relative)) == relative,
                     'INERT_SEMANTIC_NAMESPACE_INVALID')
                templates[package + '/' + relative] = pin
    need(all('converter/' + name in inventory['files'] for name in APP_RENDERER_PY)
         and all(name in modules for name in ('fox', 'forms2apex', 'fox_source_contract', 'defusedxml',
         'fox.paused_stage_preservation', 'fox.completed_prototype_preservation')) and templates
         and all(type(pin) is str and re.fullmatch('[a-f0-9]{64}', pin)
                 for pin in (*modules.values(), *templates.values())), 'INERT_SEMANTIC_NAMESPACE_INCOMPLETE')
    return {'schema_version': 1, 'scope': 'fox-inert-startup-semantic-source-v1', 'root': '/app',
            'modules': modules, 'templates': templates}


def paired(baseline, fox, receiver, identity, infrastructure, *, storage, stopped=False, verifier=None):
    """One shared measured route used by startup and transition; never a grant."""
    completed = baseline['scope'] == 'fox-inert-startup-baseline-v2'
    runtime_jobs = {job for job, item in fox['jobs'].items()
                    if item.get('boundary') in ('runtime_intent_candidate', 'completed_native_prototype')}
    if completed:
        need(set(receiver) == {'receiver', 'identities', 'requests', 'completed_packages'}
             and set(receiver['completed_packages']) == {job for job, item in fox['jobs'].items()
                 if item.get('boundary') == 'completed_native_prototype'}, 'INERT_COMPLETED_PACKAGE_SET_CHANGED')
    need(set(fox) == {'database', 'jobs', 'fox'}
         and fox == {key: baseline[key] for key in ('database', 'jobs', 'fox')}
         and receiver['receiver'] == baseline['receiver']
         and set(receiver['receiver']) == set(fox['jobs'])
         and set(receiver['identities']) == set(receiver['requests']) == runtime_jobs)
    need(all(receiver['requests'][job] == fox['jobs'][job]['runtime_request_sha256'] for job in runtime_jobs))
    host, profile = collect(baseline['runtime'], receiver['receiver'], receiver['identities'], fox['jobs'],
                            infrastructure, storage=storage, stopped=stopped, verifier=verifier,
                            **({'completed_host': baseline['completed_host']} if completed else {}))
    # Profile contents are existing nonsecret target metadata, not credentials.
    # Both actual mounted focused profile and installed converter profile must
    # independently have been checked by the caller around this measurement.
    need(identity['profile_sha256'] == hashed(profile), 'INERT_PROVIDER_PROFILE_CHANGED')
    now = datetime.now(timezone.utc)
    from datetime import timedelta
    expected = {'baseline': baseline, 'baseline_sha256': hashed(baseline), 'identity': identity}
    packet = {'schema_version': 2 if completed else 1,
              'scope': 'fox-inert-startup-paired-read-v2' if completed else 'fox-inert-startup-paired-read-v1',
              'observed_at_utc': now.isoformat(), 'expires_at_utc': (now+timedelta(seconds=30)).isoformat(),
              'binding': expected['baseline_sha256'], 'fox': fox, 'receiver': receiver['receiver'],
              'host': host, 'identity': identity}
    return {job: {'expected': expected, 'readback': packet} for job in fox['jobs']}


def metadata(path, *, directory=False):
    path = safe(path); info = path.stat()
    need(info.st_uid == os.getuid() and stat.S_IMODE(info.st_mode) == (0o700 if directory else 0o600)
         and (stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode) and info.st_nlink == 1))
    return {'device': info.st_dev, 'inode': info.st_ino, 'mode': stat.S_IMODE(info.st_mode)}


def retained_tree(root):
    """Exact historical host nodes, including every original inode; read only.

    This is deliberately stdlib-only: the host runs from measured standalone
    bytes, not a development import path or an execution-capable worker.
    """
    root = safe(root)
    def stamp(path, directory):
        info = path.lstat()
        need(not stat.S_ISLNK(info.st_mode)
             and not getattr(info, 'st_file_attributes', 0) & getattr(stat, 'FILE_ATTRIBUTE_REPARSE_POINT', 0x400)
             and (stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode) and info.st_nlink == 1)
             and (os.name == 'nt' or info.st_uid == os.getuid()
                  and stat.S_IMODE(info.st_mode) == (0o700 if directory else 0o600)),
             'INERT_COMPLETED_HOST_NODE_UNSAFE')
        return {'device': info.st_dev, 'inode': info.st_ino, 'owner': info.st_uid, 'group': info.st_gid,
                'mode': stat.S_IMODE(info.st_mode), 'links': info.st_nlink,
                'mtime_ns': info.st_mtime_ns, 'ctime_ns': info.st_ctime_ns}
    namespace = stamp(root, True)
    files, directories, total, pending = {}, {}, 0, [root]
    while pending:
        directory = pending.pop()
        for path in sorted(directory.iterdir()):
            need(len(files) + len(directories) < 20000, 'INERT_COMPLETED_HOST_TREE_BOUNDS')
            name = path.relative_to(root).as_posix()
            is_directory = stat.S_ISDIR(path.lstat().st_mode)
            before = stamp(path, is_directory)
            if is_directory:
                directories[name] = before; pending.append(path)
            else:
                size = path.stat().st_size
                need(0 < size <= 64 * 1024 * 1024, 'INERT_COMPLETED_HOST_TREE_BOUNDS')
                raw = path.read_bytes(); total += len(raw)
                need(len(raw) == size and total <= 128 * 1024 * 1024
                     and before == stamp(path, False), 'INERT_COMPLETED_HOST_TREE_CHANGED')
                files[name] = {**before, 'sha256': hashlib.sha256(raw).hexdigest(), 'bytes': len(raw)}
    need(namespace == stamp(root, True)
         and all(value == stamp(root / name, True) for name, value in directories.items()),
         'INERT_COMPLETED_HOST_TREE_CHANGED')
    return {'files': files, 'directories': directories, 'namespace': namespace}


def completed_host_read(runtime, identities, jobs, receiver, expected):
    """Bind original retained browser/staging bytes, never rerun a browser.

    The receiver's pure collector and full measured FOX child separately prove
    semantic receipts/package. Here those exact bytes are joined to original
    configured runner/producer hashes and immutable host tree identities.
    """
    completed = {job: item['completed'] for job, item in jobs.items()
                 if item.get('boundary') == 'completed_native_prototype'}
    need(type(expected) is dict and set(expected) == set(completed) and completed,
         'INERT_COMPLETED_HOST_BASELINE_REQUIRED')
    producer = 'converter/forms2apex/prototype_runtime_bridge.py'
    need(producer in runtime['sources'], 'INERT_ORIGINAL_PRODUCER_SOURCE_REQUIRED')
    original = {name: runtime['sources']['qa/' + name]
                for name in ('run-prototype.mjs', 'lib/contracts.mjs')}
    observed = {}
    for job, value in completed.items():
        need(set(expected[job]) == {'staging', 'qa'} and identities[job] == value['runtime_identity'],
             'INERT_COMPLETED_HOST_BINDING_CHANGED')
        stage_job = safe(runtime['staging_root']) / job
        stage = stage_job / 'prototype-converter'
        attempt = safe(runtime['qa_root']) / ('prototype-' + hashed(identities[job]))
        first = {'staging': retained_tree(stage_job), 'qa': retained_tree(attempt)}
        need(first == expected[job], 'INERT_COMPLETED_HOST_TREE_CHANGED')
        def object_at(path):
            raw = path.read_bytes(); need(0 < len(raw) <= 4_000_000, 'INERT_COMPLETED_HOST_JSON_BOUNDS')
            return parse(raw)
        packet = object_at(stage / 'runtime-request.json')
        request = packet['request']; identity = identities[job]
        need(packet['binding'] == identity and hashed(request) == jobs[job]['runtime_request_sha256']
             and packet['producer'] == {'component': 'fox-prototype-runtime-bridge',
                 'code_sha256': runtime['sources'][producer]}, 'INERT_COMPLETED_ORIGINAL_PRODUCER_CHANGED')
        # Staging is an intentionally small worker copy, not a second export.
        artifacts = object_at(stage / 'runtime-evidence/browser-report.json')
        report_raw = (stage / 'runtime-evidence/browser-report.json').read_bytes()
        receipt = {**artifacts, 'artifacts': [{'path': 'runtime-evidence/browser-report.json',
                    'sha256': hashlib.sha256(report_raw).hexdigest(), 'bytes': len(report_raw)}]}
        need(hashed(receipt) == value['runtime_receipt_sha256']
             and object_at(stage / 'snapshot.json') == packet['artifact_binding']
             and object_at(stage / 'import.json') == packet['imported'], 'INERT_COMPLETED_STAGING_CHANGED')
        expected_stage = {'prototype-converter/runtime-request.json', 'prototype-converter/snapshot.json',
                          'prototype-converter/import.json', 'prototype-converter/runtime-evidence/browser-report.json'}
        need(set(first['staging']['files']) == expected_stage
             and set(first['staging']['directories']) == {'prototype-converter', 'prototype-converter/runtime-evidence'},
             'INERT_COMPLETED_STAGING_EXTRA_OR_MISSING')
        receiver_files = receiver[job]['files']
        for name in expected_stage:
            published, staged = receiver_files[name], first['staging']['files'][name]
            values = {'prototype-converter/snapshot.json': packet['artifact_binding'],
                      'prototype-converter/import.json': packet['imported']}
            if name in values:
                # The worker stages project_reviews.canonical(value); gateway
                # publish() adds one LF and preserves an existing equal-object
                # canonical record. Keep BOTH actual raw fingerprints intact.
                raw = json.dumps(values[name], sort_keys=True, separators=(',', ':'),
                                 ensure_ascii=False, allow_nan=False).encode('utf-8')
                need(staged['sha256'] == hashlib.sha256(raw).hexdigest() and staged['bytes'] == len(raw)
                     and any(published['sha256'] == hashlib.sha256(candidate).hexdigest()
                             and published['bytes'] == len(candidate) for candidate in (raw, raw+b'\n')),
                     'INERT_COMPLETED_RECEIVER_STAGING_CHANGED')
            else:
                need(published['sha256'] == staged['sha256'] and published['bytes'] == staged['bytes'],
                     'INERT_COMPLETED_RECEIVER_STAGING_CHANGED')
        target = object_at(attempt / 'target.json'); intent = object_at(attempt / 'launch-intent.json')
        files = {name: hashlib.sha256((attempt / 'source' / name).read_bytes()).hexdigest() for name in original}
        expected_pages = []
        for block in request['rendering_spec']['blocks']:
            checks = (['render', 'report_columns', 'search'] + (['detail_navigation'] if block['native_component'] == 'form' else [])
                      if block['classification'] == 'database' else ['render', 'native_items'])
            expected_pages.append({'page_id': 2 * block['sequence'] - 1,
                                   'source_block_id': block['source_block_id'], 'checks': checks})
            if block['native_component'] == 'form':
                expected_pages.append({'page_id': 2 * block['sequence'], 'source_block_id': block['source_block_id'],
                    'checks': ['render', 'native_items', 'create', 'update', 'synthetic_records_accounted'] +
                    (['additional_required_input_validation'] if request['rendering_spec']['profile_id'] ==
                     'native-blueprint-prototype-required-v1' else [])})
        authority = target.get('credential_authority')
        authority_hashes = {'credentials_sha256', 'username_sha256', 'authorization_reference_sha256'}
        need(type(authority) is dict and set(authority) == {'schema_version', 'scope', 'workspace', 'db_name',
             'ords_origin'} | authority_hashes and type(authority['schema_version']) is int
             and authority['schema_version'] == 1 and authority['scope'] == 'fox-prototype-runtime-credentials-target-v1'
             and all(authority[key] == packet['target'][key] for key in ('workspace', 'db_name', 'ords_origin'))
             and all(type(authority[key]) is str and re.fullmatch('[a-f0-9]{64}', authority[key])
                     for key in authority_hashes), 'INERT_COMPLETED_BROWSER_CREDENTIAL_BINDING_CHANGED')
        need(set(target) == {'binding', 'spec', 'trace', 'pages', 'credential_authority', 'runner_files', 'code_sha256',
             'image_id', 'data_retention', 'deadline_at_utc', 'request_deadline_at_utc', 'url'}
             and target['pages'] == expected_pages and target['data_retention'] == 'synthetic_test_rows_retained'
             and target['url'] == packet['target']['ords_origin'] + '/ords/r/forms2apex_poc/' +
                 packet['imported']['application_alias'].lower() + '/'
             and files == original and target.get('binding') == identity and target.get('spec') == request['rendering_spec']
             and target.get('trace') == packet['trace'] and target.get('runner_files') == original
             and target.get('code_sha256') == hashed(original) and target.get('image_id') == runtime['qa_image']
             and target.get('request_deadline_at_utc') == packet['deadline_at_utc'],
             'INERT_COMPLETED_BROWSER_TARGET_CHANGED')
        need(intent == {'binding': identity, 'code_sha256': hashed(original), 'image_id': runtime['qa_image'],
             'state': 'ATTEMPT_STARTED_NO_AUTOMATIC_REPLAY', 'deadline_at_utc': target.get('deadline_at_utc'),
             'request_deadline_at_utc': packet['deadline_at_utc']}, 'INERT_COMPLETED_BROWSER_INTENT_CHANGED')
        need(artifacts.get('runner') == {'kind': 'authenticated_browser', 'tool': 'playwright',
             'code_sha256': hashed(original), 'image_id': runtime['qa_image']}, 'INERT_COMPLETED_BROWSER_REPORT_CHANGED')
        times = [datetime.fromisoformat(v.replace('Z', '+00:00')) for v in
                 (packet['issued_at_utc'], artifacts['started_at_utc'], artifacts['completed_at_utc'],
                  target['deadline_at_utc'], packet['deadline_at_utc'])]
        need(all(v.tzinfo is not None and v.utcoffset().total_seconds() == 0 for v in times)
             and times == sorted(times) and 0 < (times[-1] - times[0]).total_seconds() <= 540,
             'INERT_COMPLETED_HISTORICAL_DEADLINE_CHANGED')
        ledger_names = set(); sequence = 0
        rows = {row['source_block_id']: row for row in artifacts['retained_rows']}
        for block in request['rendering_spec']['blocks']:
            if block['native_component'] != 'form':
                continue
            row = rows[block['source_block_id']]
            required = next((field for field in block['fields']
                             if field['in_edit_form'] and field.get('value_required')), None)
            if request['rendering_spec']['profile_id'] == 'native-blueprint-prototype-required-v1' and required:
                sequence += 1; name = 'required-input-' + str(sequence).zfill(3) + '.json'; ledger_names.add(name)
                need(object_at(attempt / name) == {'binding': identity, 'source_block_id': block['source_block_id'],
                    'source_item_id': required['source_item_id'],
                    'state': 'INVALID_SUBMIT_ATTEMPT_STARTED_NO_AUTOMATIC_REPLAY'},
                    'INERT_COMPLETED_REQUIRED_INPUT_INTENT_CHANGED')
            for button, key in (('Create', None), ('Save Changes', row['primary_key'])):
                sequence += 1; name = 'write-' + str(sequence).zfill(3) + '.json'; ledger_names.add(name)
                write = object_at(attempt / name)
                need(type(write) is dict and set(write) == {'binding', 'source_block_id', 'table_name', 'button',
                     'primary_key', 'intended_values_sha256', 'state'}
                     and write == {'binding': identity, 'source_block_id': block['source_block_id'],
                         'table_name': block['table_name'], 'button': button, 'primary_key': key,
                         'intended_values_sha256': write.get('intended_values_sha256'),
                         'state': 'ATTEMPT_STARTED_NO_AUTOMATIC_REPLAY'}
                     and type(write['intended_values_sha256']) is str
                     and re.fullmatch('[a-f0-9]{64}', write['intended_values_sha256']),
                     'INERT_COMPLETED_WRITE_INTENT_CHANGED')
        need(object_at(attempt / 'progress.json') == artifacts, 'INERT_COMPLETED_BROWSER_PROGRESS_CHANGED')
        need(set(first['qa']['files']) == {'target.json', 'launch-intent.json', 'progress.json',
                 'source/run-prototype.mjs', 'source/lib/contracts.mjs'} | ledger_names
             and set(first['qa']['directories']) == {'source', 'source/lib'}, 'INERT_COMPLETED_BROWSER_EXTRA_OR_MISSING')
        need(first == {'staging': retained_tree(stage_job), 'qa': retained_tree(attempt)},
             'INERT_COMPLETED_HOST_TREE_CHANGED')
        observed[job] = first
    return observed


def effective_unit(runtime, config):
    service = runtime['service']
    need(type(service) is str and re.fullmatch('[A-Za-z0-9_.-]+\\.service', service))
    raw = command(['systemctl', '--user', 'show', service,
        '--property=FragmentPath,ActiveState,SubState,MainPID,WorkingDirectory,Environment,ExecStart,DropInPaths'])
    value = dict(line.split('=', 1) for line in raw.decode().splitlines() if '=' in line)
    need(value.get('FragmentPath') == runtime['unit']['path'] and value.get('DropInPaths') == ''
         and value.get('MainPID') == '0' and value.get('ActiveState') == 'inactive'
         and value.get('SubState') == 'dead' and value.get('WorkingDirectory') == runtime['source_root']
         and 'FOX_PROTOTYPE_HOST_CONFIG=' + runtime['config']['path'] in value.get('Environment', '').split()
         and 'path=' + runtime['python']['path'] + ' ;' in value.get('ExecStart', '')
         and '-m qa.operator.prototype_host' in value['ExecStart'], 'INERT_RUNTIME_UNIT_NOT_IDLE_OR_BOUND')
    # Config is metadata only. No configure(), auth callback or credential read.
    need(config['scope'] == 'fox-prototype-host-v1' and config['schema_version'] == 1
         and config['jobs_root'] == runtime['receiver_jobs']
         and config['staging_jobs_root'] == runtime['staging_root'] and config['qa_root'] == runtime['qa_root']
         and config['image_id'] == runtime['qa_image']
         and config['target_profile_file'] == runtime['profile']['path']
         and config['target_profile_sha256'] == runtime['profile']['sha256'])
    return value


def ancestor_pids():
    allowed = {os.getpid()}; pid = os.getppid()
    while pid > 1 and pid not in allowed:
        allowed.add(pid)
        text = (Path('/proc') / str(pid) / 'stat').read_text()
        pid = int(text.rsplit(')', 1)[1].split()[1])
    return allowed


def launcher_process(pid):
    """Bounded /proc identity read, including PID birth; never environment."""
    need(type(pid) is int and pid > 1, 'INERT_LAUNCHER_PID_INVALID')
    root=Path('/proc')/str(pid)
    def read():
        fields=(root/'stat').read_text().rsplit(')',1)[1].split()
        raw=(root/'cmdline').read_bytes();status=(root/'status').read_text()
        groups=(root/'cgroup').read_text().splitlines()
        uid=re.search(r'^Uid:\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s*$',status,re.M)
        need(uid is not None and all(int(value)==os.getuid() for value in uid.groups())
             and 0<len(raw)<=16384 and raw.endswith(b'\0') and len(groups)<=64
             and all(len(line)<=2048 for line in groups), 'INERT_LAUNCHER_PROCESS_INVALID')
        return {'pid':pid,'start_ticks':int(fields[19]),'uid':int(uid[1]),
            'executable':os.readlink(root/'exe'),'argv':[arg.decode('ascii') for arg in raw[:-1].split(b'\0')],
            'cgroups':groups,'command_sha256':hashlib.sha256(raw).hexdigest()}
    first=read();need(first==read(), 'INERT_LAUNCHER_PROCESS_CHANGED')
    need(first['start_ticks']>0, 'INERT_LAUNCHER_PROCESS_INVALID')
    return first


def pair_launchers(items, infrastructure, *, stopped=False):
    """Attribute only actual fixed-pair systemd attach MainPIDs, not descendants."""
    proofs=[]
    for name in ('fox','forms2apex-mcp'):
        unit=name+'.service';pin=infrastructure[name]
        matches=[item for item in items if item['Id']==pin['id']]
        need(len(matches)==1, 'INERT_LAUNCHER_CONTAINER_MISSING')
        item=matches[0]
        need(item['Image'].removeprefix('sha256:')==pin['image'].removeprefix('sha256:')
             and type(item.get('Name')) is str and re.fullmatch('[A-Za-z0-9][A-Za-z0-9_.-]{0,127}',item['Name']),
             'INERT_LAUNCHER_CONTAINER_CHANGED')
        def service():
            raw=command(['systemctl','--user','show',unit,
                '--property=Id,LoadState,ActiveState,SubState,MainPID,ControlGroup,ExecStart,FragmentPath,DropInPaths'])
            rows=[line.split('=',1) for line in raw.decode().splitlines()]
            need(all(len(row)==2 for row in rows) and len({row[0] for row in rows})==len(rows),
                 'INERT_LAUNCHER_UNIT_INVALID')
            value=dict(rows)
            need(set(value)=={'Id','LoadState','ActiveState','SubState','MainPID','ControlGroup','ExecStart','FragmentPath','DropInPaths'}
                 and value['Id']==unit and value['LoadState']=='loaded' and value['DropInPaths']==''
                 and value['FragmentPath']==str(Path.home()/'.config/systemd/user'/unit), 'INERT_LAUNCHER_UNIT_INVALID')
            return value
        state=service()
        if stopped:
            need(state['ActiveState']=='inactive' and state['SubState']=='dead' and state['MainPID']=='0'
                 and item['State']['Running'] is False and item['State']['Pid']==0,
                 'INERT_STOPPED_PAIR_LAUNCHER_PRESENT')
            identity=None
            target='(?:'+re.escape(pin['id'])+'|'+re.escape(item['Name'])+')'
            need(re.fullmatch(r'\{ path=/usr/bin/podman ; argv\[\]=/usr/bin/podman start --attach '+target+
                 r' ; ignore_errors=no ; start_time=\[[^\]\r\n]*\] ; stop_time=\[[^\]\r\n]*\] ; pid=[0-9]{1,10}'
                 r' ; code=[A-Za-z0-9()_-]+ ; status=[A-Za-z0-9/_-]+ \}',state['ExecStart']) is not None,
                 'INERT_LAUNCHER_EXECSTART_CHANGED')
        else:
            need(state['ActiveState']=='active' and state['SubState']=='running'
                 and re.fullmatch('[1-9][0-9]{0,9}',state['MainPID'])
                 and item['State']['Running'] is True and item['State']['Pid']>0,
                 'INERT_LAUNCHER_UNIT_NOT_RUNNING')
            pid=int(state['MainPID']);identity=launcher_process(pid)
            group=state['ControlGroup']
            need(group.startswith('/') and str(PurePosixPath(group))==group and '..' not in PurePosixPath(group).parts
                 and PurePosixPath(group).name==unit
                 and ('0::'+group in identity['cgroups'] or any(re.fullmatch('[0-9]+:name=systemd:'+re.escape(group),line)
                     for line in identity['cgroups'])), 'INERT_LAUNCHER_CGROUP_CHANGED')
            argv=identity['argv']
            need(identity['pid']==pid and identity['uid']==os.getuid() and identity['start_ticks']>0
                 and identity['executable']=='/usr/bin/podman' and len(argv)==4
                 and argv[:3]==['/usr/bin/podman','start','--attach'] and argv[3] in {pin['id'],item['Name']},
                 'INERT_LAUNCHER_ARGV_CHANGED')
            # systemctl renders one structured ExecStart. No shell parsing,
            # alternate executable, extra command or extra option is accepted.
            expected=r'\{ path=/usr/bin/podman ; argv\[\]='+re.escape(' '.join(argv))+r' ; ignore_errors=no ; '
            # Podman's user-unit ExecStart metadata legitimately retains pid=0;
            # only independently observed MainPID + /proc birth grants exclusion.
            expected+=r'start_time=\[[^\]\r\n]*\] ; stop_time=\[[^\]\r\n]*\] ; pid=(?:0|'+str(pid)+')'
            expected+=r' ; code=[A-Za-z0-9()_-]+ ; status=[A-Za-z0-9/_-]+ \}'
            need(re.fullmatch(expected,state['ExecStart']) is not None, 'INERT_LAUNCHER_EXECSTART_CHANGED')
            need(launcher_process(pid)==identity, 'INERT_LAUNCHER_PROCESS_CHANGED')
        need(service()==state, 'INERT_LAUNCHER_SERVICE_CHANGED')
        proofs.append({'service':unit,'state':state,'identity':identity,
                       'container_id':pin['id'],'container_image':pin['image'],'container_name':item['Name']})
    return proofs


def process_inventory(container_roots, *, verifier=None, launchers=()):
    """Actual own-UID producer inventory. Unknown Python/Node/engine work blocks."""
    allowed=ancestor_pids()
    rows = []
    for entry in Path('/proc').iterdir():
        if not entry.name.isdigit() or int(entry.name) in allowed:
            continue
        try:
            status = (entry / 'status').read_text()
            uid = re.search(r'^Uid:\s+(\d+)', status, re.M)
            if not uid or int(uid[1]) != os.getuid():
                continue
            name = (entry / 'comm').read_text().strip()
            if not any(word in name.lower() for word in ('python', 'node', 'podman', 'conmon', 'timeout')):
                continue
            raw = (entry / 'cmdline').read_bytes()
            ticks = int((entry / 'stat').read_text().rsplit(')', 1)[1].split()[19])
            launcher=[row['identity'] for row in launchers if row['identity'] is not None
                      and row['identity']['pid']==int(entry.name)]
            if launcher:
                need(len(launcher)==1 and ticks==launcher[0]['start_ticks']
                     and hashlib.sha256(raw).hexdigest()==launcher[0]['command_sha256']
                     and launcher_process(int(entry.name))==launcher[0], 'INERT_LAUNCHER_PROCESS_CHANGED')
                continue
            if verifier is not None and int(entry.name)==verifier['identity']['pid']:
                need(ticks==verifier['identity']['start_ticks']
                     and hashlib.sha256(raw).hexdigest()==verifier['argv_sha256'],
                     'INERT_VERIFIER_PROCESS_CHANGED')
                continue
            # Attribute current container descendants by actual inspected host
            # PID/ConmonPid and /proc ancestry, not Python/Node language alone.
            ancestor = int(entry.name); seen = set()
            while ancestor > 1 and ancestor not in seen and ancestor not in container_roots:
                seen.add(ancestor)
                ancestor = int((Path('/proc') / str(ancestor) / 'stat').read_text().rsplit(')', 1)[1].split()[1])
            if ancestor in container_roots:continue
            rows.append({'pid': int(entry.name), 'start_ticks': ticks,
                         'command_sha256': hashlib.sha256(raw).hexdigest()})
        except FileNotFoundError:
            continue
    return sorted(rows, key=lambda row: row['pid'])


def lock_holders(root):
    lock = safe(root) / 'runtime-worker.lock'
    need(not lock.is_symlink())
    if not lock.exists():
        return []
    identity = metadata(lock); text = Path('/proc/locks').read_text()
    need(len(text) <= 2_000_000)
    rows = []
    for line in text.splitlines():
        for field in line.split():
            match = re.fullmatch('([a-fA-F0-9]+):([a-fA-F0-9]+):([0-9]+)', field)
            if match and (int(match[1], 16), int(match[2], 16), int(match[3])) == (
                    os.major(identity['device']), os.minor(identity['device']), identity['inode']):
                rows.append(line)
    return rows


def overlaps(left, right):
    """Both-direction lexical overlap of measured canonical absolute mount roots."""
    a,b=PurePosixPath(left),PurePosixPath(right)
    need(a.is_absolute() and b.is_absolute() and str(a)==left and str(b)==right
         and '..' not in a.parts and '..' not in b.parts,'INERT_MOUNT_PATH_UNKNOWN')
    return a==b or a in b.parents or b in a.parents


def collect(runtime, receiver, identities, jobs, infrastructure, *, storage, stopped=False, verifier=None,
            completed_host=None):
    """Measure configured sources, roots, effective service, processes and engine.

    Historical unknown outcomes are NOT interpreted. Old unrelated stopped QA
    containers are retained only with exact inspection showing no bound mounts
    and finish before every paused job's creation. Unknown/live producers reject.
    """
    need(os.name == 'posix' and os.getuid() > 0, 'INERT_POSIX_HOST_REQUIRED')
    need(type(storage) is dict and set(storage)=={'fox_data','receiver_jobs'}
         and storage['receiver_jobs']==runtime['receiver_jobs'],'INERT_INDEPENDENT_STORAGE_BINDING_REQUIRED')
    need(type(runtime) is dict and set(runtime) == {'config', 'unit', 'python', 'profile', 'source_root',
        'sources', 'receiver_jobs', 'staging_root', 'qa_root', 'qa_image', 'service', 'other_containers'})
    refs = [runtime[key] for key in ('config', 'unit', 'python', 'profile')]
    refs += [{'path': str(safe(runtime['source_root']) / name), 'sha256': pin}
             for name, pin in runtime['sources'].items()]
    need(set(runtime['sources']) >= {'qa/operator/prototype_host.py', 'qa/operator/prototype_runtime_worker.py',
        'qa/operator/prototype_browser.py', 'qa/run-prototype.mjs', 'qa/lib/contracts.mjs'})
    need(all(type(name) is str and re.fullmatch('[A-Za-z0-9_./-]+\\.(?:py|mjs)',name)
             and not name.startswith('/') and not set(name.split('/')) & {'','.', '..'} for name in runtime['sources']))
    first_bytes = [read_ref(ref) for ref in refs]
    config = parse(first_bytes[0]); profile = parse(first_bytes[3])
    need(re.fullmatch('[a-f0-9]{64}',config['converter_id'])
         and re.fullmatch('sha256:[a-f0-9]{64}',config['converter_image']))
    staging = safe(runtime['staging_root']); qa = safe(runtime['qa_root'])
    staging_identity = metadata(staging, directory=True); qa_identity = metadata(qa, directory=True)
    completed = {job for job, item in jobs.items() if item.get('boundary') == 'completed_native_prototype'}
    runtime_jobs = {job for job, item in jobs.items()
                    if item.get('boundary') in ('runtime_intent_candidate', 'completed_native_prototype')}
    need(set(identities) == runtime_jobs and set(receiver) == set(jobs), 'INERT_RUNTIME_SUBSET_CHANGED')
    need((completed_host is None and not completed) or
         type(completed_host) is dict and set(completed_host) == completed and completed,
         'INERT_COMPLETED_HOST_BASELINE_REQUIRED')
    attempts = {job: qa / ('prototype-' + hashed(identities[job])) for job in runtime_jobs}
    for job in jobs:
        if job in completed:
            continue
        for path in [staging / job] + ([attempts[job]] if job in attempts else []):
            need(not path.exists() and not path.is_symlink(), 'INERT_HOST_ATTEMPT_PRESENT')
    def retained():
        if not completed:
            return None
        # Unknown siblings may still be producers/history; never select fresh
        # empty roots to hide the configured originals or adopt extra attempts.
        need({path.name for path in staging.iterdir()} <= completed | {'runtime-worker.lock'}
             and {path.name for path in qa.iterdir()} == {attempts[job].name for job in completed},
             'INERT_UNCLASSIFIED_HOST_ATTEMPT_PRESENT')
        return completed_host_read(runtime, identities, jobs, receiver, completed_host)
    retained_before = retained()
    oldest = min(row['row']['created'] for row in jobs.values())
    verifier_ref=dict(verifier) if verifier is not None else None
    def current_verifier():
        proof=verifier_observation(verifier_ref) if verifier_ref is not None else None
        if proof is not None:verifier_ref['session']=proof['witness']['session']
        return proof
    def snapshot():
        ids = command(['podman', '--remote=false', 'ps', '-aq', '--no-trunc']).decode().split()
        need(0 < len(ids) <= 256 and len(set(ids)) == len(ids)
             and all(re.fullmatch('[a-f0-9]{64}', identity) for identity in ids))
        # Never fetch arbitrary container Config/Env or health logs: unrelated
        # containers may carry credentials. Only producer/mount metadata crosses
        # this boundary. This Podman exposes the template field as .ID.
        fmt=('{'+'"Id":{{json .ID}},"Name":{{json .Name}},"Image":{{json .Image}},"State":{'
             '"Running":{{json .State.Running}},"Pid":{{json .State.Pid}},'
             '"ConmonPid":{{json .State.ConmonPid}},"Status":{{json .State.Status}},'
             '"FinishedAt":{{json .State.FinishedAt}}},"Mounts":['
             '{{range $i,$m := .Mounts}}{{if $i}},{{end}}'
             '{"Source":{{json $m.Source}},"Destination":{{json $m.Destination}},'
             '"Type":{{json $m.Type}},"RW":{{json $m.RW}}}{{end}}]}')
        raw=command(['podman', '--remote=false', 'inspect', *sorted(ids),'--format',fmt])
        items=[parse(line) for line in raw.splitlines() if line.strip()]
        need(type(items) is list and sorted(item['Id'] for item in items) == sorted(ids))
        original=[item for item in items if item['Id']==config['converter_id']]
        need(len(original)==1 and original[0]['Image'].removeprefix('sha256:')==config['converter_image'][7:]
             and any(mount['Source']==runtime['receiver_jobs'] and mount['Destination']=='/opt/forms2apex/outputs/jobs'
                     for mount in original[0]['Mounts']), 'INERT_RUNTIME_RECEIVER_BINDING_UNKNOWN')
        # An upgraded pair may retain the original (now stopped) host config.
        # Observe that exact old receiver as stopped; never rewrite/rebind it or
        # pretend it can dispatch against the new pair. Runtime readiness is NOT
        # claimed. If it is still live and is not the actual pair, fail closed.
        if config['converter_id']!=infrastructure['forms2apex-mcp']['id']:
            need(original[0]['State']['Running'] is False and original[0]['State']['Pid']==0
                 and original[0]['State']['Status'] in ('stopped','exited'), 'INERT_OLD_RUNTIME_RECEIVER_STILL_LIVE')
        allowed = {pin['id']: pin['image'] for pin in infrastructure.values()}
        for pin in runtime['other_containers']:
            need(set(pin) == {'id', 'image'} and pin['id'] not in allowed)
            allowed[pin['id']] = pin['image']
        container_roots, result = [], []
        roots = [str(staging / job) for job in jobs] + [str(path) for path in attempts.values()]
        protected=[storage['fox_data'],storage['receiver_jobs'],str(staging),str(qa)]
        pair_mounts={infrastructure['fox']['id']:('/data',storage['fox_data']),
                     infrastructure['forms2apex-mcp']['id']:('/opt/forms2apex/outputs/jobs',storage['receiver_jobs'])}
        for item in items:
            state = item['State']; image = item['Image']
            image = image if image.startswith('sha256:') else 'sha256:' + image
            sources = [mount['Source'] for mount in item['Mounts']]
            need(not any((overlaps(source, root) if completed else source == root or source.startswith(root + '/'))
                         for source in sources for root in roots),
                 'INERT_BOUND_QA_CONTAINER_PRESENT')
            if state['Running']:
                expected=pair_mounts.get(item['Id'])
                if expected is not None:
                    legitimate=[mount for mount in item['Mounts'] if mount['Destination']==expected[0]]
                    need(len(legitimate)==1 and legitimate[0]['Source']==expected[1]
                         and legitimate[0].get('Type')=='bind' and legitimate[0].get('RW') is True,
                         'INERT_PAIR_PERSISTENT_MOUNT_CHANGED')
                for mount in item['Mounts']:
                    if any(overlaps(mount['Source'],root) for root in protected):
                        need(expected is not None and mount['Destination']==expected[0]
                             and mount['Source']==expected[1] and mount.get('Type')=='bind'
                             and mount.get('RW') is True,'INERT_NONPAIR_OR_EXTRA_PERSISTENT_MOUNT')
            if item['Id'] in allowed:
                need(image == allowed[item['Id']], 'INERT_CONTAINER_IDENTITY_CHANGED')
                if item['Id'] in {infrastructure[n]['id'] for n in ('fox', 'forms2apex-mcp')}:
                    need(state['Running'] is (not stopped) and (state['Pid'] == 0 if stopped else state['Pid'] > 0))
                if state['Running']:
                    need(image!=runtime['qa_image'],'INERT_LIVE_QA_PRODUCER')
                    need(type(state.get('ConmonPid')) is int and state['ConmonPid'] > 0,
                         'INERT_CONMON_ATTRIBUTION_UNAVAILABLE')
                    container_roots.extend((state['ConmonPid'],state['Pid']))
            else:
                need(state['Running'] is False and state['Pid'] == 0 and state['Status'] in ('exited', 'stopped', 'created'),
                     'INERT_UNKNOWN_LIVE_PRODUCER')
                if image == runtime['qa_image'] and state['Status'] != 'created':
                    finished = datetime.fromisoformat(state['FinishedAt'].replace('Z', '+00:00')).timestamp()
                    need(finished < oldest, 'INERT_UNATTRIBUTED_QA_CONTAINER')
            result.append({'id': item['Id'], 'image': image, 'state': state,
                           'mounts_sha256': hashed(item['Mounts'])})
        need(set(allowed) <= set(ids), 'INERT_EXPECTED_CONTAINER_MISSING')
        if not stopped:
            top=command(['podman','--remote=false','top',infrastructure['forms2apex-mcp']['id'],'pid']).decode().splitlines()
            need(len(top)==2 and top[1].strip()=='1','INERT_RECEIVER_OPERATION_PRESENT')
        launchers=pair_launchers(items,infrastructure,stopped=stopped)
        proof=current_verifier()
        processes = process_inventory(container_roots,verifier=proof,launchers=launchers); locks = lock_holders(staging)
        need(pair_launchers(items,infrastructure,stopped=stopped)==launchers,'INERT_LAUNCHER_OBSERVATION_CHANGED')
        again=current_verifier()
        need(proof==again,'INERT_VERIFIER_OBSERVATION_CHANGED')
        need(not processes and not locks, 'INERT_ACTIVE_OR_UNKNOWN_HOST_PRODUCER')
        return {'containers': result, 'processes': processes, 'locks': locks,
                'unit': effective_unit(runtime, config),'verifier':proof,'pair_launchers':launchers}
    first = snapshot(); second = snapshot()
    need(first == second and [read_ref(ref) for ref in refs] == first_bytes
         and metadata(staging, directory=True) == staging_identity and metadata(qa, directory=True) == qa_identity,
         'INERT_HOST_CHANGED_DURING_READ')
    for job in jobs:
        if job in completed:
            continue
        need(not (staging / job).exists() and not (staging / job).is_symlink(), 'INERT_HOST_ATTEMPT_PRESENT')
    for job, path in attempts.items():
        if job in completed:
            continue
        need(not path.exists() and not path.is_symlink(), 'INERT_HOST_ATTEMPT_PRESENT')
    need(retained_before == retained(), 'INERT_COMPLETED_HOST_TREE_CHANGED')
    return {'runtime_sha256': hashed(runtime), 'receiver_sha256': hashed(receiver),
            'observation_sha256': hashed(first), 'blockers': [],
            **({'completed_host_sha256': hashed(retained_before)} if completed else {})}, profile
