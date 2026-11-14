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
    if baseline.get('scope') != 'fox-inert-startup-baseline-v1':
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
    return baseline, inventory['files']['fox/fox/paused_stage_preservation.py'],profile,verifier_binding(plan)


def paired(baseline, fox, receiver, identity, infrastructure, *, storage, stopped=False, verifier=None):
    """One shared measured route used by startup and transition; never a grant."""
    runtime_jobs = {job for job, item in fox['jobs'].items() if item.get('boundary') == 'runtime_intent_candidate'}
    need(set(fox) == {'database', 'jobs', 'fox'}
         and fox == {key: baseline[key] for key in ('database', 'jobs', 'fox')}
         and receiver['receiver'] == baseline['receiver']
         and set(receiver['receiver']) == set(fox['jobs'])
         and set(receiver['identities']) == set(receiver['requests']) == runtime_jobs)
    need(all(receiver['requests'][job] == fox['jobs'][job]['runtime_request_sha256'] for job in runtime_jobs))
    host, profile = collect(baseline['runtime'], receiver['receiver'], receiver['identities'], fox['jobs'],
                            infrastructure, storage=storage, stopped=stopped, verifier=verifier)
    # Profile contents are existing nonsecret target metadata, not credentials.
    # Both actual mounted focused profile and installed converter profile must
    # independently have been checked by the caller around this measurement.
    need(identity['profile_sha256'] == hashed(profile), 'INERT_PROVIDER_PROFILE_CHANGED')
    now = datetime.now(timezone.utc)
    from datetime import timedelta
    expected = {'baseline': baseline, 'baseline_sha256': hashed(baseline), 'identity': identity}
    packet = {'schema_version': 1, 'scope': 'fox-inert-startup-paired-read-v1',
              'observed_at_utc': now.isoformat(), 'expires_at_utc': (now+timedelta(seconds=30)).isoformat(),
              'binding': expected['baseline_sha256'], 'fox': fox, 'receiver': receiver['receiver'],
              'host': host, 'identity': identity}
    return {job: {'expected': expected, 'readback': packet} for job in fox['jobs']}


def metadata(path, *, directory=False):
    path = safe(path); info = path.stat()
    need(info.st_uid == os.getuid() and stat.S_IMODE(info.st_mode) == (0o700 if directory else 0o600)
         and (stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode) and info.st_nlink == 1))
    return {'device': info.st_dev, 'inode': info.st_ino, 'mode': stat.S_IMODE(info.st_mode)}


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


def process_inventory(container_roots, *, verifier=None):
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


def collect(runtime, receiver, identities, jobs, infrastructure, *, storage, stopped=False, verifier=None):
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
    runtime_jobs = {job for job, item in jobs.items() if item.get('boundary') == 'runtime_intent_candidate'}
    need(set(identities) == runtime_jobs and set(receiver) == set(jobs), 'INERT_RUNTIME_SUBSET_CHANGED')
    attempts = {job: qa / ('prototype-' + hashed(identities[job])) for job in runtime_jobs}
    for job in jobs:
        for path in [staging / job] + ([attempts[job]] if job in attempts else []):
            need(not path.exists() and not path.is_symlink(), 'INERT_HOST_ATTEMPT_PRESENT')
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
        fmt=('{'+'"Id":{{json .ID}},"Image":{{json .Image}},"State":{'
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
            need(not any(source == root or source.startswith(root + '/') for source in sources for root in roots),
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
        proof=current_verifier()
        processes = process_inventory(container_roots,verifier=proof); locks = lock_holders(staging)
        again=current_verifier()
        need(proof==again,'INERT_VERIFIER_OBSERVATION_CHANGED')
        need(not processes and not locks, 'INERT_ACTIVE_OR_UNKNOWN_HOST_PRODUCER')
        return {'containers': result, 'processes': processes, 'locks': locks,
                'unit': effective_unit(runtime, config),'verifier':proof}
    first = snapshot(); second = snapshot()
    need(first == second and [read_ref(ref) for ref in refs] == first_bytes
         and metadata(staging, directory=True) == staging_identity and metadata(qa, directory=True) == qa_identity,
         'INERT_HOST_CHANGED_DURING_READ')
    for job in jobs:
        need(not (staging / job).exists() and not (staging / job).is_symlink(), 'INERT_HOST_ATTEMPT_PRESENT')
    for path in attempts.values():
        need(not path.exists() and not path.is_symlink(), 'INERT_HOST_ATTEMPT_PRESENT')
    return {'runtime_sha256': hashed(runtime), 'receiver_sha256': hashed(receiver),
            'observation_sha256': hashed(first), 'blockers': []}, profile
