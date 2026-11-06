"""Protected current-I prewrite failure closure; no service or Oracle operations.

Run with the installed host Python, outside the immutable installation. The
protected canonical plan pins this controller, the original activation helper,
current installation, reviewed assessment and three separate overlay sources.
The original namespace owns the real OS lease. Only the exact recovery reader
is overlaid in a transient container child; installed files remain untouched.
Inspect is read-only. Apply first exports a SQLite online backup, all current-I
reference bytes and the exact 22/17/13 capture, then initializes/appends once.
An uncertain reply requires inspect, never an automatic second apply.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import importlib.util
import json
import os
from pathlib import Path, PurePosixPath
import re
import select
import stat
import subprocess
import sys
import time
import types

sys.dont_write_bytecode = True
SCOPE = 'fox-current-project-prewrite-closure-v1'
SHA = re.compile(r'[a-f0-9]{64}\Z')
REFS = ('helper', 'installation', 'assessment', 'recovery', 'classifier', 'project_contracts')


class ClosureError(RuntimeError):
    """Closed diagnostic categories, never captured payloads or child stderr."""


def need(ok, code):
    if not ok:
        raise ClosureError(code)


def canonical(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False,
                       allow_nan=False) + '\n').encode()


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def document(raw):
    def unique(pairs):
        value = {}
        for key, item in pairs:
            need(key not in value, 'CLOSURE_DUPLICATE_JSON_KEY')
            value[key] = item
        return value
    return json.loads(raw, object_pairs_hook=unique,
                      parse_constant=lambda _: (_ for _ in ()).throw(ValueError()))


def absolute(value):
    need(type(value) is str and 1 < len(value) <= 1024 and '\\' not in value
         and not any(ord(c) < 32 for c in value), 'CLOSURE_ABSOLUTE_PATH_REQUIRED')
    p = PurePosixPath(value)
    need(p.is_absolute() and str(p) == value and '..' not in p.parts,
         'CLOSURE_ABSOLUTE_PATH_REQUIRED')
    return Path(value)


def protected_read(path, *, private=False, maximum=16_000_000):
    path = absolute(str(path))
    for part in (path, *path.parents):
        info = part.lstat()
        sticky_root = part != path and stat.S_ISDIR(info.st_mode) and info.st_uid == 0 and info.st_mode & stat.S_ISVTX
        need(not stat.S_ISLNK(info.st_mode) and info.st_uid in (0, os.geteuid())
             and (not stat.S_IMODE(info.st_mode) & 0o022 or sticky_root), 'CLOSURE_UNTRUSTED_PATH')
    info = path.lstat()
    need(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and 0 < info.st_size <= maximum,
         'CLOSURE_INPUT_BOUND')
    if private:
        need(info.st_uid == os.geteuid() and stat.S_IMODE(info.st_mode) == 0o600, 'CLOSURE_PRIVATE_INPUT_REQUIRED')
    with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW), 'rb') as stream:
        opened = os.fstat(stream.fileno()); raw = stream.read(maximum + 1); after = os.fstat(stream.fileno())
    fields = ('st_dev', 'st_ino', 'st_size', 'st_mtime_ns', 'st_ctime_ns')
    need(len(raw) == info.st_size and all(getattr(info, k) == getattr(opened, k) == getattr(after, k)
         == getattr(path.lstat(), k) for k in fields), 'CLOSURE_INPUT_CHANGED')
    return raw


def plan_document(raw, expected):
    need(type(raw) is bytes and len(raw) <= 65536 and type(expected) is str
         and SHA.fullmatch(expected) and sha(raw) == expected, 'CLOSURE_EXACT_PLAN_REQUIRED')
    p = document(raw)
    need(type(p) is dict and set(p) == {'schema_version', 'scope', 'controller_sha256', 'export', *REFS}
         and type(p['schema_version']) is int and p['schema_version'] == 1 and p['scope'] == SCOPE
         and type(p['controller_sha256']) is str and SHA.fullmatch(p['controller_sha256'])
         and canonical(p) == raw, 'CLOSURE_PLAN_FIELDS')
    for key in REFS:
        ref = p[key]
        need(type(ref) is dict and set(ref) == {'path', 'sha256'} and type(ref['sha256']) is str
             and SHA.fullmatch(ref['sha256']), 'CLOSURE_REFERENCE_INVALID')
        absolute(ref['path'])
    absolute(p['export'])
    return p


def load(name, raw, path):
    module = types.ModuleType(name); module.__file__ = str(path); module.__package__ = name.rpartition('.')[0]
    sys.modules[name] = module
    exec(compile(raw, str(path), 'exec'), module.__dict__)
    parent, _, member = name.rpartition('.')
    if parent in sys.modules:
        setattr(sys.modules[parent], member, module)
    return module


def child_message(child, *, seconds=120):
    deadline = time.monotonic() + seconds
    raw = bytearray()
    while not raw.endswith(b'\n'):
        remaining = deadline - time.monotonic()
        need(remaining > 0 and select.select([child.stdout], [], [], remaining)[0], 'CLOSURE_CHILD_RESPONSE_TIMEOUT')
        chunk = os.read(child.stdout.fileno(), 4096)
        need(chunk and len(raw) + len(chunk) <= 65536, 'CLOSURE_CHILD_RESPONSE_BOUND')
        raw.extend(chunk)
    need(raw.count(b'\n') == 1, 'CLOSURE_CHILD_RESPONSE_BOUND')
    return document(bytes(raw))


def child_write(child, raw, *, seconds=120):
    """Bound the entire packet, including a child that never drains its pipe."""
    need(type(raw) is bytes and 0 < len(raw) <= 2_000_000, 'CLOSURE_CHILD_PACKET_BOUND')
    fd = child.stdin.fileno()
    blocking = os.get_blocking(fd)
    deadline = time.monotonic() + seconds
    try:
        os.set_blocking(fd, False)
        remaining_raw = memoryview(raw)
        while remaining_raw:
            remaining = deadline - time.monotonic()
            need(remaining > 0 and select.select([], [fd], [], remaining)[1], 'CLOSURE_CHILD_WRITE_TIMEOUT')
            try:
                written = os.write(fd, remaining_raw[:4096])
            except BlockingIOError:
                continue
            need(written > 0, 'CLOSURE_CHILD_WRITE_UNCONFIRMED')
            remaining_raw = remaining_raw[written:]
    finally:
        os.set_blocking(fd, blocking)


# Executed only in the exact admitted FOX container. The parent retains the
# current-I OS lease. The handshake invokes fresh host observation only after
# VerificationRecovery has reserved BEGIN IMMEDIATE in this child.
BACKEND = r'''
import base64,hashlib,json,pathlib,sqlite3,sys,tempfile,types,os,select,time
from contextlib import closing
# Unbuffered first line must not consume a later observer response into a
# Python buffer invisible to select/os.read.
with os.fdopen(os.dup(sys.stdin.fileno()),'rb',buffering=0) as incoming:
 first=incoming.readline(2_000_001)
assert first.endswith(b'\n') and len(first)<=2_000_000
p=json.loads(first);sys.path.insert(0,'/app')
raw=base64.b64decode(p['recovery'],validate=True)
assert hashlib.sha256(raw).hexdigest()==p['recovery_sha256']
m=types.ModuleType('fox._protected_prewrite_closure');m.__package__='fox';sys.modules[m.__name__]=m
exec(compile(raw,'<source-pinned-prewrite-recovery>','exec'),m.__dict__)
store=m.VerificationRecovery(pathlib.Path('/data/fox.sqlite3'),enabled=True)
a=base64.b64decode(p['assessment'],validate=True);assert m.digest(a)==p['assessment_sha256']
assessment=m._load(a);binding=store._project_prewrite_assessment(assessment)
if p['action']=='product':
 with store._db() as db:
  db.execute('BEGIN')
  result={'queue':dict(db.execute('SELECT * FROM verification_queue WHERE job_id=?',(binding.job_id,)).fetchone()),
   'run':dict(db.execute('SELECT id,state,source_hash,artifact FROM runs WHERE id=?',(binding.job_id,)).fetchone()),
   'technical_proof_count':db.execute('SELECT count(*) FROM technical_verifications WHERE run=?',(binding.job_id,)).fetchone()[0],
   'human_acceptance_count':db.execute('SELECT count(*) FROM acceptances WHERE run=?',(binding.job_id,)).fetchone()[0]}
elif p['action']=='status':
 with store._db() as db:
  db.execute('BEGIN');result=store._closed_project_prewrite(db,binding.job_id)
  if result:assert result['assessment_sha256']==p['assessment_sha256'];result=dict(result,action='ALREADY_RECORDED_NO_REPLAY')
elif p['action']=='backup':
 with tempfile.TemporaryDirectory(prefix='fox-prewrite-export-') as tmp:
  target=pathlib.Path(tmp)/'fox.sqlite3'
  with closing(sqlite3.connect('file:/data/fox.sqlite3?mode=ro',uri=True)) as src,closing(sqlite3.connect(target)) as dst:
   src.backup(dst);assert dst.execute('PRAGMA integrity_check').fetchall()==[('ok',)]
  assert 0<target.stat().st_size<=64*1024*1024
  result={'sqlite_b64':base64.b64encode(target.read_bytes()).decode()}
elif p['action']=='apply':
 def observer(bound,session):
  assert bound==binding and session==assessment['session']
  print(json.dumps({'request':'FRESH_CAPTURE_INSIDE_RESERVED_TRANSACTION'}),flush=True)
  # A detached/lost host client must not strand the reserved SQLite writer.
  # Expiry raises inside the store transaction, rolling back any append.
  deadline=time.monotonic()+180;reply=bytearray()
  while not reply.endswith(b'\n'):
   remaining=deadline-time.monotonic()
   assert remaining>0 and select.select([sys.stdin],[],[],remaining)[0], 'CLOSURE_OBSERVER_TIMEOUT'
   chunk=os.read(sys.stdin.fileno(),4096)
   assert chunk and len(reply)+len(chunk)<=65536, 'CLOSURE_OBSERVER_BOUND'
   reply.extend(chunk)
  assert reply.count(b'\n')==1
  return json.loads(bytes(reply))
 store.initialize_project_prewrite_ledger(apply=True)
 result=store.close_project_prewrite_failure(a,expected_sha256=p['assessment_sha256'],observer=observer,apply=True)
else:raise RuntimeError('CLOSURE_UNKNOWN_BACKEND_ACTION')
print(json.dumps({'result':result}),flush=True)
'''


CLEAN_CAPTURE = r'''
import base64,json,os,pathlib,stat,sys
p=json.load(sys.stdin);root=pathlib.Path('/opt/forms2apex/outputs/jobs/.operator-project-clean')/p['plan']
assert root.resolve(strict=True)==root and all(not x.is_symlink() for x in (root,*root.parents))
assert len(p['names'])==17 and 'runtime-credentials.json' not in p['names']
out={};total=0
for name in p['names']:
 assert pathlib.PurePosixPath(name).name==name and '\\' not in name and name not in ('.','..')
 path=root/name;info=path.lstat();bound=8000000 if name=='package.zip' else 2000000
 assert stat.S_ISREG(info.st_mode) and info.st_uid==os.geteuid() and info.st_nlink==1 and not stat.S_IMODE(info.st_mode)&0o077 and 0<info.st_size<=bound
 with os.fdopen(os.open(path,os.O_RDONLY|os.O_NOFOLLOW),'rb') as stream:
  opened=os.fstat(stream.fileno());raw=stream.read(bound+1);after=os.fstat(stream.fileno())
 assert len(raw)==info.st_size and all(getattr(info,k)==getattr(opened,k)==getattr(after,k)==getattr(path.lstat(),k) for k in ('st_dev','st_ino','st_size','st_mtime_ns','st_ctime_ns'))
 total+=len(raw);assert total<=20000000;out[name]=base64.b64encode(raw).decode()
print(json.dumps(out))
'''


class Adapter:
    def __init__(self, p):
        need(os.name == 'posix' and os.geteuid() == 1000, 'CLOSURE_EXISTING_OPC_HOST_REQUIRED')
        self.p = p
        need(sha(protected_read(Path(__file__).resolve())) == p['controller_sha256'], 'CLOSURE_CONTROLLER_CHANGED')
        self.raw = {key: protected_read(absolute(p[key]['path']), private=key in ('installation', 'assessment')) for key in REFS}
        need(all(sha(raw) == p[key]['sha256'] for key, raw in self.raw.items()), 'CLOSURE_PINNED_INPUT_CHANGED')
        self.A = A = load('_prewrite_original_activation_helper', self.raw['helper'], p['helper']['path'])
        A.host_identity()
        installation = A.parse(self.raw['installation']); root = absolute(installation['layout']['release_root'])
        A.source_namespace(root, installation['layout']['inventory']['sha256'])
        from qa.operator import hosted_service, product_verifier
        self.current = A.CurrentBaseline({'schema_version': 2, 'current_installation': p['installation']})
        self.admission = hosted_service.HostedAdmission(p['installation']['path'], expected_sha256=p['installation']['sha256'])
        self.admission.archive.read(); self.journal = product_verifier.PrivateJournal(self.current.release_sha256)
        for key in ('recovery', 'classifier', 'project_contracts'):
            source = absolute(p[key]['path'])
            need(source != root and root not in source.parents, 'CLOSURE_OVERLAY_MUST_NOT_PATCH_INSTALLATION')
        load('qa.operator.project_qa_contracts', self.raw['project_contracts'], p['project_contracts']['path'])
        self.classifier = load('qa.operator._protected_prewrite_classifier', self.raw['classifier'], p['classifier']['path'])
        self.assessment = document(self.raw['assessment'])
        need(canonical(self.assessment) == self.raw['assessment'] and self.assessment['installation_sha256'] == p['installation']['sha256']
             and self.assessment['binding']['verifier_release_sha256'] == self.current.release_sha256,
             'CLOSURE_ASSESSMENT_INSTALLATION_CHANGED')
        self.signature = A.baseline_signature(A.baseline(self.current))

    def guard(self, lease):
        lease.require_active(self.current.release_sha256, self.journal.root)
        self.current.recheck(); self.admission.preflight()
        need(self.A.baseline_signature(self.A.baseline(self.current)) == self.signature, 'CLOSURE_CURRENT_PAIR_CHANGED')

    def backend(self, action, observe=None):
        p = {'action': action, 'recovery': base64.b64encode(self.raw['recovery']).decode(),
             'recovery_sha256': self.p['recovery']['sha256'], 'assessment': base64.b64encode(self.raw['assessment']).decode(),
             'assessment_sha256': self.p['assessment']['sha256']}
        argv = ['/usr/bin/podman', 'exec', '-i', self.current.infrastructure['fox']['id'], '/usr/local/bin/python', '-I', '-B', '-c', BACKEND]
        if action != 'apply':
            done = subprocess.run(argv, input=canonical(p), capture_output=True, timeout=120)
            need(done.returncode == 0 and len(done.stdout) <= 90_000_000, 'CLOSURE_BACKEND_UNCONFIRMED')
            return document(done.stdout)['result']
        # stderr stays in a temporary protected file, never printed or returned.
        import tempfile
        with tempfile.TemporaryFile() as errors:
            child = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=errors)
            try:
                child_write(child, canonical(p))
                message = child_message(child)
                if message == {'request': 'FRESH_CAPTURE_INSIDE_RESERVED_TRANSACTION'}:
                    need(callable(observe), 'CLOSURE_OBSERVER_REQUIRED')
                    child_write(child, canonical(observe()))
                    message = child_message(child)
                child.stdin.close()
                need(child.wait(timeout=120) == 0 and set(message) == {'result'}, 'CLOSURE_APPEND_UNCONFIRMED_INSPECT_NO_REPLAY')
                return message['result']
            finally:
                if child.poll() is None:
                    child.kill(); child.wait()

    def capture(self, lease):
        self.guard(lease); A = self.A; current = self.current; a = self.assessment
        journal = self.journal.root / a['session']
        docs = {path.name: A.read(path, private=True, maximum=65536) for path in journal.iterdir()}
        need(len(docs) == 22, 'CLOSURE_EXACT_JOURNAL_REQUIRED')
        from qa.operator import project_qa_dispatch, qa_stage_reconciliation
        _, _, descriptor, source = project_qa_dispatch.bundle(images=current.manifest['images'])
        need(source == a['qa_source_sha256'], 'CLOSURE_HISTORICAL_QA_SOURCE_CHANGED')
        converter = current.infrastructure['forms2apex-mcp']['id']
        done = subprocess.run(['/usr/bin/podman', 'exec', '-i', converter, 'python', '-I', '-B', '-c', CLEAN_CAPTURE],
            input=canonical({'plan': a['plan_sha256'], 'names': sorted(qa_stage_reconciliation.CLEAN_FILES)}), capture_output=True, timeout=60)
        need(done.returncode == 0 and len(done.stdout) <= 28_000_000, 'CLOSURE_CLEAN_CAPTURE_UNCONFIRMED')
        clean = document(done.stdout)
        collection_root = current.provider.path('project') / a['plan_sha256'] / ('qa-' + source[:16])
        names = set(self.classifier.COLLECTION_FILES) | {'collection-manifest.json'}
        need({x.name for x in collection_root.iterdir()} == names, 'CLOSURE_COLLECTION_MEMBERS_CHANGED')
        collection = {name: A.read(collection_root / name, private=True, maximum=8_000_000 if name == 'package.zip' else 2_000_000) for name in names}
        product = self.backend('product')
        sql = self.run_json(['/usr/bin/podman', 'exec', converter, 'python', '-I', '-B', '-c',
            "import pathlib,json;print(json.dumps([int(p.name) for p in pathlib.Path('/proc').iterdir() if p.name.isdigit() and (p/'comm').exists() and (p/'comm').read_text().strip()=='java']))"])
        service = dict(line.split('=', 1) for line in A.command(['/usr/bin/systemctl', '--user', 'show', 'fox-product-verifier.service',
            '--property=LoadState,ActiveState,SubState,MainPID']).decode().splitlines())
        identity = document(A.read(Path('/home/opc/.local/share/fox-project-transitions') / current.release_sha256 / 'operator-startup.json', private=True))['identity']
        original_live = same_process(identity)
        stage = '/home/opc/.config/fox-qa/project-v1-stages/' + a['plan_sha256'] + '/' + source
        active, browser = [], []
        ids = A.command(['/usr/bin/podman', 'ps', '-a', '-q', '--no-trunc']).decode().splitlines()
        need(len(ids) <= 256 and len(set(ids)) == len(ids), 'CLOSURE_CONTAINER_INVENTORY_BOUND')
        for cid in ids:
            item = A.inspect_container(cid)
            if item['Image'].removeprefix('sha256:') != a['qa_image'].removeprefix('sha256:') and not any(
                    m.get('Source', '') == stage or m.get('Source', '').startswith(stage + '/') for m in item['Mounts']):
                continue
            s = item['State']; started = s.get('StartedAt', ''); finished = s.get('FinishedAt', '')
            never = s['Status'] == 'created' and s['Running'] is False and s['Pid'] == 0 and s['ExitCode'] == 0 and started.startswith('0001-') and finished.startswith('0001-')
            stopped = s['Status'] in ('stopped', 'exited') and s['Running'] is False and s['Pid'] == 0 and started and finished and not started.startswith('0001-') and not finished.startswith('0001-')
            if not (never or stopped): active.append(cid)
            if s['Pid'] > 0: browser.append(s['Pid'])
        allocation = document(collection['stage-receipt.json'])['allocation_receipt_sha256']
        observation = {'service': service, 'converter': {'id': converter, 'image': current.manifest['images']['converter']},
            'active_sqlcl_pids': sql, 'active_browser_pids': browser, 'active_qa_containers': active, 'original_coordinator_live': original_live,
            'stage_path': stage, 'stage_exists': Path(stage).is_dir(),
            'launch_intent_exists': (Path('/home/opc/.config/fox-qa/launch-project-v1') / (allocation + '.json')).is_file(),
            'launch_completion_exists': (Path(stage) / 'launch.complete.json').is_file(),
            'dispatch_receipt_exists': (Path('/home/opc/.config/fox-qa/dispatch-project-v1') / (allocation + '.json')).exists()}
        capture = {'scope': self.classifier.CAPTURE_SCOPE, 'writes_requested': False, 'installation_sha256': self.p['installation']['sha256'],
            'release': current.manifest, 'session': a['session'], 'journal': {k: base64.b64encode(v).decode() for k, v in docs.items()},
            'product': product, 'clean': clean, 'collection': {k: base64.b64encode(v).decode() for k, v in collection.items()},
            'qa_descriptor': descriptor, 'observation': observation}
        classified = self.classifier.assess_capture(capture, expected_release_sha256=current.release_sha256,
            expected_installation_sha256=self.p['installation']['sha256'], expected_converter_id=converter,
            expected_converter_image=current.manifest['images']['converter'])
        need(canonical(classified) == self.raw['assessment'], 'CLOSURE_FRESH_ASSESSMENT_CHANGED')
        self.guard(lease)
        return capture, classified

    @staticmethod
    def run_json(argv):
        done = subprocess.run(argv, capture_output=True, timeout=60)
        need(done.returncode == 0 and len(done.stdout) <= 2_000_000, 'CLOSURE_OBSERVATION_UNCONFIRMED')
        return document(done.stdout)

    def export(self, capture, lease):
        self.guard(lease); A = self.A; path = absolute(self.p['export'])
        # Create-only export outside all installation/operator/data roots.
        roots = [self.current.root, self.current.provider.path('journal').parent,
                 Path('/home/opc/fox/data'), Path('/home/opc/fox/jobs')]
        need(all(path != root and root not in path.parents and path not in root.parents for root in roots), 'CLOSURE_EXPORT_OVERLAPS_STATE')
        A.private_dir(path.parent); path.mkdir(mode=0o700); A.private_dir(path)
        A.create_file(path / 'plan.json', canonical(self.p))
        A.create_file(path / 'capture.private.json', canonical(capture))
        A.create_file(path / 'assessment.json', self.raw['assessment'])
        references = {'installation': self.raw['installation'], **self.current.content}
        for name, raw in references.items(): A.create_file(path / (name + '.original'), raw)
        backup = self.backend('backup'); raw = base64.b64decode(backup['sqlite_b64'], validate=True)
        A.create_file(path / 'fox.sqlite3', raw)
        inventory = {file.name: sha(A.read(file, private=True, maximum=90_000_000)) for file in path.iterdir()}
        A.create_file(path / 'complete.json', canonical({'scope': 'fox-project-prewrite-recovery-export-v1',
            'installation_sha256': self.p['installation']['sha256'], 'assessment_sha256': self.p['assessment']['sha256'],
            'sha256': inventory, 'credentials_excluded': True, 'full_hosted_snapshot': False}))
        self.guard(lease)

    def run(self, *, apply=False):
        with self.journal.lock(create=False) as lease:
            self.guard(lease)
            existing = self.backend('status')
            if existing:
                return {**existing, 'old_installed_reader_changed': False}
            capture, _ = self.capture(lease)
            if not apply:
                return {'status': 'PROJECT_PREWRITE_CLOSURE_INSPECTED_NOT_APPLIED', 'assessment_sha256': self.p['assessment']['sha256'],
                    'technical_success': False, 'human_acceptance_recorded': False, 'automatic_retry_permitted': False}
            self.export(capture, lease)
            def observe():
                _, assessment = self.capture(lease)
                return assessment
            result = self.backend('apply', observe)
            self.guard(lease)
            self.A.create_file(absolute(self.p['export']) / 'closure-result.json', canonical(result))
            return {**result, 'old_installed_reader_changed': False}


def same_process(identity):
    try:
        fields = (Path('/proc') / str(identity['pid']) / 'stat').read_text().rsplit(')', 1)[1].split()
        return fields[0] not in ('Z', 'X') and int(fields[19]) == identity['start_ticks'] and Path('/proc/sys/kernel/random/boot_id').read_text().strip() == identity['boot_id']
    except FileNotFoundError:
        return False


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--plan', required=True); parser.add_argument('--plan-sha256', required=True)
    parser.add_argument('--apply', action='store_true')
    args = parser.parse_args(argv)
    try:
        p = plan_document(protected_read(absolute(args.plan), private=True, maximum=65536), args.plan_sha256)
        print(json.dumps(Adapter(p).run(apply=args.apply), sort_keys=True)); return 0
    except Exception:
        print(json.dumps({'status': 'ATTENTION', 'code': 'PROJECT_PREWRITE_CLOSURE_UNCONFIRMED_INSPECT_NO_REPLAY',
            'technical_success': False, 'automatic_replay_permitted': False})); return 1


if __name__ == '__main__':
    raise SystemExit(main())
