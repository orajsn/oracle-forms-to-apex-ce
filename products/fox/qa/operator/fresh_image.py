"""Read-only FOX/converter application-payload measurements, never admission.

The reader executes fixed standard-library code, not the application. It reads
only fixed package/UI roots and rejects extra files, caches, links and drift.
OS/base-image, OPAF vendor files and dependency contents remain separate gates.
"""
from __future__ import annotations

import hashlib
import inspect
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import subprocess


MAX_FILES = 2048
MAX_FILE = 8_000_000
MAX_TOTAL = 80_000_000
ROOTS = {'fox': ('/app/fox', '/app/dist'),
         'converter': ('/opt/forms2apex/converter/forms2apex', '/opt/forms2apex/converter/fox_source_contract')}
PYTHON = {'fox': '/usr/local/bin/python', 'converter': '/usr/bin/python3.11'}


class ImagePayloadError(RuntimeError):
    """Fixed codes only; no code bytes, source text, paths or credentials."""


def need(value, code):
    if not value:
        raise ImagePayloadError(code)


def canonical(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False,
                       allow_nan=False) + '\n').encode('utf-8')


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def parse(raw):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            need(key not in result, 'IMAGE_PAYLOAD_DUPLICATE_KEY'); result[key] = value
        return result
    need(type(raw) is bytes and 0 < len(raw) <= 1_000_000, 'IMAGE_PAYLOAD_PACKET_BOUND')
    return json.loads(raw, object_pairs_hook=unique,
        parse_constant=lambda _: (_ for _ in ()).throw(ImagePayloadError('IMAGE_PAYLOAD_NONFINITE')))


def measure_files(roots, expected):
    """Read an exact, bounded tree without imports, writes or symlink following."""
    need(type(roots) in (tuple, list) and 1 <= len(roots) <= 4 and type(expected) is dict
         and 0 < len(expected) <= MAX_FILES, 'IMAGE_PAYLOAD_LAYOUT_INVALID')
    paths = [Path(root) for root in roots]
    need(len(set(paths)) == len(paths) and all(path.is_absolute() and path.resolve(strict=True) == path for path in paths),
         'IMAGE_PAYLOAD_ROOT_UNSAFE')
    for name, wanted in expected.items():
        path = Path(name) if type(name) is str else None
        need(path is not None and path.is_absolute() and str(path) == name and '..' not in path.parts
             and '__pycache__' not in path.parts and not name.endswith(('.pyc', '.pyo'))
             and sum(root in path.parents for root in paths) == 1
             and type(wanted) is str and re.fullmatch('[a-f0-9]{64}', wanted), 'IMAGE_PAYLOAD_MEMBER_INVALID')
    wanted_dirs = set(paths)
    for name in expected:
        for parent in Path(name).parents:
            if any(parent == root or root in parent.parents for root in paths):
                wanted_dirs.add(parent)
    measured, directories, file_snapshots, todo, total = {}, {}, {}, list(paths), 0
    identity = lambda value: (value.st_dev, value.st_ino, value.st_mode, value.st_nlink,
                              value.st_size, value.st_mtime_ns, value.st_ctime_ns)
    while todo:
        directory = todo.pop()
        info = directory.lstat()
        need(stat.S_ISDIR(info.st_mode) and not directory.is_symlink(), 'IMAGE_PAYLOAD_DIRECTORY_UNSAFE')
        directories[directory] = identity(info)
        with os.scandir(directory) as entries:
            for entry in entries:
                path = Path(entry.path)
                need(not entry.is_symlink(), 'IMAGE_PAYLOAD_LINK_FORBIDDEN')
                if entry.is_dir(follow_symlinks=False):
                    need(path in wanted_dirs and path not in directories, 'IMAGE_PAYLOAD_EXTRA_DIRECTORY')
                    todo.append(path)
                    continue
                need(str(path) in expected and str(path) not in measured, 'IMAGE_PAYLOAD_EXTRA_FILE')
                before = path.lstat()
                need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and 0 <= before.st_size <= MAX_FILE,
                     'IMAGE_PAYLOAD_REGULAR_FILE_REQUIRED')
                with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW), 'rb') as stream:
                    opened = os.fstat(stream.fileno()); raw = stream.read(MAX_FILE+1); after = os.fstat(stream.fileno())
                need(identity(before) == identity(opened) == identity(after) == identity(path.lstat())
                     and len(raw) == before.st_size, 'IMAGE_PAYLOAD_CHANGED_DURING_READ')
                total += len(raw)
                need(total <= MAX_TOTAL, 'IMAGE_PAYLOAD_TOTAL_BOUND')
                measured[str(path)] = digest(raw)
                file_snapshots[path] = identity(before)
                need(measured[str(path)] == expected[str(path)], 'IMAGE_PAYLOAD_CONTENT_MISMATCH')
    need(set(measured) == set(expected) and set(directories) == wanted_dirs,
         'IMAGE_PAYLOAD_INVENTORY_INCOMPLETE')
    need(all(identity(path.lstat()) == before and path.resolve(strict=True) == path
             for path, before in directories.items()), 'IMAGE_PAYLOAD_DIRECTORY_CHANGED')
    need(all(identity(path.lstat()) == before and not path.is_symlink()
             for path, before in file_snapshots.items()), 'IMAGE_PAYLOAD_CHANGED_DURING_MEASUREMENT')
    return {'file_count': len(measured), 'measured_sha256': digest(canonical(measured)), 'total_bytes': total}


READER_BODY = r'''
import sys
try:
 packet=parse(sys.stdin.buffer.read(1000001))
 need(type(packet) is dict and set(packet)=={'schema_version','scope','role','files','expected_bytes'}
  and type(packet['schema_version']) is int and packet['schema_version']==1
  and packet['scope']=='fox-fresh-image-payload-request-v1' and packet['role'] in ROOTS,
  'IMAGE_PAYLOAD_REQUEST_INVALID')
 measured=measure_files(ROOTS[packet['role']],packet['files'])
 need(type(packet['expected_bytes']) is int and 0<=packet['expected_bytes']<=MAX_TOTAL
  and measured['total_bytes']==packet['expected_bytes'],'IMAGE_PAYLOAD_BYTES_MISMATCH')
 result={'schema_version':1,'scope':'fox-fresh-image-payload-observation-v1',
  'status':'MEASURED_NOT_ADMITTED','role':packet['role'],'request_sha256':digest(canonical(packet)),
  'read_only':True,**measured}
except Exception as error:
 result={'status':'REFUSED','code':str(error) if type(error) is ImagePayloadError else 'IMAGE_PAYLOAD_UNCONFIRMED',
  'read_only':True}
print(json.dumps(result,sort_keys=True))
'''


def reader_program():
    """Build only fixed reader code at operation time; importing stays inert."""
    prefix = ('import hashlib,json,os,re,stat\nfrom pathlib import Path\n'
        + 'MAX_FILES='+repr(MAX_FILES)+'\nMAX_FILE='+repr(MAX_FILE)+'\nMAX_TOTAL='+repr(MAX_TOTAL)
        + '\nROOTS='+repr(ROOTS)+'\n')
    return prefix + '\n'.join(inspect.getsource(item) for item in
        (ImagePayloadError, need, canonical, digest, parse, measure_files)) + '\n' + READER_BODY


def payload_plans(provider):
    """Map the already source-checked inventory to the fixed image interfaces."""
    from . import runtime_provider as runtime
    need(type(provider) is runtime.FreshHostedProvider and runtime.selected_hosted() is provider,
         'CONCRETE_SELECTED_FRESH_PROVIDER_REQUIRED')
    provider.configuration
    layout = parse(provider.layout_raw)
    inventory = parse(dict(provider.references_raw)[layout['inventory']['path']])['files']
    result, sizes = {'fox': {}, 'converter': {}}, {'fox': 0, 'converter': 0}
    for name, wanted in inventory.items():
        target, role = None, None
        if name.startswith('fox/fox/'):
            role, target = 'fox', '/app/fox/'+name.removeprefix('fox/fox/')
        elif name.startswith('fox/dist/'):
            need(re.fullmatch(r'fox/dist/(?:index\.html|assets/[A-Za-z0-9_.-]+\.(?:js|css|svg|png|jpg|webp))', name),
                 'IMAGE_PAYLOAD_UI_MEMBER_UNSUPPORTED')
            role, target = 'fox', '/app/dist/'+name.removeprefix('fox/dist/')
        elif name.startswith(('converter/forms2apex/', 'converter/fox_source_contract/')):
            role, target = 'converter', '/opt/forms2apex/converter/'+name.removeprefix('converter/')
        if target:
            need('__pycache__' not in PurePosixPath(name).parts and not name.endswith(('.pyc','.pyo')),
                 'IMAGE_PAYLOAD_CACHE_FORBIDDEN')
            result[role][target] = wanted
            sizes[role] += (Path(layout['release_root'])/name).stat().st_size
    required_fox = {'/app/fox/__init__.py','/app/fox/app.py','/app/fox/worker.py','/app/fox/fresh_startup.py',
                    '/app/fox/backend_storage.py','/app/dist/index.html'}
    required_converter = {'/opt/forms2apex/converter/forms2apex/__init__.py',
        '/opt/forms2apex/converter/forms2apex/native_project.py',
        '/opt/forms2apex/converter/forms2apex/project_workflow.py',
        '/opt/forms2apex/converter/fox_source_contract/__init__.py',
        '/opt/forms2apex/converter/fox_source_contract/source-manifest.json',
        '/opt/forms2apex/converter/forms2apex/templates/native-table-v1/.apex/apexlang.json',
        '/opt/forms2apex/converter/forms2apex/templates/native-table-v1/_fragments/report.apx.tmpl',
        '/opt/forms2apex/converter/forms2apex/templates/native-table-v1/_fragments/form.apx.tmpl'}
    need(required_fox <= set(result['fox']) and required_converter <= set(result['converter'])
         and any(name.startswith('/app/dist/assets/') and name.endswith('.js') for name in result['fox']),
         'IMAGE_PAYLOAD_SOURCE_CLOSURE_INCOMPLETE')
    need(all(0 <= size <= MAX_TOTAL for size in sizes.values()), 'IMAGE_PAYLOAD_TOTAL_BOUND')
    return {role: {'schema_version':1,'scope':'fox-fresh-image-payload-request-v1','role':role,'files':files,
                  'expected_bytes':sizes[role]}
            for role, files in result.items()}


def measure_runtime_payload(provider, infrastructure):
    """Fixed read-only exec of the reader on already measured running role IDs."""
    plans = payload_plans(provider)
    config = provider.configuration
    program = reader_program(); program_sha = digest(program.encode())
    receipts = {}
    for role in ('fox','converter'):
        value = infrastructure[role]
        need(type(value) is dict and set(value)=={'id','static_runtime_sha256'}
             and re.fullmatch('[a-f0-9]{64}',value['id']), 'IMAGE_PAYLOAD_ROLE_ID_INVALID')
        packet = canonical(plans[role])
        need(len(packet)<=1_000_000, 'IMAGE_PAYLOAD_PACKET_BOUND')
        # Override loader/site/bytecode settings only for this read process.
        args = ['/usr/bin/podman','--remote=false','exec','-i',
            '--env','LD_PRELOAD=','--env','LD_AUDIT=','--env','LD_LIBRARY_PATH=',
            '--env','PYTHONDONTWRITEBYTECODE=1',value['id'],PYTHON[role],'-I','-S','-B','-c',program]
        result = subprocess.run(args,input=packet,cwd='/',env=provider._environment(),
            stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=120)
        need(result.returncode==0 and not result.stderr.strip() and 0<len(result.stdout)<=65536,
             'IMAGE_PAYLOAD_READER_UNAVAILABLE')
        receipt = parse(result.stdout)
        need(type(receipt) is dict and set(receipt)=={'schema_version','scope','status','role','request_sha256',
             'read_only','file_count','measured_sha256','total_bytes'}
             and type(receipt['schema_version']) is int and receipt['schema_version']==1
             and receipt['scope']=='fox-fresh-image-payload-observation-v1'
             and receipt['status']=='MEASURED_NOT_ADMITTED' and receipt['role']==role and receipt['read_only'] is True
             and receipt['request_sha256']==digest(packet)
             and type(receipt['file_count']) is int and receipt['file_count']==len(plans[role]['files'])
             and receipt['measured_sha256']==digest(canonical(plans[role]['files']))
             and type(receipt['total_bytes']) is int and receipt['total_bytes']==plans[role]['expected_bytes'],
             'IMAGE_PAYLOAD_RECEIPT_UNCONFIRMED')
        receipts[role] = {**receipt,'container_id':value['id'],'image':config['images'][role],
                          'reader_program_sha256':program_sha}
    need(provider.configuration==config,'IMAGE_PAYLOAD_PROVIDER_CHANGED')
    return receipts
