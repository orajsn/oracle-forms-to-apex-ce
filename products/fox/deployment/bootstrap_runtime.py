#!/usr/bin/env python3
"""Python3.6-compatible Linux bootstrap for the FOX setup wizard only.

No system Python/pip changes, privilege escalation, Oracle media or credentials.
Downloaded artifacts are pinned before extraction/execution; cached executables
are independently rechecked against those artifacts, not trusted by a ready flag.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import platform
import posixpath
import re
import stat
import subprocess
import sys
import tarfile
import urllib.request
import zipfile

PYTHON = {'name':'python.tar.gz','sha256':'ce4f6d0a6cfdb3bed6e44c2f9affd85943c76a42e25ad3a259002f31d6fb8a20',
    'url':'https://github.com/astral-sh/python-build-standalone/releases/download/20261026/cpython-3.12.16%2B20261026-x86_64-unknown-linux-gnu-install_only_stripped.tar.gz','max':50000000}
XML = {'name':'defusedxml.whl','sha256':'a352e7e428770286cc899e2542b6cdaedb2b4953ff269a210103ec58f6198a61',
    'url':'https://files.pythonhosted.org/packages/07/6c/aa3f2f849e01cb6a001cd8554a88d4c77c5c1a31c95bdf1cf9301e6d9ef4/defusedxml-0.7.1-py2.py3-none-any.whl','max':100000}
SCOPE='fox-managed-setup-runtime-v1'
ROOT=Path(__file__).resolve().parents[1]
PROBE="import json,sys,ssl,sqlite3,defusedxml; assert sys.version_info[:3]==(3,12,16); assert defusedxml.__version__=='0.7.1'; print(json.dumps({'python':sys.version.split()[0],'defusedxml':defusedxml.__version__}))"


class BootstrapError(ValueError):pass
def need(value,code):
    if not value:raise BootstrapError(code)
def canonical(value):return (json.dumps(value,sort_keys=True,separators=(',',':'))+'\n').encode('utf-8')
def sha(raw):return hashlib.sha256(raw).hexdigest()


def environment():
    return {'PATH':'/usr/bin:/bin','LANG':'C.UTF-8','PYTHONDONTWRITEBYTECODE':'1'}


def supported():
    need(os.name=='posix' and sys.platform=='linux' and os.geteuid()>0,
         'NONROOT_LINUX_REQUIRED')
    need(platform.machine()=='x86_64','X86_64_SETUP_RUNTIME_REQUIRED')
    value=os.confstr('CS_GNU_LIBC_VERSION')
    match=re.fullmatch(r'glibc ([0-9]+)\.([0-9]+)',value or '')
    need(match is not None and tuple(map(int,match.groups()))>=(2,17), 'GLIBC_RUNTIME_UNSUPPORTED')


def safe(path,private=False):
    path=Path(os.path.abspath(str(path)))
    need(path.resolve(strict=False)==path,'RUNTIME_LINKED_PATH')
    for item in (path,*path.parents):
        try:info=item.lstat()
        except FileNotFoundError:continue
        sticky=info.st_uid==0 and stat.S_ISDIR(info.st_mode) and info.st_mode&stat.S_ISVTX
        need(not stat.S_ISLNK(info.st_mode) and info.st_uid in (0,os.geteuid())
             and (not stat.S_IMODE(info.st_mode)&0o022 or sticky),'RUNTIME_PATH_UNSAFE')
    if private:
        info=path.stat();need(stat.S_ISDIR(info.st_mode) and info.st_uid==os.geteuid()
            and stat.S_IMODE(info.st_mode)==0o700,'PRIVATE_RUNTIME_ROOT_REQUIRED')
    return path


def read(path,maximum):
    path=safe(path)
    info=path.lstat()
    need(stat.S_ISREG(info.st_mode) and info.st_nlink==1 and info.st_uid==os.geteuid()
         and info.st_size<=maximum,'RUNTIME_FILE_UNSAFE')
    with path.open('rb') as f:raw=f.read(maximum+1)
    need(len(raw)==info.st_size and len(raw)<=maximum,'RUNTIME_FILE_CHANGED')
    return raw


def new(path,raw,mode=0o600):
    fd=os.open(str(path),os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,mode)
    with os.fdopen(fd,'wb') as f:
        os.fchmod(f.fileno(),mode);f.write(raw);f.flush();os.fsync(f.fileno())


def sync_dir(path):
    fd=os.open(str(path),os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try:os.fsync(fd)
    finally:os.close(fd)


def manifest():
    return {'scope':SCOPE,'schema_version':1,'python_sha256':PYTHON['sha256'],
            'xml_sha256':XML['sha256'],'python_version':'3.12.16','xml_version':'0.7.1'}


def member_name(name):
    need(type(name) is str and not any(ord(c)<32 or ord(c)==127 for c in name),'ARCHIVE_PATH_UNSAFE')
    p=PurePosixPath(name)
    need(type(name) is str and name==p.as_posix() and not p.is_absolute()
         and '..' not in p.parts and '\\' not in name,'ARCHIVE_PATH_UNSAFE')
    return name


def tar_entries(path):
    entries={}
    with tarfile.open(str(path)) as tf:
        members=tf.getmembers()
        need(len(members)<10000 and sum(m.size for m in members)<200000000,'RUNTIME_ARCHIVE_BOUND')
        for m in members:
            name=member_name(m.name)
            need(name.startswith('python/') and name not in entries
                 and (m.isfile() or m.isdir() or m.issym()) and not m.islnk(), 'RUNTIME_MEMBER_UNSUPPORTED')
            if m.isfile():
                need(m.size<=50000000,'RUNTIME_MEMBER_BOUND')
                data=tf.extractfile(m).read(m.size+1)
                need(len(data)==m.size,'RUNTIME_MEMBER_CHANGED')
                entries[name]={'kind':'file','sha256':sha(data),'bytes':m.size,'mode':m.mode&0o755}
            elif m.isdir():entries[name]={'kind':'dir','mode':0o755}
            else:
                target=posixpath.normpath(posixpath.join(posixpath.dirname(name),m.linkname))
                need(not m.linkname.startswith('/') and target.startswith('python/'),'RUNTIME_LINK_ESCAPE')
                entries[name]={'kind':'link','target':m.linkname,'resolved':target}
    for name,entry in list(entries.items()):
        parent=posixpath.dirname(name)
        while parent:
            need(parent not in entries or entries[parent]['kind']=='dir','RUNTIME_LINK_PARENT')
            entries.setdefault(parent,{'kind':'dir','mode':0o755});parent=posixpath.dirname(parent)
        if entry['kind']=='link':
            target=entry['resolved'];seen={name}
            while True:
                need(target in entries and target not in seen,'RUNTIME_LINK_INVALID')
                seen.add(target);node=entries[target]
                if node['kind']!='link':break
                target=node['resolved']
    return entries


def wheel_entries(path):
    entries={};prefix='python/lib/python3.12/site-packages/'
    with zipfile.ZipFile(str(path)) as z:
        need(len(z.infolist())<100,'SETUP_WHEEL_BOUND')
        for info in z.infolist():
            if info.is_dir():continue
            name=member_name(info.filename)
            need(name.startswith(('defusedxml/','defusedxml-0.7.1.dist-info/'))
                 and not name.endswith(('.pth','.pyc','.so')) and info.file_size<100000,
                 'SETUP_WHEEL_MEMBER_UNSUPPORTED')
            data=z.read(info);target=prefix+name
            need(target not in entries,'SETUP_WHEEL_DUPLICATE')
            entries[target]={'kind':'file','sha256':sha(data),'bytes':len(data),'mode':0o644}
    return entries


def expected_tree(root):
    for spec in (PYTHON,XML):
        need(sha(read(root/spec['name'],spec['max']))==spec['sha256'],'RUNTIME_ARTIFACT_HASH_CHANGED')
    entries=tar_entries(root/PYTHON['name']);extra=wheel_entries(root/XML['name'])
    need(not set(entries)&set(extra),'SETUP_WHEEL_OVERLAPS_RUNTIME');entries.update(extra)
    for name in list(entries):
        parent=posixpath.dirname(name)
        while parent:
            need(parent not in entries or entries[parent]['kind']=='dir','RUNTIME_LINK_PARENT')
            entries.setdefault(parent,{'kind':'dir','mode':0o755});parent=posixpath.dirname(parent)
    return entries


def verify_tree(root,entries):
    observed=set()
    for directory,dirs,files in os.walk(str(root/'python'),followlinks=False):
        for name in dirs+files:
            path=Path(directory)/name;relative=path.relative_to(root).as_posix();observed.add(relative)
            need(len(observed)<=len(entries) and relative in entries,'RUNTIME_TREE_INVENTORY_CHANGED')
            info=path.lstat();entry=entries[relative]
            need(info.st_uid==os.geteuid(),'RUNTIME_TREE_OWNER_CHANGED')
            if entry['kind']=='link':need(stat.S_ISLNK(info.st_mode) and os.readlink(str(path))==entry['target'],'RUNTIME_TREE_LINK_CHANGED')
            elif entry['kind']=='dir':need(stat.S_ISDIR(info.st_mode) and stat.S_IMODE(info.st_mode)==entry['mode'],'RUNTIME_TREE_MODE_CHANGED')
            else:
                need(stat.S_ISREG(info.st_mode) and info.st_nlink==1
                     and stat.S_IMODE(info.st_mode)==entry['mode']
                     and info.st_size==entry['bytes'],'RUNTIME_TREE_FILE_CHANGED')
                need(sha(read(path,entry['bytes']))==entry['sha256'],'RUNTIME_TREE_CONTENT_CHANGED')
    observed.add('python')
    need(observed==set(entries),'RUNTIME_TREE_MEMBER_MISSING')


def probe(root):
    result=subprocess.run([str(root/'python/bin/python3.12'),'-I','-B','-c',PROBE],
        cwd=str(root),env=environment(),stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,universal_newlines=True,timeout=30)
    need(result.returncode==0 and result.stdout.strip()=='{"python": "3.12.16", "defusedxml": "0.7.1"}',
         'MANAGED_SETUP_RUNTIME_PROBE_FAILED')


def result(root,reused=True,changed=False):
    return {'status':'SETUP_RUNTIME_VERIFIED_NOT_PRODUCT_INSTALLED',
            'python':str(root/'python/bin/python3.12'),'conversion_ready':False,
            'system_python_changed':False,'changes_performed':changed,'reused':reused}


def finish(root,entries):
    verify_tree(root,entries);probe(root);verify_tree(root,entries)
    for name in sorted(entries,key=lambda n:n.count('/'),reverse=True):
        if entries[name]['kind']=='dir':sync_dir(root/name)
    new(root/'complete.json',canonical({'scope':SCOPE,'tree_sha256':sha(canonical(entries)),
        'manifest_sha256':sha(canonical(manifest()))}))
    sync_dir(root)


def inspect(root):
    supported();need(os.path.lexists(root),'SETUP_RUNTIME_NOT_FOUND');root=safe(root,private=True)
    names=set()
    for index,p in enumerate(root.iterdir()):
        need(index<5,'PARTIAL_OR_UNKNOWN_RUNTIME_REQUIRES_REVIEW');names.add(p.name)
    need(names=={'intent.json','complete.json',PYTHON['name'],XML['name'],'python'},
         'PARTIAL_OR_UNKNOWN_RUNTIME_REQUIRES_REVIEW')
    need(read(root/'intent.json',8192)==canonical(manifest()),'RUNTIME_MANIFEST_CHANGED')
    entries=expected_tree(root)
    completion={'scope':SCOPE,'tree_sha256':sha(canonical(entries)),
                'manifest_sha256':sha(canonical(manifest()))}
    need(read(root/'complete.json',8192)==canonical(completion),'RUNTIME_COMPLETION_CHANGED')
    verify_tree(root,entries);probe(root);verify_tree(root,entries)
    return result(root)


def acquire(root,spec,source,allow_download):
    if source:
        data=read(Path(source),spec['max'])
    else:
        need(allow_download is True,'EXPLICIT_RUNTIME_DOWNLOAD_APPROVAL_REQUIRED')
        with urllib.request.urlopen(spec['url'],timeout=45) as response:
            need(response.geturl().startswith('https://'),'HTTPS_ARTIFACT_REQUIRED')
            data=response.read(spec['max']+1)
    need(len(data)<=spec['max'] and sha(data)==spec['sha256'],'RUNTIME_DOWNLOAD_INTEGRITY_FAILED')
    new(root/spec['name'],data)


def prepare(root,python_archive=None,xml_wheel=None,allow_download=False):
    supported();root=safe(root)
    need(not (root==ROOT or ROOT in root.parents or root in ROOT.parents),'RUNTIME_OVERLAPS_SOURCE')
    for item in root.parents:
        need(not os.path.lexists(str(item/'fox.sqlite3'))
             and not os.path.lexists(str(item/'setup-storage-plan.json')),
             'RUNTIME_OVERLAPS_PROJECT_STATE')
    if root.exists():
        if (root/'complete.json').is_file():return inspect(root)
        safe(root,private=True)
        names=set()
        for index,p in enumerate(root.iterdir()):
            need(index<4,'PARTIAL_OR_UNKNOWN_RUNTIME_REQUIRES_REVIEW');names.add(p.name)
        need('intent.json' in names and names<={'intent.json',PYTHON['name'],XML['name'],'python'}
             and read(root/'intent.json',8192)==canonical(manifest()),
             'PARTIAL_OR_UNKNOWN_RUNTIME_REQUIRES_REVIEW')
        # Retained bytes must still match pins. No download/extraction is
        # replayed over existing files. A complete tree without its last receipt
        # can finish only after independent full-tree verification; a partial
        # or altered executable tree is held for review.
        for spec in (PYTHON,XML):
            if (root/spec['name']).exists():
                need(sha(read(root/spec['name'],spec['max']))==spec['sha256'],'RUNTIME_ARTIFACT_HASH_CHANGED')
        if 'python' in names:
            need(names=={'intent.json',PYTHON['name'],XML['name'],'python'},'PARTIAL_OR_UNKNOWN_RUNTIME_REQUIRES_REVIEW')
            entries=expected_tree(root);finish(root,entries)
            value=result(root,changed=True);value['continued']='COMPLETE_TREE_RECONCILED';return value
    parent=safe(root.parent);need(parent.is_dir() and parent.stat().st_uid==os.geteuid(),'OWNED_RUNTIME_PARENT_REQUIRED')
    need(bool(python_archive)==bool(xml_wheel),'PAIRED_OFFLINE_ARTIFACTS_REQUIRED')
    need(bool(python_archive) or allow_download is True or
         ((root/PYTHON['name']).is_file() and (root/XML['name']).is_file()),
         'EXPLICIT_RUNTIME_DOWNLOAD_APPROVAL_REQUIRED')
    if not root.exists():
        root.mkdir(mode=0o700);os.chmod(str(root),0o700);new(root/'intent.json',canonical(manifest()))
    if not (root/PYTHON['name']).exists():acquire(root,PYTHON,python_archive,allow_download)
    if not (root/XML['name']).exists():acquire(root,XML,xml_wheel,allow_download)
    entries=expected_tree(root)
    for name in sorted(entries,key=lambda n:(n.count('/'),n)):
        if entries[name]['kind']=='dir':
            (root/name).mkdir(mode=0o755);os.chmod(str(root/name),0o755)
    with tarfile.open(str(root/PYTHON['name'])) as tf:
        for m in tf.getmembers():
            entry=entries[m.name]
            if m.isfile():new(root/m.name,tf.extractfile(m).read(),entry['mode'])
            elif m.issym():os.symlink(m.linkname,str(root/m.name))
    with zipfile.ZipFile(str(root/XML['name'])) as z:
        for info in z.infolist():
            if not info.is_dir():new(root/'python/lib/python3.12/site-packages'/info.filename,z.read(info),0o644)
    finish(root,entries)
    return result(root,reused=False,changed=True)


def main(argv=None):
    class Parser(argparse.ArgumentParser):
        def error(self,_message):raise BootstrapError('INVALID_BOOTSTRAP_ARGUMENTS')
    parser=Parser(description=__doc__)
    parser.add_argument('--runtime-root');parser.add_argument('--python-archive');parser.add_argument('--xml-wheel')
    parser.add_argument('--allow-download',action='store_true');parser.add_argument('--prepare-only',action='store_true')
    parser.add_argument('--inspect',action='store_true')
    args=parser.parse_args(argv);supported()
    import pwd
    root=Path(args.runtime_root) if args.runtime_root else Path(pwd.getpwuid(os.geteuid()).pw_dir)/'.fox-setup-runtime-cp312-20261026-v1'
    if (not args.inspect and not (root/'complete.json').exists() and not args.python_archive
            and not args.allow_download and not all((root/x['name']).is_file() for x in (PYTHON,XML))):
        need(sys.stdin.isatty(),'EXPLICIT_RUNTIME_DOWNLOAD_APPROVAL_REQUIRED')
        args.allow_download=input('Prepare the private FOX setup runtime using verified public downloads? [y/N] ').strip().lower()=='y'
    result=inspect(root) if args.inspect else prepare(root,args.python_archive,args.xml_wheel,args.allow_download)
    if args.prepare_only or args.inspect:print(json.dumps(result));return 0
    need((ROOT/'scripts/fox-setup.py').is_file(),'FOX_SETUP_SOURCE_MISSING')
    os.execve(result['python'],[result['python'],'-I','-B',str(ROOT/'scripts/fox-setup.py'),'setup'],environment())


if __name__=='__main__':
    try:sys.exit(main())
    except BootstrapError as error:
        print(json.dumps({'status':'SETUP_RUNTIME_NEEDS_ATTENTION','code':str(error),
                          'conversion_ready':False,'partial_files_preserved':True}));sys.exit(2)
    except Exception:
        print(json.dumps({'status':'SETUP_RUNTIME_NEEDS_ATTENTION','code':'RUNTIME_OPERATION_UNCONFIRMED',
                          'conversion_ready':False,'partial_files_preserved':True}));sys.exit(2)
