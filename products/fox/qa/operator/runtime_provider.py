"""Explicit, immutable hosted-local adapter for the existing JSN operator.

Importing this module selects nothing and performs no IO. An installed caller
may configure hosted mode once, before resolving any path or performing work.
Without that explicit selection the established Windows/SSH behavior remains.
This module neither installs software nor creates paths, secrets or services.
"""
from __future__ import annotations

import base64
from dataclasses import dataclass
from datetime import datetime, timezone
from functools import wraps
import hashlib
import inspect
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import subprocess
import sys
import threading


MAX_WIRE = 20_000_000
MAX_PROGRAM = 1_000_000
SCOPE = 'fox-hosted-operator-runtime-v1'
IMAGE_SCOPE = 'fox-hosted-operator-runtime-v2'
_SOURCE_FILES = ('forms2apex/__init__.py', 'forms2apex/config.py',
                 'forms2apex/target_profile.py', 'forms2apex/oci_identity.py')
_PATHS = {'native': 'clean-install', 'project': 'project-clean-install',
          'journal': 'product-verifier', 'handoff': 'handoffs'}
_HASH = re.compile(r'[a-f0-9]{64}\Z')
_SECRET = re.compile(rb'[A-Za-z0-9_!#%+.,:=?@^*-]{12,128}\Z')
_UNSELECTED = object()
_selected = _UNSELECTED
_selection_lock = threading.RLock()


class ProviderError(RuntimeError):
    """Only bounded codes; never supplied paths, output or secret values."""


def _need(value, code):
    if not value:
        raise ProviderError(code)


def _protected(method):
    @wraps(method)
    def run(*args, **kwargs):
        try:
            return method(*args, **kwargs)
        except ProviderError:
            raise
        except Exception:
            raise ProviderError('HOSTED_PROVIDER_CHECK_FAILED') from None
    return run


def _sha(raw):
    return hashlib.sha256(raw).hexdigest()


def _canonical(value):
    try:
        return (json.dumps(value, sort_keys=True, separators=(',', ':'),
                           ensure_ascii=False, allow_nan=False) + '\n').encode('utf-8')
    except (TypeError, ValueError, UnicodeError, RecursionError):
        raise ProviderError('HOSTED_CONFIGURATION_INVALID') from None


def _unique(pairs):
    result = {}
    for key, value in pairs:
        _need(key not in result, 'HOSTED_DUPLICATE_JSON_FIELD')
        result[key] = value
    return result


def _json(raw):
    try:
        return json.loads(raw.decode('utf-8'), object_pairs_hook=_unique,
                          parse_constant=lambda _: (_ for _ in ()).throw(ValueError()))
    except (ValueError, UnicodeError, RecursionError):
        raise ProviderError('HOSTED_JSON_INVALID') from None


def _path(value):
    _need(type(value) is str and 1 < len(value) <= 1024 and '\\' not in value
          and '\x00' not in value, 'HOSTED_ABSOLUTE_PATH_REQUIRED')
    parsed = PurePosixPath(value)
    _need(parsed.is_absolute() and value == parsed.as_posix()
          and all(part not in ('.', '..') for part in parsed.parts),
          'HOSTED_ABSOLUTE_PATH_REQUIRED')
    return Path(value)


def _ancestors(path):
    """Reject linked or untrusted writable ancestors, including the leaf."""
    _need(path.is_absolute() and path.resolve() == path, 'HOSTED_PATH_LINK_FORBIDDEN')
    for part in (path, *path.parents):
        info = part.lstat()
        _need(not stat.S_ISLNK(info.st_mode) and info.st_uid in (0, os.geteuid()),
              'HOSTED_PATH_OWNER_OR_LINK_INVALID')
        # Root-owned sticky /tmp is safe for an owner-private unique child.
        writable = stat.S_IMODE(info.st_mode) & 0o022
        _need(not writable or (part != path and stat.S_ISDIR(info.st_mode)
              and info.st_uid == 0 and info.st_mode & stat.S_ISVTX),
              'HOSTED_PATH_WRITABLE_BY_OTHER')


def _private_directory(path):
    _ancestors(path)
    info = path.lstat()
    _need(stat.S_ISDIR(info.st_mode) and info.st_uid == os.geteuid()
          and stat.S_IMODE(info.st_mode) == 0o700, 'HOSTED_PRIVATE_DIRECTORY_REQUIRED')


def _read(path, maximum, *, private=False):
    """Bounded no-follow read, with file identity checked across the open."""
    _ancestors(path)
    before = path.lstat()
    _need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1
          and 0 < before.st_size <= maximum, 'HOSTED_REGULAR_FILE_REQUIRED')
    if private:
        _need(before.st_uid == os.geteuid() and stat.S_IMODE(before.st_mode) == 0o600,
              'HOSTED_PRIVATE_FILE_REQUIRED')
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        with os.fdopen(descriptor, 'rb') as stream:
            opened = os.fstat(stream.fileno())
            _need((opened.st_dev, opened.st_ino, opened.st_size, opened.st_mode, opened.st_uid)
                  == (before.st_dev, before.st_ino, before.st_size, before.st_mode, before.st_uid),
                  'HOSTED_FILE_CHANGED')
            raw = stream.read(maximum + 1)
            after = os.fstat(stream.fileno())
        final = path.lstat()
        identity = lambda value: (value.st_dev, value.st_ino, value.st_mode, value.st_uid,
                                  value.st_gid, value.st_nlink, value.st_size,
                                  value.st_mtime_ns, value.st_ctime_ns)
        _need(0 < len(raw) == before.st_size <= maximum
              and (after.st_size, after.st_mtime_ns, after.st_ctime_ns)
                  == (before.st_size, before.st_mtime_ns, before.st_ctime_ns)
              and identity(final) == identity(before), 'HOSTED_FILE_CHANGED')
        return raw
    except Exception:
        # fdopen owns the descriptor once successfully entered.
        raise


def _outside(path, roots):
    return all(path != root and root not in path.parents and path not in root.parents
               for root in roots)


def validated_image_pins(value):
    """Detached immutable-reference declaration; no provider selection or IO."""
    _need(type(value) is dict and set(value) == {'fox', 'converter'}
          and all(type(item) is str and re.fullmatch(r'sha256:[a-f0-9]{64}', item)
                  for item in value.values()), 'HOSTED_IMAGE_PINS_INVALID')
    return dict(value)


def configuration_document(raw, *, expected_sha256):
    """Offline declaration validation, not owner admission or provider selection.

    The same canonical document is later owner/path/runtime checked by
    configure_hosted. This function performs no process or filesystem access.
    A release may bind its hash; this document never binds the release back.
    """
    _need(type(raw) is bytes and 0 < len(raw) <= 65_536 and type(expected_sha256) is str
          and _HASH.fullmatch(expected_sha256) and _sha(raw) == expected_sha256,
          'HOSTED_CONFIGURATION_HASH_INVALID')
    config = _json(raw)
    keys = {'schema_version', 'scope', 'owner_uid', 'provider_sha256', 'target_profile',
            'target_profile_sha256', 'python', 'converter_root', 'converter_sources',
            'state_root', 'admin_secret_file', 'public_mount_roots'}
    _need(type(config) is dict, 'HOSTED_CONFIGURATION_FIELDS_INVALID')
    version = config.get('schema_version')
    _need(type(version) is int and version in (1, 2)
          and set(config) == keys | ({'images'} if version == 2 else set())
          and raw == _canonical(config)
          and config['scope'] == (SCOPE if version == 1 else IMAGE_SCOPE)
          and type(config['owner_uid']) is int and config['owner_uid'] > 0
          and type(config['provider_sha256']) is str and _HASH.fullmatch(config['provider_sha256']),
          'HOSTED_CONFIGURATION_FIELDS_INVALID')
    if version == 2:
        validated_image_pins(config['images'])
    from forms2apex.target_profile import validate_target_profile, target_profile_sha256
    try:
        profile = validate_target_profile(config['target_profile'])
        _need(target_profile_sha256(profile) == config['target_profile_sha256'],
              'HOSTED_TARGET_PROFILE_CHANGED')
    except ProviderError:
        raise
    except Exception:
        raise ProviderError('HOSTED_TARGET_PROFILE_INVALID') from None
    python = config['python']
    _need(type(python) is dict and set(python) == {'path', 'sha256', 'version'}
          and type(python['sha256']) is str and _HASH.fullmatch(python['sha256'])
          and type(python['version']) is list and len(python['version']) == 3
          and all(type(item) is int and item >= 0 for item in python['version'])
          and python['version'][0] == 3 and python['version'][1] >= 11,
          'HOSTED_PYTHON_CONFIGURATION_INVALID')
    _path(python['path'])
    for name in ('converter_root', 'state_root', 'admin_secret_file'):
        _path(config[name])
    _need(type(config['converter_sources']) is dict and set(config['converter_sources']) == set(_SOURCE_FILES)
          and all(type(value) is str and _HASH.fullmatch(value) for value in config['converter_sources'].values()),
          'HOSTED_IDENTITY_SOURCE_INVENTORY_INVALID')
    _need(type(config['public_mount_roots']) is list and 0 < len(config['public_mount_roots']) <= 64,
          'HOSTED_PUBLIC_ROOTS_REQUIRED')
    roots = [_path(item) for item in config['public_mount_roots']]
    roots.append(Path('/home/opc/fox'))
    _need(_outside(_path(config['state_root']), roots)
          and _outside(_path(config['admin_secret_file']), roots)
          and _outside(_path(config['admin_secret_file']), [_path(config['state_root'])]),
          'HOSTED_PRIVATE_PATH_OVERLAPS_PUBLIC_OR_STATE')
    return config


# The same guard precedes every hosted program, including read-only scope and
# secret-mount checks. The caller's existing host/container guards still run.
HOST_IDENTITY_GUARD = r'''
import json,urllib.request
_request=urllib.request.Request('http://169.254.169.254/opc/v2/instance/',headers={'Authorization':'Bearer Oracle'})
with urllib.request.urlopen(_request,timeout=5) as _response:
 _metadata=json.loads(_response.read(100001))
_region_info=_metadata.get('regionInfo',{})
_canonical=_metadata.get('canonicalRegionName')
_region=_region_info.get('regionIdentifier') if type(_region_info) is dict else None
if _region is None:_region=_canonical
if not (_metadata.get('id')=='ocid1.instance.oc1.iad.anuwcljtc7x6gxic5w37qsyp3rst64betkt4uk2pdcrtmy3okspcpbv77qea'
 and _metadata.get('compartmentId')=='ocid1.compartment.oc1..aaaaaaaa2q5aelkapmt5mhumvxadcynq5chez2faeucy5plefhy3ylmahtba'
 and _region=='us-ashburn-1' and _canonical in (None,'us-ashburn-1')):
 raise RuntimeError('PINNED_HOST_GUARD_FAILED')
_host_imds={'instance_id':_metadata['id'],'compartment_id':_metadata['compartmentId'],'region':_region}
'''

_OCI_PROGRAM = r'''
import base64,json,sys,types
_packet=json.load(sys.stdin)
_sources=_packet['sources']
if set(_sources)!={'forms2apex/__init__.py','forms2apex/config.py','forms2apex/target_profile.py','forms2apex/oci_identity.py'}:
 raise RuntimeError('HOSTED_IDENTITY_SOURCE_INVALID')
for _filename in ('forms2apex/__init__.py','forms2apex/config.py','forms2apex/target_profile.py','forms2apex/oci_identity.py'):
 _name='forms2apex' if _filename.endswith('/__init__.py') else _filename[:-3].replace('/','.')
 _module=types.ModuleType(_name);_module.__package__='forms2apex';_module.__file__=_filename
 if _name=='forms2apex':_module.__path__=[]
 sys.modules[_name]=_module
 exec(compile(base64.b64decode(_sources[_filename],validate=True),_filename,'exec'),_module.__dict__)
_result=sys.modules['forms2apex.oci_identity'].collect_operator_oci_identity(_packet['profile'],_host_imds,
 require_database_available=_packet['require_database_available'])
print(json.dumps(_result,sort_keys=True))
'''

_MOUNT_PROGRAM = r'''
import json,subprocess,sys
from pathlib import Path,PurePosixPath
_paths=[PurePosixPath(x) for x in json.load(sys.stdin)['private_paths']]
_inspection=subprocess.run(['/usr/bin/podman','inspect','fox'],stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=20)
if _inspection.returncode!=0 or len(_inspection.stdout)>2000000:raise RuntimeError('PUBLIC_MOUNT_GUARD_FAILED')
_containers=json.loads(_inspection.stdout)
if type(_containers) is not list or len(_containers)!=1:raise RuntimeError('PUBLIC_MOUNT_GUARD_FAILED')
_fox=_containers[0];_mounts=_fox.get('Mounts')
if _fox.get('State',{}).get('Running') is not True or type(_mounts) is not list or len(_mounts)>64:
 raise RuntimeError('PUBLIC_MOUNT_GUARD_FAILED')
for _mount in _mounts:
 _source=_mount.get('Source')
 if type(_source) is not str or not _source.startswith('/') or '\\' in _source:raise RuntimeError('PUBLIC_MOUNT_GUARD_FAILED')
 _root=PurePosixPath(_source)
 if str(_root)!=_source or '..' in _root.parts:raise RuntimeError('PUBLIC_MOUNT_GUARD_FAILED')
 if Path(_source).resolve(strict=True)!=Path(_source):raise RuntimeError('PUBLIC_MOUNT_GUARD_FAILED')
 for _path in _paths:
  if _path==_root or _root in _path.parents or _path in _root.parents:raise RuntimeError('PUBLIC_MOUNT_GUARD_FAILED')
print('{"safe":true}')
'''

def persistent_mounts(role, host_config, mounts):
    """Check fixed ephemeral /tmp policy, returning persistent mounts only.

    C3 records host-backed mounts separately. A readonly FOX root must also
    have bounded writable scratch for tempfile-based conversion staging.
    This function is pure; it performs no discovery or mount operation.
    """
    _need(type(role) is str and role in ('fox', 'converter', 'opaf')
          and type(host_config) is dict and type(mounts) is list and len(mounts) <= 16,
          'FRESH_EPHEMERAL_MOUNT_POLICY_INVALID')
    tmpfs = host_config.get('Tmpfs')
    if tmpfs is None:
        tmpfs = {}
    _need(type(tmpfs) is dict and set(tmpfs) <= {'/tmp'}, 'FRESH_EPHEMERAL_MOUNT_POLICY_INVALID')
    _need(role != 'fox' or set(tmpfs) == {'/tmp'}, 'FRESH_WRITABLE_SCRATCH_REQUIRED')
    if tmpfs:
        options = tmpfs['/tmp']
        _need(type(options) is str and 0 < len(options) <= 256,
              'FRESH_EPHEMERAL_MOUNT_POLICY_INVALID')
        items = options.split(',')
        keys = [item.split('=', 1)[0] for item in items]
        _need(len(items) == len(set(keys)) and set(keys) <=
              {'rw', 'noexec', 'nosuid', 'nodev', 'size', 'mode'}
              and {'rw', 'noexec', 'nosuid', 'size', 'mode'} <= set(keys)
              and all(item == key for item, key in zip(items, keys) if key not in ('size', 'mode')),
              'FRESH_EPHEMERAL_MOUNT_POLICY_INVALID')
        values = dict(item.split('=', 1) for item in items if '=' in item)
        _need(set(values) == {'size', 'mode'}, 'FRESH_EPHEMERAL_MOUNT_POLICY_INVALID')
        match = re.fullmatch(r'([1-9][0-9]{0,9})([kKmMgG]?)', values['size'])
        _need(match is not None and values['mode'] == '1777', 'FRESH_EPHEMERAL_MOUNT_POLICY_INVALID')
        size = int(match.group(1)) * {'': 1, 'k': 1024, 'm': 1024**2, 'g': 1024**3}[match.group(2).lower()]
        _need(16 * 1024**2 <= size <= 512 * 1024**2, 'FRESH_EPHEMERAL_MOUNT_SIZE_INVALID')
    result, ephemeral = [], []
    for mount in mounts:
        _need(type(mount) is dict, 'FRESH_EPHEMERAL_MOUNT_POLICY_INVALID')
        if mount.get('Type') == 'tmpfs':
            _need(bool(tmpfs) and mount.get('Destination') == '/tmp' and mount.get('RW') is True,
                  'FRESH_EPHEMERAL_MOUNT_POLICY_INVALID')
            ephemeral.append(mount)
        else:
            result.append(mount)
    _need(len(ephemeral) <= 1, 'FRESH_EPHEMERAL_MOUNT_POLICY_INVALID')
    return result


# Fresh roles are installation-owned and must never inherit the canonical G
# names. This read-only program is used only by FreshHostedProvider's own
# mount check, never as a general caller-supplied execution capability.
_FRESH_MOUNT_BODY = r'''
import hashlib,json,subprocess,sys
from pathlib import Path,PurePosixPath
_packet=json.load(sys.stdin)
_projection=_packet['projection'];_roles=_projection['runtime']['roles']
_canonical=(json.dumps(_projection,sort_keys=True,separators=(',',':'),ensure_ascii=False,allow_nan=False)+'\n').encode()
if hashlib.sha256(_canonical).hexdigest()!=_packet['projection_sha256']:raise RuntimeError('FRESH_PROJECTION_CHANGED')
if set(_roles)!={'fox','converter','opaf'}:raise RuntimeError('FRESH_ROLES_CHANGED')
_names=[_roles[x]['name'] for x in ('fox','converter','opaf')]
_inspection=subprocess.run(['/usr/bin/podman','inspect','--',*_names],stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=20)
if _inspection.returncode!=0 or _inspection.stderr.strip() or len(_inspection.stdout)>2000000:raise RuntimeError('FRESH_MOUNT_INSPECTION_FAILED')
_containers=json.loads(_inspection.stdout)
if type(_containers) is not list or len(_containers)!=3:raise RuntimeError('FRESH_ROLE_INVENTORY_CHANGED')
_by_name={x.get('Name','').lstrip('/'):x for x in _containers}
if set(_by_name)!=set(_names):raise RuntimeError('FRESH_ROLE_INVENTORY_CHANGED')
_private=[PurePosixPath(x) for x in _packet['private_paths']]
_observed={};_ids=set()
for _role in ('fox','converter','opaf'):
 _expected=_roles[_role];_actual=_by_name[_expected['name']]
 _id=_actual.get('Id');_image=_actual.get('Image');_state=_actual.get('State',{})
 if type(_id) is not str or len(_id)!=64 or any(x not in '0123456789abcdef' for x in _id) or _id in _ids:raise RuntimeError('FRESH_ROLE_ID_INVALID')
 _ids.add(_id)
 if not (_image in (_expected['image'],_expected['image'][7:]) and _state.get('Running') is True
  and _actual.get('Config',{}).get('User')==_expected['user']
  and _actual.get('HostConfig',{}).get('ReadonlyRootfs') is _expected['read_only_rootfs']):raise RuntimeError('FRESH_ROLE_CONFIGURATION_CHANGED')
 _mounts=persistent_mounts(_role,_actual.get('HostConfig'),_actual.get('Mounts'))
 if len(_mounts)!=len(_expected['mounts']):raise RuntimeError('FRESH_ROLE_MOUNTS_CHANGED')
 _wanted={x['destination']:x for x in _expected['mounts']};_seen=set()
 for _mount in _mounts:
  _destination=_mount.get('Destination');_source=_mount.get('Source');_rw=_mount.get('RW')
  if type(_source) is not str or _destination not in _wanted or _destination in _seen or type(_rw) is not bool:raise RuntimeError('FRESH_ROLE_MOUNTS_CHANGED')
  _seen.add(_destination);_wanted_mount=_wanted[_destination]
  if not (_mount.get('Type') in ('bind','volume') and _source==_wanted_mount['source'] and _rw is not _wanted_mount['read_only']):raise RuntimeError('FRESH_ROLE_MOUNTS_CHANGED')
  _root=PurePosixPath(_source)
  if not (_root.is_absolute() and str(_root)==_source and '..' not in _root.parts and Path(_source).resolve(strict=True)==Path(_source)):raise RuntimeError('FRESH_MOUNT_PATH_CHANGED')
  if any(_path==_root or _root in _path.parents or _path in _root.parents for _path in _private):raise RuntimeError('FRESH_PRIVATE_PATH_MOUNTED')
 _observed[_role]={'container_id':_id,'image':_expected['image'],'name':_expected['name']}
print(json.dumps({'safe':True,'projection_sha256':_packet['projection_sha256'],'observed_roles':_observed},sort_keys=True))
'''


def fresh_mount_program():
    """Build the fixed reader at operation time, keeping module import inert."""
    return ('import re\n' + '\n'.join(inspect.getsource(item) for item in
            (ProviderError, _need, persistent_mounts)) + '\n' + _FRESH_MOUNT_BODY)


@dataclass(frozen=True)
class HostedProvider:
    raw: bytes
    sha256: str

    @property
    def configuration(self):
        return _json(self.raw)  # detached; no mutable configuration alias

    def _environment(self):
        import pwd
        account = pwd.getpwuid(os.geteuid())
        return {'PATH': '/usr/bin:/bin', 'HOME': account.pw_dir,
                'USER': account.pw_name, 'LOGNAME': account.pw_name,
                'XDG_RUNTIME_DIR': '/run/user/' + str(os.geteuid()),
                'LANG': 'C.UTF-8', 'LC_ALL': 'C.UTF-8',
                'PYTHONDONTWRITEBYTECODE': '1', 'PYTHONNOUSERSITE': '1'}

    def _spawn(self, program, data, timeout):
        config = self.configuration
        _need(type(program) is str and 0 < len(program.encode('utf-8')) <= MAX_PROGRAM
              and type(data) is bytes and len(data) <= MAX_WIRE
              and type(timeout) in (int, float) and 0 < timeout <= 1500,
              'HOSTED_PROCESS_BOUNDS_INVALID')
        executable = _path(config['python']['path'])
        _need(_sha(_read(executable, 50_000_000)) == config['python']['sha256'],
              'HOSTED_PYTHON_CHANGED')
        # No shell, arbitrary environment, Python path, SSH or source on argv.
        loader = 'import base64,sys;exec(compile(base64.b64decode(sys.stdin.buffer.readline().rstrip(b"\\n"),validate=True),"<hosted-operator>","exec"))'
        wire = base64.b64encode(program.encode('utf-8')) + b'\n' + data
        _need(len(wire) <= MAX_WIRE, 'PROTECTED_REQUEST_TOO_LARGE')
        try:
            result = subprocess.run([str(executable), '-I', '-B', '-c', loader],
                input=wire, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                timeout=timeout, env=self._environment(), cwd='/')
        except subprocess.TimeoutExpired:
            raise ProviderError('TRANSPORT_TIMEOUT_OUTCOME_UNCERTAIN_NO_REPLAY') from None
        except (OSError, ValueError):
            raise ProviderError('HOSTED_PROCESS_UNAVAILABLE') from None
        _need(result.returncode == 0 and not result.stderr.strip(),
              'PROTECTED_TRANSPORT_FAILED_OUTPUT_WITHHELD')
        _need(len(result.stdout) <= MAX_WIRE, 'PROTECTED_RESPONSE_TOO_LARGE')
        return result.stdout

    @_protected
    def execute_host(self, program, data, *, timeout):
        return self._spawn(HOST_IDENTITY_GUARD + '\n' + program, data, timeout)

    @_protected
    def path(self, kind):
        _need(kind in _PATHS, 'HOSTED_STORAGE_KIND_INVALID')
        root = _path(self.configuration['state_root'])
        _private_directory(root)
        result = root / _PATHS[kind]
        if result.exists() or result.is_symlink():
            _private_directory(result)
        return result

    @_protected
    def private_destination(self, path, *, kinds=tuple(_PATHS)):
        _need(type(kinds) is tuple and bool(kinds) and len(set(kinds)) == len(kinds)
              and all(kind in _PATHS for kind in kinds), 'HOSTED_STORAGE_KIND_INVALID')
        roots = [self.path(kind) for kind in kinds]
        _need(any(path == root or root in path.parents for root in roots),
              'HOSTED_PRIVATE_DESTINATION_OUTSIDE_STATE')
        _private_directory(path.parent)

    @_protected
    def identity_sources(self):
        config = self.configuration
        root = _path(config['converter_root'])
        result = {}
        for name in _SOURCE_FILES:
            raw = _read(root / name, 1_000_000)
            _need(_sha(raw) == config['converter_sources'][name], 'HOSTED_IDENTITY_SOURCE_CHANGED')
            result[name] = base64.b64encode(raw).decode('ascii')
        return result

    @_protected
    def oci_scope(self, *, require_database_available):
        _need(type(require_database_available) is bool, 'HOSTED_DATABASE_STATE_FLAG_INVALID')
        config = self.configuration
        packet = {'profile': config['target_profile'], 'sources': self.identity_sources(),
                  'require_database_available': require_database_available}
        result = _json(self.execute_host(_OCI_PROGRAM, _canonical(packet), timeout=240))
        target = config['target_profile']['oci']
        expected = {'database_id': target['database_id'], 'database_compartment_id': target['compartment_id'],
                    'instance_id': target['instance_id'], 'instance_compartment_id': target['compartment_id'],
                    'region': target['region'], 'database_lifecycle_state': result.get('database_lifecycle_state') if type(result) is dict else None,
                    'instance_lifecycle_state': 'RUNNING', 'database_db_name': 'JSNF2APEX'}
        _need(result == expected and type(result) is dict, 'HOSTED_OCI_IDENTITY_DIFFERS')
        _need(expected['database_lifecycle_state'] in (('AVAILABLE',) if require_database_available
              else ('AVAILABLE', 'STOPPED')), 'HOSTED_OCI_DATABASE_STATE_INVALID')
        return {'instance_id': target['instance_id'], 'database_id': target['database_id'],
                'compartment_id': target['compartment_id'], 'region': target['region'],
                'database_db_name': result['database_db_name'], 'instance_state': 'RUNNING',
                'database_state': result['database_lifecycle_state'],
                'observed_at_utc': datetime.now(timezone.utc).isoformat()}

    @_protected
    def check_public_mounts(self):
        """Read-only install/start gate; does not open the ADMIN secret file.

        Installed startup calls this before its first journal/plan write.
        Secret retrieval repeats it rather than relying on a stale receipt.
        """
        config = self.configuration
        path = _path(config['admin_secret_file'])
        _private_directory(path.parent)
        _private_directory(_path(config['state_root']))
        packet = {'private_paths': [str(path), config['state_root']]}
        observed = _json(self.execute_host(_MOUNT_PROGRAM, _canonical(packet), timeout=40))
        _need(type(observed) is dict and set(observed) == {'safe'} and observed['safe'] is True,
              'HOSTED_PUBLIC_MOUNT_GUARD_FAILED')
        return {'safe': True}

    @_protected
    def admin_secret(self):
        self.check_public_mounts()
        path = _path(self.configuration['admin_secret_file'])
        raw = _read(path, 130, private=True)
        value = raw[:-2] if raw.endswith(b'\r\n') else raw[:-1] if raw.endswith(b'\n') else raw
        _need(_SECRET.fullmatch(value) is not None, 'PROTECTED_ADMIN_BINDING_INVALID')
        return value.decode('ascii')


@dataclass(frozen=True)
class FreshHostedProvider(HostedProvider):
    """Source-bound C3 selection, deliberately not a fresh admission authority.

    Only fixed read-only scope/mount methods are available at this stage.
    Unadapted queue/clean/QA/promotion programs and ADMIN retrieval fail before
    spawning anything, so selecting C3 cannot reach canonical G by accident.
    The protected source owner remains trusted; this is not a Python sandbox.
    """
    provider_reference_raw: bytes
    release_reference_raw: bytes
    backend_reference_raw: bytes
    layout_raw: bytes
    references_raw: tuple

    def _checked_configuration(self):
        from . import fresh_backend as fresh
        provider_ref = _json(self.provider_reference_raw)
        release_ref = _json(self.release_reference_raw)
        backend_ref = _json(self.backend_reference_raw)
        layout = _json(self.layout_raw)
        config, plan, release, inventory, artifacts = fresh._inputs(provider_ref, release_ref, layout)
        _need(artifacts[provider_ref['path']] == self.raw and provider_ref['sha256'] == self.sha256,
              'FRESH_PROVIDER_REFERENCE_CHANGED')
        fresh._read_reference(backend_ref, artifacts)
        fresh.contracts.validate_backend_initialization(backend_ref, artifacts,
            provider_reference=provider_ref, release_reference=release_ref, layout=layout)
        _need(tuple(sorted(artifacts.items())) == self.references_raw, 'FRESH_PROVIDER_ANCESTORS_CHANGED')
        root = _path(layout['release_root'])
        fresh._verify_sources(root, inventory)
        fresh._verify_release_sources(root, release)
        _need(config['provider_sha256'] == _sha(_read(Path(__file__).resolve(), 2_000_000)),
              'HOSTED_PROVIDER_SOURCE_CHANGED')
        python = config['python']
        _need(Path(sys.executable).resolve(strict=True) == _path(python['path'])
              and list(sys.version_info[:3]) == python['version']
              and _sha(_read(_path(python['path']), 128_000_000)) == python['sha256'],
              'HOSTED_PYTHON_CHANGED')
        _need(config['owner_uid'] == os.geteuid() == plan['owner_uid'], 'HOSTED_CONFIGURATION_OWNER_CHANGED')
        _private_directory(_path(config['state_root']))
        admin = _path(config['admin_secret_file'])
        _private_directory(admin.parent)
        if admin.exists() or admin.is_symlink():
            _ancestors(admin)
            info = admin.lstat()
            _need(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_uid == os.geteuid()
                  and stat.S_IMODE(info.st_mode) == 0o600, 'HOSTED_PRIVATE_FILE_REQUIRED')
        fresh._same_inputs(artifacts)
        return config

    @property
    @_protected
    def configuration(self):
        return self._checked_configuration()

    @_protected
    def runtime_projection(self):
        config = self.configuration
        return {'schema_version': 1, 'scope': 'fox-fresh-operator-projection-v1',
                'installation_id': config['storage']['installation_id'],
                'provider_configuration_sha256': self.sha256,
                'release_sha256': _json(self.release_reference_raw)['sha256'],
                'backend_initialization_sha256': _json(self.backend_reference_raw)['sha256'],
                'runtime': config['runtime']}

    def execute_host(self, program, data, *, timeout):
        # No caller-program fallback while fresh consumers/admission are not
        # integrated. In particular, do not execute legacy templates against G.
        raise ProviderError('FRESH_BOUND_TRANSPORT_AND_ADMISSION_REQUIRED')

    def admin_secret(self):
        raise ProviderError('FRESH_BOUND_TRANSPORT_AND_ADMISSION_REQUIRED')

    @_protected
    def oci_scope(self, *, require_database_available):
        _need(type(require_database_available) is bool, 'HOSTED_DATABASE_STATE_FLAG_INVALID')
        config = self.configuration
        packet = {'profile': config['target_profile'], 'sources': self.identity_sources(),
                  'require_database_available': require_database_available}
        result = _json(super().execute_host(_OCI_PROGRAM, _canonical(packet), timeout=240))
        target = config['target_profile']['oci']
        _need(type(result) is dict, 'HOSTED_OCI_IDENTITY_DIFFERS')
        expected = {'database_id': target['database_id'], 'database_compartment_id': target['compartment_id'],
                    'instance_id': target['instance_id'], 'instance_compartment_id': target['compartment_id'],
                    'region': target['region'], 'database_lifecycle_state': result.get('database_lifecycle_state'),
                    'instance_lifecycle_state': 'RUNNING', 'database_db_name': 'JSNF2APEX'}
        _need(result == expected, 'HOSTED_OCI_IDENTITY_DIFFERS')
        _need(expected['database_lifecycle_state'] in (('AVAILABLE',) if require_database_available
              else ('AVAILABLE', 'STOPPED')), 'HOSTED_OCI_DATABASE_STATE_INVALID')
        _need(self.configuration == config, 'FRESH_PROVIDER_CHANGED_DURING_OBSERVATION')
        return {'instance_id': target['instance_id'], 'database_id': target['database_id'],
                'compartment_id': target['compartment_id'], 'region': target['region'],
                'database_db_name': result['database_db_name'], 'instance_state': 'RUNNING',
                'database_state': result['database_lifecycle_state'],
                'observed_at_utc': datetime.now(timezone.utc).isoformat()}

    @_protected
    def check_public_mounts(self):
        config = self.configuration
        projection = self.runtime_projection()
        projection_hash = _sha(_canonical(projection))
        private = [config['admin_secret_file'], config['state_root'],
                   _json(dict(self.references_raw)[config['storage']['plan']['path']])['roots']['records']]
        packet = {'projection': projection, 'projection_sha256': projection_hash, 'private_paths': private}
        result = _json(super().execute_host(fresh_mount_program(), _canonical(packet), timeout=40))
        _need(type(result) is dict and set(result) == {'safe', 'projection_sha256', 'observed_roles'}
              and result['safe'] is True and result['projection_sha256'] == projection_hash,
              'HOSTED_PUBLIC_MOUNT_GUARD_FAILED')
        roles = result['observed_roles']
        _need(type(roles) is dict and set(roles) == {'fox', 'converter', 'opaf'},
              'HOSTED_PUBLIC_MOUNT_GUARD_FAILED')
        ids = set()
        for name, role in roles.items():
            expected = config['runtime']['roles'][name]
            _need(type(role) is dict and set(role) == {'container_id', 'image', 'name'}
                  and type(role['container_id']) is str and _HASH.fullmatch(role['container_id'])
                  and role['container_id'] not in ids and role['image'] == expected['image']
                  and role['name'] == expected['name'], 'HOSTED_PUBLIC_MOUNT_GUARD_FAILED')
            ids.add(role['container_id'])
        _need(self.configuration == config, 'FRESH_PROVIDER_CHANGED_DURING_OBSERVATION')
        return result

def configure_fresh(provider_reference, release_reference, backend_reference, *, layout):
    """Select a protected C3/R4/F source closure once, without admitting work.

    Actual read-only checks are available; general execution remains refused
    until concrete fresh admission and every transport consumer are integrated.
    This never selects fresh mode as a fallback from failed migration evidence.
    """
    global _selected
    with _selection_lock:
        _need(_selected is _UNSELECTED, 'OPERATOR_RUNTIME_ALREADY_SELECTED')
        _need(os.name == 'posix' and hasattr(os, 'O_NOFOLLOW') and os.geteuid() > 0,
              'HOSTED_UNPRIVILEGED_POSIX_REQUIRED')
        try:
            from . import fresh_backend as fresh
            config, _, _, _, artifacts = fresh._inputs(provider_reference, release_reference, layout)
            fresh._read_reference(backend_reference, artifacts)
            fresh.contracts.validate_backend_initialization(backend_reference, artifacts,
                provider_reference=provider_reference, release_reference=release_reference, layout=layout)
            provider = FreshHostedProvider(artifacts[provider_reference['path']], provider_reference['sha256'],
                _canonical(provider_reference), _canonical(release_reference), _canonical(backend_reference),
                _canonical(layout), tuple(sorted(artifacts.items())))
            provider.configuration
            provider.identity_sources()
            for kind in _PATHS:
                provider.path(kind)
        except ProviderError:
            raise
        except Exception:
            raise ProviderError('FRESH_HOSTED_CONFIGURATION_CHECK_FAILED') from None
        _selected = provider
        return provider.sha256


def execution_runtime():
    """Operator-only detached runtime binding; absence keeps legacy packets."""
    provider = hosted()
    if type(provider) is FreshHostedProvider:
        return provider.runtime_projection()
    return None


def _configured(raw, expected_sha256):
    _need(os.name == 'posix' and hasattr(os, 'O_NOFOLLOW') and os.geteuid() > 0,
          'HOSTED_UNPRIVILEGED_POSIX_REQUIRED')
    config = configuration_document(raw, expected_sha256=expected_sha256)
    _need(config['owner_uid'] == os.geteuid(), 'HOSTED_CONFIGURATION_FIELDS_INVALID')
    # The installed entrypoint binds this expected hash in its own source
    # closure. No self-hash is treated as independent authorization.
    _need(config['provider_sha256'] == _sha(Path(__file__).read_bytes()), 'HOSTED_PROVIDER_SOURCE_CHANGED')
    from forms2apex.target_profile import validate_target_profile, target_profile_sha256
    profile = validate_target_profile(config['target_profile'])
    _need(target_profile_sha256(profile) == config['target_profile_sha256'],
          'HOSTED_TARGET_PROFILE_CHANGED')
    python = config['python']
    _need(type(python) is dict and set(python) == {'path', 'sha256', 'version'}
          and type(python['sha256']) is str and _HASH.fullmatch(python['sha256'])
          and type(python['version']) is list and len(python['version']) == 3
          and all(type(item) is int and item >= 0 for item in python['version'])
          and python['version'][0] == 3 and python['version'][1] >= 11,
          'HOSTED_PYTHON_CONFIGURATION_INVALID')
    executable = _path(python['path'])
    _need(os.access(executable, os.X_OK), 'HOSTED_PYTHON_EXECUTABLE_REQUIRED')
    _need(type(config['converter_sources']) is dict and set(config['converter_sources']) == set(_SOURCE_FILES)
          and all(type(value) is str and _HASH.fullmatch(value) for value in config['converter_sources'].values()),
          'HOSTED_IDENTITY_SOURCE_INVENTORY_INVALID')
    state = _path(config['state_root'])
    admin = _path(config['admin_secret_file'])
    _private_directory(state)
    _private_directory(admin.parent)
    _need(type(config['public_mount_roots']) is list and 0 < len(config['public_mount_roots']) <= 64,
          'HOSTED_PUBLIC_ROOTS_REQUIRED')
    roots = [_path(item) for item in config['public_mount_roots']]
    roots.append(Path('/home/opc/fox'))
    _need(_outside(state, roots) and _outside(admin, roots) and _outside(admin, [state]),
          'HOSTED_PRIVATE_PATH_OVERLAPS_PUBLIC_OR_STATE')
    if admin.exists() or admin.is_symlink():
        _ancestors(admin)
        info = admin.lstat()
        _need(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_uid == os.geteuid()
              and stat.S_IMODE(info.st_mode) == 0o600, 'HOSTED_PRIVATE_FILE_REQUIRED')
    provider = HostedProvider(bytes(raw), expected_sha256)
    provider.identity_sources()
    for kind in _PATHS:
        provider.path(kind)
    version = _json(provider._spawn('import json,sys;print(json.dumps(list(sys.version_info[:3])))', b'', 15))
    _need(version == python['version'], 'HOSTED_PYTHON_VERSION_CHANGED')
    return provider


def configure_hosted(config_raw, *, expected_sha256):
    """One installation-owned selection before any provider/path operation."""
    global _selected
    with _selection_lock:
        _need(_selected is _UNSELECTED, 'OPERATOR_RUNTIME_ALREADY_SELECTED')
        try:
            provider = _configured(config_raw, expected_sha256)
        except ProviderError:
            raise
        except Exception:
            raise ProviderError('HOSTED_CONFIGURATION_CHECK_FAILED') from None
        _selected = provider
        return provider.sha256


def hosted():
    global _selected
    with _selection_lock:
        if _selected is _UNSELECTED:
            _selected = None
        return _selected


def selected_hosted():
    """Read a prior installation selection without selecting legacy mode."""
    with _selection_lock:
        return None if _selected is _UNSELECTED else _selected


def image_pins(legacy):
    """Resolve at operation time; v1/Windows retain their established pins."""
    provider = hosted()
    if provider is None or provider.configuration['schema_version'] == 1:
        return validated_image_pins(legacy)
    return validated_image_pins(provider.configuration['images'])


def private_root(kind, legacy_path):
    _need(kind in _PATHS, 'HOSTED_STORAGE_KIND_INVALID')
    provider = hosted()
    return Path(legacy_path) if provider is None else provider.path(kind)


def private_destination(path, *, kinds=tuple(_PATHS)):
    provider = hosted()
    if provider is not None:
        provider.private_destination(Path(path), kinds=kinds)


def execute_host(program, data, *, timeout, legacy_argv, legacy_runner, maximum=MAX_WIRE):
    """One framing seam; legacy argv/runner retain their established behavior."""
    _need(type(program) is str and type(data) is bytes, 'PROTECTED_REQUEST_INVALID')
    wire = base64.b64encode(program.encode('utf-8')) + b'\n' + data
    _need(len(wire) <= min(maximum, MAX_WIRE), 'PROTECTED_REQUEST_TOO_LARGE')
    provider = hosted()
    if provider is not None:
        return provider.execute_host(program, data, timeout=timeout)
    return legacy_runner(legacy_argv, data=wire, timeout=timeout)
