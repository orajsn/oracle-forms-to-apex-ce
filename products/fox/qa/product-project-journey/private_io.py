"""Private proof files and credential input; never repairs existing permissions."""
from __future__ import annotations

import base64
import ctypes
import json
import os
from pathlib import Path
import stat
import subprocess

from journey_contracts import JourneyError, canonical, need, object_bytes, read

ACL = r'''
$ErrorActionPreference='Stop'
try {
 $v=([Console]::In.ReadToEnd()|ConvertFrom-Json)
 $sid=[Security.Principal.WindowsIdentity]::GetCurrent().User
 $system=[Security.Principal.SecurityIdentifier]::new('S-1-5-18')
 if($v.action -eq 'protect') {
  if(![IO.Directory]::Exists($v.path) -or [IO.Directory]::EnumerateFileSystemEntries($v.path).GetEnumerator().MoveNext()){throw 'not-new-empty'}
  $acl=[Security.AccessControl.DirectorySecurity]::new();$acl.SetOwner($sid);$acl.SetAccessRuleProtection($true,$false)
  foreach($p in @($sid,$system)) {
   $r=[Security.AccessControl.FileSystemAccessRule]::new($p,[Security.AccessControl.FileSystemRights]::FullControl,
    [Security.AccessControl.InheritanceFlags]'ContainerInherit,ObjectInherit',[Security.AccessControl.PropagationFlags]::None,[Security.AccessControl.AccessControlType]::Allow)
   $acl.AddAccessRule($r)
  }
  [IO.Directory]::SetAccessControl($v.path,$acl)
 } elseif($v.action -ne 'inspect'){throw 'mode'}
 $acl=if([IO.Directory]::Exists($v.path)){[IO.Directory]::GetAccessControl($v.path)}else{[IO.File]::GetAccessControl($v.path)}
 if($acl.GetOwner([Security.Principal.SecurityIdentifier]).Value -ne $sid.Value){throw 'owner'}
 $ownerRule=$false
 foreach($r in $acl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier])) {
  if($r.AccessControlType -eq 'Allow') {
   if($r.IdentityReference.Value -notin @($sid.Value,$system.Value)){throw 'reader'}
   if($r.IdentityReference.Value -eq $sid.Value){$ownerRule=$true}
  }
 }
 if(!$ownerRule){throw 'owner access'}
 [Console]::WriteLine('PRIVATE_INPUT_VERIFIED')
} catch { [Console]::WriteLine('PRIVATE_INPUT_UNCONFIRMED');exit 1 }
'''


def _safe(path):
    path = Path(path).absolute()
    need(not str(path).startswith(('\\\\', '//')), 'LOCAL_PRIVATE_PATH_REQUIRED')
    for part in (path, *path.parents):
        if not part.exists() and not part.is_symlink():
            continue
        info = part.lstat()
        need(not stat.S_ISLNK(info.st_mode) and not getattr(info, 'st_file_attributes', 0) & 0x400,
             'PRIVATE_PATH_LINK_FORBIDDEN')
    return path


def _windows(path, action):
    buffer = ctypes.create_unicode_buffer(32768)
    count = ctypes.windll.kernel32.GetWindowsDirectoryW(buffer, len(buffer))
    need(0 < count < len(buffer), 'WINDOWS_SECURITY_API_UNAVAILABLE')
    executable = Path(buffer.value) / 'System32/WindowsPowerShell/v1.0/powershell.exe'
    environment = {key: value for key, value in os.environ.items()
                   if key.upper() in {'PATH', 'PATHEXT', 'SYSTEMROOT', 'WINDIR', 'COMSPEC', 'TEMP', 'TMP'}}
    environment.update(SystemRoot=buffer.value, WINDIR=buffer.value)
    result = subprocess.run([str(executable), '-NoProfile', '-NonInteractive', '-EncodedCommand',
        base64.b64encode(ACL.encode('utf-16-le')).decode()],
        input=json.dumps({'path': str(path), 'action': action}).encode(), capture_output=True,
        timeout=20, env=environment, creationflags=subprocess.CREATE_NO_WINDOW)
    need(result.returncode == 0 and result.stdout.strip() == b'PRIVATE_INPUT_VERIFIED', 'PRIVATE_ACL_REQUIRED')


def private(path):
    path = _safe(path)
    info = path.lstat()
    need(stat.S_ISDIR(info.st_mode) or stat.S_ISREG(info.st_mode) and info.st_nlink == 1,
         'PRIVATE_REGULAR_INPUT_REQUIRED')
    if os.name == 'nt':
        _windows(path, 'inspect')
    else:
        need(info.st_uid == os.getuid() and not stat.S_IMODE(info.st_mode) & 0o077, 'PRIVATE_MODE_REQUIRED')
    return path


def new_directory(path):
    path = _safe(path)
    need(path.parent.is_dir() and not path.exists() and not path.is_symlink(), 'NEW_PROOF_DIRECTORY_REQUIRED')
    path.mkdir(mode=0o700)
    if os.name == 'nt':
        _windows(path, 'protect')
    private(path)
    return path


def save(path, value):
    path = _safe(path)
    private(path.parent)
    with os.fdopen(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, 'O_NOFOLLOW', 0), 0o600), 'wb') as stream:
        stream.write(canonical(value)); stream.flush(); os.fsync(stream.fileno())
    if os.name != 'nt':
        descriptor = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)


def credentials(path):
    path = private(path)
    value = object_bytes(read(path, maximum=8192), maximum=8192)
    need(set(value) == {'username', 'password'} and type(value['username']) is str
         and 0 < len(value['username']) <= 100 and type(value['password']) is str
         and 0 < len(value['password']) <= 256, 'NORMAL_LOGIN_CREDENTIALS_REQUIRED')
    need(all(not any(ord(char) < 32 or 0xD800 <= ord(char) <= 0xDFFF for char in text)
             for text in value.values()), 'NORMAL_LOGIN_CREDENTIALS_REQUIRED')
    return value


def dpapi_credentials(path,username):
    """Windows user-scoped password reference; never persist a plaintext file."""
    need(os.name=='nt','WINDOWS_DPAPI_REQUIRED')
    need(type(username)is str and 0<len(username)<=100 and not any(ord(c)<32 or 0xD800<=ord(c)<=0xDFFF for c in username),
         'NORMAL_LOGIN_CREDENTIALS_REQUIRED')
    path=private(path);encrypted=read(path,maximum=32768)
    buffer=ctypes.create_unicode_buffer(32768)
    count=ctypes.windll.kernel32.GetWindowsDirectoryW(buffer,len(buffer))
    need(0<count<len(buffer),'WINDOWS_SECURITY_API_UNAVAILABLE')
    executable=Path(buffer.value)/'System32/WindowsPowerShell/v1.0/powershell.exe'
    program=r'''$ErrorActionPreference='Stop'
$ProgressPreference='SilentlyContinue'
try {
 $v=([Console]::In.ReadToEnd()|ConvertFrom-Json)
 $secure=ConvertTo-SecureString ([IO.File]::ReadAllText($v.path))
 $credential=New-Object Management.Automation.PSCredential($v.username,$secure)
 $value=@{username=$v.username;password=$credential.GetNetworkCredential().Password}|ConvertTo-Json -Compress
 [Console]::OutputEncoding=New-Object Text.UTF8Encoding($false)
 [Console]::Out.Write($value)
} catch { [Console]::Error.Write('DPAPI_LOGIN_UNAVAILABLE');exit 1 }
'''
    environment={key:value for key,value in os.environ.items() if key.upper() in {'PATH','PATHEXT','SYSTEMROOT','WINDIR','COMSPEC','TEMP','TMP'}}
    environment.update(SystemRoot=buffer.value,WINDIR=buffer.value)
    try:
        result=subprocess.run([str(executable),'-NoProfile','-NonInteractive','-EncodedCommand',
            base64.b64encode(program.encode('utf-16-le')).decode()],
            input=json.dumps({'path':str(path),'username':username}).encode(),capture_output=True,timeout=20,
            env=environment,creationflags=subprocess.CREATE_NO_WINDOW)
        need(result.returncode==0 and not result.stderr.strip(),'DPAPI_LOGIN_UNAVAILABLE')
        value=object_bytes(result.stdout,maximum=8192)
    except Exception:
        raise JourneyError('DPAPI_LOGIN_UNAVAILABLE') from None
    need(read(path,maximum=32768)==encrypted,'DPAPI_REFERENCE_CHANGED_DURING_READ')
    need(set(value)=={'username','password'} and value['username']==username and type(value['password'])is str
         and 0<len(value['password'])<=256 and not any(ord(c)<32 or 0xD800<=ord(c)<=0xDFFF for c in value['password']),
         'NORMAL_LOGIN_CREDENTIALS_REQUIRED')
    return value
