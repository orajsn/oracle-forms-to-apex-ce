"""Owner-private local-session files and lifetime locks; no network or secrets.

Windows uses fixed OS security APIs through the installed Windows PowerShell.
Only a newly created empty session directory may receive a new protected DACL.
Existing data is inspected, never permission-repaired. No password is sent to
the OS helper. POSIX uses the current uid and private filesystem modes.
"""
from __future__ import annotations

import base64
import ctypes
import json
import os
from pathlib import Path
import stat
import subprocess


class LocalSessionError(ValueError):
    """Fixed diagnostic; never echo a password, verifier, path or OS output."""


_ACL_SCRIPT = r'''
$ErrorActionPreference='Stop'
$ProgressPreference='SilentlyContinue'
try {
 $reader=New-Object System.IO.StreamReader([Console]::OpenStandardInput(),(New-Object System.Text.UTF8Encoding($false,$true)))
 $request=$reader.ReadToEnd()|ConvertFrom-Json
 if (@($request.PSObject.Properties.Name).Count -ne 2 -or $request.action -notin @('protect','inspect')) { throw 'invalid' }
 $path=[string]$request.path
 $sid=[System.Security.Principal.WindowsIdentity]::GetCurrent().User
 $system=[System.Security.Principal.SecurityIdentifier]::new('S-1-5-18')
 if ($request.action -eq 'protect') {
  if (![IO.Directory]::Exists($path) -or @(Get-ChildItem -LiteralPath $path -Force).Count -ne 0) { throw 'not-new-empty-directory' }
  $acl=[System.Security.AccessControl.DirectorySecurity]::new()
  $acl.SetOwner($sid)
  $acl.SetAccessRuleProtection($true,$false)
  foreach($principal in @($sid,$system)) {
   $rule=[System.Security.AccessControl.FileSystemAccessRule]::new($principal,[System.Security.AccessControl.FileSystemRights]::FullControl,
    [System.Security.AccessControl.InheritanceFlags]'ContainerInherit, ObjectInherit',
    [System.Security.AccessControl.PropagationFlags]::None,[System.Security.AccessControl.AccessControlType]::Allow)
   $acl.AddAccessRule($rule)
  }
  Set-Acl -LiteralPath $path -AclObject $acl
 }
 $items=@(Get-Item -LiteralPath $path -Force)
 for($index=0;$index -lt $items.Count;$index++) {
  if($items.Count -gt 20000) { throw 'session-tree-bound' }
  $item=$items[$index]
  if($item.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'linked-material' }
  $actual=Get-Acl -LiteralPath $item.FullName
  if ($actual.GetOwner([System.Security.Principal.SecurityIdentifier]).Value -ne $sid.Value) { throw 'wrong-owner' }
  $rules=@($actual.GetAccessRules($true,$true,[System.Security.Principal.SecurityIdentifier]))
  if ($rules.Count -ne 2) { throw 'unexpected-ace' }
  $seen=@{}
  foreach($rule in $rules) {
   $principal=$rule.IdentityReference.Value
   if ($principal -notin @($sid.Value,$system.Value) -or $seen.ContainsKey($principal) -or
       $rule.AccessControlType -ne [System.Security.AccessControl.AccessControlType]::Allow -or
       $rule.FileSystemRights -ne [System.Security.AccessControl.FileSystemRights]::FullControl) { throw 'not-private' }
   $seen[$principal]=$true
  }
  if ($index -eq 0 -and $item.PSIsContainer -and !$actual.AreAccessRulesProtected) { throw 'directory-inheritance-enabled' }
  if($item.PSIsContainer) { $items+=@(Get-ChildItem -LiteralPath $item.FullName -Force) }
 }
 [Console]::WriteLine((@{ok=$true;owner_id=$sid.Value}|ConvertTo-Json -Compress))
} catch {
 [Console]::WriteLine('{"ok":false}')
 exit 1
}
'''


def safe_path(path):
    path = Path(os.path.abspath(path))
    if str(path).startswith(('\\', '//')):
        raise LocalSessionError('Local session paths must not use a network share.')
    for part in [path, *path.parents]:
        try:
            info = part.lstat()
        except FileNotFoundError:
            continue
        if (stat.S_ISLNK(info.st_mode) or getattr(info, 'st_file_attributes', 0) & 0x400
                or (stat.S_ISREG(info.st_mode) and info.st_nlink != 1)):
            raise LocalSessionError('Linked local session paths are not accepted.')
    return path


def _windows_acl(path, action):
    buffer = ctypes.create_unicode_buffer(32768)
    count = ctypes.windll.kernel32.GetWindowsDirectoryW(buffer, len(buffer))
    if not 0 < count < len(buffer):
        raise LocalSessionError('Local session ownership could not be verified.')
    executable = Path(buffer.value) / 'System32/WindowsPowerShell/v1.0/powershell.exe'
    startup = subprocess.STARTUPINFO()
    startup.dwFlags |= subprocess.STARTF_USESHOWWINDOW
    startup.wShowWindow = 0
    keep = {'SYSTEMROOT', 'WINDIR', 'COMSPEC', 'TEMP', 'TMP', 'PATH', 'PATHEXT'}
    environment = {key: value for key, value in os.environ.items() if key.upper() in keep}
    # Supply OS-derived runtime locations even under a deliberately empty test
    # environment; never load a caller's PowerShell module path/profile.
    environment.update(SystemRoot=buffer.value, WINDIR=buffer.value,
                       PSModulePath=str(executable.parent / 'Modules'))
    try:
        result = subprocess.run([str(executable), '-NoProfile', '-NonInteractive', '-EncodedCommand',
                                 base64.b64encode(_ACL_SCRIPT.encode('utf-16-le')).decode('ascii')],
            input=json.dumps({'action': action, 'path': str(path)}, ensure_ascii=False).encode('utf-8'),
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=15, check=False, shell=False,
            startupinfo=startup, creationflags=subprocess.CREATE_NO_WINDOW, env=environment)
        if result.returncode or len(result.stdout) > 2048:
            raise ValueError()
        value = json.loads(result.stdout)
        if (set(value) != {'ok', 'owner_id'} or value['ok'] is not True
                or type(value['owner_id']) is not str or not value['owner_id'].startswith('S-1-')):
            raise ValueError()
        return value['owner_id']
    except (OSError, ValueError, subprocess.TimeoutExpired):
        raise LocalSessionError('Local session ownership/privacy check failed; no existing permissions were repaired.') from None


def protect_new_directory(path):
    path = safe_path(path)
    if not path.is_dir() or any(path.iterdir()):
        raise LocalSessionError('Only a new empty local session directory may be protected.')
    if os.name == 'nt':
        return _windows_acl(path, 'protect')
    os.chmod(path, 0o700)
    return verify_private(path)


def verify_private(path):
    path = safe_path(path)
    info = path.stat()
    if not (stat.S_ISDIR(info.st_mode) or stat.S_ISREG(info.st_mode)):
        raise LocalSessionError('Local session material must be ordinary files/directories.')
    if os.name == 'nt':
        return _windows_acl(path, 'inspect')
    if info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) & 0o077:
        raise LocalSessionError('Local session ownership/privacy check failed; no existing permissions were repaired.')
    return 'uid:' + str(os.getuid())


def verify_tree_paths(root):
    """Reject links before touching stored files, without following directories."""
    pending, count = [safe_path(root)], 0
    while pending:
        path = safe_path(pending.pop())
        count += 1
        if count > 20000:
            raise LocalSessionError('Local session tree exceeds the inspection bound.')
        if path.is_dir():
            pending.extend(path.iterdir())


class SessionLock:
    """Nonblocking OS lock, automatically released on process termination."""

    def __init__(self, path, *, create=False):
        self.fd = None
        path = safe_path(path)
        try:
            flags = os.O_RDWR | (os.O_CREAT | os.O_EXCL if create else 0)
            self.fd = os.open(path, flags, 0o600)
            if create:
                os.write(self.fd, b'0')
            elif not stat.S_ISREG(os.fstat(self.fd).st_mode) or os.fstat(self.fd).st_size != 1:
                raise ValueError()
            os.lseek(self.fd, 0, os.SEEK_SET)
            if os.name == 'nt':
                import msvcrt
                msvcrt.locking(self.fd, msvcrt.LK_NBLCK, 1)
            else:
                import fcntl
                fcntl.flock(self.fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except (OSError, ValueError):
            if self.fd is not None:
                os.close(self.fd)
                self.fd = None
            raise LocalSessionError('Local session is busy or its lock is unavailable; no second instance was opened.') from None

    def close(self):
        if self.fd is not None:
            try:
                os.lseek(self.fd, 0, os.SEEK_SET)
                if os.name == 'nt':
                    import msvcrt
                    msvcrt.locking(self.fd, msvcrt.LK_UNLCK, 1)
                else:
                    import fcntl
                    fcntl.flock(self.fd, fcntl.LOCK_UN)
            finally:
                os.close(self.fd)
                self.fd = None

    def __del__(self):
        try:
            self.close()
        except Exception:
            pass
