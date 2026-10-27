"""Local synthetic credentials only; no real account or network request."""
import base64
import ctypes
import json
import os
from pathlib import Path
import subprocess
import sys

import pytest

HERE=Path(__file__).resolve().parent
sys.path.insert(0,str(HERE))
from journey_contracts import JourneyError
import private_io as P


@pytest.mark.skipif(os.name!='nt',reason='Actual Windows user-scoped DPAPI')
def test_actual_owner_private_dpapi_roundtrip_without_plaintext_file(tmp_path):
    folder=P.new_directory(tmp_path/'dpapi-only')
    target=folder/'synthetic.dpapi'
    password='Synthetic fixture only ! " \\ é 12345'
    buffer=ctypes.create_unicode_buffer(32768)
    assert ctypes.windll.kernel32.GetWindowsDirectoryW(buffer,len(buffer))
    executable=Path(buffer.value)/'System32/WindowsPowerShell/v1.0/powershell.exe'
    program="""$ErrorActionPreference='Stop'
$ProgressPreference='SilentlyContinue'
$v=([Console]::In.ReadToEnd()|ConvertFrom-Json)
$s=ConvertTo-SecureString $v.password -AsPlainText -Force
$cipher=ConvertFrom-SecureString $s
[IO.File]::WriteAllText($v.path,$cipher)
"""
    result=subprocess.run([str(executable),'-NoProfile','-NonInteractive','-EncodedCommand',base64.b64encode(program.encode('utf-16-le')).decode()],
        input=json.dumps({'path':str(target),'password':password}).encode(),capture_output=True,timeout=20,creationflags=subprocess.CREATE_NO_WINDOW)
    assert result.returncode==0 and not result.stdout and not result.stderr
    assert password.encode() not in target.read_bytes()
    assert P.dpapi_credentials(target,'synthetic-observer')=={'username':'synthetic-observer','password':password}
    assert sorted(p.name for p in folder.iterdir())==['synthetic.dpapi']


@pytest.mark.skipif(os.name!='nt',reason='Actual Windows user-scoped DPAPI')
def test_invalid_cipher_returns_closed_code_not_decryptor_output(tmp_path):
    folder=P.new_directory(tmp_path/'bad-cipher');target=folder/'bad.dpapi'
    target.write_text('Synthetic invalid cipher; never a real credential',encoding='utf-8')
    with pytest.raises(JourneyError,match='^DPAPI_LOGIN_UNAVAILABLE$'):P.dpapi_credentials(target,'synthetic')


@pytest.mark.skipif(os.name!='nt',reason='Windows DPAPI input validation')
@pytest.mark.parametrize('username',['','x\n',True,'x'*101])
def test_invalid_username_rejects_before_private_file_access(monkeypatch,username):
    monkeypatch.setattr(P,'private',lambda path:pytest.fail('Must reject before reading private input'))
    with pytest.raises(JourneyError,match='NORMAL_LOGIN_CREDENTIALS_REQUIRED'):P.dpapi_credentials('not-read',username)
