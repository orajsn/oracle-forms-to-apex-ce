import subprocess
from pathlib import Path
import pytest
from forms2apex.sqlcl import import_apexlang

def test_alias_collision_never_imports(monkeypatch,tmp_path):
    calls=[]
    def run(*args,**kwargs):
        calls.append(args)
        assert 'upper(alias)' in '\n'.join(args[2])
        assert 'target identity mismatch' in '\n'.join(args[2])
        return subprocess.CompletedProcess([],0,'F2A_ALIAS_COUNT=1','')
    monkeypatch.setattr('forms2apex.sqlcl._run_script',run)
    with pytest.raises(RuntimeError,match='already exists'):
        import_apexlang(Path('/sql'),'F2A_APEX','FORMS2APEX_POC','fox-123',tmp_path/'apexlang',tmp_path/'import.log')
    assert len(calls)==1

def test_success_requires_actual_import_confirmation(monkeypatch,tmp_path):
    calls=[]
    def run(*args,**kwargs):
        calls.append(args)
        return subprocess.CompletedProcess([],0,'F2A_ALIAS_COUNT=0' if len(calls)==1 else 'ORA-20000: failed','')
    monkeypatch.setattr('forms2apex.sqlcl._run_script',run)
    with pytest.raises(RuntimeError,match='import failed'):
        import_apexlang(Path('/sql'),'F2A_APEX','FORMS2APEX_POC','fox-123',tmp_path/'apexlang',tmp_path/'import.log')
