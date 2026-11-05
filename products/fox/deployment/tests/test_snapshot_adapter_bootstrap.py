"""Real pinned module import, not a live host transition or capture authority."""
import hashlib
import importlib.util
import os
from pathlib import Path
import sys

import pytest

ROOT=Path(__file__).resolve().parents[2]
spec=importlib.util.spec_from_file_location('snapshot_adapter_import_contract',ROOT/'deployment/current_pair_transition.py')
T=importlib.util.module_from_spec(spec);spec.loader.exec_module(T)


@pytest.mark.skipif(os.name!='posix',reason='Actual POSIX source ownership/no-follow import boundary')
def test_new_adapter_load_is_distinct_from_existing_namespace_and_hash_checked(tmp_path):
    from qa.operator import hosted_snapshot as existing
    original=Path(existing.__file__).read_bytes();identity=id(existing)
    root=tmp_path/'new-bundle';adapter=root/'qa/operator/hosted_snapshot.py';adapter.parent.mkdir(parents=True)
    adapter.write_bytes(original);adapter.chmod(0o600)
    digest=hashlib.sha256(original).hexdigest()
    plan={'schema_version':2,'snapshot_adapter':{'path':str(adapter),'sha256':digest}}
    installation={'layout':{'release_root':str(root)}}
    inventory={'files':{'qa/operator/hosted_snapshot.py':digest}}
    try:
        loaded=T.snapshot_adapter(plan,existing,installation,inventory)
        assert loaded is not existing and loaded.__name__=='qa.operator._current_transition_snapshot'
        assert loaded.SCOPE_V2=='fox-hosted-snapshot-plan-v2'
        assert sys.modules['qa.operator.hosted_snapshot'] is existing and id(existing)==identity
        assert Path(existing.__file__).read_bytes()==original
        adapter.write_bytes(original+b'\n')
        with pytest.raises(T.TransitionError,match='HELPER_SOURCE_CHANGED'):
            T.snapshot_adapter(plan,existing,installation,inventory)
    finally:
        sys.modules.pop('qa.operator._current_transition_snapshot',None)
