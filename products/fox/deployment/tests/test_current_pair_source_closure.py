"""Measured pure-reader imports only; no job, service, cloud or model access."""
import base64
from copy import deepcopy
import json
from pathlib import Path
import subprocess
import sys
from types import SimpleNamespace

import pytest

from test_current_pair_transition import M, ROOT


@pytest.fixture
def measured():
    files = {}
    for prefix in ('fox/fox', 'converter/forms2apex', 'converter/fox_source_contract'):
        for path in sorted((ROOT / prefix).glob('*.py')):
            files[path.relative_to(ROOT).as_posix()] = path.read_bytes()
    inventory = {'files': {name: M.sha(raw) for name, raw in files.items()}}
    root = Path('/measured/release')
    inventory_path = Path('/measured/inventory.json')

    def read(path, **kwargs):
        if path == inventory_path:
            assert kwargs == {'private': True}
            return M.cb(inventory)
        assert not kwargs
        return files[path.relative_to(root).as_posix()]

    context = object.__new__(M.Transition)
    context.A = SimpleNamespace(read=read)
    context.new_i = {'layout': {'release_root': root.as_posix(),
                               'inventory': {'path': inventory_path.as_posix()}}}
    return SimpleNamespace(context=context, files=files, inventory=inventory)


def isolated(packet, directory):
    # Run the exact production bootstrap before its real retained-job proof.
    # The harness imports real measured renderer bytes; it does not replace a
    # module, source origin, template, technical predicate or real job result.
    bootstrap, _ = M.PRECLAIM_TECHNICAL.split('from fox import verification_recovery as r\n', 1)
    harness = '''
assert sys.flags.isolated and not any('publication-orajsn' in item for item in sys.path)
from forms2apex import native_blueprint, native_project
from fox_source_contract import project_conversion
from fox import project_conversion as canonical
assert native_project.source_contract is project_conversion
assert project_conversion.PROFILE_ID == canonical.PROFILE_ID == 'native-project-v1'
assert native_blueprint.PROFILE_ID == 'native-blueprint-prototype-v1'
assert sys.modules['fox_source_contract'].__path__ == []
print(json.dumps({'modules': {name: module.__file__ for name, module in sys.modules.items()
    if name.split('.')[0] in ('fox', 'forms2apex', 'fox_source_contract')},
    'render_imported': True}, sort_keys=True))
'''
    return subprocess.run([sys.executable, '-I', '-B', '-c', bootstrap + harness],
                          input=M.cb({'sources': packet}), capture_output=True,
                          cwd=directory, timeout=30)


def test_collector_and_isolated_loader_import_real_third_package(measured, tmp_path):
    packet = measured.context._preclaim_sources()
    assert {name for name in packet if name.split('.')[0] == 'fox_source_contract'} == {
        'fox_source_contract', 'fox_source_contract.intake',
        'fox_source_contract.native_source', 'fox_source_contract.project_conversion'}
    for tail in ('intake', 'native_source', 'project_conversion'):
        assert packet['fox_source_contract.' + tail] == packet['fox.' + tail]
    result = isolated(packet, tmp_path)
    assert result.returncode == 0, result.stderr.decode()
    assert result.stderr == b''
    observed = json.loads(result.stdout)
    assert observed['render_imported'] is True
    assert 'forms2apex.native_project' in observed['modules']
    assert 'fox_source_contract.project_conversion' in observed['modules']


@pytest.mark.parametrize('member', ['__init__', 'intake', 'native_source', 'project_conversion'])
def test_missing_measured_third_package_member_rejects(measured, member):
    del measured.inventory['files']['converter/fox_source_contract/' + member + '.py']
    with pytest.raises(M.TransitionError, match='^PRECLAIM_TECHNICAL_NAMESPACE_INCOMPLETE$'):
        measured.context._preclaim_sources()


@pytest.mark.parametrize('member', ['__init__', 'intake', 'native_source', 'project_conversion'])
def test_tampered_measured_third_package_member_rejects(measured, member):
    measured.files['converter/fox_source_contract/' + member + '.py'] += b'\n# changed\n'
    with pytest.raises(M.TransitionError, match='^PRECLAIM_TECHNICAL_SOURCE_CHANGED$'):
        measured.context._preclaim_sources()


@pytest.mark.parametrize('member', ['intake', 'native_source', 'project_conversion'])
def test_rehashed_mirror_must_still_match_measured_canonical_source(measured, member):
    name = 'converter/fox_source_contract/' + member + '.py'
    measured.files[name] += b'\n# independently changed\n'
    measured.inventory['files'][name] = M.sha(measured.files[name])
    with pytest.raises(M.TransitionError, match='^PRECLAIM_TECHNICAL_MIRROR_CHANGED$'):
        measured.context._preclaim_sources()


@pytest.mark.parametrize('fault', ['missing-package', 'missing-module', 'tampered-bytes', 'extra-dependency'])
def test_isolated_loader_refuses_unmeasured_or_tampered_dependency(measured, tmp_path, fault):
    packet = deepcopy(measured.context._preclaim_sources())
    if fault == 'missing-package':
        del packet['fox_source_contract']
    elif fault == 'missing-module':
        del packet['fox_source_contract.project_conversion']
    elif fault == 'tampered-bytes':
        packet['fox_source_contract.project_conversion']['bytes'] = base64.b64encode(b'# changed').decode()
    else:
        raw = base64.b64decode(packet['fox_source_contract']['bytes']) + b'\nfrom . import unmeasured\n'
        packet['fox_source_contract'] = {'bytes': base64.b64encode(raw).decode(), 'sha256': M.sha(raw)}
    result = isolated(packet, tmp_path)
    assert result.returncode != 0
    assert result.stdout == b''
    assert b'AssertionError' in result.stderr
    if fault != 'tampered-bytes':
        assert b'UNMEASURED_PURE_READER_DEPENDENCY' in result.stderr


@pytest.mark.parametrize('name', ['fox', 'fox.verification_recovery', 'forms2apex',
                                 'forms2apex.native_project', 'fox_source_contract',
                                 'fox_source_contract.project_conversion'])
def test_origin_preserves_matching_physical_file_and_never_attests_different_bytes(name):
    package = name in ('fox', 'forms2apex', 'fox_source_contract')
    physical = '/app/' + name.replace('.', '/') + ('/__init__.py' if package else '.py')
    assert M.preclaim_module_origin(name, 'a' * 64, 'a' * 64) == physical
    for prior in (None, 'b' * 64):
        assert M.preclaim_module_origin(name, 'a' * 64, prior) == '<measured-new:' + name + ':' + 'a' * 64 + '>'
