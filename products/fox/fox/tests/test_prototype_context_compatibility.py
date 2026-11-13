"""Trusted static historical context; archived job Python is never executable."""
import builtins
import ast
import base64
from copy import deepcopy
import hashlib
import importlib.util
import inspect
import json
from pathlib import Path
import subprocess
import sys

import pytest

from fox import prototype_design_context as current
from fox import prototype_design_context_v1 as legacy
from fox import prototype_container_proof as proof, prototype_container_epoch as epoch
from test_prototype_container_proof import case, manifest
from test_prototype_design_context import example, structural, TARGET

LEGACY_SHA = 'b48195fc859f52a7786e999350af3c7ec96c737d516caef906ea093347d2498c'


def members(root):
    return {name: (root / name).read_bytes() for name in proof.JSON_FILES}


def test_v1_is_exact_static_shipped_sibling_and_only_historical_alias_uses_it():
    assert Path(legacy.__file__).name == 'prototype_design_context_v1.py'
    assert Path(legacy.__file__).parent == Path(current.__file__).parent
    assert hashlib.sha256(Path(legacy.__file__).read_bytes()).hexdigest() == proof.CONTEXT_MODULE_SHA256 == LEGACY_SHA
    assert hashlib.sha256(Path(current.__file__).read_bytes()).hexdigest() != LEGACY_SHA
    assert proof.context is legacy and proof.context is not current
    assert epoch.validate_prefix_context is current.validate_prefix_context
    assert epoch.build_review_context is current.build_review_context
    assert 'prototype_design_context.py' in proof.FILES
    assert 'prototype_design_context.py' not in proof.JSON_FILES


def test_original_archive_manifest_and_json_receiver_pass_with_current_optimized(case, monkeypatch):
    root, bindings = case
    original = deepcopy(bindings)
    pins = manifest(root)
    assert pins['prototype_design_context.py'] == {'sha256': LEGACY_SHA, 'bytes': len(Path(legacy.__file__).read_bytes())}
    def forbidden(*args, **kwargs): pytest.fail('Historical proof invoked current optimized context')
    monkeypatch.setattr(current, 'propose_container_retention', forbidden)
    monkeypatch.setattr(current, 'validate_prefix_context', forbidden)
    archive = proof.read_container_proof(root, **bindings)
    receiver = proof.validate_container_proof_members(members(root), context_module_sha256=LEGACY_SHA, **bindings)
    assert archive[:2] == receiver[:2]
    assert archive[2]['archived_module_bytes_checked'] is True
    assert receiver[2]['archived_module_bytes_checked'] is False
    archive[2]['archived_module_bytes_checked'] = False
    assert archive == receiver and bindings == original and manifest(root) == pins
    assert archive[2]['context_module_sha256'] == LEGACY_SHA
    assert archive[2]['current_state_or_owner_consent_verified'] is False


@pytest.mark.parametrize('mutation', ['missing', 'bytes', 'alias-current'])
def test_missing_or_changed_installed_v1_and_alias_to_new_module_are_rejected(case, tmp_path, monkeypatch, mutation):
    root, bindings = case
    json_members = members(root)
    if mutation == 'alias-current':
        monkeypatch.setattr(proof, 'context', current)
    else:
        altered = tmp_path / 'isolated-module-bytes.py'
        if mutation == 'bytes': altered.write_bytes(Path(legacy.__file__).read_bytes() + b'\n')
        monkeypatch.setattr(legacy, '__file__', str(altered))
    with pytest.raises(ValueError, match='Invalid retained unadopted container-review proof'):
        proof.validate_container_proof_members(json_members, context_module_sha256=LEGACY_SHA, **bindings)


@pytest.mark.parametrize('mutation', ['new-hash', 'wrong-size', 'boolean-size', 'wrong-module', 'python-member'])
def test_new_module_hash_or_manifest_cannot_relabel_legacy_proof(case, mutation):
    root, bindings = case
    json_members = members(root)
    module_sha = LEGACY_SHA
    if mutation == 'new-hash':
        raw = Path(current.__file__).read_bytes()
        bindings['approved_manifest']['prototype_design_context.py'] = {'sha256': hashlib.sha256(raw).hexdigest(), 'bytes': len(raw)}
    elif mutation == 'wrong-size': bindings['approved_manifest']['prototype_design_context.py']['bytes'] += 1
    elif mutation == 'boolean-size': bindings['approved_manifest']['prototype_design_context.py']['bytes'] = True
    elif mutation == 'wrong-module': module_sha = hashlib.sha256(Path(current.__file__).read_bytes()).hexdigest()
    else: json_members['prototype_design_context.py'] = Path(legacy.__file__).read_bytes()
    with pytest.raises(ValueError):
        proof.validate_container_proof_members(json_members, context_module_sha256=module_sha, **bindings)


def test_archive_python_never_compiled_or_executed_even_when_accepted(case, monkeypatch):
    root, bindings = case
    def forbidden(*args, **kwargs): raise AssertionError('Archived Python execution attempted')
    with monkeypatch.context() as patch:
        patch.setattr(builtins, 'exec', forbidden)
        patch.setattr(builtins, 'compile', forbidden)
        result = proof.read_container_proof(root, **bindings)
    assert result[2]['archived_module_bytes_checked'] is True


def test_self_consistent_malicious_archive_module_is_still_rejected_without_execution(case, monkeypatch):
    root, bindings = case
    (root / 'prototype_design_context.py').write_bytes(b'raise AssertionError("DO NOT EXECUTE ARCHIVE")\n')
    bindings['approved_manifest'] = manifest(root)
    def forbidden(*args, **kwargs): raise AssertionError('Archived Python execution attempted')
    with monkeypatch.context() as patch:
        patch.setattr(builtins, 'exec', forbidden)
        patch.setattr(builtins, 'compile', forbidden)
        with pytest.raises(ValueError): proof.read_container_proof(root, **bindings)


def test_json_virtual_receiver_reads_only_installed_v1_not_archive_source(case, monkeypatch):
    root, bindings = case
    json_members = members(root)
    original_open, installed = Path.open, Path(legacy.__file__)
    def installed_only(path, mode='r', *args, **kwargs):
        assert path == installed and mode in ('r', 'rb'), 'JSON receiver tried to dereference archived/original paths'
        return original_open(path, mode, *args, **kwargs)
    monkeypatch.setattr(Path, 'open', installed_only)
    result = proof.validate_container_proof_members(json_members, context_module_sha256=LEGACY_SHA, **bindings)
    assert result[2]['archived_module_bytes_checked'] is False


def test_current_summary_and_default_full_context_keep_same_legacy_outputs():
    packet, plan, originals, proposed, _ = example()
    candidates, refs = structural(packet, plan, originals, proposed)
    args = (packet, plan, candidates, refs, TARGET, None, None)
    assert current._prefix(*args) == legacy._prefix(*args)
    assert current._prefix(*args, materialize_rows=False)[0] == legacy._prefix(*args)[0]
    current_focus = candidates[-1]['focus_id']
    refs.pop(current_focus)
    assert current.build_review_context(packet, plan, candidates, refs, expected_target_sha256=TARGET,
        focus_id=current_focus) == legacy.build_review_context(packet, plan, candidates, refs,
        expected_target_sha256=TARGET, focus_id=current_focus)


@pytest.mark.parametrize('projection', ['fox-build', 'host-bundle'])
def test_genuine_all_fox_source_projection_includes_v1_and_validates_without_checkout(case, tmp_path, projection):
    root, bindings = case
    product = Path(__file__).resolve().parents[2]
    source = product / 'deployment/prepare_project_release.py'
    spec = importlib.util.spec_from_file_location('_context_projection_preparer', source)
    preparer = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(preparer)
    # The normal release adapter supplies named deployment profiles separately;
    # this source-only test exercises the EXACT runtime-source enumeration and
    # projections, not a claimed full archive build with invented profile input.
    source_tree = ast.parse(inspect.getsource(preparer.source_files))
    enumeration = next(node for node in source_tree.body[0].body if isinstance(node, ast.For)
        and isinstance(node.iter, ast.Tuple)
        and [item.value for item in node.iter.elts] == ['fox/fox', 'qa/operator'])
    namespace = {**vars(preparer), 'root': product, 'names': set()}
    exec(compile(ast.Module(body=[enumeration], type_ignores=[]), '<trusted-runtime-source-enumeration>', 'exec'), namespace)
    files = {name: preparer.read(product / name, allow_empty=True) for name in namespace['names'] if name.startswith('fox/fox/')}
    files['fox/fox/release.json'] = preparer.read(product / 'fox/fox/release.json')
    expected = Path(legacy.__file__).read_bytes()
    assert files['fox/fox/prototype_design_context_v1.py'] == expected
    # Evaluate only the genuine preparer's pure projection expressions, not
    # prepare()/UI/wheel/cloud operations or any archived job Python.
    tree = ast.parse(inspect.getsource(preparer.materialize))
    if projection == 'fox-build':
        expression = next(node for node in ast.walk(tree) if isinstance(node, ast.DictComp)
            and isinstance(node.key, ast.BinOp) and isinstance(node.key.left, ast.Constant)
            and node.key.left.value == 'build/fox/fox/')
        projected = eval(compile(ast.Expression(expression), '<trusted-preparer-data-projection>', 'eval'), {}, {'files': files})
        wanted = 'build/fox/fox/prototype_design_context_v1.py'
        assert projected[wanted] == expected
        projected = {name.removeprefix('build/fox/'): raw for name, raw in projected.items()}
        import_root = tmp_path / 'fox-context'
    else:
        assignment = next(node for node in ast.walk(tree) if isinstance(node, ast.Assign)
            and any(isinstance(target, ast.Name) and target.id == 'bundle' for target in node.targets))
        projected = eval(compile(ast.Expression(assignment.value), '<trusted-host-bundle-data-projection>', 'eval'), {}, {'files': files})
        assert projected['fox/fox/prototype_design_context_v1.py'] == expected
        import_root = tmp_path / 'host-bundle' / 'fox'
        projected = {name.removeprefix('fox/'): raw for name, raw in projected.items() if name.startswith('fox/')}
    import_root.mkdir(parents=True)
    for name, raw in projected.items():
        path = import_root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(raw)
    program = r'''
import base64,hashlib,json,pathlib,sys
v=json.load(sys.stdin);checkout=pathlib.Path(v['checkout']).resolve();root=pathlib.Path(v['root']).resolve()
sys.path=[name for name in sys.path if name and not pathlib.Path(name).resolve().is_relative_to(checkout)]
sys.path.insert(0,str(root))
from fox import prototype_container_proof as proof,prototype_design_context_v1 as legacy,prototype_design_context as current
assert pathlib.Path(proof.__file__).resolve().is_relative_to(root)
assert pathlib.Path(legacy.__file__).resolve().is_relative_to(root)
assert pathlib.Path(current.__file__).resolve().is_relative_to(root)
assert proof.context is legacy
assert hashlib.sha256(pathlib.Path(legacy.__file__).read_bytes()).hexdigest()==proof.CONTEXT_MODULE_SHA256==v['legacy_sha256']
assert hashlib.sha256(pathlib.Path(current.__file__).read_bytes()).hexdigest()!=v['legacy_sha256']
members={name:base64.b64decode(raw)for name,raw in v['members'].items()}
candidate,checked,provenance=proof.validate_container_proof_members(members,context_module_sha256=v['legacy_sha256'],**v['bindings'])
assert checked['verdict']=='APPROVED'and provenance['context_module_sha256']==v['legacy_sha256']
assert provenance['archived_module_bytes_checked']is False and provenance['adoption_authorized']is False
print(json.dumps({'isolated_projection_imported':True,'legacy_proof_validated':True,'archive_executed':False}))
'''
    payload = {'checkout': str(product), 'root': str(import_root), 'legacy_sha256': LEGACY_SHA,
               'members': {name: base64.b64encode(raw).decode() for name, raw in members(root).items()}, 'bindings': bindings}
    done = subprocess.run([sys.executable, '-I', '-B', '-c', program], input=json.dumps(payload).encode(),
                          capture_output=True, timeout=30, cwd=tmp_path)
    assert done.returncode == 0, done.stderr.decode()
    assert json.loads(done.stdout) == {'isolated_projection_imported': True, 'legacy_proof_validated': True, 'archive_executed': False}
