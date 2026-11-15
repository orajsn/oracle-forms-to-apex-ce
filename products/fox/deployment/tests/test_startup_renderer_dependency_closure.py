"""Real closed startup imports in the actual FOX COPY payload; no live proof.

The child has no site packages/development paths, DB, network, process or writes.
Only the fixed /app root is relocated for a portable local materialization.
"""
import ast
from copy import deepcopy
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import sys

import pytest

from test_paired_release_build import HERE, inputs, p, r


COUNT_RENDERER_PY = {
    'forms2apex/forms_count_guard.py',
    'forms2apex/native_blueprint_count_guard.py',
    'forms2apex/count_guard_fixture.py',
}


def host_module():
    path = HERE.parent / 'qa/operator/paused_stage_host.py'
    spec = importlib.util.spec_from_file_location('_startup_renderer_host_projection', path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def startup_prefix(app):
    raw = (HERE.parent / 'qa/operator/retirement_remote.py').read_text(encoding='utf-8')
    assignment = next(n for n in ast.parse(raw).body if isinstance(n, ast.Assign)
        and any(isinstance(t, ast.Name) and t.id == 'STARTUP_INERT' for t in n.targets))
    tree = ast.parse(ast.literal_eval(assignment.value))
    stop = next(i for i, n in enumerate(tree.body) if isinstance(n, ast.ImportFrom) and n.module == 'fox')
    prefix = ast.Module(body=tree.body[:stop], type_ignores=[])
    finder = next(n for n in ast.walk(prefix) if isinstance(n, ast.ClassDef) and n.name == 'Finder')
    original_finder = ast.dump(finder, include_attributes=False)
    replacements = []

    class PhysicalRoot(ast.NodeTransformer):
        def visit_Constant(self, node):
            if node.value == '/app':
                replacements.append(node.value)
                return ast.copy_location(ast.Constant(str(app)), node)
            return node

    prefix = PhysicalRoot().visit(prefix)
    assert len(replacements) == 2  # sys.path root and exact semantic root assertion.
    finder = next(n for n in ast.walk(prefix) if isinstance(n, ast.ClassDef) and n.name == 'Finder')
    assert ast.dump(finder, include_attributes=False) == original_finder
    return ast.unparse(ast.fix_missing_locations(prefix))


def test_startup_python_projection_equals_exact_fox_renderer_copy():
    H = host_module()
    expected = {name for name in p.APP_RENDERER_FILES if name.endswith('.py')}
    assert len(H.APP_RENDERER_PY) == len(set(H.APP_RENDERER_PY))
    assert set(H.APP_RENDERER_PY) == expected
    assert COUNT_RENDERER_PY <= expected


@pytest.fixture(scope='module')
def physical_app(tmp_path_factory):
    root = tmp_path_factory.mktemp('startup-renderer')
    value = inputs()
    value['files'].update({'fox/fox/' + path.name: p.read(path, allow_empty=True)
                           for path in (HERE.parent / 'fox/fox').glob('*.py')})
    for name in ('paused_stage_host.py', 'retirement_remote.py'):
        value['files']['qa/operator/' + name] = p.read(HERE.parent / 'qa/operator' / name)
    frozen = root / 'frozen'
    result = p.materialize(**value, output_root=frozen)
    files, _ = r.load_archive((frozen / 'paired-source.tar').read_bytes(), result['archive_sha256'])
    app = root / 'app'
    app.mkdir()
    for prefix, destination in (('build/fox/fox/', app / 'fox'), ('build/fox/renderer/', app)):
        for name, raw in files.items():
            if name.startswith(prefix):
                path = destination / name.removeprefix(prefix)
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(raw)
    inventory = json.loads(files['source-inventory.json'])
    before = {path.relative_to(app).as_posix(): hashlib.sha256(path.read_bytes()).hexdigest()
              for path in app.rglob('*') if path.is_file()}
    return app, inventory, before


CHILD = r'''
import hashlib,io,json,os,pathlib,sys
assert sys.flags.isolated and sys.flags.no_site and sys.dont_write_bytecode
v=json.load(sys.stdin);app=pathlib.Path(v['app']).resolve()
def deny_effects(event,args):
 if event.startswith(('socket.','sqlite3.')) or event in ('subprocess.Popen','os.system','os.posix_spawn'):
  raise AssertionError('NO_DB_NETWORK_OR_PROCESS')
 if event=='open':
  mode,flags=args[1],args[2]
  assert not (isinstance(mode,str) and any(c in mode for c in 'wax+')),'NO_WRITE'
  assert not (isinstance(flags,int) and flags & (os.O_WRONLY|os.O_RDWR|os.O_CREAT|os.O_TRUNC|os.O_APPEND)),'NO_WRITE'
 if event in ('os.mkdir','os.remove','os.rmdir','os.rename','os.chmod','os.chown','os.link','os.symlink'):
  raise AssertionError('NO_FILESYSTEM_MUTATION')
sys.addaudithook(deny_effects)
sys.stdin=io.StringIO(json.dumps(v['packet']))
scope={'__name__':'_exact_startup_prefix'}
exec(compile(v['startup_prefix'],'<exact-startup-root-relocated-only>','exec'),scope)
try:
 from fox import paused_stage_preservation as inert
 from fox.prototype_job import load_prototype_profile
 from fox.completed_prototype_preservation import validate_completed_fox
 from forms2apex import prototype_package,native_blueprint_count_guard,count_guard_fixture
except AssertionError as error:
 assert v['expected_missing'] is not None and str(error)=='UNMEASURED_STARTUP_SEMANTIC_DEPENDENCY'
 trace=error.__traceback__;missing=None
 while trace:
  if trace.tb_frame.f_code.co_name=='find_spec':missing=trace.tb_frame.f_locals['name']
  trace=trace.tb_next
 assert missing==v['expected_missing'],missing
 print(json.dumps({'status':'EXACT_UNMEASURED_GUARD_REJECTED','missing':missing,'effects_permitted':False}))
else:
 assert v['expected_missing'] is None,'Incomplete startup map unexpectedly imported'
 for name in ('forms2apex.forms_count_guard','forms2apex.native_blueprint_count_guard','forms2apex.count_guard_fixture'):
  assert name in sys.modules and name in v['packet']['semantic_sources']['modules']
 for name,module in tuple(sys.modules.items()):
  if name.split('.')[0] in ('fox','forms2apex','fox_source_contract','defusedxml'):
   assert pathlib.Path(module.__file__).resolve().is_relative_to(app),(name,module.__file__)
   assert hashlib.sha256(pathlib.Path(module.__file__).read_bytes()).hexdigest()==v['packet']['semantic_sources']['modules'][name]
 assert 'forms2apex.sqlcl' not in sys.modules and 'forms2apex.server' not in sys.modules
 print(json.dumps({'status':'EXACT_CLOSED_STARTUP_IMPORTS_PASSED','effects_permitted':False}))
'''


@pytest.mark.parametrize('omitted', [None, 'pre-fix', *sorted(COUNT_RENDERER_PY)])
def test_actual_startup_finder_with_copy_payload_and_old_map_rejection(physical_app, omitted):
    app, inventory, before = physical_app
    H = host_module()
    expected_missing = None
    if omitted is not None:
        removed = COUNT_RENDERER_PY if omitted == 'pre-fix' else {omitted}
        H.APP_RENDERER_PY = tuple(name for name in H.APP_RENDERER_PY if name not in removed)
        expected_missing = ('forms2apex.native_blueprint_count_guard' if omitted == 'pre-fix'
                            else omitted.removesuffix('.py').replace('/', '.'))
    pins = H.semantic_sources(inventory)
    pins['root'] = str(app)
    packet = {'baseline_scope': 'fox-inert-startup-baseline-v2', 'semantic_sources': pins}
    value = {'app': str(app), 'packet': packet, 'startup_prefix': startup_prefix(app),
             'expected_missing': expected_missing}
    child = subprocess.run([sys.executable, '-I', '-S', '-B', '-c', CHILD],
        input=json.dumps(value).encode(), cwd=app, capture_output=True, timeout=30)
    assert child.returncode == 0, child.stderr.decode(errors='replace')
    proof = json.loads(child.stdout)
    assert proof['status'] == ('EXACT_CLOSED_STARTUP_IMPORTS_PASSED' if omitted is None else 'EXACT_UNMEASURED_GUARD_REJECTED')
    assert proof['effects_permitted'] is False
    after = {path.relative_to(app).as_posix(): hashlib.sha256(path.read_bytes()).hexdigest()
             for path in app.rglob('*') if path.is_file()}
    assert after == before
