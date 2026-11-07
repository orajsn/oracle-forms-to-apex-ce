"""Exact synthetic package validation in the actual isolated frozen app payload.

SQLcl/browser results are authored fixtures, not real Oracle/runtime evidence.
The child receives only the measured app COPY payload, stdlib and fixture bytes.
"""
from copy import deepcopy
import json
from pathlib import Path
import subprocess
import sys

from test_paired_release_build import HERE, inputs, p, r

# Reuse the existing explicit synthetic SQLcl/browser fixture producer. These
# test-only imports are never copied into the materialized app payload.
_fixtures = str(HERE.parent / 'converter/tests')
sys.path.insert(0, _fixtures)
try:
    from test_prototype_gateway import case, advance
    from test_prototype_release import imported_case
finally:
    sys.path.remove(_fixtures)


def test_isolated_exact_package(imported_case, tmp_path):
    item = imported_case
    advance(item, 'verify_runtime')
    request = deepcopy(item.request)
    exported = advance(item, 'export')
    raw = item.adapter.read_package(request['job_id'])
    value = inputs()
    value['files'].update({'fox/fox/' + path.name: p.read(path, allow_empty=True)
                           for path in (HERE.parent / 'fox/fox').glob('*.py')})
    frozen = tmp_path / 'frozen'
    result = p.materialize(**value, output_root=frozen)
    files, _ = r.load_archive((frozen / 'paired-source.tar').read_bytes(), result['archive_sha256'])
    app = tmp_path / 'app'
    app.mkdir()
    for prefix, destination in (('build/fox/fox/', app / 'fox'), ('build/fox/renderer/', app)):
        for name, contents in files.items():
            if name.startswith(prefix):
                path = destination / name.removeprefix(prefix)
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(contents)
    (app / 'fixture.zip').write_bytes(raw)
    (app / 'fixture.json').write_text(json.dumps({'request': request, 'export_receipt': exported}), encoding='utf-8')
    code = r'''import hashlib,json,pathlib,sys,zipfile
app=pathlib.Path(sys.argv[1]).resolve()
assert sys.flags.isolated and sys.flags.no_site and sys.dont_write_bytecode
sys.path.insert(0,str(app))
def reject_external(event,args):
 if event.startswith('socket.') or event in ('subprocess.Popen','os.system','os.posix_spawn'):
  raise AssertionError('External operation forbidden during pure package validation')
sys.addaudithook(reject_external)
from fox.prototype_download import validate_generated_package
fixture=json.loads((app/'fixture.json').read_bytes())
raw=(app/'fixture.zip').read_bytes()
assert validate_generated_package(raw,**fixture)==raw
for changed in (raw+b'tampered',b'not-a-zip'):
 try:validate_generated_package(changed,**fixture)
 except (RuntimeError,ValueError,zipfile.BadZipFile):pass
 else:raise AssertionError('Tampered package was accepted')
for name,module in tuple(sys.modules.items()):
 if name.split('.')[0] in ('fox','forms2apex','fox_source_contract','defusedxml') and getattr(module,'__file__',None):
  assert pathlib.Path(module.__file__).resolve().is_relative_to(app),(name,module.__file__)
for forbidden in ('fastapi','oci','forms2apex.server','forms2apex.sqlcl','forms2apex.runtime_preflight',
                  'forms2apex.prototype_release','forms2apex.project_reviews','forms2apex.security'):
 assert forbidden not in sys.modules,forbidden
proof={'scope':'isolated-frozen-app-exact-synthetic-prototype-package',
 'source_bundle_sha256':sys.argv[2],'package_sha256':hashlib.sha256(raw).hexdigest(),
 'package_bytes':len(raw),'valid_package_accepted':True,'tampered_package_rejected':True,
 'site_packages_disabled':True,'development_paths_used':False,
 'sqlcl_or_oracle_run':False,'business_behavior_accepted':False}
(app/'package-proof.json').write_text(json.dumps(proof,sort_keys=True))
print(json.dumps(proof,sort_keys=True))
'''
    child = subprocess.run([sys.executable, '-I', '-S', '-B', '-c', code, str(app), result['source_bundle_sha256']],
                           cwd=app, capture_output=True, timeout=30)
    assert child.returncode == 0, child.stderr.decode()
    proof = json.loads(child.stdout)
    assert proof['package_sha256'] == exported['package_sha256']
    assert proof['source_bundle_sha256'] == result['source_bundle_sha256']
    assert proof['valid_package_accepted'] is proof['tampered_package_rejected'] is True
