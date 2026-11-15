"""Actual emitted completed-history readers; synthetic retained conversion."""
import base64
from copy import deepcopy
from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path
import shutil
import sqlite3
import subprocess
import sys
import zipfile

import pytest

from test_current_pair_transition import M, ROOT
from test_current_pair_source_closure import measured
from test_completed_prototype_preservation import (
    completed_case, connected, prepared, queued, base_queued, settings, no_external_actions, tmp_path,
)
from test_paused_stage_transition import execute
from test_paired_release_build import p as build, r as archive_reader, inputs as build_inputs
from fox import paused_stage_preservation as inert, verification_recovery as recovery
from qa.operator import retirement_remote as remote, product_queue_transport as queue_transport, paused_stage_host as host

REAL_RUN = subprocess.run
REAL_POPEN = subprocess.Popen
CHILD_GUARD = '''import sys
assert sys.flags.isolated and not any('publication-orajsn' in path for path in sys.path)
def no_external(event,args):
 if event in ('subprocess.Popen','os.system','socket.connect','socket.bind'):
  raise RuntimeError('PURE_CHILD_EXECUTION_OR_NETWORK_FORBIDDEN')
sys.addaudithook(no_external)
'''


def child(monkeypatch, source, payload, directory):
    # Restore only Python process creation for this real isolated test harness.
    # The fixture's converter/provider mocks do not cross into the child, and
    # the child audit hook forbids further execution/network operations.
    with monkeypatch.context() as patch:
        patch.setattr(subprocess, 'Popen', REAL_POPEN)
        return REAL_RUN([sys.executable, '-I', '-B', '-c', CHILD_GUARD + source],
                        input=M.cb(payload), capture_output=True, timeout=60, cwd=directory)


def packet(case):
    root, job, _, stage, _, target, _ = case
    return {'inert': True, 'data': str(root), 'baseline_scope': inert.BASELINE_SCOPE_V2,
            'target': target, 'completed_packages': {job.name: base64.b64encode(
                (stage / 'prototype-package.zip').read_bytes()).decode()}}


def installed_program(measured, root, *, old=False, bad_native=False):
    """Model only the /app mount spelling; never add development import paths.

    Renderers legitimately reread their own source and original templates. The
    closed physical namespace therefore contains their real measured bytes,
    not a replacement context/hash validator or synthetic successful result.
    """
    physical, _ = materialized_app(root)
    sources = measured.context._preclaim_sources()
    if old:
        for name in ('completed_prototype_preservation.py', 'paused_stage_preservation.py'):
            (physical / 'fox' / name).unlink()
        path = physical / 'fox/prototype_download.py'; path.write_bytes(path.read_bytes() + b'\n# Different old physical revision.\n')
    if bad_native:
        path = physical / 'forms2apex/native.py'; path.write_bytes(path.read_bytes() + b'\n# Different physical renderer.\n')
    return M.PRECLAIM_TECHNICAL.replace("'/app/'", repr(physical.as_posix() + '/')), sources


def materialized_app(root):
    """Only actual build/fox COPY members; never the full converter directory."""
    values = build_inputs()
    values['files'].update({'fox/fox/' + path.name: path.read_bytes() for path in (ROOT / 'fox/fox').glob('*.py')})
    output = root / 'b'; result = build.materialize(**values, output_root=output)
    files, _ = archive_reader.load_archive((output / 'paired-source.tar').read_bytes(), result['archive_sha256'])
    app = root / 'physical-app'; app.mkdir()
    for prefix, destination in (('build/fox/fox/', app / 'fox'), ('build/fox/renderer/', app)):
        for name, raw in files.items():
            if name.startswith(prefix):
                path = destination / name[len(prefix):]; path.parent.mkdir(parents=True, exist_ok=True); path.write_bytes(raw)
    assert {path.name for path in (app / 'forms2apex').glob('*.py')} == {
        Path(name).name for name in build.APP_RENDERER_FILES if name.startswith('forms2apex/') and name.endswith('.py')}
    assert not (app / 'forms2apex/server.py').exists() and not (app / 'forms2apex/config.py').exists()
    return app, json.loads(files['source-inventory.json'])


@pytest.mark.parametrize('old', [False, True])
def test_full_measured_completed_child_reconstructs_actual_synthetic_source_package(completed_case, measured, monkeypatch, old):
    source, sources = installed_program(measured, completed_case[0], old=old)
    payload = {**packet(completed_case), 'sources': sources}
    before = (completed_case[0] / 'fox.sqlite3').read_bytes()
    result = child(monkeypatch, source, payload, completed_case[0])
    assert result.returncode == 0, result.stderr.decode()
    observed = json.loads(result.stdout)
    assert observed['jobs'][completed_case[1].name]['completed'] == inert.completed_projection(completed_case[1])
    assert before == (completed_case[0] / 'fox.sqlite3').read_bytes()


@pytest.mark.parametrize('fault', ['missing-helper', 'tampered-helper', 'missing-package', 'wrong-package', 'v1-scope', 'physical-native'])
def test_full_measured_child_rejects_unmeasured_or_incomplete_completed_source(completed_case, measured, monkeypatch, fault):
    source, sources = installed_program(measured, completed_case[0], old=True, bad_native=fault == 'physical-native')
    payload = {**packet(completed_case), 'sources': sources}
    if fault == 'missing-helper':del payload['sources']['fox.completed_prototype_preservation']
    elif fault == 'tampered-helper':payload['sources']['fox.completed_prototype_preservation']['bytes'] = base64.b64encode(b'changed').decode()
    elif fault == 'missing-package':payload['completed_packages'].clear()
    elif fault == 'wrong-package':payload['completed_packages'][completed_case[1].name] = base64.b64encode(b'wrong').decode()
    elif fault == 'v1-scope':payload['baseline_scope'] = inert.BASELINE_SCOPE
    result = child(monkeypatch, source, payload, completed_case[0])
    assert result.returncode != 0 and result.stdout == b''
    if fault == 'missing-helper':assert b'UNMEASURED_PURE_READER_DEPENDENCY' in result.stderr


def startup_program(case, measured, monkeypatch):
    root, _, _, _, _, target, _ = case
    physical, inventory = materialized_app(root)
    pins = host.semantic_sources(inventory); pins['root'] = physical.as_posix()
    profile = root / 'focused-profile.json'; profile.write_bytes(M.cb(target))
    monkeypatch.setenv('FOX_VERIFICATION_ENABLED', '1'); monkeypatch.setenv('FOX_VERIFIER_RELEASE_SHA256', 'f' * 64)
    monkeypatch.setenv('FOX_PROTOTYPE_PROFILE_FILE', str(profile))
    database = root / 'fox.sqlite3'
    source = remote.STARTUP_INERT.replace("'/app'", repr(physical.as_posix()))
    source = source.replace("'file:/data/fox.sqlite3?mode=ro'", repr(database.as_uri() + '?mode=ro'))
    source = source.replace("'/data/fox.sqlite3'", repr(str(database)))
    source = source.replace("pathlib.Path('/data/jobs')", 'pathlib.Path(' + repr(str(root / 'jobs')) + ')')
    payload = {'source_sha256': hashlib.sha256(Path(inert.__file__).read_bytes()).hexdigest(),
               'release_sha256': 'f' * 64, 'baseline_scope': inert.BASELINE_SCOPE_V2, 'semantic_sources': pins}
    return source, payload


def test_startup_projection_is_exact_actual_fox_renderer_copy():
    assert set(host.APP_RENDERER_PY) == {name for name in build.APP_RENDERER_FILES if name.endswith('.py')}
    assert host.APP_RENDERER_TEMPLATE_ROOTS == build.APP_RENDERER_TEMPLATE_ROOTS


def stopped_packet(case, measured):
    root = case[0]; release = root / 'new/source'; release.mkdir(parents=True)
    sources = measured.context._preclaim_sources(); files = {}
    for name, row in sources.items():
        package, _, tail = name.partition('.')
        prefix = 'fox/fox/' if package == 'fox' else 'converter/' + package + '/'
        relative = prefix + (tail if tail else '__init__') + '.py'
        raw = base64.b64decode(row['bytes'], validate=True)
        path = release / relative; path.parent.mkdir(parents=True, exist_ok=True); path.write_bytes(raw)
        files[relative] = hashlib.sha256(raw).hexdigest()
    templates = ROOT / 'converter/forms2apex/templates'
    shutil.copytree(templates, release / 'converter/forms2apex/templates')
    for path in templates.rglob('*'):
        if path.is_file():files['converter/forms2apex/templates/' + path.relative_to(templates).as_posix()] = hashlib.sha256(path.read_bytes()).hexdigest()
    raw = M.cb({'schema_version': 1, 'scope': 'fox-hosted-source-inventory-v1', 'files': files})
    inventory = release.parent / 'source-inventory.json'; inventory.write_bytes(raw)
    return {**packet(case), 'sources': sources, 'stopped': True, 'physical_sources': {
        'schema_version': 1, 'scope': 'fox-preclaim-stopped-source-v1', 'release_root': str(release),
        'inventory': {'path': str(inventory), 'sha256': hashlib.sha256(raw).hexdigest()}}}


NO_APP = '''import os
def no_app(event,args):
 if event=='open':
  path=os.fspath(args[0]) if isinstance(args[0],(str,bytes,os.PathLike)) else ''
  if isinstance(path,str) and ('/app/' in path.replace('\\\\','/').lower() or '<measured-new:' in path):
   raise AssertionError('STOPPED_READER_MUST_NOT_READ_APP_OR_VIRTUAL_ORIGIN')
sys.addaudithook(no_app)
'''


def test_stopped_full_semantics_uses_verified_release_tree_with_no_app(completed_case, measured, monkeypatch):
    payload = stopped_packet(completed_case, measured)
    root = completed_case[0]
    assert not (root / 'physical-app').exists() and not (root / 'app').exists()
    before = (root / 'fox.sqlite3').read_bytes()
    result = child(monkeypatch, NO_APP + M.PRECLAIM_TECHNICAL, payload, root)
    assert result.returncode == 0, result.stderr.decode()
    assert json.loads(result.stdout)['jobs'][completed_case[1].name]['completed'] == inert.completed_projection(completed_case[1])
    assert before == (root / 'fox.sqlite3').read_bytes()


@pytest.mark.parametrize('fault', ['missing-binding', 'wrong-root', 'inventory-hash', 'module', 'missing-template', 'extra-template'])
def test_stopped_physical_origins_fail_closed_without_app_or_dev_fallback(completed_case, measured, monkeypatch, fault):
    payload = stopped_packet(completed_case, measured); binding = payload['physical_sources']
    root = completed_case[0]; release = Path(binding['release_root'])
    if fault == 'missing-binding':del payload['physical_sources']
    elif fault == 'wrong-root':binding['release_root'] = str(root / 'wrong/source')
    elif fault == 'inventory-hash':binding['inventory']['sha256'] = '0' * 64
    elif fault == 'module':(release / 'converter/forms2apex/native.py').write_bytes(b'changed')
    elif fault == 'missing-template':next((release / 'converter/forms2apex/templates').rglob('*.apx')).unlink()
    else:(release / 'converter/forms2apex/templates/unknown.txt').write_bytes(b'unknown')
    result = child(monkeypatch, NO_APP + M.PRECLAIM_TECHNICAL, payload, root)
    assert result.returncode != 0 and result.stdout == b''


def test_controller_physical_binding_is_explicitly_pinned(completed_case, measured, monkeypatch):
    payload = stopped_packet(completed_case, measured); binding = payload['physical_sources']
    context = object.__new__(M.Transition)
    context.new_i = {'layout': {'release_root': binding['release_root'], 'inventory': binding['inventory']}}
    context.A = type('Reader', (), {'read': staticmethod(lambda path, **kwargs: path.read_bytes())})()
    monkeypatch.setattr(M, 'absolute', lambda path: Path(path))  # Native Windows path spelling only.
    assert context._preclaim_physical_binding() == binding
    binding['inventory']['sha256'] = '0' * 64
    with pytest.raises(M.TransitionError, match='INVENTORY_CHANGED'):context._preclaim_physical_binding()


def test_actual_installed_startup_has_discovery_then_required_semantic_package_phase(completed_case, measured, monkeypatch):
    root, job, _, _, _, target, _ = completed_case
    source, payload = startup_program(completed_case, measured, monkeypatch)
    discovery = child(monkeypatch, source, {**payload, 'discover_completed': True}, root)
    checked = child(monkeypatch, source, {**payload, 'completed_packages': packet(completed_case)['completed_packages']}, root)
    assert discovery.returncode == checked.returncode == 0, checked.stderr.decode() + discovery.stderr.decode()
    assert json.loads(checked.stdout) == json.loads(discovery.stdout)
    assert child(monkeypatch, source, payload, root).returncode != 0
    assert child(monkeypatch, source, {**payload, 'completed_packages': {job.name: base64.b64encode(b'wrong').decode()}}, root).returncode != 0


@pytest.mark.parametrize('fault', ['missing', 'tampered', 'wrong-root', 'already-loaded', 'extra-template'])
def test_startup_semantic_closure_refuses_unmeasured_or_wrong_origin(completed_case, measured, monkeypatch, fault):
    source, payload = startup_program(completed_case, measured, monkeypatch)
    root = completed_case[0]
    if fault == 'missing':del payload['semantic_sources']['modules']['fox.prototype_download']
    elif fault == 'tampered':
        path = root / 'physical-app/fox/completed_prototype_preservation.py'; path.write_bytes(path.read_bytes() + b'\n# tamper\n')
    elif fault == 'wrong-root':payload['semantic_sources']['root'] = str(root / 'other-app')
    elif fault == 'extra-template':
        (root / 'physical-app/forms2apex/templates/unknown.txt').write_bytes(b'Unknown template must not be read or adopted.')
    else:
        source = "import sys,types\nm=types.ModuleType('fox.prototype_download');m.__file__='/untrusted/fox/prototype_download.py'\nsys.modules[m.__name__]=m\n" + source
    result = child(monkeypatch, source, {**payload, 'completed_packages': packet(completed_case)['completed_packages']}, root)
    assert result.returncode != 0 and result.stdout == b''


def test_exact_v2_native_scope_still_requires_explicit_baseline():
    assert M.preservation_stage({'scope': inert.BASELINE_SCOPE_V2}) == 'inert'
    M.validate_native_bindings({'prototype_authority': {}}, {'scope': inert.BASELINE_SCOPE_V2})
    with pytest.raises(M.TransitionError):M.validate_native_bindings({'prototype_authority': {}}, {'scope': 'completed'})


def test_protected_backend_uses_bounded_core_without_new_semantic_dependency(completed_case, tmp_path, monkeypatch):
    root, job, _, stage, _, _, _ = completed_case; database = root / 'fox.sqlite3'
    from fox.verification_queue import initialize_schema
    with sqlite3.connect(database) as db:initialize_schema(db)  # Fixture setup only, never a production read.
    with sqlite3.connect(database.as_uri() + '?mode=ro', uri=True) as db:
        db.row_factory = sqlite3.Row; db.execute('PRAGMA query_only=ON'); db.execute('BEGIN')
        observed = inert.observe_fox(database, db)
    baseline = {'schema_version': 2, 'scope': inert.BASELINE_SCOPE_V2, **observed,
        'receiver': {job.name: inert.receiver_job_tree(job.parent, job.name, completed=True)},
        'runtime': {'synthetic': 'protected-hash-read-only'}, 'completed_host': {job.name: {
            'staging': {'files': {}, 'directories': {}, 'namespace': {}},
            'qa': {'files': {}, 'directories': {}, 'namespace': {}}}}}
    now = datetime.now(timezone.utc)
    identity = {**{key: 'f' * 64 for key in ('pair_sha256', 'lease_sha256', 'release_sha256', 'source_sha256', 'profile_sha256')},
        'runtime_state': 'running', 'stopped_writer_sha256': None,
        'admission': {'enabled': True, 'release_sha256': 'f' * 64}}
    expected = {'baseline': baseline, 'baseline_sha256': inert.hashed(baseline), 'identity': identity}
    readback = {'schema_version': 2, 'scope': inert.READ_SCOPE_V2, 'binding': expected['baseline_sha256'],
        'identity': identity, 'observed_at_utc': now.isoformat(), 'expires_at_utc': (now + timedelta(seconds=30)).isoformat(),
        'fox': observed, 'receiver': baseline['receiver'], 'host': {'runtime_sha256': inert.hashed(baseline['runtime']),
            'receiver_sha256': inert.hashed(baseline['receiver']), 'observation_sha256': 'b' * 64, 'blockers': [],
            'completed_host_sha256': inert.hashed(baseline['completed_host'])}}
    # Real packaged queue-module closure, without the semantic helper/renderer.
    # The injected new pure core must work against this closed old-style reader
    # namespace; a developer-path import cannot hide a missing dependency.
    installed = tmp_path / 'closed'; package = installed / 'fox'; package.mkdir(parents=True)
    (package / '__init__.py').write_bytes(b'')
    names = set(queue_transport.PROJECT_QUEUE_MODULES) | set(queue_transport.MODULES) | set(queue_transport.PROJECT_MODULES)
    for name in names:
        if name != 'paused_stage_preservation.py':
            (package / name).write_bytes((ROOT / 'fox/fox' / name).read_bytes())
    raw = Path(recovery.__file__).read_bytes(); core = Path(inert.__file__).read_bytes()
    payload = {'paths': [str(installed)], 'source': base64.b64encode(raw).decode(), 'sha256': hashlib.sha256(raw).hexdigest(),
        'data': str(root), 'paired_preclaim': {job.name: {'readback': readback, 'expected': expected}},
        'inert_release': 'f' * 64, 'inert_source': {'bytes': base64.b64encode(core).decode(), 'sha256': hashlib.sha256(core).hexdigest()}}
    before = database.read_bytes()
    result = child(monkeypatch, M.BACKEND, payload, installed)
    assert result.returncode == 0, result.stderr.decode()
    value = json.loads(result.stdout)
    assert value['eligibility'][job.name] == {'blocks_admission': True, 'retry_eligible': False,
                                            'recovery_state': inert.STATE_V2}
    assert before == database.read_bytes()
