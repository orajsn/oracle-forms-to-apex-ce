"""Isolated synthetic product UI fixture. Never seed an existing FOX data tree.

prepare uses local test builders; serve uses only production FOX dependencies.
The historical Oracle/OPAF receipts are SIMULATED and authorize no live release.
"""
import argparse
from datetime import datetime
import gc
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import sqlite3
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
ORIGIN = 'http://127.0.0.1:8100'
BACKEND_IMAGE = 'd69b0e8a39dfe3fabf6c703dbd4ec42513e5a19bad75988096db3f22c7584bec'
QA_IMAGE = '142e37662816c276b33ca8b1be3da0d5afcc5e075667809be4f11898a34685f3'
UI = {
    'index.html': '8a5ebb5325f2abed410ae09a7ecb16b68f7673a7cfff64cda56895d151e281db',
    'assets/index-DcyynC8H.js': '3fd3b2430080b84d9134721124766f9732f06c500d06f74aab72939730f0d95b',
    'assets/index-7JXG_oaM.css': '9776c2b71fc626803a40411f7b4893ca9edc464979a1f3b476c31aad30637ac6',
}
NOTES = 'Synthetic isolated browser regression only; not Jason approval, customer review, or live acceptance.'
INPUTS = ('source-snapshot.json', 'release-evidence.json', 'apex-package.zip',
          'clean-install.json', 'qa-result.json', 'qa-target.json', 'qa-profile.json',
          'verification-profile.json', 'allocation-receipt.json', 'credentials.json')


def require(condition, message):
    if not condition:
        raise ValueError(message)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def raw(value):
    return json.dumps(value, sort_keys=True).encode()


def write_new(path, value):
    with path.open('xb') as stream:
        stream.write(value)
    path.chmod(0o600)


def read_file(path, limit=8_000_000):
    require(not path.is_symlink() and path.is_file(), 'Expected a regular fixture file')
    require(0 < path.stat().st_size <= limit, 'Fixture file exceeds bound')
    return path.read_bytes()


def check_ui(directory):
    require(not directory.is_symlink() and directory.is_dir(), 'UI directory required')
    for name, expected in UI.items():
        require(sha(read_file(directory / name)) == expected, 'Candidate UI bytes differ')


def prepare(destination, ui):
    """Local export only. No network, process, service, or actual owner mutation."""
    destination, ui = Path(destination).absolute(), Path(ui).absolute()
    require(not destination.exists(), 'Destination already exists; preserve prior attempt')
    check_ui(ui)
    # Keep app.py's unused module-level default app inside this disposable root.
    with tempfile.TemporaryDirectory(prefix='fox-product-fixture-') as temp:
        import pytest
        sys.path[:0] = [str(ROOT / 'fox'), str(ROOT / 'fox/tests')]
        with pytest.MonkeyPatch.context() as patch:
            patch.setenv('FOX_DATA_DIR', str(Path(temp) / 'import-data'))
            from test_native_pipeline import NativeHarness, valid_package
            from test_native_verification import proof_case, NOW, arguments
            from test_native_verification_policy import bind_v2, v2_arguments
            from fox import native_verification as gate
            from fox.app import password_hash
            harness = NativeHarness(Path(temp), patch)
            case = bind_v2(proof_case.__wrapped__(valid_package.__wrapped__(harness), harness))
            gate.verify_detached_proof(**v2_arguments(case))
            owner = 'synthetic-product-' + secrets.token_hex(6)
            project = secrets.token_hex(12)
            case['snapshot']['project'] = project
            password = secrets.token_urlsafe(32)
            credentials = {'username': owner, 'password': password, 'password_hash': password_hash(password)}
            files = {'source-snapshot.json': raw(case['snapshot']), 'release-evidence.json': raw(case['release']),
                     'apex-package.zip': case['package'], 'verification-profile.json': case['verification_policy'].raw,
                     'allocation-receipt.json': case['allocation_raw'], 'credentials.json': raw(credentials)}
            files.update({name: raw(case[key]) for name, key in zip(gate.RECEIPT_NAMES, ('clean', 'qa', 'target', 'profile'))})
            manifest = {'schema_version': 1, 'scope': 'fox-isolated-product-download-v1',
                        'simulated_fixtures': True, 'live_acceptance_recorded': False, 'origin': ORIGIN,
                        'backend_image': BACKEND_IMAGE, 'qa_image': QA_IMAGE, 'ui': UI,
                        'owner': owner, 'project_id': project, 'project_name': 'Synthetic isolated acceptance browser check',
                        'run_id': case['release']['job_id'], 'source_hash': case['snapshot']['source_hash'],
                        'package_sha256': sha(case['package']), 'package_bytes': len(case['package']),
                        'fixture_now': NOW.isoformat(), 'run_created': arguments(case)['run_created'],
                        'notes': NOTES, 'files': {name: sha(value) for name, value in files.items()}}
        # sqlite3's transaction context does not close its connection. Collect
        # the unreachable module-import schema connection before Windows cleanup.
        gc.collect()
    destination.mkdir(mode=0o700)
    for name, value in files.items():
        write_new(destination / name, value)
    write_new(destination / 'manifest.json', raw(manifest))
    return manifest


def load_fixture(directory):
    directory = Path(directory)
    require(not directory.is_symlink() and directory.is_dir(), 'Fixture directory required')
    manifest = json.loads(read_file(directory / 'manifest.json', 32_768))
    require(manifest['schema_version'] == 1 and manifest['scope'] == 'fox-isolated-product-download-v1'
            and manifest['simulated_fixtures'] is True and manifest['live_acceptance_recorded'] is False,
            'Only synthetic fixtures are permitted')
    require(manifest['origin'] == ORIGIN and manifest['backend_image'] == BACKEND_IMAGE
            and manifest['qa_image'] == QA_IMAGE and manifest['ui'] == UI, 'Unexpected isolated release binding')
    require(re.fullmatch(r'synthetic-product-[a-f0-9]{12}', manifest['owner']) is not None,
            'An explicitly synthetic owner is required')
    require(re.fullmatch(r'[a-f0-9]{24}', manifest['project_id']) is not None
            and re.fullmatch(r'fox-[a-f0-9]{20}', manifest['run_id']) is not None, 'Invalid synthetic identifiers')
    require(manifest['notes'] == NOTES and set(manifest['files']) == set(INPUTS), 'Unexpected fixture inputs')
    for name in INPUTS:
        require(sha(read_file(directory / name)) == manifest['files'][name], 'Fixture bytes differ')
    credentials = json.loads(read_file(directory / 'credentials.json'))
    require(credentials['username'] == manifest['owner'], 'Credential owner differs')
    package = read_file(directory / 'apex-package.zip')
    require(sha(package) == manifest['package_sha256'] and len(package) == manifest['package_bytes'], 'Package differs')
    return manifest, credentials


def seed(directory, data, dist):
    """Create ONE fresh isolated data tree using the actual production gate."""
    directory, data, dist = map(lambda value: Path(value).absolute(), (directory, data, dist))
    manifest, credentials = load_fixture(directory)
    check_ui(dist)
    require(not data.is_symlink() and (not data.exists() or not any(data.iterdir())),
            'Data directory must be new or empty; never reuse an existing FOX tree')
    require(data != directory and data not in directory.parents and directory not in data.parents,
            'Fixture and data directories must be separate')
    for key in os.environ:
        require(not key.startswith(('FOX_OPAF', 'FOX_CONVERTER', 'FOX_NATIVE_PROFILE', 'FOX_RUN_ADAPTER')),
                'Live integration configuration is forbidden')
    os.environ.update(FOX_DATA_DIR=str(data), FOX_PUBLIC_ORIGIN=ORIGIN, FOX_ADMIN_USERNAME=manifest['owner'],
                      FOX_PASSWORD_HASH=credentials['password_hash'], FOX_CONVERSION_PROFILE='native-table-form-v1')
    from fox.app import create_app, check_password
    from fox import native_verification as gate
    from fox.native_verification_policy import BoundVerificationPolicy
    require(check_password(credentials['password'], credentials['password_hash']), 'Synthetic credential hash differs')
    app = create_app(data, enable_worker=False)
    snapshot = json.loads(read_file(directory / 'source-snapshot.json'))
    require(snapshot['project'] == manifest['project_id'] and snapshot['source_hash'] == manifest['source_hash'],
            'Synthetic source binding differs')
    job = data / 'jobs' / manifest['run_id']
    (job / 'native-pipeline').mkdir(parents=True, mode=0o700)
    for name in ('source-snapshot.json', 'release-evidence.json', 'apex-package.zip'):
        write_new(job / name, read_file(directory / name))
    write_new(job / 'native-pipeline/download.json', raw({'package_sha256': manifest['package_sha256'],
                                                        'source_hash': manifest['source_hash']}))
    with sqlite3.connect(data / 'fox.sqlite3') as connection:
        connection.execute('PRAGMA foreign_keys=ON')
        connection.execute('INSERT INTO projects VALUES(?,?,?,?,?,?)',
                           (manifest['project_id'], manifest['owner'], 'Synthetic isolated QA', manifest['project_name'], NOTES, 1))
        for source in snapshot['files']:
            connection.execute('INSERT INTO sources VALUES(?,?,?,?,?,?,?)',
                               (secrets.token_hex(12), manifest['project_id'], source['name'], source['sha256'],
                                source['bytes'], source['text'], 1))
        connection.execute('INSERT INTO runs VALUES(?,?,?,?,?,?,?,?)',
                           (manifest['run_id'], manifest['project_id'], manifest['source_hash'], 'QA_REQUIRED', NOTES,
                            manifest['run_created'], 1, str((job / 'apex-package.zip').relative_to(data))))
    result = gate.promote_native_run(root=data, run_id=manifest['run_id'], operator_receipt_dir=directory,
                                    policy=BoundVerificationPolicy(read_file(directory / 'verification-profile.json')),
                                    now=datetime.fromisoformat(manifest['fixture_now']))
    require(result['state'] == 'VERIFIED', 'Synthetic fixture was not verified')
    write_new(data / 'synthetic-bootstrap.json', raw({'scope': manifest['scope'], 'simulated_fixtures': True,
              'live_acceptance_recorded': False, 'manifest_sha256': sha(read_file(directory / 'manifest.json')),
              'proof_sha256': result['proof_sha256'], 'worker_enabled': False}))
    return app


def inspect(directory, data):
    manifest, _ = load_fixture(Path(directory))
    data = Path(data).resolve()
    with sqlite3.connect((data / 'fox.sqlite3').as_uri() + '?mode=ro', uri=True) as connection:
        owners = connection.execute('SELECT DISTINCT owner FROM projects').fetchall()
        state = connection.execute('SELECT state FROM runs WHERE id=?', (manifest['run_id'],)).fetchone()
        accepted = connection.execute('SELECT owner,artifact_sha256,notes FROM acceptances WHERE run=?', (manifest['run_id'],)).fetchall()
        events = connection.execute("SELECT COUNT(*) FROM events WHERE action='human_accepted'").fetchone()[0]
    require(owners == [(manifest['owner'],)] and state == ('ACCEPTED',)
            and accepted == [(manifest['owner'], manifest['package_sha256'], NOTES)] and events == 1,
            'Synthetic acceptance state differs')
    bootstrap = json.loads(read_file(data / 'synthetic-bootstrap.json'))
    proof = read_file(data / 'jobs' / manifest['run_id'] / 'technical-verification/verification.json')
    require(sha(proof) == bootstrap['proof_sha256'], 'Technical proof changed')
    return {'passed': True, 'simulated_acceptance_only': True, 'live_acceptance_recorded': False,
            'state': 'ACCEPTED', 'acceptance_count': 1, 'acceptance_event_count': events,
            'package_sha256': manifest['package_sha256'], 'proof_unchanged': True}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='command', required=True)
    export = sub.add_parser('prepare'); export.add_argument('--output', required=True); export.add_argument('--ui', required=True)
    serve = sub.add_parser('serve'); serve.add_argument('--fixture', required=True); serve.add_argument('--data', required=True); serve.add_argument('--dist', default='/app/dist')
    read = sub.add_parser('inspect'); read.add_argument('--fixture', required=True); read.add_argument('--data', required=True)
    args = parser.parse_args()
    if args.command == 'prepare':
        value = prepare(args.output, args.ui)
        print(json.dumps({'prepared': True, 'simulated_fixtures': True, 'package_sha256': value['package_sha256']}))
    elif args.command == 'serve':
        require(os.name == 'posix' and os.getenv('FOX_ISOLATED_PRODUCT_QA') == '1', 'Isolated Linux launch required')
        app = seed(args.fixture, args.data, args.dist)
        import uvicorn
        uvicorn.run(app, host='127.0.0.1', port=8100, access_log=False, proxy_headers=False)
    else:
        print(json.dumps(inspect(args.fixture, args.data), sort_keys=True))


if __name__ == '__main__':
    main()
