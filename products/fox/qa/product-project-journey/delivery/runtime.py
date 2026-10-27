"""Run inside an isolated copy of the exact FOX image; never in live /data."""
from __future__ import annotations

import argparse
import hashlib
import importlib
import json
import os
from pathlib import Path
import re
import sys

sys.dont_write_bytecode = True
from contract import (OWNER, DeliveryError, MAX_EXPORT, audit_isolated, canonical,
                      need, parsed, read, seed_isolated, sha, validate_export)

ORIGIN = 'http://127.0.0.1:8123'


def image_imports(root=Path('/app')):
    """Audit and serve use the image package, never an incidental cwd import."""
    root = Path(root).resolve(strict=True)
    if str(root) not in sys.path:
        sys.path.insert(0, str(root))
    package = importlib.import_module('fox')
    need(Path(package.__file__).resolve() == root / 'fox/__init__.py', 'ACTUAL_IMAGE_PACKAGE_REQUIRED')
    return root


def export_input(path, expected_sha256, image, release):
    raw = read(path, MAX_EXPORT)
    expected = parsed(raw)['binding']
    need(expected['fox_image'] == image and expected['release_sha256'] == release,
         'ISOLATED_IMAGE_OR_RELEASE_CHANGED')
    validate_export(raw, expected_sha256=expected_sha256, expected_binding=expected)
    return raw, expected


def ui_inventory(root=Path('/app/dist')):
    need(root.is_dir() and not root.is_symlink() and root.resolve() == root, 'ACTUAL_IMAGE_UI_REQUIRED')
    files = {}
    for path in sorted(root.rglob('*')):
        need(not path.is_symlink(), 'LINKED_UI_FORBIDDEN')
        if path.is_file():
            name = path.relative_to(root).as_posix()
            need(name == 'index.html' or re.fullmatch(r'assets/[A-Za-z0-9_.-]+\.(js|css|svg|png|jpg|webp)', name),
                 'UNEXPECTED_IMAGE_UI_MEMBER')
            files[name] = sha(read(path, 8_000_000))
    need('index.html' in files and 2 <= len(files) <= 30, 'IMAGE_UI_INVENTORY_INVALID')
    return files


def save_new(path, value):
    with os.fdopen(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, 'O_NOFOLLOW', 0), 0o600), 'wb') as stream:
        stream.write(canonical(value)); stream.flush(); os.fsync(stream.fileno())


def isolated_app(data, raw, expected_sha256, expected, credentials):
    need(type(credentials) is dict and set(credentials) == {'username', 'password'}
         and credentials['username'] == OWNER and type(credentials['password']) is str
         and re.fullmatch(r'[A-Za-z0-9_-]{32,128}', credentials['password']), 'SYNTHETIC_STDIN_CREDENTIALS_REQUIRED')
    data = Path(data).absolute()
    need(data.is_dir() and data.resolve() == data and not data.is_symlink()
         and list(data.iterdir()) == [], 'FRESH_ISOLATED_DATA_REQUIRED')
    # Set the new private data root BEFORE importing fox.app; its module-level
    # app constructor initializes storage even when that instance is not served.
    for name in tuple(os.environ):
        upper = name.upper()
        if upper.startswith(('FOX_', 'F2A_', 'OCI_')) or upper in {
            'HTTP_PROXY', 'HTTPS_PROXY', 'ALL_PROXY', 'REQUESTS_CA_BUNDLE', 'CURL_CA_BUNDLE'}:
            os.environ.pop(name, None)
    os.environ.update(FOX_DATA_DIR=str(data), FOX_PUBLIC_ORIGIN=ORIGIN, FOX_ADMIN_USERNAME=OWNER,
                      FOX_CONVERSION_PROFILE='native-project-v1', FOX_VERIFICATION_ENABLED='0')
    need('fox.app' not in sys.modules, 'FRESH_FOX_APP_NAMESPACE_REQUIRED')
    # The image's installed application remains unchanged. No replacement API,
    # login/session injection, promotion or mocked positive validator is used.
    image_imports()
    module = importlib.import_module('fox.app')
    need(Path(module.__file__).resolve() == Path('/app/fox/app.py'), 'ACTUAL_IMAGE_APPLICATION_REQUIRED')
    os.environ['FOX_PASSWORD_HASH'] = module.password_hash(credentials['password'])
    app = module.create_app(data, enable_worker=False)
    need(app.state.worker_monitor.enabled is False
         and module.conversion_configuration()['conversion_configured'] is False,
         'ISOLATED_WORKER_AND_INTEGRATION_MUST_BE_DISABLED')
    fixture = seed_isolated(data, raw, expected_sha256=expected_sha256, expected_binding=expected)
    audit = audit_isolated(data, raw, expected_sha256=expected_sha256, expected_binding=expected, accepted=False)
    fixture['ui'] = ui_inventory()
    fixture.update(fox_image=expected['fox_image'], release_sha256=expected['release_sha256'],
                   origin=ORIGIN, worker_enabled=False, integration_configured=False)
    return app, fixture, audit


def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('serve', 'audit'))
    parser.add_argument('--input', required=True, type=Path)
    parser.add_argument('--input-sha256', required=True)
    parser.add_argument('--image', required=True)
    parser.add_argument('--release', required=True)
    parser.add_argument('--data', required=True, type=Path)
    parser.add_argument('--output', type=Path)
    args = parser.parse_args()
    raw, expected = export_input(args.input, args.input_sha256, args.image, args.release)
    if args.action == 'audit':
        need(args.output is None, 'AUDIT_IS_READ_ONLY')
        image_imports()  # Imports fox only, never the storage-initializing fox.app.
        print(json.dumps(audit_isolated(args.data, raw, expected_sha256=args.input_sha256,
            expected_binding=expected, accepted=True), sort_keys=True))
        return 0
    need(args.output is not None and args.output.is_dir() and args.output.resolve() == args.output
         and not args.output.is_symlink() and list(args.output.iterdir()) == [], 'FRESH_PRIVATE_RUNTIME_OUTPUT_REQUIRED')
    line = sys.stdin.buffer.readline(4097)
    need(0 < len(line) <= 4096 and line.endswith(b'\n'), 'BOUNDED_STDIN_CREDENTIALS_REQUIRED')
    credentials = parsed(line)
    app, fixture, audit = isolated_app(args.data, raw, args.input_sha256, expected, credentials)
    credentials.clear()
    save_new(args.output / 'fixture.json', fixture)
    save_new(args.output / 'initial-audit.json', audit)
    save_new(args.output / 'prepared.json', {'status': 'ISOLATED_INPUTS_PREPARED_NOT_HEALTH_CHECKED',
        'input_sha256': args.input_sha256, 'image': args.image, 'release_sha256': args.release,
        'worker_enabled': False, 'integration_configured': False, 'live_acceptance_recorded': False})
    import uvicorn
    uvicorn.run(app, host='127.0.0.1', port=8123, access_log=False, log_config=None, log_level='critical')
    return 0


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except Exception:
        # Never expose arbitrary JSON, environment, source or credential text.
        print('{"status":"ISOLATED_DELIVERY_RUNTIME_BLOCKED"}', file=sys.stderr)
        raise SystemExit(1)
