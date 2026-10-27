"""Assessment-only localhost preview; never a hosted conversion launcher.

Invoked by start-local.ps1 in a private child environment. A fresh retained data
directory is selected before importing fox.app, whose import initializes SQLite.
An exact, owner-private marked session can be explicitly resumed; preparation
jobs are never replayed. No Oracle credentials or target connection are consumed.
"""
from __future__ import annotations

import importlib
from contextlib import asynccontextmanager
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import secrets
import sqlite3
import stat
import sys
import uuid

from .local_security import (LocalSessionError, SessionLock, protect_new_directory,
                             safe_path, verify_private, verify_tree_paths)


ENVIRONMENT_ALLOWLIST = (
    'SystemRoot', 'WINDIR', 'COMSPEC', 'PATH', 'PATHEXT', 'TEMP', 'TMP',
    'OS', 'LANG', 'LC_ALL', 'NUMBER_OF_PROCESSORS',
)
SESSION_TYPE = 'fox-local-assessment-session-v1'
SESSION_MARKER = '.fox-local-session.json'
SESSION_LOCK = '.fox-local-session.lock'
DEFAULT_USERNAME = 'fox-local'
DEFAULT_PROFILE = 'native-project-v1'
_ASSESSMENT_PROFILES = frozenset({'native-table-form-v1', 'native-project-v1'})
_SESSION_ID = re.compile(r'session-[0-9a-f]{32}\Z')
_VERIFIER = re.compile(r'[0-9a-f]{32}:[0-9a-f]{128}\Z')
_USERNAME = re.compile(r'[A-Za-z0-9][A-Za-z0-9._@+-]{0,99}\Z')


def child_environment(source):
    """Retain OS runtime necessities, never inherited integration/secret config."""
    allowed = {name.upper() for name in ENVIRONMENT_ALLOWLIST}
    result = {name: value for name, value in source.items() if name.upper() in allowed}
    result.update(PYTHONNOUSERSITE='1', PYTHONDONTWRITEBYTECODE='1', PYTHONUNBUFFERED='1')
    return result


def read_request(stream):
    try:
        raw = stream.read(8193)
        if len(raw) > 8192:
            raise ValueError()
        def unique(pairs):
            value = {}
            for key, item in pairs:
                if key in value:
                    raise ValueError()
                value[key] = item
            return value
        return validate_request(json.loads(raw, object_pairs_hook=unique))
    except (ValueError, TypeError, UnicodeError, RecursionError):
        raise ValueError('Invalid local assessment request; no supplied values are logged.') from None


def validate_request(request):
    required, tools = {'port', 'password'}, {'oracle_home', 'java_exe'}
    optional = tools | {'resume_session', 'username'}
    if (type(request) is not dict or not required <= set(request) or set(request) - required - optional
            or type(request['port']) is not int or not 1024 <= request['port'] <= 65535
            or type(request['password']) is not str or not 1 <= len(request['password']) <= 256
            or (bool(set(request) & tools) and not tools <= set(request))
            or ('resume_session' in request and (type(request['resume_session']) is not str
                                                 or not _SESSION_ID.fullmatch(request['resume_session'])))):
        raise ValueError('Invalid local assessment request; no supplied values are logged.')
    if 'username' in request:
        validate_username(request['username'])
    for key in tools & set(request):
        path = request[key]
        if (type(path) is not str or not 1 <= len(path) <= 1024 or path != path.strip()
                or any(ord(char) < 32 for char in path) or path.startswith(('\\', '//'))
                or '://' in path or not Path(path).is_absolute()):
            raise ValueError('Provide both explicit local absolute tool paths; no supplied values are logged.')
    return request


def validate_username(value):
    """A login identifier, preserved exactly rather than trimmed or case-folded."""
    if type(value) is not str or not _USERNAME.fullmatch(value):
        raise ValueError('Local username must be 1-100 ASCII letters, digits, dots, underscores, @, + or hyphens, starting with a letter or digit.')
    return value


def username_option(arguments):
    """Only the non-secret identity may be supplied on the command line."""
    if not arguments:
        return None
    if len(arguments) == 2 and arguments[0] == '--username':
        return validate_username(arguments[1])
    if len(arguments) == 1 and arguments[0].startswith('--username='):
        return validate_username(arguments[0].removeprefix('--username='))
    raise ValueError('Only --username is accepted; the remaining local request must use protected stdin.')


def apply_username_option(request, supplied):
    """Reject disagreement between argv and stdin instead of overriding it."""
    if supplied is None:
        return request
    supplied = validate_username(supplied)
    if 'username' in request and request['username'] != supplied:
        raise ValueError('Local username arguments do not match; no supplied values are logged.')
    return {**request, 'username': supplied}


def configured_backend(request):
    if 'oracle_home' not in request:
        return None
    from .extractor import OracleFormsBackend, assert_local_path
    # Explicit trusted startup paths only. check() later reports file presence;
    # construction does not run Java, extract a module or certify compatibility.
    return OracleFormsBackend(assert_local_path(Path(request['oracle_home'])),
                              assert_local_path(Path(request['java_exe'])))


def new_data_directory(base=None):
    base = Path(base) if base is not None else Path(__file__).resolve().parents[1] / 'work' / 'local-assessment'
    base = base.absolute()
    if base.is_symlink() or base.resolve() != base:
        raise ValueError('Local assessment storage must not use linked paths.')
    # Do not rely on Python's version-dependent Windows mode=0700 handling.
    # The new directory is empty until the explicit DACL is set and read back.
    mode = 0o777 if os.name == 'nt' else 0o700
    base.mkdir(parents=True, exist_ok=True, mode=mode)
    directory = base / ('session-' + uuid.uuid4().hex)
    directory.mkdir(mode=mode)  # Create only. Never reuse existing FOX data.
    protect_new_directory(directory)
    return directory


def _password_verifier(password, salt=None):
    # Fixed parameters match FOX's existing authentication format. No app import
    # or caller-provided work factor is needed to authenticate a saved session.
    salt = salt or secrets.token_hex(16)
    return salt + ':' + hashlib.scrypt(password.encode('utf-8'), salt=bytes.fromhex(salt),
                                       n=16384, r=8, p=1).hex()


def _validated_assessment_profile(value):
    if type(value) is not str or value not in _ASSESSMENT_PROFILES:
        raise ValueError('Local assessment profile is invalid.')
    return value


def _startup_binding(request, *, saved_username=None, saved_profile=None):
    username = validate_username(request.get('username', DEFAULT_USERNAME)
                                 if saved_username is None else saved_username)
    # No request/environment option selects a profile. Only a checked saved
    # marker can preserve an older assessment profile instead of today's default.
    profile = _validated_assessment_profile(DEFAULT_PROFILE if saved_profile is None else saved_profile)
    return {'username': username, 'origin': f"http://127.0.0.1:{request['port']}",
            'mode': 'assessment-only', 'conversion_profile': profile, 'worker_enabled': False,
            'oracle_home': str(Path(request['oracle_home']).resolve()) if 'oracle_home' in request else None,
            'java_exe': str(Path(request['java_exe']).resolve()) if 'java_exe' in request else None}


def _read_marker(directory):
    path = safe_path(directory / SESSION_MARKER)
    try:
        before = path.stat()
        if not stat.S_ISREG(before.st_mode) or before.st_size > 8192:
            raise ValueError()
        with path.open('rb') as stream:
            opened = os.fstat(stream.fileno())
            if (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino):
                raise ValueError()
            raw = stream.read(8193)
        if len(raw) > 8192:
            raise ValueError()
        def unique(pairs):
            result = {}
            for key, value in pairs:
                if key in result:
                    raise ValueError()
                result[key] = value
            return result
        return json.loads(raw, object_pairs_hook=unique)
    except (OSError, ValueError, UnicodeError, RecursionError):
        raise LocalSessionError('Local session marker is missing or invalid; unmarked/incomplete data is not adopted.') from None


def _check_assessment_database(directory, username):
    database = safe_path(directory / 'fox.sqlite3')
    if not database.is_file():
        raise LocalSessionError('Local assessment database is missing; no replacement was initialized.')
    try:
        connection = sqlite3.connect(database.as_uri() + '?mode=ro', uri=True)
        try:
            if (connection.execute('SELECT COUNT(*) FROM runs').fetchone()[0]
                    or connection.execute('SELECT COUNT(*) FROM acceptances').fetchone()[0]
                    or connection.execute('SELECT COUNT(*) FROM projects WHERE owner<>?', (username,)).fetchone()[0]
                    or connection.execute('SELECT COUNT(*) FROM sessions WHERE owner<>?', (username,)).fetchone()[0]):
                raise ValueError()
        finally:
            connection.close()
    except (sqlite3.Error, ValueError):
        raise LocalSessionError('Stored data does not match this assessment-only owner/session; nothing was migrated.') from None


def open_session(request, *, base=None):
    """Validate and lock before importing code that initializes existing SQLite."""
    request = validate_request(request)
    if 'resume_session' not in request:
        binding = _startup_binding(request)
        directory = new_data_directory(base)
        lock = SessionLock(directory / SESSION_LOCK, create=True)
        try:
            owner_id = verify_private(directory)
            marker = {'document_type': SESSION_TYPE, 'schema_version': 1, 'session_id': directory.name,
                      'owner_id': owner_id, **binding, 'password_verifier': _password_verifier(request['password'])}
            return directory, lock, marker, False
        except Exception:
            lock.close()
            raise
    fixed_root = Path(base) if base is not None else Path(__file__).resolve().parents[1] / 'work' / 'local-assessment'
    directory = safe_path(fixed_root.absolute() / request['resume_session'])
    if not directory.is_dir():
        raise LocalSessionError('The selected local session does not exist; no alternative was selected.')
    verify_tree_paths(directory)
    owner_id = verify_private(directory)  # Actual ACL/owner check; never repair.
    if not (directory / SESSION_MARKER).is_file() or not (directory / SESSION_LOCK).is_file():
        raise LocalSessionError('Local session marker/lock is missing; unmarked or incomplete data is not adopted.')
    lock = SessionLock(directory / SESSION_LOCK)
    try:
        marker = _read_marker(directory)
        if type(marker) is not dict:
            raise LocalSessionError('Local session owner/startup settings do not match; existing data is unchanged.')
        try:
            saved_username = validate_username(marker.get('username'))
        except ValueError:
            raise LocalSessionError('Local session identity is invalid; existing data is unchanged.') from None
        if 'username' in request and request['username'] != saved_username:
            raise LocalSessionError('Local session username does not match; existing data is unchanged.')
        try:
            saved_profile = _validated_assessment_profile(marker.get('conversion_profile'))
        except ValueError:
            raise LocalSessionError('Local session assessment profile is invalid; existing data is unchanged.') from None
        # The owner-private marker is read only after the existing lifetime
        # lock is held. Keep its identity and profile, not today's defaults.
        binding = _startup_binding(request, saved_username=saved_username, saved_profile=saved_profile)
        expected_keys = {'document_type', 'schema_version', 'session_id', 'owner_id', 'password_verifier', *binding}
        if (type(marker) is not dict or set(marker) != expected_keys
                or marker.get('document_type') != SESSION_TYPE or type(marker.get('schema_version')) is not int
                or marker['schema_version'] != 1 or marker['session_id'] != directory.name
                or marker['owner_id'] != owner_id
                or type(marker.get('worker_enabled')) is not bool
                or any(type(marker[key]) is not type(value) or marker[key] != value for key, value in binding.items())
                or type(marker.get('password_verifier')) is not str or not _VERIFIER.fullmatch(marker['password_verifier'])):
            raise LocalSessionError('Local session owner/startup settings do not match; existing data is unchanged.')
        verifier = _password_verifier(request['password'], marker['password_verifier'].split(':', 1)[0])
        if not hmac.compare_digest(verifier, marker['password_verifier']):
            raise LocalSessionError('Local session password does not match; existing data is unchanged.')
        _check_assessment_database(directory, binding['username'])
        return directory, lock, marker, True
    except Exception:
        lock.close()
        raise


def _bind_session_lifetime(app, lock):
    previous = app.router.lifespan_context
    @asynccontextmanager
    async def session_lifespan(instance):
        try:
            async with previous(instance):
                yield
        finally:
            lock.close()
    app.router.lifespan_context = session_lifespan
    app.state.local_session_lock = lock


def build_assessment_app(request, *, base=None):
    """Open only a new or explicitly verified local store, with worker disabled."""
    request = validate_request(request)
    # Defense in depth for direct module invocation, before importing application
    # or dependency code. The PowerShell wrapper already isolates the child env.
    clean = child_environment(dict(os.environ))
    os.environ.clear()
    os.environ.update(clean)
    backend = configured_backend(request)
    directory, lock, marker, resumed = open_session(request, base=base)
    try:
        os.environ.update(FOX_DATA_DIR=str(directory), FOX_PUBLIC_ORIGIN=marker['origin'],
                          FOX_ADMIN_USERNAME=marker['username'], FOX_CONVERSION_PROFILE=marker['conversion_profile'],
                          FOX_PASSWORD_HASH=marker['password_verifier'])
        # Ownership, lock, startup binding and password all pass BEFORE import.
        module = importlib.import_module('fox.app')
        app = module.create_app(data_dir=directory, enable_worker=False,
                               enable_local_preparation=True, local_preparation_backend=backend)
        if not resumed:
            _check_assessment_database(directory, marker['username'])
            path = directory / SESSION_MARKER
            with path.open('xb') as stream:
                stream.write(json.dumps(marker, sort_keys=True, separators=(',', ':')).encode('utf-8'))
            if os.name != 'nt':
                path.chmod(0o600)
            verify_private(directory)
        _bind_session_lifetime(app, lock)
        app.state.local_session_resumed = resumed
        app.state.local_session_id = directory.name
        app.state.local_session_username = marker['username']
        return app, directory
    except Exception:
        lock.close()
        raise


def main():
    app = None
    try:
        selected_username = username_option(sys.argv[1:])
        request = apply_username_option(read_request(sys.stdin.buffer), selected_username)
        app, directory = build_assessment_app(request)
        port = request['port']
        request['password'] = None
        import uvicorn
        print(f'FOX assessment preview: http://127.0.0.1:{port} | username: {app.state.local_session_username}', flush=True)
        print(f'Isolated assessment data retained at: {directory}', flush=True)
        print(f'Local session ID: {directory.name}', flush=True)
        if app.state.local_session_resumed:
            print('Saved projects/source history resumed. Preparation history is not resumed; select a new preparation. No extraction is retried.', flush=True)
        print('Assessment only: conversion and worker disabled; no OPAF/APEX connection. Stop with Ctrl+C.', flush=True)
        uvicorn.run(app, host='127.0.0.1', port=port, access_log=False,
                    proxy_headers=False, log_level='warning')
        return 0
    except KeyboardInterrupt:
        return 0
    except LocalSessionError as error:
        print(str(error), file=sys.stderr)
        return 1
    except Exception:
        # No traceback, raw request, password or inherited configuration is echoed.
        print('Local assessment preview could not start. Check the existing dependencies, build and local storage.', file=sys.stderr)
        return 1
    finally:
        if app is not None:
            app.state.local_session_lock.close()


if __name__ == '__main__':
    raise SystemExit(main())
