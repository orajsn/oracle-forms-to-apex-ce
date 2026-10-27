"""Synthetic local POSIX installation fixture; never reads a real secret."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

from qa.operator.tests.test_hosted_state_paths import hosted_configuration


SYNTHETIC_ADMIN = b'SyntheticAdminOnly9!'


def canonical_bytes(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':'),
                       ensure_ascii=False, allow_nan=False) + '\n').encode('utf-8')


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def create_hosted_fixture(base: Path, *, secret=SYNTHETIC_ADMIN):
    """Return a detached config backed by actual private files and interpreter.

    The caller owns cleanup and must supply a new path under an owner-private
    temporary directory. Passing None leaves the private secret reference absent.
    """
    raw, _, _ = hosted_configuration(base)
    config = json.loads(raw)
    for reference in config['public_mount_roots']:
        Path(reference).mkdir(mode=0o700)
    for member in config['converter_sources']:
        (Path(config['converter_root']) / member).chmod(0o644)
    if secret is not None:
        path = Path(config['admin_secret_file'])
        path.write_bytes(secret + b'\n')
        path.chmod(0o600)
    return config


def configure_fixture(config, provider):
    raw = canonical_bytes(config)
    provider.configure_hosted(raw, expected_sha256=digest(raw))
    return provider.hosted()
