"""Canonical test imports never initialize an operator's existing FOX data.

The application creates its default ASGI object at import time. Isolate that
initialization before pytest imports any test module; individual fixtures still
provide their own fresh data directories and explicitly mocked integrations.
"""
import os
from pathlib import Path
import sys
import tempfile


REPOSITORY = Path(__file__).resolve().parents[1]
SCRATCH = REPOSITORY / 'work'
if SCRATCH.is_symlink() or SCRATCH.resolve() != SCRATCH:
    raise RuntimeError('FOX test scratch must be an ordinary repository directory.')
SCRATCH.mkdir(exist_ok=True)
IMPORT_DATA = Path(tempfile.mkdtemp(prefix='test-import-', dir=SCRATCH))

# Only this pytest process is affected. Never inherit operator endpoints,
# credential references, live data paths, or enabled verification settings.
for key in tuple(os.environ):
    if key.startswith(('FOX_', 'F2A_')):
        os.environ.pop(key)
os.environ['FOX_DATA_DIR'] = str(IMPORT_DATA)
os.environ['FOX_VERIFICATION_ENABLED'] = '0'
os.environ['FOX_CONVERSION_PROFILE'] = 'legacy-html-prototype-v1'

if str(REPOSITORY) not in sys.path:
    sys.path.insert(0, str(REPOSITORY))
import fox
if Path(fox.__file__).resolve() != REPOSITORY / 'fox' / '__init__.py':
    raise RuntimeError('FOX tests must import the canonical repository package.')


def pytest_report_header(config):
    return 'Canonical FOX package; fresh import-time data; external integration settings cleared.'
