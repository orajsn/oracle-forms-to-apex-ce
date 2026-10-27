"""Isolate import-time FOX storage before any application test import."""
import os
from pathlib import Path
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[4]
for path in (ROOT / 'fox', ROOT / 'converter', ROOT / 'fox/tests', ROOT / 'converter/tests',
             Path(__file__).resolve().parents[1]):
    sys.path.insert(0, str(path))
for name in tuple(os.environ):
    if name.startswith(('FOX_', 'F2A_', 'OCI_')):
        os.environ.pop(name)
os.environ['FOX_DATA_DIR'] = tempfile.mkdtemp(prefix='delivery-import-', dir=ROOT / 'work')
os.environ['FOX_VERIFICATION_ENABLED'] = '0'
os.environ['FOX_CONVERSION_PROFILE'] = 'native-project-v1'
os.environ['PYTHONDONTWRITEBYTECODE'] = '1'
