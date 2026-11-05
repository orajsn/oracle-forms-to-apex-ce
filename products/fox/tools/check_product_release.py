"""Offline consistency check; no import of FOX, credentials or installed state."""
import argparse
from datetime import date
import json
from pathlib import Path
import re

ROOT=Path(__file__).resolve().parents[1]


def check(root=ROOT):
    root=Path(root)
    info=json.loads((root/'fox/fox/release.json').read_text(encoding='utf-8'))
    version=info.get('version');released=info.get('released_on')
    if type(version) is not str or not re.fullmatch(r'(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)',version):
        raise ValueError('Invalid product version.')
    if type(released) is not str or date.fromisoformat(released).isoformat()!=released:
        raise ValueError('Invalid release date.')
    package=json.loads((root/'fox/package.json').read_text(encoding='utf-8'))
    lock=json.loads((root/'fox/package-lock.json').read_text(encoding='utf-8'))
    if not all(v==version for v in (package.get('version'),lock.get('version'),lock.get('packages',{}).get('',{}).get('version'))):
        raise ValueError('Product, package and lock versions differ.')
    if f'## [{version}] - {released}' not in (root/'CHANGELOG.md').read_text(encoding='utf-8').splitlines():
        raise ValueError('Matching changelog entry is missing.')
    return {'version':version,'tag':'fox-v'+version,'release_metadata_consistent':True,'deployment_verified':False}


if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('--root',default=ROOT);args=parser.parse_args()
    try:print(json.dumps(check(args.root),sort_keys=True))
    except (OSError,ValueError,KeyError):
        print('Release metadata check failed. Check the manifest, package, lock and changelog.');raise SystemExit(1)
