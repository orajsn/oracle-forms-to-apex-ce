#!/usr/bin/env python3
"""Build a clean FOX preview archive with prebuilt UI and offline wheels.

No installed history, secrets, Oracle binaries, dependency downloads or execution.
The operator supplies a wheelhouse prepared for the destination Python/platform.
"""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path
import tarfile
import io

EXCLUDED = {'node_modules', '__pycache__', '.pytest_cache', '.venv', '.git', 'data', 'outputs', 'work'}

def build(root: Path, wheelhouse: Path, output: Path):
    root, wheelhouse, output = root.resolve(), wheelhouse.resolve(), output.absolute()
    if output.exists():
        raise ValueError('Choose a new output archive; existing artifacts are preserved.')
    if not (root/'fox/dist/index.html').is_file():
        raise ValueError('Build the UI before packaging.')
    if not wheelhouse.is_dir() or not list(wheelhouse.glob('*.whl')):
        raise ValueError('Provide an offline wheelhouse for the target platform.')
    rows = {}
    for folder in ('fox/fox', 'fox/dist', 'converter/forms2apex', 'converter/fox_source_contract', 'qa', 'deployment'):
        for path in (root/folder).rglob('*'):
            rel = path.relative_to(root)
            if set(rel.parts) & EXCLUDED or path.suffix in {'.pyc', '.log'}:
                continue
            if path.is_symlink():
                raise ValueError('Package inputs must not contain links.')
            if path.is_file():
                rows[rel.as_posix()] = path
    for name in ('fox/requirements-lock.txt', 'fox/requirements.txt', 'converter/pyproject.toml', 'README.md', 'THIRD_PARTY.md', 'docs/direct-oci-preview.md'):
        rows[name] = root/name
    for path in wheelhouse.iterdir():
        if path.is_file() and (path.suffix == '.whl' or path.name == 'requirements.txt'):
            if path.is_symlink():
                raise ValueError('Wheelhouse links are not allowed.')
            rows['wheelhouse/'+path.name] = path
    if 'wheelhouse/requirements.txt' not in rows:
        raise ValueError('Wheelhouse needs exact pinned requirements.txt.')
    manifest = {'schema_version':1, 'scope':'fox-direct-preview-package-v1',
                'version':json.loads((root/'fox/fox/release.json').read_text())['version'],
                'files':[],'oracle_binaries_included':False}
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open('xb') as stream, tarfile.open(fileobj=stream, mode='w:gz') as archive:
        for name, path in sorted(rows.items()):
            raw = path.read_bytes()
            manifest['files'].append({'path':name,'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest()})
            info=tarfile.TarInfo(name); info.size=len(raw); info.mode=0o644
            archive.addfile(info, io.BytesIO(raw))
        raw=(json.dumps(manifest,sort_keys=True,indent=2)+'\n').encode()
        info=tarfile.TarInfo('package-manifest.json');info.size=len(raw);info.mode=0o644
        archive.addfile(info,io.BytesIO(raw))
    return {'archive':str(output),'sha256':hashlib.sha256(output.read_bytes()).hexdigest(),'files':len(rows),'version':manifest['version']}

if __name__ == '__main__':
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--product-root',type=Path,default=Path(__file__).resolve().parents[1])
    p.add_argument('--wheelhouse',type=Path,required=True)
    p.add_argument('--output',type=Path,required=True)
    args=p.parse_args()
    print(json.dumps(build(args.product_root,args.wheelhouse,args.output)))
