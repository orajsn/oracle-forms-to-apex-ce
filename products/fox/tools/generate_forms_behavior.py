"""Generate a separate source-derived behavior package; no database import."""
from pathlib import Path
import argparse
import hashlib
import json
import os
import sys
import zipfile

PRODUCT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(PRODUCT/'fox'), str(PRODUCT/'converter')]
from fox.behavior_package import prepare_behavior_package, validate_behavior_package


def _write(path, raw):
    with path.open('xb') as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--parent-package', required=True, type=Path)
    parser.add_argument('--xml', required=True, type=Path, action='append')
    parser.add_argument('--output', required=True, type=Path)
    parser.add_argument('--unit', action='append', default=None)
    parser.add_argument('--validate-sqlcl', action='store_true')
    args = parser.parse_args(argv)
    if args.parent_package.is_symlink() or any(path.is_symlink() for path in args.xml):
        raise ValueError('Input links are not supported.')
    parent = args.parent_package.read_bytes()
    with zipfile.ZipFile(args.parent_package) as archive:
        manifest = json.loads(archive.read('fox-package/source-manifest.json'))
    supplied = [path.read_bytes() for path in args.xml]
    docs, used = [], set()
    for row in manifest['files']:
        matches = [i for i, raw in enumerate(supplied) if hashlib.sha256(raw).hexdigest() == row['sha256']]
        if len(matches) != 1 or matches[0] in used:
            raise ValueError('Supply the exact original XML files from the parent source manifest.')
        used.add(matches[0]); docs.append((row['name'], supplied[matches[0]]))
    if len(used) != len(supplied):
        raise ValueError('Extra or duplicate XML input is outside the parent source set.')
    candidate, result = prepare_behavior_package(docs, parent, args.unit)
    args.output.mkdir(parents=True, exist_ok=False)
    _write(args.output/'candidate.zip', candidate)
    for name, value in (('behavior-plan.json', result['plan']), ('generation-receipt.json', result['renderer_receipt'])):
        _write(args.output/name, json.dumps(value, ensure_ascii=False, indent=2).encode('utf-8'))
    final = None
    if args.validate_sqlcl:
        final, validation = validate_behavior_package(candidate, args.output)
        _write(args.output/'APEXlang-behavior-package.zip', final)
        _write(args.output/'format-validation.json', json.dumps(validation, indent=2).encode('utf-8'))
    counts = {}
    for row in result['renderer_receipt']['coverage']:
        counts[row['status']] = counts.get(row['status'], 0) + 1
    summary = {'status': 'FORMAT_VALIDATED' if final else 'GENERATED_VALIDATION_PENDING',
        'source_binding': result['plan']['source_binding'], 'coverage': counts,
        'source_unit_count': result['plan']['code_unit_count'],
        'candidate_sha256': result['candidate_sha256'],
        'package_sha256': hashlib.sha256(final).hexdigest() if final else None,
        'runtime_verified': False, 'business_behavior_accepted': False,
        'provider_calls': 0, 'database_imports': 0}
    _write(args.output/'result.json', json.dumps(summary, indent=2).encode('utf-8'))
    print(json.dumps(summary))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
