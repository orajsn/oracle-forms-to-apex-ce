"""Durable local XML mapping jobs. No provider, target connection or replay."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import stat
import time

from . import source_history, xml_mapping
from .forms_native_plan import POLICY_ID
from .forms_understanding_packet import _build
from .prototype_export_only import _sqlcl_path
from .xml_mapping_retained import verify_retained_package
from .forms_mapping_gaps import CATEGORIES

PROFILE = 'xml-mapping-v1'
APPROVAL = 'xml_mapping_local_consent:'
RESULT = 'xml_mapping_result:'
SCOPE_NOTICE = ('Installed deterministic mappings process the complete original XML locally, including unredacted '
    'source. No AI transmission or database import. One synthetic APEX application; database blocks are '
    'read-only reports. Unconverted code and unverified dependencies remain explicit. Format validation, runtime '
    'verification and business acceptance are separate.')


def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False,
                      allow_nan=False).encode('utf-8')


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def job_path(root, rid):
    if not re.fullmatch(r'fox-[a-f0-9]{20}', rid):
        raise ValueError('Invalid XML mapping run identity.')
    return Path(root) / 'jobs' / rid


def read_file(root, path, maximum=20_000_000):
    """Read only a bounded, unlinked regular file below ordinary directories."""
    root, path = Path(root), Path(path)
    path.relative_to(root)
    if root.is_symlink() or not root.is_dir():
        raise ValueError('Unsafe XML mapping storage.')
    current = root
    for part in path.relative_to(root).parts:
        current = current / part
        info = current.lstat()
        if stat.S_ISLNK(info.st_mode) or getattr(info, 'st_file_attributes', 0) & 0x400:
            raise ValueError('Unsafe XML mapping storage.')
        if current != path and not stat.S_ISDIR(info.st_mode):
            raise ValueError('Unsafe XML mapping storage.')
    before = path.lstat()
    if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or not 0 < before.st_size <= maximum:
        raise ValueError('Unsafe XML mapping file.')
    def identity(info):
        return tuple(getattr(info, key) for key in ('st_dev', 'st_ino', 'st_mode', 'st_nlink', 'st_size', 'st_mtime_ns'))
    with os.fdopen(os.open(path, os.O_RDONLY | getattr(os, 'O_BINARY', 0) | getattr(os, 'O_NOFOLLOW', 0)), 'rb') as stream:
        if identity(os.fstat(stream.fileno())) != identity(before):
            raise ValueError('XML mapping file changed.')
        raw = stream.read(maximum + 1)
        if identity(os.fstat(stream.fileno())) != identity(before):
            raise ValueError('XML mapping file changed.')
    if len(raw) != before.st_size or identity(path.lstat()) != identity(before):
        raise ValueError('XML mapping file changed.')
    return raw


def source_state(c, pid):
    sources = source_history.selected_sources(c, pid)
    if not sources or any(not row['name'].lower().endswith('.xml') for row in sources):
        raise ValueError('Select a complete supported Forms XML source set. Other files cannot be silently omitted.')
    documents = [(row['name'], source_history.readable_source_bytes(row)) for row in sources]
    packet, chunks = _build(documents)
    if not any(obj['kind'] == 'Block' and obj['classification'] in {'database', 'control'}
               for entry in packet['sources'] for obj in entry['facts']['objects']):
        raise ValueError('This XML set has no supported source block for a synthetic application.')
    return {'source_hash': source_history._hash(sources),
            'selected_source_set_id': source_history.selected_source_set_id(c, pid),
            'source_binding': packet['source_binding'],
            'catalog_sha256': xml_mapping.mapping_catalog()['catalog_sha256'],
            'source_count': len(sources), 'code_unit_count': len(chunks)}, sources, documents


def load_snapshot(c, root, run):
    raw = read_file(root, job_path(root, run['id']) / 'source-snapshot.json')
    snapshot = json.loads(raw)
    if type(snapshot) is not dict or type(snapshot.get('request')) is not dict:
        raise ValueError('XML mapping snapshot is invalid.')
    owner = c.execute('SELECT owner FROM projects WHERE id=?', (run['project'],)).fetchone()
    if (not owner or snapshot.get('conversion_profile') != PROFILE
            or snapshot.get('project_id') != run['project'] or snapshot.get('source_hash') != run['source_hash']
            or snapshot.get('owner') != owner['owner']
            or snapshot.get('policy_id') != POLICY_ID
            or snapshot.get('request', {}).get('approved_synthetic_scope') is not True
            or snapshot.get('request', {}).get('approved_local_source_processing') is not True
            or not c.execute('SELECT 1 FROM events WHERE owner=? AND object_id=? AND action=?',
                (owner['owner'], run['id'], APPROVAL + sha(raw))).fetchone()):
        raise ValueError('XML mapping source or consent identity changed.')
    return snapshot, raw


def is_mapping_run(c, run):
    # Durable DB event identifies the profile even if a file is missing/tampered.
    return c.execute('SELECT 1 FROM events WHERE object_id=? AND action LIKE ?',
                     (run['id'], APPROVAL + '%')).fetchone() is not None


def checked_output(c, root, run):
    """Read-only reconstruction of source, candidate, compiler log and final ZIP."""
    if run['state'] != 'GENERATED' or run['artifact'] is not None:
        raise ValueError('XML mapping output is unavailable.')
    snapshot, _ = load_snapshot(c, root, run)
    directory = job_path(root, run['id']) / 'xml-mapping'
    receipt_raw = read_file(root, directory / 'result.json', 1_000_000)
    if not c.execute('SELECT 1 FROM events WHERE owner=? AND object_id=? AND action=?',
            (snapshot['owner'], run['id'], RESULT + sha(receipt_raw))).fetchone():
        raise ValueError('XML mapping result identity changed.')
    receipt = json.loads(receipt_raw)
    if receipt['snapshot_sha256'] != sha(encoded(snapshot)):
        raise ValueError('XML mapping snapshot identity changed.')
    docs = [(row['name'], source_history.readable_source_bytes(row)) for row in snapshot['files']]
    stored_candidate = read_file(root, directory / 'candidate.zip')
    package = read_file(root, directory / 'apexlang.zip')
    if snapshot['catalog_sha256'] == xml_mapping.mapping_catalog()['catalog_sha256']:
        candidate, report = xml_mapping.generate_xml_package(docs, snapshot['project_id'], snapshot['project_name'], POLICY_ID)
        if report['source_binding'] != snapshot['source_binding'] or stored_candidate != candidate:
            raise ValueError('XML mapping candidate differs from the approved original source.')
        sealed, proof = xml_mapping._seal_validated_xml_package(candidate,
            {'candidate_sha256': sha(candidate), 'validation': receipt['proof']['validation']}, directory / 'validation')
        if proof != receipt['proof'] or package != sealed:
            raise ValueError('XML mapping package proof changed.')
        metadata, ledger, gaps = report['metadata'], report['mapping_ledger'], report.get('gap_report')
    else:
        # Original consent/result event anchors were verified above. Preserve
        # old completed output under its own catalog, not current-engine claims.
        metadata, ledger, files = verify_retained_package(stored_candidate, package,
            receipt['proof'], snapshot, docs, directory / 'validation')
        gaps = json.loads(files['fox-package/mapping-gaps.json']) if 'fox-package/mapping-gaps.json' in files else None
    if receipt['source_binding'] != snapshot['source_binding']:
        raise ValueError('XML mapping source binding changed.')
    counts = metadata['behavior_coverage']
    generated = sum(1 for row in ledger['code_units'] if row['status'] == 'generated_wired_adapted')
    details = _gap_fields(gaps, ledger, snapshot['source_binding'])
    details['context_summary'] = _context_fields(metadata, ledger)
    return package, {'generated_units': generated, 'unsupported_units': counts['total'] - generated,
                     'total_units': counts['total'], 'package_sha256': sha(package), **details}


def _context_fields(metadata, ledger):
    summary = metadata.get('context_summary')
    if summary is None:
        return None  # Older artifacts did not record this capability.
    keys = {'relations_generated', 'relations_not_converted', 'assignments_generated_unwired'}
    if (type(summary) is not dict or set(summary) != keys
            or any(type(value) is not int or value < 0 for value in summary.values())):
        raise ValueError('Saved record-context summary is invalid.')
    relations, assignments = ledger.get('relations'), ledger.get('assignment_review')
    if type(relations) is not list or type(assignments) is not list:
        raise ValueError('Saved record-context evidence is missing.')
    generated = sum(row['status'] == 'read_navigation_generated' for row in relations)
    ids = {row['source_unit_id'] for row in assignments}
    units = {row['source_unit_id']:row for row in ledger['code_units']}
    if (len(ids) != len(assignments) or not ids <= set(units)
            or summary != {'relations_generated': generated, 'relations_not_converted': len(relations)-generated,
                           'assignments_generated_unwired': len(assignments)}):
        raise ValueError('Saved record-context counts differ from their evidence.')
    for row in assignments:
        unit = units[row['source_unit_id']]
        if (row.get('generation_status') != 'generated_unwired'
                or unit['status'] == 'generated_wired_adapted'
                or unit.get('encoding_status') != 'generated_unwired'
                or any(row.get(k) is not False for k in
                       ('write_lifecycle','event_activated','oracle_compiled','runtime_verified','business_accepted'))):
            raise ValueError('An unwired assignment was incorrectly promoted to converted behavior.')
    return summary


def _gap_fields(report, ledger, source_binding):
    if report is None:
        return {'gaps_available': False, 'gap_summary': None, 'gaps': []}
    remaining = {r['source_unit_id'] for r in ledger['code_units'] if r['status'] != 'generated_wired_adapted'}
    rows, summary = report['gaps'], report['summary']
    if (report['scope'] != 'fox-source-mapping-gaps-v1' or report['source_binding'] != source_binding
            or type(rows) is not list or len(rows) != len(remaining)
            or {r['source_unit_id'] for r in rows} != remaining
            or report['not_yet_converted'] != len(rows) or set(summary) != set(CATEGORIES)):
        raise ValueError('Saved mapping gaps do not match the source coverage.')
    owners = {'engine_mapping': 'FOX_ENGINE', 'engine_context': 'FOX_ENGINE',
              'missing_source': 'SOURCE_OWNER', 'review_required': 'REVIEWER'}
    fields = {'source_unit_id', 'source_name', 'source_file', 'source_line',
              'category', 'reason', 'message', 'next_action', 'owner'}
    for row in rows:
        if (set(row) != fields or row['category'] not in owners or row['owner'] != owners[row['category']]
                or type(row['source_line']) is not int or row['source_line'] < 1
                or any(type(row[k]) is not str or not 0 < len(row[k]) <= 4000 for k in fields - {'source_line'})):
            raise ValueError('Saved mapping gap fields are invalid.')
    if any(type(summary[k]) is not int or summary[k] < 0
           or summary[k] != sum(r['category'] == k for r in rows) for k in CATEGORIES):
        raise ValueError('Saved mapping gap counts are invalid.')
    return {'gaps_available': True, 'gap_summary': summary, 'gaps': rows}


def public_run(c, root, run, current_hash=None, current_sid=None):
    result = {key: run[key] for key in ('id', 'source_hash', 'state', 'message', 'created', 'updated')}
    result.update(project_id=run['project'], conversion_profile=PROFILE, request_id=None,
        selected_source_set_id=None, current_source=False, format_validated=False,
        generated_units=None, unsupported_units=None, total_units=None,
        download_url=None, package_sha256=None, runtime_verified=False, business_behavior_accepted=False,
        gaps_available=False, gap_summary=None, gaps=[], context_summary=None)
    try:
        snapshot, _ = load_snapshot(c, root, run)
        result.update(selected_source_set_id=snapshot['selected_source_set_id'], request_id=snapshot['request']['request_id'])
        result['current_source'] = run['source_hash'] == current_hash and snapshot['selected_source_set_id'] == current_sid
        if run['state'] == 'GENERATED':
            _, checked = checked_output(c, root, run)
            result.update(checked, format_validated=True,
                download_url=f"/api/projects/{run['project']}/xml-mapping/runs/{run['id']}/download")
    except (ValueError, OSError, KeyError, TypeError, RuntimeError):
        result.update(state='ATTENTION', message='Saved XML mapping evidence could not be verified. No operation was repeated.')
    return result


def run_job(db, root, run):
    with db() as c:
        c.execute('BEGIN')
        snapshot, snapshot_raw = load_snapshot(c, root, run)
        current, _, documents = source_state(c, run['project'])
        if any(current[key] != snapshot[key] for key in ('source_hash', 'selected_source_set_id', 'source_binding', 'catalog_sha256')):
            raise RuntimeError('XML mapping source version or installed catalog changed. No compilation was started.')
    _sqlcl_path()
    directory = job_path(root, run['id']) / 'xml-mapping'
    # Exclusive durable attempt marker. An interrupted attempt must never replay.
    directory.mkdir()
    candidate, report = xml_mapping.generate_xml_package(documents, snapshot['project_id'], snapshot['project_name'], POLICY_ID)
    (directory / 'candidate.zip').write_bytes(candidate)
    with db() as c:
        c.execute('UPDATE runs SET message=?,updated=? WHERE id=?',
            ('Generating supported mappings and validating the complete APEXlang package with SQLcl /nolog.', time.time(), run['id']))
        current, _, _ = source_state(c, run['project'])
        if any(current[key] != snapshot[key] for key in ('source_hash', 'selected_source_set_id', 'source_binding', 'catalog_sha256')):
            raise RuntimeError('XML mapping source changed before compilation. Retained attempt needs reconciliation.')
    package, proof = xml_mapping.validate_xml_package(candidate, directory / 'validation')
    if read_file(root, job_path(root, run['id']) / 'source-snapshot.json') != snapshot_raw:
        raise RuntimeError('XML mapping snapshot changed. Retained attempt needs reconciliation.')
    receipt = encoded({'snapshot_sha256': sha(snapshot_raw), 'source_binding': report['source_binding'], 'proof': proof})
    (directory / 'apexlang.zip').write_bytes(package)
    (directory / 'result.json').write_bytes(receipt)
    with db() as c:
        c.execute('BEGIN IMMEDIATE')
        load_snapshot(c, root, run)
        c.execute('INSERT INTO events(owner,action,object_id,created) VALUES(?,?,?,?)',
                  (snapshot['owner'], RESULT + sha(receipt), run['id'], time.time()))
        c.execute("UPDATE runs SET state='GENERATED',message=?,artifact=NULL,updated=? WHERE id=?",
                  ('APEXlang generated and format validated. Remaining conversion gaps are explained; runtime and business acceptance are pending.', time.time(), run['id']))
