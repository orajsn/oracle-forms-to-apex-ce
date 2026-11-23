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
from .forms_discrepancies import validate_discrepancies
from .forms_gap_requirements import valid_gap_requirements
from . import xml_supporting_inputs

PROFILE = 'xml-mapping-v1'
APPROVAL = 'xml_mapping_local_consent:'
RESULT = 'xml_mapping_result:'
MAX_SNAPSHOT_BYTES = 20_000_000
SCOPE_NOTICE = ('FOX processes Forms XML locally and generates one synthetic APEX application. '
    'Selected SQL, package and PLD sources are retained as declaration evidence. They are never installed or executed. '
    'The package can include reports, session drafts and current-row saves to its generated test tables. '
    'Source-unit notes identify the behavior each screen supports. Generation uses no AI calls or database imports.')


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
    documents = [(row['name'], source_history.readable_source_bytes(row)) for row in sources]
    xml, _ = xml_supporting_inputs.split_inputs(documents)
    packet, chunks = _build(xml)
    if not any(obj['kind'] == 'Block' and obj['classification'] in {'database', 'control'}
               for entry in packet['sources'] for obj in entry['facts']['objects']):
        raise ValueError('This XML set has no supported source block for a synthetic application.')
    return {'source_hash': source_history._hash(sources),
            'selected_source_set_id': source_history.selected_source_set_id(c, pid),
            'source_binding': packet['source_binding'],
            'catalog_sha256': xml_mapping.mapping_catalog()['catalog_sha256'],
            'source_count': len(sources), 'code_unit_count': len(chunks)}, sources, documents


def load_snapshot(c, root, run):
    raw = read_file(root, job_path(root, run['id']) / 'source-snapshot.json', MAX_SNAPSHOT_BYTES)
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


def checked_output(c, root, run, *, interface_csv=False):
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
    # Completion anchored the exact source and compiler proof in the result event.
    # Serve those verified bytes for every catalog, including the current one.
    metadata, ledger, files = verify_retained_package(
        stored_candidate, package, receipt['proof'], snapshot, docs, directory / 'validation')
    gap_member = 'fox-package/mapping-gaps.json'
    gaps = json.loads(files[gap_member]) if gap_member in files else None
    if receipt['source_binding'] != snapshot['source_binding']:
        raise ValueError('XML mapping source binding changed.')
    counts = metadata['behavior_coverage']
    generated = sum(1 for row in ledger['code_units'] if row['status'] == 'generated_wired_adapted')
    details = _gap_fields(gaps, ledger, snapshot['source_binding'])
    details['context_summary'] = _context_fields(metadata, ledger)
    details['policy_summary'] = _policy_fields(metadata, ledger)
    details['buffer_summary'] = _buffer_fields(metadata, ledger)
    details['item_validation_summary'] = _item_validation_fields(metadata, ledger)
    details['synthetic_save_summary'] = _synthetic_save_fields(metadata, ledger)
    details['lookup_summary'] = _lookup_fields(metadata, ledger)
    number_summary = _rate_number_summary(metadata, files)
    if number_summary:
        details['rate_numbers'] = number_summary
    parent_summary = _rate_parent_summary(metadata, files)
    if parent_summary:
        details['parent_rates'] = parent_summary
    coverage_summary = _saved_rate_field_coverage(metadata, files)
    if coverage_summary:
        details['rate_field_coverage'] = coverage_summary
    checkbox_summary = _saved_checkbox_summary(metadata, ledger, files)
    if checkbox_summary is not None:
        details['checkbox_drafts'] = checkbox_summary
    details['discrepancies'] = _discrepancy_fields(metadata, ledger, gaps, files)
    details['interface_summary'] = _interface_fields(metadata, files)
    if 'supporting_inputs' in metadata:
        evidence = json.loads(files[xml_supporting_inputs.MEMBER])
        changes = [r for r in evidence['declaration_changes'] if all(len(r[k]) <= 1000 for k in ('kind','target','routine','source'))]
        details['supporting_inputs'] = {
            'files': [{key: entry[key] for key in ('name','role')} for entry in evidence['files']],
            'declaration_changes': changes[:100], 'limited': len(changes[:100]) != len(evidence['declaration_changes']),
            'source_execution': False}
    payload = files.get('fox-package/interface-register.csv') if interface_csv else package
    if interface_csv and not (details['interface_summary'] and details['interface_summary']['csv_available']):
        payload = None
    return payload, {'saved_source_binding': snapshot['source_binding'],
                     'generated_units': generated, 'unsupported_units': counts['total'] - generated,
                     'total_units': counts['total'], 'package_sha256': sha(package), **details}


def _saved_checkbox_summary(metadata, ledger, files):
    """Project only verified display fields from an authenticated retained ZIP.

    No compiler, current parser, source SQL or source event body enters this
    reader. checked_output authenticates package bytes before calling it.
    """
    if 'checkbox_drafts' not in metadata:
        return None  # Older packages do not acquire a newly inferred capability.
    def need(ok):
        if not ok:
            raise ValueError('Saved checkbox draft evidence is invalid.')
    def identifier(value):
        need(type(value) is str and re.fullmatch(r'[A-Za-z][A-Za-z0-9_$#]{0,127}', value))
        return value
    def source_id(value):
        need(type(value) is str and re.fullmatch(r'ff1-[a-f0-9]{24}', value))
        return value
    def unique(pairs):
        value = {}
        for key, item in pairs:
            need(key not in value)
            value[key] = item
        return value
    def nonfinite(_):
        raise ValueError('Nonfinite checkbox evidence.')
    try:
        descriptor = metadata['checkbox_drafts']
        member = 'fox-package/checkbox-drafts.json'
        need(type(descriptor) is dict and len(encoded(descriptor)) <= 200_000)
        raw = files[member]
        need(type(raw) is bytes and 0 < len(raw) <= MAX_SNAPSHOT_BYTES
             and descriptor.get('member') == member and descriptor.get('sha256') == sha(raw))
        receipt = json.loads(raw, object_pairs_hook=unique, parse_constant=nonfinite)
        need(type(receipt) is dict and set(receipt) == {
            'schema_version', 'scope', 'source_binding', 'project_id', 'groups', 'gaps',
            'converted_code_unit_count', 'customer_table_writes', 'original_access_rights_proven',
            'runtime_verified', 'business_accepted', 'scope_note'})
        need(type(receipt['schema_version']) is int and receipt['schema_version'] == 1
             and receipt['scope'] == 'fox-source-checkbox-group-v1'
             and receipt['source_binding'] == metadata['source_binding']
             and receipt['project_id'] == metadata['project_id']
             and type(receipt['scope_note']) is str and len(receipt['scope_note']) <= 4000
             and type(receipt['converted_code_unit_count']) is int and receipt['converted_code_unit_count'] == 0)
        for key in ('customer_table_writes', 'original_access_rights_proven', 'runtime_verified', 'business_accepted'):
            need(receipt[key] is False)
        groups, gaps = receipt['groups'], receipt['gaps']
        need(type(groups) is list and len(groups) <= 16 and type(gaps) is list and len(gaps) <= 1000)
        units = {u['source_unit_id']: u for u in ledger['code_units']}
        blocks = {o['source_object_id']: o['target'] for o in ledger['objects'] if o['kind'] == 'Block'}
        seen, pages, tables, summaries = set(), set(), set(), []
        def proof(row):
            need(type(row) is dict)
            uid = source_id(row['source_unit_id'])
            unit = units.get(uid)
            need(uid not in seen and unit is not None and row['source_unit_sha256'] == unit['source_unit_sha256']
                 and type(row['source_unit_sha256']) is str and re.fullmatch(r'[a-f0-9]{64}', row['source_unit_sha256']))
            seen.add(uid)
            return uid
        for group in groups:
            uid = proof(group)
            bid = source_id(group['source_block_id'])
            target, block = group['native_target'], blocks.get(bid)
            need(type(target) is dict and type(block) is dict)
            page = target['page_id']
            need(type(page) is int and 8100 <= page <= 9999 and page not in pages)
            path = f'pages/p{page:05d}-fox_checkbox_{page}.apx'
            need(target['scope'] == 'fox-native-checkbox-workspace-v1'
                 and target['page_file'] == path and path in files and path in metadata['apex_members']
                 and metadata['apex_members'][path] == sha(files[path])
                 and target['source_page_file'] == group['report_file'] == block['report_file']
                 and target['source_page_file'] in files
                 and target['source_page_id'] == group['report_page_id'] == block['report_page_id']
                 and target['source_unit_id'] == uid and target['source_unit_sha256'] == group['source_unit_sha256']
                 and target['source_block_id'] == bid
                 and target['source_binding'] == group['source_binding'] == metadata['source_binding']
                 and target['project_id'] == group['project_id'] == metadata['project_id']
                 and target['source_table'] == group['table_name'] == block['table_name'])
            table = target['draft_table']
            need(type(table) is str and re.fullmatch(r'FOX_CD_[A-F0-9]{18}', table) and table not in tables)
            for key in ('business_table_writes', 'durable_synthetic_save', 'source_record_entry_executed',
                        'original_interface_enabled', 'oracle_compiled', 'runtime_verified', 'business_accepted'):
                need(target[key] is False)
            for key in ('record_entry_initialization_implemented', 'original_access_rights_proven',
                        'original_save_authorized', 'source_widget_equivalence_proven'):
                need(group[key] is False)
            need(target['session_draft_table_writes'] is True
                 and group['source_event'] == target['source_event'] == 'WHEN-CHECKBOX-CHANGED')
            policy = {'allowed_values': 'exact_checked_or_unchecked_only', 'null_values': 'reject',
                      'other_values': 'reject', 'source_other_values_policy_proven': True,
                      'other_value_display_implemented': False}
            need(group['input_policy'] == target['input_policy'] == policy)
            fields = [group['controller']] + group['dependents']
            need(type(group['dependents']) is list and 2 <= len(fields) <= 30 and target['fields'] == fields)
            item_ids = [source_id(field['source_item_id']) for field in fields]
            need(len(set(item_ids)) == len(item_ids))
            field_names = [identifier(field['source_name']) for field in fields]
            need(len(set(name.upper() for name in field_names)) == len(field_names))
            summaries.append({'source_unit_id': uid, 'source_unit_sha256': group['source_unit_sha256'],
                              'source_block_id': bid, 'source_block_name': identifier(group['source_block_name']),
                              'controller': field_names[0], 'dependents': field_names[1:],
                              'page_id': page, 'page_file': path, 'reset_on_manual_off': True})
            pages.add(page)
            tables.add(table)
        gap_summaries = []
        for gap in gaps:
            uid = proof(gap)
            reason = gap['reason']
            need(type(reason) is str and 0 < len(reason) <= 4000)
            gap_summaries.append({'source_unit_id': uid, 'reason': reason})
        fixed = {'scope': 'synthetic_session_draft_only', 'converted_code_unit_count': 0,
                 'exact_checked_unchecked_only': True, 'null_other_values_accepted': False,
                 'original_access_rights_proven': False, 'record_entry_initialization_implemented': False,
                 'durable_synthetic_save': False, 'customer_table_writes': False,
                 'runtime_verified': False, 'business_accepted': False}
        expected = dict(fixed, member=member, sha256=sha(raw), groups=summaries, gaps=gap_summaries,
                        generated_group_count=len(groups), gap_count=len(gaps))
        need(descriptor == expected)
        for key in ('generated_group_count', 'gap_count', 'converted_code_unit_count'):
            need(type(descriptor[key]) is int)
        for key, value in fixed.items():
            if type(value) is bool:
                need(descriptor[key] is value)
        need(all(g['reset_on_manual_off'] is True and type(g['page_id']) is int for g in descriptor['groups']))
        # Unexpected validator messages remain package evidence, never UI text.
        safe_gaps = [{'source_unit_id': row['source_unit_id'],
                      'reason': row['reason'] if re.fullmatch(r'CHECKBOX_(?:GROUP|WORKSPACE|PACKAGE)_[A-Z0-9_]{1,120}', row['reason'])
                      else 'CHECKBOX_WORKSPACE_ADMISSION_UNRESOLVED'} for row in gap_summaries]
        return dict(fixed, member=member, sha256=sha(raw), groups=summaries, gaps=safe_gaps,
                    generated_group_count=len(groups), gap_count=len(gaps))
    except (KeyError, TypeError, UnicodeError, RecursionError, OverflowError) as error:
        raise ValueError('Saved checkbox draft evidence is invalid.') from error


def _interface_fields(metadata, files):
    descriptor = metadata.get('interface_register')
    if descriptor is None:
        return None
    if (descriptor['scope'] != 'fox-source-interface-register-v1'
            or descriptor['source_binding'] != metadata['source_binding']
            or type(descriptor['record_count']) is not int or descriptor['record_count'] < 0
            or type(descriptor['detail_limited']) is not bool
            or type(descriptor['size_limited']) is not bool):
        raise ValueError('Interface register differs from the saved source.')
    artifacts = descriptor['artifacts']
    if (type(artifacts) is not dict or not set(artifacts) <= {'csv','json'}
            or descriptor['size_limited'] != (len(artifacts) < 2)):
        raise ValueError('Invalid interface register formats.')
    for kind, entry in artifacts.items():
        path = 'fox-package/interface-register.' + kind
        if entry['path'] != path or path not in files or sha(files[path]) != entry['sha256']:
            raise ValueError('Saved interface register evidence changed.')
    return {'records': descriptor['record_count'], 'csv_available': 'csv' in artifacts,
            'detail_limited': descriptor['detail_limited'],
            'json_available': 'json' in artifacts, 'size_limited': descriptor['size_limited']}


def _discrepancy_fields(metadata, ledger, gaps, files):
    path = metadata.get('discrepancy_report_path')
    if path is None:
        return None  # Historical outputs do not acquire new classifications.
    if path != 'fox-package/discrepancies.json' or path not in files:
        raise ValueError('Saved discrepancy report is missing or has an invalid path.')
    raw = files[path]
    if metadata.get('discrepancy_report_sha256') != sha(raw):
        raise ValueError('Saved discrepancy report changed.')
    report = json.loads(raw)
    evidence_path = metadata.get('discrepancy_evidence_path')
    evidence = None
    if evidence_path is not None:
        if (evidence_path != 'fox-package/discrepancy-evidence.json' or evidence_path not in files
                or metadata.get('discrepancy_evidence_sha256') != sha(files[evidence_path])):
            raise ValueError('Saved discrepancy reference evidence changed.')
        evidence = json.loads(files[evidence_path])
    catalog = json.loads(files['fox-package/mapping-catalog.json'])
    # checked_output has already authenticated exact candidate/final bytes,
    # source/version consent, compiler proof and immutable catalog. Do not
    # reclassify an old saved report with a newer parser or mapping registry.
    return validate_discrepancies(report, ledger, gaps, catalog, dependency_evidence=evidence)


def _saved_rate_field_coverage(metadata, files):
    descriptor = metadata.get('rate_field_coverage')
    if descriptor is None:
        return None
    member = 'fox-package/rate-field-coverage.json'
    raw = files[member]
    if (descriptor.get('member') != member or descriptor.get('sha256') != sha(raw)
            or descriptor.get('source_binding') != metadata['source_binding']):
        raise ValueError('Saved rate field inventory binding changed.')
    report = json.loads(raw)
    if (report.get('schema_version') != 1 or report.get('scope') != 'fox-rate-field-coverage-v1'
            or report.get('source_binding') != metadata['source_binding']):
        raise ValueError('Saved rate field inventory source changed.')
    expected = {(w['source_block_id'], w['page_file']) for w in metadata['saved_lookup_workspaces']}
    workspaces = []
    statuses = ('saved', 'parent_linked', 'pending', 'control')
    def clean(value, limit):
        return re.sub(r'[\x00-\x1f\x7f-\x9f]', ' ', value).strip()[:limit]
    for w in report['workspaces']:
        key = (w['block_id'], w['page_file'])
        if key not in expected:
            raise ValueError('Unexpected workspace in saved field inventory.')
        expected.remove(key)
        counts = {k: w['counts'][k] for k in statuses}
        if (any(type(n) is not int or n < 0 for n in counts.values())
                or sum(counts.values()) != w['counts']['total']):
            raise ValueError('Invalid saved field inventory counts.')
        items = w['items']
        visible = dict.fromkeys(statuses, 0)
        for f in items:
            visible[f['status']] += 1
        if (any(visible[k] > counts[k] for k in statuses)
                or (not w['limited'] and visible != counts)
                or len({f['id'] for f in items}) != len(items)):
            raise ValueError('Saved rate field dispositions disagree with their counts.')
        if len(workspaces) >= 20:
            continue
        if len(items) > 100:
            items = sorted(items, key=lambda f: f['status'] != 'pending')[:100]
        rows = []
        for field in items:
            name = clean(field['name'] or '', 160) or field['id']
            rows.append({'name': name, 'label': clean(field['label'] or '', 160) or name,
                         'status': field['status'], 'database_item': field['database_item'] if type(field['database_item']) is bool else None,
                         'note': clean(field['note'], 600)})
        workspaces.append({'block': clean(w['block'] or '', 160) or w['block_id'], 'counts': counts, 'items': rows,
                           'limited': len(rows) < w['counts']['total']})
    if expected:
        raise ValueError('Rate field evidence is missing for a saved workspace.')
    return {'workspaces': workspaces, 'limited': len(workspaces) < len(report['workspaces'])}


def _rate_parent_summary(metadata, files):
    expected = {row['page_file']: row for row in metadata.get('saved_lookup_workspaces', [])
                if 'parent_launcher_page' in row or 'parent_copy_gaps' in row}
    if not expected:
        return None
    def label(value):
        return re.sub(r'[\x00-\x1f\x7f-\x9f]', ' ', value).strip()[:160] or 'Unnamed source field'
    notes = {
        'RATE_PARENT_EXPLICIT_PARENT_RELATION_REQUIRED': 'The source specifies a field copy, but its parent relation is missing.',
        'RATE_PARENT_INCOMING_PARENT_RELATION_NOT_UNIQUE': 'More than one incoming relation could supply the parent. Confirm which relation owns this copy.',
        'RATE_PARENT_MATCHING_NATIVE_RELATION_REQUIRED': 'The parent relation still needs a matching generated detail page.',
    }
    items = []
    receipt = json.loads(files['fox-package/lov-return-receipt.json'])
    for op in receipt['generated_operations']:
        if op.get('kind') != 'source_optional_row_lookup' or 'parent_copy' not in op:
            continue
        workspace = expected.pop(op['page_file'])
        plan = op['parent_copy']
        reasons = [g['reason'] for g in plan['gaps']]
        if (plan['source_binding'] != metadata['source_binding'] or plan['source_block_id'] != workspace['source_block_id']
                or reasons != workspace.get('parent_copy_gaps', [])):
            raise ValueError('Parent-copy summary does not match the saved rate workspace.')
        child = label(op['contract']['source_block_name'])
        binding = plan['binding']
        if binding:
            pairs = binding['join_pairs']
            if (workspace.get('parent_launcher_page') != op['native_target']['parent_launcher']['page_file']
                    or workspace.get('copied_parent_keys') != [
                        {'parent_item_id': f['parent_item_id'], 'child_item_id': f['child_item_id'],
                         'column': f['column']} for f in pairs]):
                raise ValueError('Parent-copy fields do not match their saved source evidence.')
            note = 'Creating a draft from the selected parent copies these values once. Save and Reopen retain them in synthetic storage.'
            if 'RATE_PARENT_SOURCE_LENGTH_SEMANTICS_ABSENT_CONSERVATIVE_BYTE_AND_CHAR_LIMIT' in reasons:
                note += ' A source length has no declared unit. The copy must fit both its byte and character limits.'
            items.append({'child': child, 'parent': label(binding['parent_name']), 'linked': True,
                          'fields': [{'parent': label(f['parent_name']), 'child': label(f['child_name'])} for f in pairs],
                          'note': note})
        elif reasons:
            items.append({'child': child, 'parent': 'Unresolved parent', 'linked': False, 'fields': [],
                          'note': notes.get(reasons[0], 'The declared copy still needs verified source fields, edit rules and a matching parent selection.')})
    if expected:
        raise ValueError('Parent-copy evidence is missing for a saved workspace.')
    return {'items': items[:100], 'limited': len(items) > 100}


def _rate_number_summary(metadata, files):
    """Read field notes from the retained package after byte verification."""
    expected = {w['page_file']: w for w in metadata.get('saved_lookup_workspaces', [])
                if 'stored_number_fields' in w}
    if not expected:
        return None
    receipt = json.loads(files['fox-package/lov-return-receipt.json'])
    items = []
    pending = {
        'STATIC_EDIT_DISABLED': 'The source restricts edits to this field.',
        'DERIVED_NUMBER_UNIMPLEMENTED': 'The source calculates this value. Its calculation still needs a binding.',
        'SOURCE_DEFAULT_UNIMPLEMENTED': 'The default value or synchronized source item still needs a binding.',
        'LIST_NUMBER_UNIMPLEMENTED': 'The numeric list selection still needs a binding.',
        'ITEM_EVENT_UNIMPLEMENTED': 'This item has an event that still needs a binding.',
        'SOURCE_REFERENCE_UNIMPLEMENTED': 'Other source code refers to this field. Check the event before editing it.',
        'DYNAMIC_REFERENCE_UNPROVEN': 'A dynamic source reference may affect this field.',
        'FIELD_CAPACITY': 'This editor reached its limit for numeric fields.',
    }
    for op in receipt['generated_operations']:
        if op.get('kind') != 'source_optional_row_lookup' or 'stored_numbers' not in op:
            continue
        plan = op['stored_numbers']
        workspace = expected.pop(op['page_file'])
        fields = plan['fields']
        if (plan['source_binding'] != metadata['source_binding']
                or plan['source_block_id'] != workspace['source_block_id']
                or workspace['stored_number_fields'] != [
                    {'id': f['source_item_id'], 'name': f['source_name'], 'column': f['column']} for f in fields]
                or workspace['stored_number_gaps'] != plan['gaps']):
            raise ValueError('Saved numeric field evidence differs from its workspace.')
        block = op['contract']['source_block_name']
        for f in fields:
            note = 'Save and Reopen retain this number using its source picture ' + f['picture'] + '.'
            if f.get('omitted_legacy_date_callbacks'):
                note += ' The original date-picker callback remains unverified and does not run in this editor.'
            if f.get('omitted_source_identifier_references'):
                note += ' Other source code uses this column name. That code still needs its own mapping.'
            items.append({'block': block, 'item': f['source_name'], 'label': f['label'], 'stored': True, 'note': note})
        for gap in plan['gaps']:
            code = gap['reason'].removeprefix('RATE_NUMBERS_')
            note = pending.get(code, 'The source column, decimal format or edit policy still needs verification.')
            source_name = gap['source_name'] or gap['source_item_id']
            items.append({'block': block, 'item': source_name, 'label': source_name,
                          'stored': False, 'note': note})
    if expected:
        raise ValueError('Saved numeric field receipt is missing.')
    # Long source labels are display text; retain complete source identity in the package.
    for row in items[:100]:
        for key in ('block', 'item', 'label'):
            row[key] = re.sub(r'[\x00-\x1f\x7f-\x9f]', ' ', row[key]).strip()[:160] or 'Unnamed source field'
    return {'items': items[:100], 'limited': len(items) > 100} if items else None


def _lookup_fields(metadata, ledger):
    summary = metadata.get('lookup_summary')
    if summary is None:
        return None
    if (type(summary) is not dict or set(summary) != {'generated_lookup_handlers','original_reads_enabled'}
            or type(summary['generated_lookup_handlers']) is not int or summary['generated_lookup_handlers'] < 0
            or summary['original_reads_enabled'] is not False):
        raise ValueError('Saved lookup summary is invalid.')
    rows = ledger.get('source_lookups')
    units = {r['source_unit_id']: r for r in ledger['code_units']}
    if (type(rows) is not list or len(rows) != summary['generated_lookup_handlers']
            or len({r['source_unit_id'] for r in rows}) != len(rows)):
        raise ValueError('Saved lookup counts differ from their evidence.')
    for row in rows:
        unit = units.get(row['source_unit_id'])
        if (unit is None or unit['status'] != 'generated_wired_adapted'
                or unit.get('target') != row or unit.get('rule_id') != 'fox.lookup.source-read-event'
                or row.get('native_event_wired') is not True
                or row.get('generation_status') != 'generated_wired_adapted'
                or any(row.get(k) is not False for k in ('event_activated','original_interface_enabled',
                    'source_query_executed','customer_table_writes','oracle_compiled','runtime_verified','business_accepted'))):
            raise ValueError('Saved source lookup evidence is invalid.')
    return summary


def _buffer_fields(metadata, ledger):
    summary = metadata.get('buffer_summary')
    if summary is None:
        return None
    if (type(summary) is not dict or set(summary) != {'record_validation_flows'}
            or type(summary['record_validation_flows']) is not int or summary['record_validation_flows'] < 0):
        raise ValueError('Saved draft-flow summary is invalid.')
    rows = ledger.get('buffer_flows')
    units = {r['source_unit_id']: r for r in ledger['code_units']}
    if (type(rows) is not list or len(rows) != summary['record_validation_flows']
            or len({r['source_unit_id'] for r in rows}) != len(rows)):
        raise ValueError('Saved draft counts differ from their evidence.')
    for row in rows:
        unit = units.get(row['source_unit_id'])
        if (unit is None or unit['status'] != 'generated_wired_adapted'
                or unit.get('target') != row or unit.get('rule_id') != 'fox.buffer.duplicate-record-validation'
                or row.get('native_event_wired') is not True
                or row.get('generation_status') != 'generated_wired_adapted'
                or any(row.get(k) is not False for k in ('event_activated','customer_table_writes','oracle_compiled','runtime_verified','business_accepted'))):
            raise ValueError('Saved draft event evidence is invalid.')
    return summary


def _synthetic_save_fields(metadata, ledger):
    summary = metadata.get('synthetic_save_summary')
    if summary is None:
        return None
    events = ledger['synthetic_write_events']
    units = {row['source_unit_id']: row for row in ledger['code_units']}
    written_units = {uid for uid, row in units.items() if row['rule_id'] == 'fox.assignment.synthetic-record-save'}
    if (type(events) is not list or {op['source_unit_id'] for op in events} != written_units
            or len(events) != len(written_units)):
        raise ValueError('Invalid synthetic write event list.')
    buffers = {op['operation_id']: op for op in ledger['buffer_flows']}
    phases = {}
    for event in events:
        unit = units.get(event['source_unit_id'])
        buffer = buffers.get(event['buffer_operation_id'])
        if (unit is None or unit['target'] != event or unit['rule_id'] != 'fox.assignment.synthetic-record-save'
                or buffer is None or event['page_id'] != buffer['page_id'] or event['page_file'] != buffer['page_file']
                or event.get('native_event_wired') is not True or event['operation_id'] != unit['operation_id']
                or unit['status'] != 'generated_wired_adapted' or event['source_event'] not in {'PRE-INSERT','PRE-UPDATE'}
                or event['source_unit_sha256'] != unit['source_unit_sha256'] or event.get('synthetic_table_writes') is not True
                or any(event.get(k) is not False for k in ('customer_table_writes', 'oracle_compiled', 'runtime_verified', 'business_accepted'))):
            raise ValueError('Synthetic write event does not match the source ledger.')
        phases.setdefault(event['page_file'], []).append(event['source_event'])
    if any(sorted(values) != ['PRE-INSERT','PRE-UPDATE'] for values in phases.values()):
        raise ValueError('Synthetic save screen is missing its paired write events.')
    expected = {'screens': len(phases), 'before_write_events': len(events)}
    if type(summary) is not dict or any(type(v) is not int for v in summary.values()) or summary != expected:
        raise ValueError('Synthetic save summary differs from the generated events.')
    return summary


def _item_validation_fields(metadata, ledger):
    summary = metadata.get('item_validation_summary')
    if summary is None:
        return None
    units = {u['source_unit_id']:u for u in ledger['code_units']}
    full = ledger['item_validations']
    partial = ledger['partial_item_validations']
    reviews = ledger['item_validation_review']
    review_by_id = {r['source_unit_id']:r for r in reviews}
    full_ids = {r['source_unit_id'] for r in full}
    partial_ids = {r['source_unit_id'] for r in partial}
    if (len(review_by_id) != len(reviews) or len(full_ids) != len(full) or len(partial_ids) != len(partial)
            or full_ids & set(review_by_id) or not partial_ids <= set(review_by_id)):
        raise ValueError('Item-validation source units overlap or are missing.')
    buffers = {r['operation_id']:r for r in ledger['buffer_flows']}
    for op in [*full, *partial]:
        uid = op['source_unit_id']
        unit = units[uid]
        target = buffers.get(op['contract']['buffer_operation_id'])
        if (target is None or op['page_file'] != target['page_file'] or op['page_id'] != target['page_id']
                or op['source_unit_sha256'] != unit['source_unit_sha256']
                or op['source_event'] != 'WHEN-VALIDATE-ITEM' or not op['native_event_wired']
                or any(op.get(k) is not False for k in ('event_activated','oracle_compiled','runtime_verified','business_accepted'))):
            raise ValueError('Item validation differs from its source event or editor.')
        if uid in full_ids and (unit['target'] != op or unit['status'] != 'generated_wired_adapted'
                or unit['rule_id'] != 'fox.validation.draft-item-lookup'):
            raise ValueError('A complete item validation differs from its saved coverage.')
    for uid, review in review_by_id.items():
        unit = units[uid]
        if (unit['target'] != review or unit['rule_id'] != 'fox.validation.item-lookup-review'
                or unit.get('encoding_status') != 'generated_unwired' or unit['status'] == 'generated_wired_adapted'):
            raise ValueError('An incomplete item rule was incorrectly promoted.')
    expected = {'wired':len(full),'partial':len(partial),'encoded_only':len(reviews)-len(partial)}
    if type(summary) is not dict or any(type(v) is not int for v in summary.values()) or summary != expected:
        raise ValueError('Invalid item-validation summary.')
    return summary


def _policy_fields(metadata, ledger):
    summary = metadata.get('policy_summary')
    if summary is None:
        return None  # Historical packages retain their original capabilities.
    if (type(summary) is not dict or set(summary) != {'rules_generated_unwired'}
            or type(summary['rules_generated_unwired']) is not int or summary['rules_generated_unwired'] < 0):
        raise ValueError('Saved policy summary is invalid.')
    rows = ledger.get('policy_review')
    units = {r['source_unit_id']: r for r in ledger['code_units']}
    guards = ledger.get('draft_policy_guards', [])
    if type(guards) is not list:
        raise ValueError('Invalid draft policy evidence.')
    guarded_units = set()
    guarded_buffers = set()
    buffers = {b['operation_id']: b for b in ledger.get('buffer_flows', [])}
    for guard in guards:
        unit = units.get(guard['source_unit_id'])
        buffer = buffers.get(guard['buffer_operation_id'])
        if (unit is None or unit['source_unit_sha256'] != guard['source_unit_sha256']
                or unit.get('encoding_status') != 'generated_unwired'
                or unit.get('rule_id') != 'fox.policy.parent-draft-guard'
                or buffer is None or guard['buffer_operation_id'] in guarded_buffers
                or guard['page_file'] != buffer['page_file'] or guard['page_id'] != buffer['page_id']
                or guard['status'] != 'adapted' or not guard['enforced_effects']
                or guard['generation_status'] != 'generated_wired_adapted_partial'
                or any(guard.get(key) is not False for key in ('customer_table_writes', 'oracle_compiled', 'runtime_verified', 'business_accepted'))):
            raise ValueError('A partial draft policy differs from its source.')
        guarded_units.add(guard['source_unit_id'])
        guarded_buffers.add(guard['buffer_operation_id'])
        for helper in guard['supporting_units']:
            target = units.get(helper['source_unit_id'])
            if target is None or target['source_unit_sha256'] != helper['source_unit_sha256']:
                raise ValueError('A draft policy helper differs from its source.')
            if target.get('encoding_status') == 'generated_unwired':
                guarded_units.add(helper['source_unit_id'])
    if (type(rows) is not list or len(rows) != summary['rules_generated_unwired']
            or len({r['source_unit_id'] for r in rows}) != len(rows)):
        raise ValueError('Saved policy counts differ from their evidence.')
    for row in rows:
        unit = units.get(row['source_unit_id'])
        if (unit is None or unit['status'] == 'generated_wired_adapted'
                or unit.get('encoding_status') != 'generated_unwired'
                or unit.get('rule_id') != ('fox.policy.parent-draft-guard' if row['source_unit_id'] in guarded_units
                                           else 'fox.policy.finite-review')
                or unit.get('target') != row
                or row.get('generation_status') != 'generated_unwired'
                or any(row.get(k) is not False for k in ('event_activated', 'oracle_compiled', 'runtime_verified', 'business_accepted'))):
            raise ValueError('An unwired policy was incorrectly promoted or changed.')
    return summary


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
        if (set(row) not in (fields, fields | {'requirements'})
                or ('requirements' in row and not valid_gap_requirements(row['requirements']))
                or row['category'] not in owners or row['owner'] != owners[row['category']]
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
        gaps_available=False, gap_summary=None, gaps=[], context_summary=None, policy_summary=None,
        buffer_summary=None, item_validation_summary=None, synthetic_save_summary=None,
        lookup_summary=None, interface_summary=None, discrepancies=None)
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
