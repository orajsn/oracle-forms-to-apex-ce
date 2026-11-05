"""Explicit, source-bound demo branches; never a relaxation of conversion gates.

The original selection stays immutable. A confirmed branch contains generated
readable XML for a proven table/column subset and the supplied exact DDL. Normal
assessment, independent review, SQLcl and import checks still apply to that new
source version. This is not a translation of omitted business code.
"""
from __future__ import annotations

from copy import deepcopy
import hashlib
import json
import re
from xml.etree.ElementTree import Element, SubElement, tostring

from .intake import checked_source, inventory
from .project_conversion import assess_project_conversion, ProjectConversionInputError

SCOPE = 'fox-partial-draft-v1'
_SCOPE_HEADER = '-- FOX PARTIAL DEMO SCOPE - omitted behavior is NOT implemented\n'
# Only known business/UI omissions are eligible. Ambiguous schema, XML, keys,
# column mapping, permissions and data-source semantics are never guessed.
_OMITTABLE = frozenset({
    'BUSINESS_CODE_REVIEW_REQUIRED', 'MISSING_DEPENDENCY',
    'ROUTINE_DECLARATION_UNCONFIRMED', 'UNSUPPORTED_FORMS_OBJECT',
    'CONTROL_ITEM_REVIEW_REQUIRED',
})
_PROJECT_OMITTABLE = frozenset({'UNCONVERTED_SUPPORTING_SOURCE', 'UNASSIGNED_SOURCE'})


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True,
                      allow_nan=False).encode('utf-8')


def _hash(value):
    return hashlib.sha256(canonical(value)).hexdigest()


def prepare_partial_draft(files, *, project_id, project_name, source_hash):
    """Compute a preview and exact derived inputs without writes or providers."""
    plan = assess_project_conversion(files, project_id=project_id,
                                    project_name=project_name, source_hash=source_hash)
    report = {'schema_version': 1, 'scope': SCOPE, 'mode': 'partial_demo',
        'project_id': project_id, 'parent_source_hash': source_hash,
        'parent_plan_sha256': plan['plan_sha256'], 'available': False,
        'included_forms': [], 'omitted_forms': [], 'omissions': [],
        'source_manifest': [{'name': row['name'], 'sha256': row['sha256']}
                            for row in sorted(files, key=lambda row: row['name'])],
        'warning': 'Partial demo only. Omitted actions are not implemented. '
                   'Synthetic empty tables only; no business equivalence or production readiness.',
        'next_action': 'Supply a supported table definition and unambiguous field mapping for at least one form.'}
    if (not plan['assessment_complete'] or not plan['forms']
            or any(item['code'] not in _PROJECT_OMITTABLE for item in plan['project_findings'])):
        report['next_action'] = 'Resolve malformed, conflicting or unassessed sources before creating a draft.'
        report['draft_sha256'] = _hash(report)
        return report, []
    sources = {row['name']: row for row in files}
    derived, definitions = [], {}
    for form in plan['forms']:
        unsupported = [item for item in form['findings'] if item['code'] not in _OMITTABLE]
        if not form['native_form'] or not form['ddl_sources'] or unsupported:
            report['omitted_forms'].append({'form_name': form['form_name'],
                'source_name': form['source_name'], 'module_id': form['module_id'],
                'reason': 'No unambiguous supported table/field subset. This form is not included.',
                'findings': deepcopy(form['findings'])})
            continue
        # Recompose only already-proven table fields. Never copy triggers,
        # program units, control items, library calls or executable attributes.
        module = Element('FormModule', Name=(form['form_name'][:65] + ' - Draft'))
        block = SubElement(module, 'Block', Name='DRAFT_RECORDS',
                           QueryDataSourceName=form['table_name'])
        for column in form['native_form']['columns']:
            SubElement(block, 'Item', Name=column['name'], Prompt=column['label'])
        name = 'draft_' + form['module_id'].removeprefix('form-') + '.xml'
        derived.append(checked_source(name, tostring(module, encoding='utf-8')))
        for ref in form['ddl_sources']:
            definitions[ref['name']] = sources[ref['name']]
        report['included_forms'].append({'form_name': form['form_name'],
            'draft_form_name': module.attrib['Name'], 'source_name': form['source_name'],
            'module_id': form['module_id'], 'draft_source_name': name,
            'components': ['Native report and search', 'Native record form (synthetic data)']})
        report['omissions'].extend({'form_name': form['form_name'], **deepcopy(item),
            'draft_disposition': 'Not implemented in the draft; no working substitute is invented.'}
            for item in form['findings'])
    report['omissions'].extend({'form_name': None, **deepcopy(item),
        'draft_disposition': 'Supporting source not translated; retained in the original source version.'}
        for item in plan['project_findings'])
    if derived:
        report['available'] = True
        report['next_action'] = 'Confirm the omissions to create a separate draft source version, then generate it normally.'
    report['draft_sha256'] = _hash(report)
    if not derived:
        return report, []
    # Keep the complete report inside the exported source evidence as comments.
    # Prefix EVERY line, including source-controlled strings, and recheck intake.
    header = _SCOPE_HEADER
    header += '\n'.join('-- ' + line for line in json.dumps(report, sort_keys=True,
        indent=2, ensure_ascii=True).splitlines()) + '\n'
    for index, (name, row) in enumerate(sorted(definitions.items())):
        text = (header if index == 0 else '-- FOX partial demo; see scope report in the first DDL file.\n') + row['text']
        derived.append(checked_source(name, text.encode('utf-8')))
    # A partial preview cannot become an execution bypass: the ordinary planner
    # must accept ALL derived inputs under the same supported contract.
    projected = assess_project_conversion(derived, project_id=project_id,
        project_name=project_name, source_hash=inventory(derived)['source_hash'])
    if not projected['can_generate']:
        raise ProjectConversionInputError('DRAFT_PROJECTION_BLOCKED',
            'A supported draft could not be prepared. Review the original findings; nothing was changed.')
    report['derived_source_hash'] = projected['source_hash']
    return report, derived


def saved_draft_scope(connection, project_id, source_hash):
    """Read only a server-recorded receipt, scoped to the exact saved version."""
    row = connection.execute('SELECT id FROM source_sets WHERE project=? AND source_hash=?',
                             (project_id, source_hash)).fetchone()
    if row is None:
        return None
    event = connection.execute('SELECT owner,object_id FROM events WHERE action=? ORDER BY id DESC LIMIT 1',
                               ('partial_draft:' + row['id'],)).fetchone()
    if event is None:
        # A missing receipt must not silently reclassify our immutable derived
        # sources as a complete conversion. This marker is only negative
        # evidence: it never grants branch, execution or proof authority.
        marked = connection.execute('''SELECT 1 FROM source_set_members m
            JOIN sources s ON s.id=m.source_id
            WHERE m.source_set_id=? AND substr(s.text,1,?)=? LIMIT 1''',
            (row['id'], len(_SCOPE_HEADER), _SCOPE_HEADER)).fetchone()
        if marked is None:
            return None
        raise ProjectConversionInputError('DRAFT_RECEIPT_UNAVAILABLE',
            'The partial-draft receipt cannot be verified. No complete-conversion claim is available.')
    try:
        value = json.loads(event['object_id'])
        owner = connection.execute('SELECT owner FROM projects WHERE id=?', (project_id,)).fetchone()
        if (owner is None or event['owner'] != owner['owner']
                or value['scope'] != SCOPE or value['project_id'] != project_id
                or value['derived_source_hash'] != source_hash
                or not re.fullmatch(r'[a-f0-9]{64}', value['draft_sha256'])
                or _hash({k: v for k, v in value.items() if k not in
                          {'draft_sha256', 'derived_source_hash', 'parent_source_set_id'}}) != value['draft_sha256']):
            raise ValueError()
        parent = connection.execute('SELECT source_hash FROM source_sets WHERE project=? AND id=?',
            (project_id, value['parent_source_set_id'])).fetchone()
        if parent is None or parent['source_hash'] != value['parent_source_hash']:
            raise ValueError()
        return value
    except (ValueError, KeyError, TypeError):
        raise ProjectConversionInputError('DRAFT_RECEIPT_UNAVAILABLE',
            'The partial-draft receipt cannot be verified. No complete-conversion claim is available.') from None
