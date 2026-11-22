"""Source-bound manual module navigation; no Forms lifecycle equivalence.

The caller supplies its trusted generated baseline/trace and owns packaging,
retained verification, SQLcl validation and runtime gates. Originals, source
facts, trace and pre-existing actions are never mutated. Whole-unit conversion
must stay partial: CALL_FORM return stacks, startup events, globals, parameters,
window/session semantics and transactions are not implemented by these links.
"""
from collections import Counter, defaultdict
import hashlib
import json
import re

from . import forms_facts
from .forms_behavior_plan import _source_objects, _tokens, decode_control_entities
from .forms_understanding_packet import _build
from forms2apex import native

SCOPE = 'fox-module-navigation-v1'
LIMITATIONS = [
    'Manual navigation within the same APEX application; not the original Forms call.',
    'No CALL_FORM return stack, OPEN_FORM window/session or NEW_FORM replacement behavior.',
    'No startup trigger invocation, parameter/global transfer, shared record state or transaction adaptation.',
    'Original event remains partly implemented; runtime and business acceptance are unverified.',
]
_IDENT = re.compile(r'[A-Za-z][A-Za-z0-9_$#]{0,127}\Z')
_CALL = re.compile(r'\b(?:CALL_FORM|OPEN_FORM)\s*\(', re.I)


def _need(value, code):
    if not value:
        raise ValueError('MODULE_NAV_' + code)


def _encoded(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False,
                      allow_nan=False).encode('utf-8')


def _sha(value):
    return hashlib.sha256(value).hexdigest()


def _literal_call(text):
    semantic, decoding = decode_control_entities(text)
    tokens = _tokens(semantic)
    if tokens and tokens[0] == ('word', 'BEGIN'):
        _need(tokens[-2:] == [('word', 'END'), ('symbol', ';')], 'COMPLETE_EVENT_REQUIRED')
        tokens = tokens[1:-2]
    _need(len(tokens) == 5 and tokens[0] in [('word', 'OPEN_FORM'), ('word', 'CALL_FORM')]
          and tokens[1] == ('symbol', '(') and tokens[2][0] == 'string'
          and tokens[3:] == [('symbol', ')'), ('symbol', ';')], 'SOLE_LITERAL_CALL_REQUIRED')
    _need(_IDENT.fullmatch(tokens[2][1]) is not None, 'STATIC_MODULE_IDENTIFIER_REQUIRED')
    return tokens[0][1], tokens[2][1], decoding


def _text(files, filename, page):
    _need(type(page) is int and 0 < page < 9999 and type(filename) is str
          and re.fullmatch(r'pages/p' + f'{page:05d}' + r'-[a-z0-9_\-]+\.apx', filename)
          and filename in files and type(files[filename]) is bytes, 'PAGE_BINDING')
    text = files[filename].decode('utf-8')
    _need(text.startswith(f'page {page} (\n') and text.endswith(')\n'), 'PAGE_SHAPE')
    return text


def _append(files, filename, fragment):
    text = files[filename].decode('utf-8')
    _need(text.endswith(')\n'), 'PAGE_SHAPE')
    files[filename] = (text[:-2] + fragment + ')\n').encode('utf-8')


def _region():
    return '''    region fox-module-actions (
        name: Related forms - manual navigation
        type: staticContent
        source {
            htmlCode: <p>These links open generated module pages. Original Forms startup, return, parameter, shared-state and transaction behavior is not implemented. Unsaved input is not transferred.</p>
        }
        layout {
            sequence: 9900
            slot: body
        }
        appearance {
            template: @/standard
            templateOptions: #DEFAULT#
        }
    )
'''


def _button(slug, label, page, sequence):
    return f'''    button {slug} (
        buttonName: FOX_MODULE_{slug.replace('-', '_').upper()}
        label: {native._label(label)}
        layout {{
            sequence: {sequence}
            region: @fox-module-actions
            slot: regionBody
        }}
        appearance {{
            buttonTemplate: @/text
        }}
        behavior {{
            action: redirectThisApp
            target: {{
                page: {page}
            }}
        }}
    )
'''


def _landing(page, alias, label):
    return f'''page {page} (
    name: {native._label(label)}
    alias: {alias}
    title: {native._label(label)}
    appearance {{
        pageTemplate: @/standard
        templateOptions: #DEFAULT#
    }}
    security {{
        authentication: required
        pageAccessProtection: argumentsMustHaveChecksum
    }}
{_region()})
'''.encode('utf-8')


def _qualify_labels(files, blocks, modules):
    """Change only known display fields; all existing targets/actions survive."""
    counts = Counter(b['name'].upper() for b in blocks)
    labels, changed = {}, []
    module_names = Counter((m['name'] or '').upper() for m in modules.values())
    module_numbers = {mid: n for n, mid in enumerate(modules, 1)}
    proposed = {}
    for b in blocks:
        m = modules[b['source_module_id']]
        label = b['name']
        if counts[label.upper()] > 1:
            qualifier = m['name'] or ''
            try:
                native._label(qualifier)
            except ValueError:
                qualifier = ''
            if not qualifier or module_names[qualifier.upper()] > 1:
                qualifier = f"{qualifier or 'Form'} ({module_numbers[m['id']]})"
            label = f"{qualifier} / {label}"
        proposed[b['source_block_id']] = label
    duplicates = Counter(v.upper() for v in proposed.values())
    for b in blocks:
        bid = b['source_block_id']; label = proposed[bid]
        if duplicates[label.upper()] > 1:
            label += ' [' + bid[-8:] + ']'
        # Names come from fresh bounded Forms identifiers; JSON quoting prevents
        # metadata from becoming syntax. APEX substitutions remain forbidden.
        native._label(label)
        labels[bid] = label
        if label == b['name']:
            continue
        for filename, field in [('shared-components/lists.apx', 'label'),
                                ('shared-components/breadcrumbs.apx', 'name')]:
            _need(filename in files, 'NAVIGATION_MISSING')
            text = files[filename].decode('utf-8')
            pattern = re.compile(r'^    entry block-' + str(b['sequence']) + r' \(\n.*?^    \)', re.M | re.S)
            matches = list(pattern.finditer(text)); _need(len(matches) == 1, 'NAVIGATION_ANCHOR')
            match = matches[0]; entry = match.group()
            _need(re.findall(r'^\s+page: (\d+)$', entry, re.M) == [str(b['page_id'])], 'NAVIGATION_TARGET')
            old = f'        {field}: {native._label(b["name"])}\n'
            _need(entry.count(old) == 1, 'NAVIGATION_LABEL')
            files[filename] = (text[:match.start()] + entry.replace(old, f'        {field}: {native._label(label)}\n', 1)
                               + text[match.end():]).encode('utf-8')
        text = files[b['page_file']].decode('utf-8')
        for field in ('name', 'title'):
            old = f'    {field}: {native._label(b["name"])}\n'
            pattern = re.compile('^' + re.escape(old), re.M)
            _need(len(pattern.findall(text)) == 1, 'PAGE_LABEL')
            text = pattern.sub(lambda _: f'    {field}: {native._label(label)}\n', text, count=1)
        files[b['page_file']] = text.encode('utf-8')
        changed.append({'source_block_id': bid, 'source_module_id': b['source_module_id'],
                        'page_file': b['page_file'], 'label': label})
    return labels, changed


def apply_module_navigation(documents, packet, chunks, trace, files):
    """Return copied byte members and a source-bound partial-navigation receipt.

    Unique literal targets get an explicit generated module landing page, never
    a guessed first block/startup event. Gaps produce no executable destination.
    This adapter does not claim any complete source unit converted.
    """
    fresh, fresh_chunks = _build(documents)
    _need(packet.get('source_binding') == fresh['source_binding'] and
          packet.get('sources') == fresh['sources'] and chunks == fresh_chunks, 'SOURCE_CHANGED')
    _need(trace.get('source_binding') == fresh['source_binding'], 'TRACE_SOURCE')
    _need(type(files) is dict and all(type(n) is str and type(v) is bytes for n, v in files.items()), 'MEMBERS')
    _need(not any('fox_module_nav_' in n for n in files), 'ALREADY_ADAPTED')
    result = dict(files)
    objects, properties = _source_objects(documents, fresh)
    sources = {o['id']: entry['source'] for entry in fresh['sources'] for o in entry['facts']['objects']}
    modules = {k: objects[k] for k in sorted(objects, key=lambda k: (sources[k]['name'], k))
               if objects[k]['kind'] == 'FormModule'}
    by_name, rendered = defaultdict(list), defaultdict(list)
    for mid, m in modules.items():
        if m['name']:
            by_name[m['name'].upper()].append(mid)
    blocks = trace.get('blocks', [])
    _need(type(blocks) is list and len(blocks) <= 50, 'BLOCKS')
    seen, pages = set(), set()
    for b in blocks:
        bid = b['source_block_id']; source = objects.get(bid, {})
        _need(bid not in seen and source.get('kind') == 'Block' and
              source.get('module_id') == b.get('source_module_id') and
              b['source_module_id'] in modules and source.get('name') == b.get('name'), 'BLOCK_SOURCE')
        seen.add(bid)
        _need(b['page_id'] not in pages and type(b.get('sequence')) is int and b['sequence'] > 0, 'BLOCK_PAGE')
        pages.add(b['page_id'])
        _text(result, b['page_file'], b['page_id'])
        rendered[b['source_module_id']].append(b)
    labels, qualified = _qualify_labels(result, blocks, modules)
    texts = {c['code_unit_id']: c for c in fresh_chunks}
    occupied = {int(m[1]) for name in result if (m := re.fullmatch(r'pages/p(\d+)-[^/]+\.apx', name))}
    page = 7600
    landings, operations, gaps = {}, [], []
    units = [u for entry in fresh['sources'] for u in entry['facts']['code_units']
             if _CALL.search(forms_facts._mask_code(texts[u['id']]['text']))]
    for unit in units:
        owner = objects[unit['owner_id']]
        base = {'source_unit_id': unit['id'], 'source_unit_sha256': unit['sha256'],
                'source_module_id': owner['module_id'], 'source_owner_id': owner['id'],
                'source_file': dict(sources[owner['id']]), 'source_location': dict(unit['location'])}
        target, candidates = None, []
        try:
            kind, target, decoding = _literal_call(texts[unit['id']]['text'])
            candidates = by_name.get(target.upper(), [])
            _need(owner['kind'] == 'Trigger' and (owner['name'] or '').upper() == 'WHEN-BUTTON-PRESSED'
                  and unit['source_attribute'] == 'TriggerText', 'BUTTON_EVENT_REQUIRED')
            item = objects.get(owner['parent_id'], {})
            _need(item.get('kind') == 'Item' and properties[item['id']].get('ItemType', '').strip().upper() == 'PUSH BUTTON'
                  and item['block_id'] == owner['block_id'], 'BUTTON_OWNER_REQUIRED')
            _need(sum(o['kind'] == 'Trigger' and o['parent_id'] == item['id'] and
                      (o['name'] or '').upper() == 'WHEN-BUTTON-PRESSED' for o in objects.values()) == 1,
                  'BUTTON_EVENT_AMBIGUOUS')
            owners = [b for b in blocks if b['source_block_id'] == owner['block_id']
                      and b['source_module_id'] == owner['module_id']]
            _need(len(owners) == 1, 'CALLER_BLOCK_NOT_RENDERED')
            caller = owners[0]
            _need(candidates, 'TARGET_SOURCE_ABSENT')
            _need(len(candidates) == 1, 'TARGET_SOURCE_AMBIGUOUS')
            mid = candidates[0]
            _need(rendered[mid], 'TARGET_HAS_NO_RENDERED_BLOCKS')
            _need(len(operations) < 100, 'OPERATION_CAPACITY')
            # Check all metadata and caller anchors before creating any output.
            label = 'Open ' + modules[mid]['name'] + ' (manual)'
            native._label(label)
            text = _text(result, caller['page_file'], caller['page_id'])
            slug = 'module-' + unit['id'][-16:]
            _need('button ' + slug + ' (' not in text, 'BUTTON_COLLISION')
            if mid not in landings:
                while page in occupied:
                    page += 1
                _need(page < 8000, 'PAGE_CAPACITY')
                alias = 'FOX_MODULE_NAV_' + _sha(mid.encode())[:16].upper()
                filename = f'pages/p{page:05d}-{alias.lower()}.apx'
                _need(filename not in result, 'PAGE_COLLISION')
                result[filename] = _landing(page, alias, modules[mid]['name'] + ' - generated pages')
                links = []
                for index, b in enumerate(rendered[mid], 1):
                    _append(result, filename, _button('block-' + b['source_block_id'][-16:],
                            labels[b['source_block_id']], b['page_id'], index * 10))
                    links.append({'source_block_id': b['source_block_id'], 'page_id': b['page_id'],
                                  'page_file': b['page_file'], 'label': labels[b['source_block_id']]})
                landings[mid] = {'source_module_id': mid, 'source_module_name': modules[mid]['name'],
                                 'source_file': dict(sources[mid]), 'page_id': page, 'page_file': filename,
                                 'entry_policy': 'explicit_generated_module_overview_not_forms_startup', 'blocks': links}
                occupied.add(page); page += 1
            if '    region fox-module-actions (\n' not in text:
                _append(result, caller['page_file'], _region())
            _append(result, caller['page_file'], _button(slug, label, landings[mid]['page_id'], 1000 + len(operations)))
            operations.append({**base, 'source_button_id': item['id'], 'source_button_name': item['name'],
                'source_block_id': owner['block_id'], 'call_kind': kind, 'literal_target': target,
                'target_module_id': mid, 'target_source_file': dict(sources[mid]),
                'caller_page_id': caller['page_id'], 'caller_page_file': caller['page_file'],
                'target_page_id': landings[mid]['page_id'], 'target_page_file': landings[mid]['page_file'],
                'button_alias': slug, 'decoding': decoding, 'status': 'manual_navigation_partial',
                'whole_unit_converted': False, 'limitations': list(LIMITATIONS)})
        except ValueError as exc:
            gaps.append({**base, 'literal_target': target, 'candidate_module_ids': list(candidates),
                         'reason': str(exc), 'whole_unit_converted': False})
    receipt = {'schema_version': 1, 'scope': SCOPE, 'source_binding': fresh['source_binding'],
        'modules': [{'source_module_id': mid, 'name': m['name'], 'source_file': dict(sources[mid]),
                     'rendered_block_ids': [b['source_block_id'] for b in rendered[mid]]} for mid, m in modules.items()],
        'module_pages': list(landings.values()), 'operations': operations, 'gaps': gaps,
        'qualified_labels': qualified, 'limitations': list(LIMITATIONS),
        'whole_units_converted': 0, 'runtime_verified': False, 'business_behavior_accepted': False,
        'changed_members': {n: {'before_sha256': _sha(files[n]) if n in files else None, 'sha256': _sha(raw)}
                            for n, raw in sorted(result.items()) if files.get(n) != raw}}
    return result, receipt
