"""Initialize a module session from a bounded source lookup on first entry."""
from collections import Counter
import hashlib
import json

from .forms_behavior_plan import _Parser, _tokens, decode_control_entities, UnsupportedBehavior
from forms2apex.native_record_groups import _app_item, _identifier


def _session_item(module, ref):
    raw = json.dumps([module, ref], ensure_ascii=False, separators=(',', ':')).encode()
    return 'FOX_RG_G_' + hashlib.sha256(raw).hexdigest()[:20].upper()


def parse_default(raw):
    semantic, receipt = decode_control_entities(raw)
    p = _Parser(_tokens(semantic))
    for token in ('BEGIN', 'SELECT', 'NVL', '('):
        p.take(token)
    value = _identifier(p.take(kind='word'))
    p.take(',')
    fallback = p.take(kind='number')
    if len(fallback) > 18:
        raise UnsupportedBehavior('default_value_capacity')
    for token in (')', 'INTO'):
        p.take(token)
    output = p.reference()
    p.take('FROM')
    table = [_identifier(p.take(kind='word'))]
    if p.peek('.'):
        p.take('.')
        table.append(_identifier(p.take(kind='word')))
    p.take('WHERE')
    key = _identifier(p.take(kind='word'))
    p.take('=')
    source = p.reference()
    for token in (';', 'EXCEPTION', 'WHEN', 'OTHERS', 'THEN', 'NULL', ';', 'END', ';'):
        p.take(token)
    p.end()
    if (len(source) != 2 or source[0] != 'GLOBAL' or len(output) != 2 or output[0] != 'GLOBAL'
            or source == output):
        raise UnsupportedBehavior('independent_session_bindings_required')
    return value, fallback, '.'.join(table), key, source, output, receipt


def apply_session_defaults(packet, chunks, trace, members):
    if trace['source_binding'] != packet['source_binding']:
        raise ValueError('Session default source binding changed.')
    files = dict(members)
    text = {c['code_unit_id']: c for c in chunks}
    generated = []
    for entry in packet['sources']:
        facts = entry['facts']
        objects = {o['id']: o for o in facts['objects']}
        candidates = [u for u in facts['code_units'] if u['source_attribute'] == 'TriggerText'
                      and objects[u['owner_id']]['kind'] == 'Trigger'
                      and (objects[u['owner_id']]['name'] or '').upper() == 'WHEN-NEW-FORM-INSTANCE'
                      and objects[u['owner_id']]['parent_id'] == objects[u['owner_id']]['module_id']]
        count = Counter(objects[u['owner_id']]['module_id'] for u in candidates)
        for unit in candidates:
            module = objects[unit['owner_id']]['module_id']
            if count[module] != 1:
                continue
            chunk = text[unit['id']]
            if hashlib.sha256(chunk['text'].encode()).hexdigest() != unit['sha256']:
                raise ValueError('Session default body differs from its source.')
            try:
                column, fallback, table, key, source, output, receipt = parse_default(chunk['text'])
            except ValueError:
                continue
            pages = sorted({b['page_file'] for b in trace['blocks'] if b.get('source_module_id') == module})
            if not pages:
                continue
            suffix = hashlib.sha256(unit['id'].encode()).hexdigest()[:20].upper()
            gate, done = 'FOX_INIT_'+suffix, 'FOX_SEEN_'+suffix
            src, dst = _session_item(module, source), _session_item(module, output)
            # Only assign after a successful single-row fetch. Both zero and
            # multiple rows retain the previous output under the original handler.
            process = f"""    process session-default-{suffix.lower()} (
        name: Initialize source session value
        type: executeCode
        source {{
            plsqlCode:
                ```plsql
                declare l_value varchar2(255 byte);
                begin
                  begin
                    select nvl({column},{fallback}) into l_value from {table} where {key}=:{src};
                    :{dst} := l_value;
                  exception when others then null;
                  end;
                  :{done} := 'Y';
                end;
                ```
        }}
        execution {{
            sequence: 1
            point: beforeHeader
        }}
        serverSideCondition {{
            type: expression
            language: plsql
            plsqlExpression: "v('{gate}')='Y' and v('{done}') is null"
        }}
    )
"""
            for page in pages:
                content = files[page].decode()
                if not content.endswith(')\n'):
                    raise ValueError('Unexpected module entry page.')
                files[page] = (content[:-2]+process+')\n').encode()
            path = 'shared-components/app-items.apx'
            items = files.get(path, b'').decode()
            for name in (gate, done, src, dst):
                if f'appItem {name} (' not in items:
                    items += '\n' + _app_item(name)
            files[path] = items.encode()
            generated.append({'source_unit_id': unit['id'], 'source_unit_sha256': unit['sha256'],
                'operation_id':'init-'+suffix.lower(), 'kind':'source_session_default',
                'source_module_id':module, 'source_table':table, 'readiness_item':gate,
                'source_global':source[-1], 'destination_global':output[-1], 'input_item':src,'output_item':dst,
                'entry_pages':pages, 'decode_receipt':receipt,'generation_status':'generated_wired_adapted',
                'source_query_executed':False,'original_interface_enabled':False,'customer_table_writes':False,
                'runtime_verified':False,'business_accepted':False})
    return files, {'scope':'fox-session-defaults-v1','source_binding':packet['source_binding'],
                   'generated_operations':generated,'runtime_verified':False,'business_accepted':False}
