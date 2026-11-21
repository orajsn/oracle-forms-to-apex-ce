"""Keep supporting declarations as inert evidence alongside a Forms XML conversion."""
import hashlib
import json
from pathlib import PurePosixPath

from .intake import MAX_CONVERSION_FILES, MAX_PROJECT_BYTES, checked_source, inventory

MEMBER = 'fox-package/supporting-inputs.json'
PREFIX = 'fox-package/supporting-inputs/'
TYPES = {'.sql':'SQL source', '.pks':'Package specification', '.pkb':'Package body', '.pld':'Forms library source'}


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def split_inputs(documents):
    if not isinstance(documents, list) or not 0 < len(documents) <= MAX_CONVERSION_FILES:
        raise ValueError('Choose a bounded set of Forms XML and readable supporting sources.')
    xml, support, names = [], [], set()
    total = 0
    for doc in documents:
        if not isinstance(doc, tuple) or len(doc) != 2:
            raise ValueError('Each source needs a filename and its original bytes.')
        name, raw = doc
        if not isinstance(name,str) or not isinstance(raw,bytes):
            raise ValueError('Each source needs its original name and bytes.')
        if name.casefold() in names:
            raise ValueError('Duplicate source filenames are not accepted.')
        names.add(name.casefold())
        suffix = PurePosixPath(name).suffix.lower()
        if suffix == '.xml':
            xml.append(doc)
        elif suffix in TYPES:
            # Apply the standard readable-source intake policy to attachments,
            # including the existing credential, binary and ambiguous DML checks.
            support.append((checked_source(name, raw),raw))
        else:
            raise ValueError('Select Forms XML with SQL, PKS, PKB or PLD supporting sources.')
        total += len(raw)
    if not xml or total > MAX_PROJECT_BYTES:
        raise ValueError('The complete selection must include Forms XML within the project size limit.')
    return xml, sorted(support,key=lambda pair:pair[0]['name'])


def _status(dep):
    if dep['status'] == 'MISSING':
        return 'source_missing'
    if dep.get('routine_check') == 'NOT_CONFIRMED':
        return 'routine_unconfirmed'
    return 'declaration_found'


def _xml_references(rows, xml_names):
    return {(d['kind'],d['target'],d.get('routine') or '',d['source']):d
            for d in inventory(rows)['dependencies'] if d['source'] in xml_names}


def attach(files, metadata, xml, supporting):
    if not supporting:
        return None
    xml_rows = [dict(name=n,bytes=len(v),sha256=digest(v),text=v.decode('utf-8-sig')) for n,v in xml]
    all_rows = xml_rows + [r for r,_ in supporting]
    names = {r['name'] for r in xml_rows}
    before = _xml_references(xml_rows,names)
    after = _xml_references(all_rows,names)
    declarations = []
    for key, new in sorted(after.items()):
        old = before.get(key)
        if old is None:
            continue
        prev, curr = _status(old), _status(new)
        old_parts, new_parts = old.get('missing_parts',[]), new.get('missing_parts',[])
        if (prev,old_parts) != (curr,new_parts):
            declarations.append(dict(kind=key[0],target=key[1],routine=key[2],source=key[3],
                                     before=prev,after=curr,previous_missing_parts=old_parts,missing_parts=new_parts))
    entries = []
    for i,(row,raw) in enumerate(supporting,1):
        path = PREFIX + f'{i:03d}.txt'
        files[path] = raw
        entries.append(dict(name=row['name'],sha256=row['sha256'],bytes=row['bytes'],member=path,
                            role=TYPES[PurePosixPath(row['name']).suffix.lower()]))
    version = '\n'.join(r['name']+':'+r['sha256'] for r in sorted(all_rows,key=lambda x:x['name']))
    evidence = dict(schema_version=1,scope='fox-supporting-inputs-v1',xml_binding=metadata['source_binding'],
                    selected_source_hash=digest(version.encode()),files=entries,
                    declaration_changes=declarations,source_execution=False,original_interfaces_enabled=False)
    raw = json.dumps(evidence,ensure_ascii=False,sort_keys=True,separators=(',',':')).encode()
    files[MEMBER] = raw
    metadata['supporting_inputs'] = dict(member=MEMBER,sha256=digest(raw),count=len(entries),
                                         selected_source_hash=evidence['selected_source_hash'])
    return evidence


def retained(files, metadata, original):
    """Verify authenticated historical bytes and source partition without rerunning the parser."""
    bound = metadata.get('supporting_inputs')
    if bound is None:
        if MEMBER in files or any(n.startswith(PREFIX) for n in files):
            raise ValueError('Unbound supporting evidence in the saved package.')
        return None
    raw = files[MEMBER]
    evidence = json.loads(raw)
    expect = sorted((n,v) for n,v in original.items() if not n.lower().endswith('.xml'))
    version = digest('\n'.join(n+':'+digest(v) for n,v in sorted(original.items())).encode())
    if (not expect or type(bound.get('count')) is not int
            or bound != dict(member=MEMBER,sha256=digest(raw),count=len(expect),selected_source_hash=version)
            or type(evidence['schema_version']) is not int or evidence['schema_version'] != 1
            or evidence['scope'] != 'fox-supporting-inputs-v1'
            or evidence['xml_binding'] != metadata['source_binding'] or evidence['selected_source_hash'] != version
            or evidence['source_execution'] is not False or evidence['original_interfaces_enabled'] is not False
            or type(evidence['files']) is not list or len(evidence['files']) != len(expect)):
        raise ValueError('Supporting evidence differs from the saved selection.')
    paths = set()
    for i,((name,source),entry) in enumerate(zip(expect,evidence['files'],strict=True),1):
        path = PREFIX + f'{i:03d}.txt'
        if (type(entry['bytes']) is not int
                or entry != dict(name=name,sha256=digest(source),bytes=len(source),member=path,role=TYPES[PurePosixPath(name).suffix.lower()])
                or files[path] != source):
            raise ValueError('Supporting file differs from the saved source.')
        paths.add(path)
    if paths != {p for p in files if p.startswith(PREFIX)}:
        raise ValueError('Unexpected supporting evidence file.')
    return evidence
