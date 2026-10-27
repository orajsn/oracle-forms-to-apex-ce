"""Deterministic source intake. Findings are evidence, not dependency completeness.

Recognized XML/code structure is classification evidence only: it does not prove
Oracle produced a file or that customer redaction is complete. The narrow
bind-driven DML exception below permits assessment, never model submission.
"""
from __future__ import annotations
import hashlib
import re
from pathlib import PurePosixPath
from defusedxml import ElementTree as ET

MAX_FILE_BYTES = 5 * 1024 * 1024
MAX_PROJECT_BYTES = 25 * 1024 * 1024
MAX_CONVERSION_BYTES = 300_000
MAX_CONVERSION_FILES = 50
ALLOWED = {'.xml', '.pld', '.sql', '.pks', '.pkb', '.txt'}
OBJECT_NAME = r'[A-Z][\w$#]*(?:\s*\.\s*[A-Z][\w$#]*)?'
CREATE_DEFINITION = re.compile(
    r'\bCREATE\s+(?:OR\s+REPLACE\s+)?(PACKAGE\s+BODY|PACKAGE|PROCEDURE|FUNCTION|TABLE|VIEW)\s+('
    + OBJECT_NAME + r')', re.I)
SECRETS = [
    r'-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----',
    r'(?i)\b(?:password|passwd|pwd|api_key|client_secret|auth_token)\b\s*(?::=|=|:)\s*[\"\']?[^\s\"\'<>;]{4,}',
    r'(?i)\bbearer\s+[\w.\-+/=]{16,}',
    r'(?i)\bconnect\s+\S+/\S+@',
    r'(?i)\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b',
]
UNSUPPORTED = {
    'HOST': ('Host command', 'Replace client executable behavior with a reviewed server-side process.'),
    'WEBUTIL': ('WebUtil', 'Review browser/server file handling; desktop behavior is not portable.'),
    'OLE2': ('OLE automation', 'Provide the expected document/output and design a web equivalent.'),
    'RUN_PRODUCT': ('Oracle Reports call', 'Supply readable report source and specify the required output.'),
    'TEXT_IO': ('File I/O', 'Specify the file contract and approved server-side storage.'),
    'EXECUTE IMMEDIATE': ('Dynamic SQL', 'Provide allowed runtime object names and representative statements.'),
}

_DML = re.compile(r'\b(?:INSERT|MERGE)\s+INTO\b|\bINSERT\s+(?:ALL|FIRST)\b', re.I)
_BIND = re.compile(r'(?<!:):[A-Z][A-Z0-9_$#]*(?:\.[A-Z][A-Z0-9_$#]*)?\b', re.I)
_DML_REJECTION = ('DML cannot be classified safely as record-free business source. '
                  'Data-loading scripts and ambiguous DML remain blocked; standalone PL/SQL classification is not supported. '
                  'This is not a finding that the file contains production data.')


def _has_dml(value):
    # Detect comments between keywords without dropping an original match in
    # comments/literals. Such a match still requires explicit classification.
    return bool(_DML.search(value) or _DML.search(re.sub(r'/\*.*?\*/|--[^\r\n]*', ' ', value, flags=re.S)))


def _bind_driven_dml(value):
    """Conservative lexical check, NOT a SQL/PLSQL parser or redaction proof.

    No quoted values/identifiers, numeric constants, dynamic SQL or unclosed/
    nested comments. Every DML statement needs its own non-comment bind.
    Legitimate constants and unhandled syntax deliberately remain ambiguous.
    """
    clean, position = [], 0
    while position < len(value):
        if value.startswith('--', position):
            end = value.find('\n', position + 2)
            if _has_dml(value[position + 2:len(value) if end < 0 else end]):
                return False
            position = len(value) if end < 0 else end
            clean.append(' ')
        elif value.startswith('/*', position):
            end = value.find('*/', position + 2)
            if end < 0 or '/*' in value[position + 2:end]:
                return False
            if _has_dml(value[position + 2:end]):
                return False
            clean.append(' '); position = end + 2
        elif value[position] in "'\"":
            return False
        else:
            clean.append(value[position]); position += 1
    clean = ''.join(clean)
    if re.search(r'(?<![\w$#])\d|\bEXECUTE\s+IMMEDIATE\b|\bDBMS_SQL\b', clean, re.I):
        return False
    matches = list(_DML.finditer(clean))
    if not matches:
        return False
    for index, match in enumerate(matches):
        if re.search(r'\b(?:ALL|FIRST)\b', match[0], re.I):
            return False
        end = clean.find(';', match.end())
        if index + 1 < len(matches) and matches[index + 1].start() < end:
            return False
        if end < 0 or not _BIND.search(clean[match.end():end]):
            return False
    return True


def _xml_values(root):
    for element in root.iter():
        for key, value in element.attrib.items():
            yield element, '@' + key, value
        if element.text:
            yield element, '#text', element.text
        if element.tail:
            yield element, '#tail', element.tail


def _dml_classification(text, root=None):
    """Return NONE, BUSINESS_REVIEW or BLOCKED with source-location labels."""
    if root is None:
        return ('BLOCKED' if _has_dml(text) else 'NONE'), []
    if any(_has_dml(hidden) for hidden in re.findall(r'<!--.*?-->|<\?.*?\?>',text,re.S)):
        return 'BLOCKED', []
    values = list(_xml_values(root))
    occurrences = [(element, slot, value) for element, slot, value in values if _has_dml(value)]
    if not occurrences:
        return ('BLOCKED' if _has_dml(text) else 'NONE'), []
    namespace = root.tag.rsplit('}', 1)[0] + '}' if root.tag.startswith('{') else ''
    tag = root.tag.rsplit('}', 1)[-1].lower()
    kinds = {'formmodule', 'menumodule', 'objectlibrary'}
    modules = []
    if namespace in ('', '{http://xmlns.oracle.com/Forms}'):
        modules = [root] if tag in kinds else [e for e in root if e.tag in {namespace+k for k in ('FormModule','MenuModule','ObjectLibrary')}] if tag == 'module' else []
    elif root.tag == '{urn:fox:forms-library:v1}Module' and root.get('Format') == 'FOX-JDAPI-LIBRARY-1' and root.get('DatabaseConnected') == 'false':
        modules = [e for e in root if e.tag == namespace+'LibraryModule']
    allowed = {}
    for module in modules:
        if not module.get('Name', '').strip():
            continue
        for index, element in enumerate(module.iter(), 1):
            local = element.tag.rsplit('}', 1)[-1]
            if element.tag != namespace+local or local not in {'Trigger', 'ProgramUnit'} or not element.get('Name', '').strip():
                continue
            attribute = 'TriggerText' if local == 'Trigger' else 'ProgramUnitText'
            allowed[(element, '@'+attribute)] = f'{local}[{index}].{attribute}'
            if not len(element):
                allowed[(element, '#text')] = f'{local}[{index}].text'
            if local == 'ProgramUnit':
                for child in element:
                    if child.tag == namespace+'ProgramUnitText' and not len(child):
                        allowed[(child, '#text')] = f'ProgramUnit[{index}].ProgramUnitText.text'
    locations = []
    for element, slot, value in occurrences:
        location = allowed.get((element, slot))
        if location is None or not _bind_driven_dml(value):
            return 'BLOCKED', []
        locations.append(location)
    return 'BUSINESS_REVIEW', sorted(set(locations))

def checked_source(name: str, raw: bytes) -> dict:
    if not name or len(name) > 180 or '/' in name or '\\' in name or ':' in name or '..' in name or any(ord(c)<32 for c in name):
        raise ValueError('Use a simple filename without directory paths.')
    if PurePosixPath(name).suffix.lower() not in ALLOWED:
        raise ValueError('Upload readable XML, PLD, SQL, PKS, PKB or TXT. Prepare FMB/MMB/OLB/PLL locally with the FOX extractor and installed Oracle tooling. Archives are not accepted.')
    if not raw or len(raw) > MAX_FILE_BYTES:
        raise ValueError('Each readable file must be nonempty and at most 5 MB.')
    try:
        text = raw.decode('utf-8-sig')
    except UnicodeDecodeError:
        raise ValueError('The source must be UTF-8 text, not a raw binary.') from None
    if '\0' in text:
        raise ValueError('Binary content is not accepted.')
    if any(re.search(p,text) for p in SECRETS):
        raise ValueError('Possible credential or personal identifier detected. Redact locally before uploading.')
    root = None
    if name.lower().endswith('.xml'):
        try:
            root = ET.fromstring(text, forbid_dtd=True, forbid_entities=True, forbid_external=True)
        except Exception:
            raise ValueError('Malformed or unsafe XML. Export a valid Forms XML document locally.') from None
        # XML entities/CDATA must not hide credentials from the existing scan.
        for _, slot, value in _xml_values(root):
            decoded = (slot[1:]+'="'+value+'"') if slot.startswith('@') else value
            if any(re.search(pattern, decoded) for pattern in SECRETS):
                raise ValueError('Possible credential or personal identifier detected. Redact locally before uploading.')
    if _dml_classification(text, root)[0] == 'BLOCKED':
        raise ValueError(_DML_REJECTION)
    return {'name':name,'sha256':hashlib.sha256(raw).hexdigest(),'bytes':len(raw),'text':text}

def inventory(files: list[dict]) -> dict:
    definitions: dict[str,set] = {}
    refs: list[dict] = []
    modules, issues, forms_source_files, dml_sources = [], [], [], []
    builtin = {'SYSTEM','GLOBAL','PARAMETER','DBMS_OUTPUT','SQL','TEXT_IO','WEB','OLE2','UTL_HTTP','STANDARD'}
    def define(name,kind):
        definitions.setdefault(re.sub(r'\s+', '', name).upper(),set()).add(kind)
    for f in files:
        text,name = f['text'],f['name']
        objects,blocks = {},[]
        code_parts = [(text,1)]
        root = None
        if name.lower().endswith('.xml'):
            root=ET.fromstring(text)
            root_tag = root.tag.rsplit('}', 1)[-1].lower()
            oracle_envelope = root_tag in {'module', 'formmodule', 'menumodule', 'objectlibrary'}
            recognized_forms = False
            code_parts=[]
            for e in root.iter():
                tag=e.tag.rsplit('}',1)[-1]
                objects[tag]=objects.get(tag,0)+1
                attrs={k.lower():v for k,v in e.attrib.items()}
                if tag.lower() in {'formmodule','menumodule','objectlibrary'} and attrs.get('name'):
                    define(attrs['name'],'module')
                    recognized_forms = recognized_forms or oracle_envelope
                if tag.lower()=='librarymodule' and attrs.get('name'):
                    define(attrs['name'],'library')
                    recognized_forms = recognized_forms or root.tag == '{urn:fox:forms-library:v1}Module'
                    if attrs.get('sourcefile','').lower().endswith('.pll'):
                        define(PurePosixPath(attrs['sourcefile']).stem,'library')
                if tag.lower()=='attachedlibrary' and attrs.get('name'):
                    refs.append({'source':name,'line':None,'target':attrs['name'].upper(),'kind':'library','evidence':'AttachedLibrary.Name'})
                if tag.lower()=='block':
                    blocks.append(attrs.get('name','Unnamed block'))
                    table=attrs.get('querydatasourcename')
                    if table and re.fullmatch(r'[\w$#.]+',table):
                        refs.append({'source':name,'line':None,'target':table.upper(),'kind':'table','evidence':'Block.QueryDataSourceName'})
                if tag.lower()=='programunit' and attrs.get('name'):
                    define(attrs['name'],'local_program')
                    # Oracle's library ProgramUnitType distinguishes package
                    # spec (3) and body (4), even when their names are identical.
                    if root.tag == '{urn:fox:forms-library:v1}Module':
                        kind = {'3':'package', '4':'package_body'}.get(attrs.get('programunittype'))
                        if kind: define(attrs['name'],kind)
                for key,value in attrs.items():
                    if key in {'triggertext','programunittext','plsqlcode','code','querytext'}:
                        code_parts.append((value,None))
                if e.text and e.text.strip(): code_parts.append((e.text,None))
            if recognized_forms:
                forms_source_files.append(name)
        else:
            for m in CREATE_DEFINITION.finditer(text):
                define(m[2],m[1].lower().replace(' ','_'))
            if name.lower().endswith('.pld'): define(PurePosixPath(name).stem,'library')
        dml_kind, dml_locations = _dml_classification(text, root)
        if dml_kind != 'NONE':
            dml_sources.append(name)
            issues.append({'source':name,'target':'BUSINESS_DML','kind':'remediation',
                'title':'Transaction source requires explicit mapping' if dml_kind=='BUSINESS_REVIEW' else 'DML classification requires review',
                'status':'UNCONVERTED_REVIEW_REQUIRED','action':'Review transaction semantics and supply a supported, approved mapping. Model submission and conversion remain blocked.',
                'classification':dml_kind,'evidence':dml_locations,
                'scope_note':'Recognized structure is classification evidence, not proof of Oracle provenance or complete customer redaction.'})
        for code,offset in code_parts:
            # Retain line numbers where the source provides them; XML attributes have no exact line guarantee.
            clean=re.sub(r'/\*.*?\*/|--[^\n]*',lambda m:'\n'*m[0].count('\n'),code,flags=re.S)
            for m in re.finditer(r'(?i)\b(CALL_FORM|OPEN_FORM|NEW_FORM)\s*\(\s*\x27([\w$#]+)\x27',clean):
                refs.append({'source':name,'line':None if offset is None else clean[:m.start()].count('\n')+offset,'target':m[2].upper(),'kind':'module','evidence':m[1]})
            without_strings=re.sub(r"'(?:''|[^'])*'", "''", clean)
            # A qualified CREATE TABLE name followed by '(' is a declaration,
            # not a package call. Blank only declaration headers so code in a
            # package body remains available to the candidate scanner.
            call_candidates = CREATE_DEFINITION.sub(lambda m: ' ' * len(m[0]), without_strings)
            for m in re.finditer(r'(?i)\b([A-Z][\w$#]*)\.([A-Z][\w$#]*)\s*\(',call_candidates):
                if m[1].upper() not in builtin:
                    refs.append({'source':name,'line':None if offset is None else clean[:m.start()].count('\n')+offset,'target':m[1].upper(),'kind':'package','evidence':m[1]+'.'+m[2]+'(...)'})
            for token,(title,action) in UNSUPPORTED.items():
                if re.search(r'\b'+re.escape(token)+r'\b',without_strings,re.I):
                    issues.append({'source':name,'target':token,'kind':'remediation','title':title,'status':'REVIEW','action':action})
        modules.append({'file':name,'sha256':f['sha256'],'bytes':f['bytes'],'objects':objects,'blocks':blocks})
    seen=set(); dependencies=[]
    for r in refs:
        key=(r['source'],r['target'],r['kind'])
        if key in seen: continue
        seen.add(key)
        present=definitions.get(r['target'],set())
        required={'package','package_body'} if r['kind']=='package' else {r['kind']}
        complete=required.issubset(present)
        r['status']='SOURCE_PRESENT' if complete else 'MISSING'
        r['action']='Review supplied source for behavioral coverage.' if complete else ('Upload both package specification and body.' if r['kind']=='package' else 'Upload the referenced '+r['kind']+' source.')
        dependencies.append(r)
    manifest='\n'.join(f['name']+':'+f['sha256'] for f in sorted(files,key=lambda f:f['name']))
    missing_count = sum(r['status']=='MISSING' for r in dependencies)
    # Match the UTF-8 payload sent by the OPAF adapter, not character count or
    # upload-history size. Source byte counts retain the original upload size.
    conversion_source_bytes = sum(len(f['text'].encode('utf-8')) for f in files)
    blockers = []
    if not forms_source_files:
        blockers.append({'code':'NO_FORMS_MODULE','message':'Add a readable Forms form, menu, object library or FOX JDAPI library XML. Supporting text and unrelated XML can be assessed but cannot start conversion alone.'})
    if conversion_source_bytes > MAX_CONVERSION_BYTES:
        blockers.append({'code':'CONVERSION_SIZE_LIMIT','message':f'This source version contains {conversion_source_bytes:,} UTF-8 bytes; the MVP conversion limit is {MAX_CONVERSION_BYTES:,} bytes (300 KB). Prepare a smaller coherent module with its dependencies.'})
    if len(files) > MAX_CONVERSION_FILES:
        blockers.append({'code':'CONVERSION_FILE_COUNT_LIMIT','message':f'This source version contains {len(files):,} readable files; conversion accepts at most {MAX_CONVERSION_FILES} files in total. Remove unrelated files from this version (history is retained), or split the inputs into a smaller coherent project with its dependencies.'})
    if missing_count:
        blockers.append({'code':'MISSING_DEPENDENCIES','message':'Resolve the missing source candidates in Dependencies before conversion.'})
    if dml_sources:
        blockers.append({'code':'BUSINESS_DML_REVIEW_REQUIRED','message':'DML source is assessment-only. Its transaction mapping is unsupported; no model submission or conversion is permitted.', 'sources':dml_sources})
    return {'files':modules,'dependencies':dependencies,'issues':issues,'missing_count':missing_count,'source_hash':hashlib.sha256(manifest.encode()).hexdigest(),
            'source_bytes':sum(f['bytes'] for f in files),'conversion_source_bytes':conversion_source_bytes,'max_conversion_bytes':MAX_CONVERSION_BYTES,'max_conversion_files':MAX_CONVERSION_FILES,
            'forms_source_files':forms_source_files,'conversion_eligible':not blockers,'conversion_blockers':blockers,
            'scope_note':'Static candidate dependencies only. Runtime references and dynamic SQL require review. Source presence does not establish behavioral equivalence.'}
