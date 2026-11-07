"""Pure two-clause analysis contract and explicitly derived candidate assembly.

Callers reconstruct packet evidence from preserved originals, enforce processing
consent and bind retained raw request/response bytes separately. This module does
not invoke models, grant permission, attest provenance or perform independent
review. Passing structural gates is not proof of semantic correctness.
"""
from copy import deepcopy
import hashlib
import json
import re

from .forms_blueprint import source_fact_index
from .forms_design_review import _canonical, MAX_CANDIDATE_BYTES, MAX_REQUEST_BYTES
from .opaf import canonical_hash
from .prototype_focus_projection import repair_requirements, validate_repair, source_fact_gate

SCOPE = 'fox-forms-clause-analysis-v1'
ATTRIBUTES = ('WhereClause', 'OrderByClause')
MAX_RESPONSE_BYTES = 50_000


def _fail():
    raise ValueError('Invalid source-bound two-clause analysis.') from None


def _prose(value, maximum, *, reject_refusal=False):
    if (type(value) is not str or not value.strip() or len(value) > maximum
            or any(ord(char) < 32 and char not in '\n\r\t' for char in value)
            or '```' in value or len(re.findall(r'[^\W\d_]+', value, re.UNICODE)) < 2
            or re.match(r'^\s*[A-Za-z0-9_:.$]+\s*(?:=|<>|!=|<=|>=|<|>)', value)
            or re.match(r'^\s*(?:SELECT\s+.+?\s+FROM\s+\S+|INSERT\s+INTO\s+\S+|'
                        r'UPDATE\s+\S+\s+SET\s+\S+|DELETE\s+FROM\s+\S+|'
                        r'CREATE\s+(?:OR\s+REPLACE\s+)?(?:TABLE|VIEW|PROCEDURE|FUNCTION|PACKAGE|TRIGGER)\s+\S+|'
                        r'BEGIN\s+.+;|DECLARE\s+\S+\s+(?:VARCHAR2|NUMBER|BOOLEAN|DATE)\b)', value, re.I | re.S)
            or reject_refusal and re.match(r"^\s*(?:I (?:cannot|can't|am unable)|cannot (?:analy[sz]e|interpret)|unable to (?:analy[sz]e|interpret))\b", value, re.I)):
        _fail()


def _pairs(rows):
    result = {}
    for key, value in rows:
        if key in result:
            _fail()
        result[key] = value
    return result


def validate_response(response):
    """Validate parsed JSON or exact JSON text; reject duplicate JSON keys.

    Only lexical/prose structure is checked. A separate source-grounded reviewer
    must judge interpretation and specificity, including unresolved limitations.
    """
    try:
        if type(response) is str:
            if len(response.encode('utf-8')) > MAX_RESPONSE_BYTES:
                _fail()
            response = json.loads(response, object_pairs_hook=_pairs,
                                  parse_constant=lambda _: _fail())
        _canonical(response, MAX_RESPONSE_BYTES)
        if (type(response) is not dict or set(response) != {'schema_version', 'scope', 'analyses'}
                or type(response['schema_version']) is not int or response['schema_version'] != 1
                or response['scope'] != SCOPE or type(response['analyses']) is not list
                or len(response['analyses']) != 2):
            _fail()
        seen = set()
        for row in response['analyses']:
            if (type(row) is not dict or set(row) != {'source_attribute', 'intent', 'status', 'limitations'}
                    or type(row['source_attribute']) is not str or row['source_attribute'] not in ATTRIBUTES
                    or row['source_attribute'] in seen or type(row['status']) is not str
                    or row['status'] not in ('proposal', 'unresolved')
                    or type(row['limitations']) is not list or len(row['limitations']) > 4
                    or row['status'] == 'unresolved' and not row['limitations']):
                _fail()
            seen.add(row['source_attribute'])
            _prose(row['intent'], 512, reject_refusal=True)
            for limitation in row['limitations']:
                _prose(limitation, 1000)
        return deepcopy(response)
    except (ValueError, TypeError, KeyError, AttributeError, RecursionError, OverflowError, UnicodeError):
        _fail()


def build_request(packet, focus_request, raw_candidate):
    """Select only the two complete source clauses, without old invented values.

    Selection is not approval. Source packet authenticity and transfer permission
    remain caller duties; verify unit metadata and actual whole-body hashes here.
    """
    try:
        _canonical(focus_request, MAX_REQUEST_BYTES)
        _canonical(raw_candidate, MAX_CANDIDATE_BYTES)
        if canonical_hash({key: value for key, value in focus_request.items() if key != 'focus_binding'}) != focus_request['focus_binding']:
            _fail()
        objects, _, _ = source_fact_index(packet)
        requirements = repair_requirements(packet, focus_request, raw_candidate)
        units = requirements['required_behavior_units']
        if len(units) != 2 or {unit['source_attribute'] for unit in units} != set(ATTRIBUTES):
            _fail()
        for category, key in (('code_units', 'id'), ('chunks', 'code_unit_id'), ('owned_objects', 'id')):
            rows = focus_request[category]
            if len({row[key] for row in rows}) != len(rows):
                _fail()
        source_units = {unit['id']: (entry['source'], unit)
                        for entry in packet['sources'] for unit in entry['facts']['code_units']}
        request_units = {unit['id']: unit for unit in focus_request['code_units']}
        selected = {chunk['code_unit_id']: chunk for chunk in focus_request['chunks']}
        packet_chunks = {chunk['code_unit_id']: chunk for chunk in packet['chunks']}
        owners = {row['id']: row for row in focus_request['owned_objects']}
        clauses = []
        for attribute in ATTRIBUTES:
            required = next(unit for unit in units if unit['source_attribute'] == attribute)
            ref = required['unit_id']
            source, unit = source_units[ref]
            chunk = selected[ref]
            text = chunk['text']
            if type(text) is not str:
                _fail()
            body = text.encode('utf-8')
            digest = hashlib.sha256(body).hexdigest()
            if (not text.strip() or 'FOX_REDACTED_' in text or digest != unit['sha256']
                    or digest != chunk['sha256'] or len(body) != unit['bytes'] or len(body) != chunk['bytes']
                    or canonical_hash(unit) != canonical_hash(request_units[ref])
                    or canonical_hash({key: value for key, value in chunk.items() if key != 'text'})
                    != canonical_hash({key: value for key, value in packet_chunks[ref].items() if key != 'text'})
                    or canonical_hash(owners[unit['owner_id']]) != canonical_hash(objects[unit['owner_id']])
                    or chunk['source_sha256'] != source['sha256']):
                _fail()
            clauses.append({'source_attribute': attribute, 'text': text, 'unit': deepcopy(unit),
                            'owner': deepcopy(owners[unit['owner_id']]), 'source': deepcopy(source)})
        result = {'schema_version': 1, 'scope': SCOPE + '-request', 'clauses': clauses}
        _canonical(result, MAX_REQUEST_BYTES)
        return result
    except (ValueError, TypeError, KeyError, AttributeError, StopIteration, RecursionError, OverflowError, UnicodeError):
        _fail()


def _new_id(stem, used):
    ref, suffix = stem, 1
    while ref in used:
        ref = stem + '-' + str(suffix)
        suffix += 1
    used.add(ref)
    return ref


def assemble_candidate(packet, focus_request, raw_candidate, response):
    """Return NEW derived design plus exact change receipt; never raw model output."""
    request = build_request(packet, focus_request, raw_candidate)
    response = validate_response(response)
    requirements = repair_requirements(packet, focus_request, raw_candidate)
    candidate = deepcopy(raw_candidate)
    blueprint = candidate['blueprint']
    used = set()
    for category in ('screens', 'claims', 'relationships', 'actions', 'questions', 'assumptions'):
        ids = [row['id'] for row in blueprint[category]]
        if len(set(ids)) != len(ids):
            _fail()
        used.update(ids)
    analyses = {row['source_attribute']: row for row in response['analyses']}
    changes = []
    for clause in request['clauses']:
        attribute, unit = clause['source_attribute'], clause['unit']
        required = next(row for row in requirements['required_behavior_units'] if row['source_attribute'] == attribute)
        index = next(index for index, claim in enumerate(blueprint['claims']) if claim['id'] == required['defective_claim_id'])
        before = deepcopy(blueprint['claims'][index])
        analysis = analyses[attribute]
        if ' '.join(analysis['intent'].split()).casefold() in {
                ' '.join(clause['text'].split()).casefold(), ' '.join(str(before['value']).split()).casefold()}:
            _fail()
        after = {'id': before['id'], 'source_object_id': unit['owner_id'], 'kind': 'behavior.intent',
                 'value': analysis['intent'], 'status': analysis['status'], 'evidence_refs': [unit['id']],
                 'reason': 'Derived model interpretation of ' + attribute + '; not a source fact. Independent source-grounded review required.'}
        blueprint['claims'][index] = after
        stem = 'clause-v1-' + canonical_hash([unit['id'], unit['sha256']])[:24]
        action = {'id': _new_id(stem + '-action', used), 'claim_ids': [after['id']]}
        blueprint['actions'].append(action)
        questions = []
        for limitation in analysis['limitations']:
            question = {'id': _new_id(stem + '-question', used), 'source_object_id': unit['owner_id'], 'text': limitation}
            blueprint['questions'].append(question)
            questions.append(deepcopy(question))
        changes.append({'source_attribute': attribute, 'unit_id': unit['id'], 'unit_sha256': unit['sha256'],
                        'claim_index': index, 'before': before, 'after': deepcopy(after),
                        'analysis': deepcopy(analysis), 'added_action': deepcopy(action), 'added_questions': questions})
    repair_gate = validate_repair(packet, focus_request, raw_candidate, candidate, requirements)
    fact_gate = source_fact_gate(packet, focus_request, candidate)
    receipt = {'schema_version': 1, 'scope': SCOPE + '-derived-assembly',
               'assembler_version': 1,
               'source_binding': focus_request['source_binding'],
               'focus_request_sha256': canonical_hash(focus_request), 'analysis_request_sha256': canonical_hash(request),
               'analysis_response_sha256': canonical_hash(response), 'original_candidate_sha256': canonical_hash(raw_candidate),
               'derived_candidate_sha256': canonical_hash(candidate), 'changes': changes,
               'repair_check': repair_gate, 'source_fact_check': fact_gate,
               'raw_model_output': False, 'independent_review_required': True,
               'generation_ready': False, 'business_behavior_accepted': False}
    return candidate, receipt
