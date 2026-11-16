"""Provider selection and pure historical evidence checks for focused design.

Legacy OPAF evidence keeps its original validator. Direct OCI evidence has no
workflow, room or conversation claims. Neither format grants source permission.
"""
from datetime import datetime
import re

from .opaf import OpafError, canonical_hash, validate_model_environment as validate_opaf

DIRECT = 'oci_genai'
PROMPTS = {'mapper': 'fox-focus-mapper-v1', 'reviewer': 'fox-focus-reviewer-v1'}
_SHA = re.compile(r'[a-f0-9]{64}\Z')
_ID = re.compile(r'[A-Za-z0-9_.:/+-]{1,256}\Z')


def is_direct(target):
    return isinstance(target, dict) and 'design_provider' in target


def direct_config(target):
    try:
        value = target['design_provider']
        if (set(value) != {'schema_version', 'provider', 'endpoint', 'authentication', 'roles'}
                or type(value['schema_version']) is not int or value['schema_version'] != 1
                or value['provider'] != DIRECT or value['authentication'] != 'instance_principal'
                or value['endpoint'] != 'https://inference.generativeai.' + target['oci']['region'] + '.oci.oraclecloud.com'
                or target['oci']['region'] != 'us-ashburn-1' or 'opaf' in target
                or set(value['roles']) != set(PROMPTS)):
            raise ValueError()
        for name, role in value['roles'].items():
            if (type(role) is not dict or set(role) != {'model', 'prompt_version'}
                    or not isinstance(role['model'], str) or not re.fullmatch(r'[A-Za-z0-9_.:-]{1,200}', role['model'])
                    or role['prompt_version'] != PROMPTS[name]):
                raise ValueError()
        return value
    except (KeyError, TypeError, ValueError, AttributeError):
        raise OpafError('Direct OCI design provider configuration is invalid.') from None


def roles(target):
    return direct_config(target)['roles'] if is_direct(target) else target['opaf']['roles']


def validate_roles(value):
    if type(value) is not dict or set(value) != set(PROMPTS) or any(type(r) is not dict for r in value.values()):
        raise OpafError('Separate mapper and reviewer roles are required.')
    if all('prompt_version' in r for r in value.values()):
        if any(value[n].get('prompt_version') != PROMPTS[n] for n in PROMPTS):
            raise OpafError('Separate versioned mapper and reviewer prompts are required.')
    elif (any(not isinstance(r.get('workflow_id'), str) for r in value.values())
            or value['mapper']['workflow_id'].upper() == value['reviewer']['workflow_id'].upper()):
        raise OpafError('Prototype requires separately configured mapper and reviewer workflows.')


def invocation_id(value):
    if value.get('provider') == DIRECT:
        return value['request_id']
    return value['room_id']


def valid_invocation_identity(value):
    if value.get('provider') == DIRECT:
        return isinstance(value.get('request_id'), str) and _ID.fullmatch(value['request_id']) is not None
    return isinstance(value.get('room_id'), str) and re.fullmatch(r'[A-Za-z0-9_.:-]{1,128}', value['room_id']) is not None


def validate_environment(value, target, name, identity, invocation):
    if not is_direct(target):
        return validate_opaf(value, target, name, identity, invocation)
    try:
        config = direct_config(target)
        from .genai_prompts import prompt_hash
        expected = {'schema_version': 2, 'scope': 'fox-design-model-environment-v2',
            'provider': DIRECT, 'trust_boundary': 'authenticated_fox_executor_not_vendor_attestation',
            'job_id': identity['job_id'], 'role': name,
            'source_manifest_sha256': identity['source_hash'],
            'target_profile_sha256': canonical_hash(target), 'observed_at_utc': value['observed_at_utc'],
            'endpoint': config['endpoint'], 'region': target['oci']['region'],
            'compartment_id': target['oci']['compartment_id'], 'authentication': 'instance_principal',
            'sdk_version': value['sdk_version'], 'model': config['roles'][name]['model'],
            'prompt_version': PROMPTS[name], 'prompt_sha256': prompt_hash(name)}
        fields = {'schema_version', 'provider', 'role', 'model', 'model_version', 'prompt_version', 'prompt_sha256',
                  'request_id', 'client_request_id', 'request_sha256', 'wire_request_sha256',
                  'response_sha256', 'started_at_utc', 'completed_at_utc'}
        if (canonical_hash(expected) != canonical_hash(value) or not value['sdk_version']
                or set(invocation) != fields or type(invocation['schema_version']) is not int
                or invocation['schema_version'] != 2 or invocation['provider'] != DIRECT
                or not isinstance(invocation['model_version'], str) or not 1 <= len(invocation['model_version']) <= 200
                or any(invocation[k] != expected[k] for k in ('role', 'model', 'prompt_version', 'prompt_sha256'))
                or any(not isinstance(invocation[k], str) or not _SHA.fullmatch(invocation[k])
                       for k in ('request_sha256', 'wire_request_sha256', 'response_sha256'))
                or any(not isinstance(invocation[k], str) or not _ID.fullmatch(invocation[k])
                       for k in ('request_id', 'client_request_id'))):
            raise ValueError()
        def utc(text):
            if not isinstance(text, str) or not re.fullmatch(r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?(?:Z|\+00:00)', text):
                raise ValueError()
            return datetime.fromisoformat(text.replace('Z', '+00:00'))
        start, end, observed = map(utc, (invocation['started_at_utc'], invocation['completed_at_utc'], value['observed_at_utc']))
        if end < start or not -5 <= (start - observed).total_seconds() <= 120:
            raise ValueError()
    except (KeyError, TypeError, ValueError, AttributeError, OverflowError):
        raise OpafError('Direct model evidence does not match its historical invocation.') from None
    return value
