"""Additive G2 registration protocol; never invokes models or activates profiles.

Transport, authentication, and an exclusive/fsynced create-only journal belong to
the caller. No CLI, credential discovery, persistent configuration, retry, or
live execution is provided. Each authorized act issues at most one POST or PUT.
"""
from __future__ import annotations

from copy import deepcopy
import hashlib
import json
import re
from urllib.parse import urlsplit

from deployment.forms_understanding_profiles import build_candidates


ROLES = ('baseline43', 'candidate47', 'reviewer43')
MODELS = {'baseline43': 'xai.grok-4.3', 'candidate47': 'xai.grok-4.7',
          'reviewer43': 'xai.grok-4.3'}
SCOPE = {
    'instance_id': 'ocid1.instance.oc1.iad.anuwcljtc7x6gxic5w37qsyp3rst64betkt4uk2pdcrtmy3okspcpbv77qea',
    'compartment_id': 'ocid1.compartment.oc1..aaaaaaaa2q5aelkapmt5mhumvxadcynq5chez2faeucy5plefhy3ylmahtba',
    'region': 'us-ashburn-1',
}
PLAN_SCOPE = 'fox-forms-understanding-registration-v1'
HEADERS = ('name', 'description', 'category', 'icon')
READBACK_HEADERS = ('name', 'description', 'icon')
ENDPOINT = 'https://inference.generativeai.us-ashburn-1.oci.oraclecloud.com'


class RegistrationError(RuntimeError):
    """Fixed, secret-free operator-facing error."""


def canonical_hash(value):
    raw = json.dumps(value, sort_keys=True, separators=(',', ':'),
                     ensure_ascii=False, allow_nan=False).encode('utf-8')
    return hashlib.sha256(raw).hexdigest()


def _require(condition, message):
    if not condition:
        raise RegistrationError(message)


def _id(value):
    _require(type(value) is str and re.fullmatch(r'[A-Fa-f0-9]{16,64}', value),
             'Invalid workflow identity.')
    return value


def _record_id(record):
    values = [record[key] for key in ('id', 'ID', 'agentId') if key in record]
    _require(bool(values) and all(value == values[0] for value in values),
             'Missing or ambiguous workflow identity.')
    return _id(values[0])


def _published(value):
    _require(type(value) in (bool, int) and value in (0, 1), 'Invalid publication state.')
    return bool(value)


def _profile(existing_profile):
    """Retain only public, necessary identity fields; permit v2 capability fields."""
    _require(all(existing_profile['oci'][key] == value for key, value in SCOPE.items()),
             'Profile OCI scope differs.')
    opaf = existing_profile['opaf']
    base, pin = opaf['base_url'], opaf['certificate_sha256']
    parsed = urlsplit(base)
    _require(parsed.scheme == 'https' and parsed.hostname and not parsed.username
             and not parsed.password and not parsed.query and not parsed.fragment
             and parsed.path == '/agentFactory', 'Invalid public OPAF base URL.')
    _require(type(pin) is str and re.fullmatch('[a-f0-9]{64}', pin), 'Invalid certificate pin.')
    roles = {}
    for role in ('mapper', 'reviewer'):
        source = opaf['roles'][role]
        workflow_id, model, digest = source['workflow_id'], source['model'], source['graph_sha256']
        _id(workflow_id)
        _require(model == 'xai.grok-4.3' and type(digest) is str
                 and re.fullmatch('[a-f0-9]{64}', digest), 'Invalid original workflow profile.')
        roles[role] = dict(workflow_id=workflow_id, model=model, graph_sha256=digest)
    _require(len({item['workflow_id'].upper() for item in roles.values()}) == 2,
             'Original workflow identities alias.')
    return {'oci': deepcopy(SCOPE), 'opaf': {'base_url': base, 'certificate_sha256': pin, 'roles': roles}}


def build_registration_plan(candidates, existing_profile):
    """Pure plan builder; reconstruct candidates from bundled resources, not hashes supplied by callers."""
    try:
        fresh = build_candidates()
        _require(canonical_hash(candidates) == canonical_hash(fresh),
                 'Candidates differ from freshly rebuilt resources.')
        return {'schema_version': 1, 'scope': PLAN_SCOPE, 'oci': deepcopy(SCOPE),
                'model_invocation': False, 'profile_activation': False,
                'existing_profile': _profile(existing_profile), 'candidates': deepcopy(fresh)}
    except RegistrationError:
        raise
    except Exception:
        raise RegistrationError('Invalid registration inputs.') from None


def validate_plan(plan, expected_plan_sha256=None):
    try:
        rebuilt = build_registration_plan(plan['candidates'], plan['existing_profile'])
        _require(canonical_hash(plan) == canonical_hash(rebuilt), 'Registration plan was altered.')
        digest = canonical_hash(rebuilt)
        if expected_plan_sha256 is not None:
            _require(type(expected_plan_sha256) is str and digest == expected_plan_sha256,
                     'Reviewed registration hash differs.')
        return digest
    except RegistrationError:
        raise
    except Exception:
        raise RegistrationError('Invalid registration plan.') from None


class RegistrationExecutor:
    """Injected OpafClient + read/create store + fresh OCI scope check.

    Store.create must be atomic exclusive and durable (file and directory fsync)
    before returning. A durable intent is deliberately never cleared or retried.
    The helper never writes profile files or stores raw remote response bodies.
    """
    def __init__(self, *, client, store, scope_check):
        self.client, self.store, self.scope_check = client, store, scope_check

    def _validated_plan(self, plan, expected_hash):
        return validate_plan(plan, expected_hash)

    def _receipt_scope(self):
        return PLAN_SCOPE

    @staticmethod
    def _key(digest, role, operation, kind):
        return digest + '-' + role + '-' + operation + '-' + kind + '.json'

    def _get(self, path, **kwargs):
        return self.client._request('GET', path, **kwargs)

    def _guard(self, plan):
        _require(self.scope_check() == SCOPE, 'Fresh OCI scope check failed.')
        opaf = plan['existing_profile']['opaf']
        _require(self.client.origin + '/agentFactory' == opaf['base_url']
                 and self.client.pin == opaf['certificate_sha256'], 'OPAF origin or certificate differs.')
        # Establish the existing client's pinned session before protected GETs.
        # The transport owns credentials; neither the response nor cookies persist.
        self._get('/v1/loginValidation', login=True)
        originals = {}
        selected = {}
        for role, expected in opaf['roles'].items():
            current = self._get('/v1/agents/' + expected['workflow_id'])['data']
            if any(key in current for key in ('id', 'ID', 'agentId')):
                _require(_record_id(current).upper() == expected['workflow_id'].upper(),
                         'Original readback identity differs.')
            _require(_published(current['published'])
                     and canonical_hash(current['data']) == expected['graph_sha256'],
                     'Original workflow graph or publication changed.')
            nodes = current['data']['nodes']
            llms = [node for node in nodes if node['data']['type'] == 'llmStep']
            _require(len(llms) == 1, 'Original model selection is ambiguous.')
            selected[llms[0]['data']['template']['llmToUse']['value']] = expected['model']
            originals[role] = expected['graph_sha256']
        for role, candidate in plan['candidates']['candidates'].items():
            name = candidate['connection_name']
            _require(name not in selected or selected[name] == MODELS[role], 'Model selection conflicts.')
            selected[name] = MODELS[role]
        rows = self._get('/v1/getSavedLLMConfigurations')['data']['savedConfiguration']
        _require(type(rows) is list, 'Invalid saved model list.')
        registered = self._get('/v1/agentBuilderGetRegisteredLLMS')['data']
        _require(type(registered) is list, 'Invalid registered model list.')
        for name, model in selected.items():
            matches = [row for row in rows if isinstance(row, dict) and row.get('name') == name]
            _require(len(matches) == 1 and sum(isinstance(row, dict) and row.get('value') == name
                                              for row in registered) == 1,
                     'Model connection is missing or ambiguous.')
            row = matches[0]
            detail = row['connectionDetails']
            _require(row.get('provider') == 'oci' and row.get('isActive') == 'Y'
                     and detail.get('credentials_type') == 'INSTANCE_PRINCIPAL'
                     and detail.get('model_id') == model
                     and detail.get('compartment_id') == SCOPE['compartment_id']
                     and detail.get('service_endpoint') == ENDPOINT, 'Saved model OCI path differs.')
        return originals

    def _candidates(self, plan):
        response = self._get('/v1/agents')
        container = response.get('data', response)
        _require(isinstance(container, dict) and type(container.get('items')) is list, 'Invalid workflow listing.')
        items = container['items']
        for meta in (response, container):
            _require(not any(meta.get(key) for key in ('hasMore', 'has_more', 'next', 'nextPage',
                                                      'nextPageToken', 'continuationToken', 'nextLink', 'next_page')),
                     'Incomplete workflow listing.')
            for key in ('total', 'totalCount'):
                if key in meta:
                    _require(type(meta[key]) is int and meta[key] == len(items), 'Incomplete workflow listing.')
        _require(all(type(item) is dict for item in items), 'Invalid workflow listing item.')
        seen = set(item['workflow_id'].upper() for item in plan['existing_profile']['opaf']['roles'].values())
        output = {}
        for role in ROLES:
            candidate = plan['candidates']['candidates'][role]
            matches = [item for item in items if item.get('name') == candidate['header']['name']]
            _require(len(matches) <= 1, 'Duplicate candidate workflow name.')
            if not matches:
                output[role] = None
                continue
            workflow_id = _record_id(matches[0])
            _require(workflow_id.upper() not in seen, 'Candidate identity aliases another workflow.')
            seen.add(workflow_id.upper())
            current = self._get('/v1/agents/' + workflow_id)['data']
            if any(key in current for key in ('id', 'ID', 'agentId')):
                _require(_record_id(current).upper() == workflow_id.upper(), 'Candidate readback identity differs.')
            _require(canonical_hash(current.get('data')) == candidate['graph_sha256']
                     and canonical_hash({key: current.get(key) for key in READBACK_HEADERS})
                     == canonical_hash({key: candidate['header'][key] for key in READBACK_HEADERS}),
                'Candidate graph or readback header differs.')
            if 'category' in current:
                _require(canonical_hash(current['category']) == canonical_hash(candidate['header']['category']),
                         'Candidate category differs.')
            output[role] = {'workflow_id': workflow_id, 'published': _published(current['published']),
                            'graph_sha256': canonical_hash(current['data']),
                            'header_sha256': canonical_hash({key: current[key] for key in READBACK_HEADERS})}
        return output

    def inspect(self, plan, *, expected_plan_sha256=None):
        try:
            digest = self._validated_plan(plan, expected_plan_sha256)
            originals = self._guard(plan)
            return {'scope': self._receipt_scope() + '-inspection', 'plan_sha256': digest,
                    'remote_methods': ['GET'], 'model_invocation': False, 'profile_activation': False,
                    'originals': originals, 'roles': self._candidates(plan)}
        except RegistrationError:
            raise
        except Exception:
            raise RegistrationError('Registration inspection failed; inspect privately.') from None

    def act(self, plan, *, role, operation, expected_plan_sha256, explicit_apply=False):
        """One create OR publish only. Unknown outcomes retain intent and prohibit retry."""
        try:
            _require(explicit_apply is True, 'Explicit registration authorization is required.')
            _require(role in ROLES and operation in ('create', 'publish'), 'Invalid registration operation.')
            digest = self._validated_plan(plan, expected_plan_sha256)
            key = self._key(digest, role, operation, 'intent')
            _require(self.store.read(key) is None, 'Operation already attempted; no automatic replay.')
            self._guard(plan)
            before = self._candidates(plan)
            candidate = plan['candidates']['candidates'][role]
            if operation == 'create':
                _require(before[role] is None, 'Candidate name already exists; no overwrite.')
                login = self._get('/v1/loginValidation', login=True)['data']
                ids = [login[key] for key in ('USER_ID', 'userId', 'user_id') if key in login]
                _require(bool(ids) and all(type(value) is str and value == ids[0] for value in ids)
                         and re.fullmatch(r'[A-Za-z0-9_.:@-]{1,128}', ids[0]), 'Invalid authenticated user identity.')
                method, path = 'POST', '/v1/agents'
                payload = {**deepcopy(candidate['header']), 'data': deepcopy(candidate['graph']), 'user_id': ids[0]}
            else:
                created = self.store.read(self._key(digest, role, 'create', 'outcome'))
                _require(type(created) is dict and created.get('plan_sha256') == digest
                         and created.get('role') == role and created.get('operation') == 'create'
                         and created.get('status') == 'CONFIRMED'
                         and before[role] == created.get('readback') and before[role] is not None
                         and not before[role]['published'], 'Exact recorded unpublished creation is required.')
                method, path = 'PUT', '/v1/agents/' + _id(before[role]['workflow_id']) + '/publish'
                payload = {}
            # Store owns exclusive durable creation. Failure here prevents every write.
            self.store.create(key, {'scope': self._receipt_scope(), 'plan_sha256': digest, 'role': role,
                                   'operation': operation, 'method': method, 'path': path,
                                   'graph_sha256': candidate['graph_sha256'],
                                   'payload_sha256': canonical_hash(payload)})
            _require(self.scope_check() == SCOPE, 'Fresh OCI scope check failed immediately before write.')
            response_id = None
            classification = 'response_received'
            try:
                response = self.client._request(method, path, payload)
            except Exception as error:
                known201 = operation == 'create' and (getattr(error, 'status_code', None) == 201 or str(error) ==
                    'OPAF request did not complete (HTTP 201). No automatic retry was attempted.')
                _require(known201, 'Registration outcome unknown; inspect only, never replay.')
                classification = 'http_201_exact_readback'
            else:
                if operation == 'create':
                    response_id = _record_id(response.get('data', response))
            # Includes original graph readback after every mutation. No inference.
            originals = self._guard(plan)
            after = self._candidates(plan)[role]
            _require(after is not None and after['published'] == (operation == 'publish'),
                     'Registration readback is not confirmed; inspect only.')
            if operation == 'create' and response_id is not None:
                _require(after['workflow_id'].upper() == response_id.upper(), 'Created identity differs from response.')
            if operation == 'publish':
                _require(after['workflow_id'] == before[role]['workflow_id'], 'Published identity differs.')
            result = {'scope': self._receipt_scope(), 'plan_sha256': digest, 'role': role, 'operation': operation,
                      'status': 'CONFIRMED', 'response_classification': classification, 'readback': after,
                      'originals': originals, 'model_invocation': False, 'profile_activation': False}
            self.store.create(self._key(digest, role, operation, 'outcome'), result)
            return result
        except RegistrationError:
            raise
        except Exception:
            raise RegistrationError('Registration incomplete; inspect privately, never replay.') from None
