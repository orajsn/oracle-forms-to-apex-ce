"""One-shot, additive registration of the reviewed JSN mapped-project v2 roles.

This module grants no authority, loads no credentials, and implements no transport.
Inject the existing authenticated fox.opaf.OpafClient, a durable private store, and
a fresh scope_check() returning instance_id, compartment_id and region. Planning
is pure. inspect() performs GETs only. apply() requires an exact reviewed plan hash
and explicit_apply=True. Neither a retry nor an overwrite API exists.

Load from stdin without installing or modifying FOX, for example:
    module = types.ModuleType('project_opaf_registration')
    exec(compile(verified_source_bytes, '<reviewed-registration>', 'exec'), module.__dict__)
The outer operator is responsible for checking those source bytes, authorization,
and actual process exit. Receipts never claim a process exit or model invocation.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
from pathlib import Path
import re
import stat
from datetime import datetime, timezone


ROLES = ('mapper', 'reviewer')
NAMES = {
    'mapper': 'JSN FOX Project Mapped Storage v2 Mapper',
    'reviewer': 'JSN FOX Project Mapped Storage v2 Independent Reviewer',
}
CONNECTIONS = {'mapper': 'JSN Forms Converter 4.3', 'reviewer': 'JSN Forms Reviewer'}
SOURCE_SHA256 = {
    'mapper': '009e1bbd71a0ac53f268c6b63ad8ac5ec6b93d7b0bb591ff997bab6a58a69e7e',
    'reviewer': '7d79b2bc35e0dfc03b4fca3a24b7606108573e7ca3c07afec3c0b79ecbcc854c',
}
GRAPH_SHA256 = {
    'mapper': '897c6ff34f011fd53084623532d843a21d284308f9490ac0c1fee3a11ec3e22e',
    'reviewer': '882434ecc24994eee8945cbad7a9e14986d5e4b53b35ea0c46f473a45709bdb9',
}
CONTRACT_SHA256 = '225ca24de9eee601e62e254943a45b2fc1fd62333b29ac21b78c5507404a1cbb'
LEGACY_TARGET_SHA256 = '7c7b73d43febc9befb1d43e47449a02cc7894b879dd4bc32904cec538e5f95e6'
SCOPE = {
    'instance_id': 'ocid1.instance.oc1.iad.anuwcljtc7x6gxic5w37qsyp3rst64betkt4uk2pdcrtmy3okspcpbv77qea',
    'compartment_id': 'ocid1.compartment.oc1..aaaaaaaa2q5aelkapmt5mhumvxadcynq5chez2faeucy5plefhy3ylmahtba',
    'region': 'us-ashburn-1',
}
DESCRIPTION = ('Source-preserving mapped-project v2 metadata role. Original XML/DDL '
               'remain unchanged; explicit deterministic fox-project-storage-v1 mapping. '
               'OCI xai.grok-4.3; no tools, custom code, imports or release authority.')
HEADERS = ('name', 'description', 'category', 'icon')
# Observed OPAF 26.4 GET /agents/{id} omits category. Bind it in the
# submitted request, but never manufacture it in a server readback.
READBACK_HEADERS = ('name', 'description', 'icon')


class RegistrationError(RuntimeError):
    """Public, secret-free failure. Inspect; never blindly repeat an apply."""


def canonical_bytes(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'),
                      ensure_ascii=False, allow_nan=False).encode('utf-8')


def sha256(value):
    return hashlib.sha256(value).hexdigest()


def canonical_hash(value):
    return sha256(canonical_bytes(value))


def _copy(value):
    return json.loads(canonical_bytes(value))


def _require(condition, message):
    if not condition:
        raise RegistrationError(message)


def _json(raw):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            _require(key not in result, 'Duplicate JSON field.')
            result[key] = value
        return result
    try:
        return json.loads(raw, object_pairs_hook=unique,
                          parse_constant=lambda _: (_ for _ in ()).throw(ValueError()))
    except (ValueError, TypeError, UnicodeError):
        raise RegistrationError('Invalid JSON document.') from None


def _build(sources, legacy_target, contract_sha256):
    _require(isinstance(sources, dict) and set(sources) == set(ROLES), 'Exactly two sources are required.')
    _require(contract_sha256 == CONTRACT_SHA256, 'Candidate contract changed.')
    _require(canonical_hash(legacy_target) == LEGACY_TARGET_SHA256, 'Legacy target profile changed.')
    entries = {}
    for role in ROLES:
        raw = sources[role]
        _require(type(raw) is bytes and sha256(raw) == SOURCE_SHA256[role], 'Candidate source bytes changed.')
        source = _json(raw)
        _require(set(source) == set(HEADERS) | {'data'}, 'Candidate header shape changed.')
        graph = source['data']
        _require(canonical_hash(graph) == GRAPH_SHA256[role], 'Candidate graph changed.')
        nodes, edges = graph['nodes'], graph['edges']
        types = ['chatInputComponent', 'promptComponent', 'llmStep', 'chatOutputComponent']
        _require(len(nodes) == 4 and len(edges) == 3
                 and sorted(n['data']['type'] for n in nodes) == sorted(types), 'Graph must remain tool-free.')
        selection = next(n['data']['template']['llmToUse']['value'] for n in nodes if n['data']['type'] == 'llmStep')
        _require(selection == CONNECTIONS[role], 'Model connection changed.')
        document = {**source, 'name': NAMES[role], 'description': DESCRIPTION}
        entries[role] = {
            'source_base64': base64.b64encode(raw).decode('ascii'),
            'source_bytes_sha256': sha256(raw),
            'source_header_sha256': canonical_hash({k: source[k] for k in HEADERS}),
            'request_header_sha256': canonical_hash({k: document[k] for k in HEADERS}),
            'readback_header_sha256': canonical_hash({k: document[k] for k in READBACK_HEADERS}),
            'graph_sha256': GRAPH_SHA256[role],
            'document_sha256': canonical_hash(document),
            'connection_name': selection, 'document': document,
        }
    return _copy({
        'schema_version': 1, 'scope': 'fox-project-opaf-registration-plan-v1',
        'authority': 'requires_separate_explicit_JSN_registration_authorization',
        'operations': ['create_two_distinct_roles', 'publish_exact_created_ids'],
        'model_invocation': False, 'profile_activation': False,
        'oci': SCOPE, 'candidate_contract_sha256': contract_sha256,
        'legacy_target_sha256': LEGACY_TARGET_SHA256, 'legacy_target': legacy_target,
        'roles': entries,
    })


def build_plan(*, sources, legacy_target, candidate_contract):
    """Pure builder; accepts original bytes and the unchanged legacy target dict."""
    _require(type(candidate_contract) is bytes, 'Original contract bytes are required.')
    return _build(sources, legacy_target, sha256(candidate_contract))


def validate_plan(plan, expected_plan_sha256=None):
    """Pure full reconstruction; altered fields cannot self-authorize a write."""
    try:
        sources = {role: base64.b64decode(plan['roles'][role]['source_base64'], validate=True) for role in ROLES}
        rebuilt = _build(sources, plan['legacy_target'], plan['candidate_contract_sha256'])
        _require(canonical_bytes(rebuilt) == canonical_bytes(plan), 'Plan was altered.')
        digest = canonical_hash(plan)
        if expected_plan_sha256 is not None:
            _require(type(expected_plan_sha256) is str and digest == expected_plan_sha256,
                     'Reviewed plan hash differs.')
        return digest
    except (KeyError, TypeError, ValueError, AttributeError):
        raise RegistrationError('Invalid registration plan.') from None


class FileStore:
    """Fixed-base POSIX private, create-only JSON store with file+directory fsync.

    Operator creates a dedicated 0700 directory owned by the container uid first.
    No directory creation, chmod, overwrite, delete or arbitrary path API exists.
    Injected alternatives must provide the same atomic/durable create(key, value)
    and read(key) contract. Never use an ephemeral or shared store for live apply.
    """
    def __init__(self, base):
        _require(os.name == 'posix' and hasattr(os, 'O_NOFOLLOW'), 'Private store requires POSIX no-follow support.')
        self.base = Path(base)
        _require(self.base.is_absolute() and '..' not in self.base.parts, 'Store base must be absolute and normalized.')
        self._check_path()
        flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
        descriptor = os.open('/', flags)
        try:
            for component in self.base.parts[1:]:
                child = os.open(component, flags, dir_fd=descriptor)
                os.close(descriptor)
                descriptor = child
            self.fd = descriptor
            self._check_directory()
        except Exception:
            os.close(descriptor)
            raise

    def _check_path(self):
        for path in (self.base, *self.base.parents):
            _require(not stat.S_ISLNK(path.lstat().st_mode), 'Store path contains a symlink.')

    def _check_directory(self):
        self._check_path()
        info = os.fstat(self.fd)
        current = self.base.lstat()
        _require(stat.S_ISDIR(info.st_mode) and stat.S_IMODE(info.st_mode) == 0o700
                 and info.st_uid == os.geteuid() and (info.st_dev, info.st_ino) == (current.st_dev, current.st_ino),
                 'Store directory identity or private permissions changed.')

    @staticmethod
    def _key(key):
        _require(type(key) is str and re.fullmatch(r'[a-z0-9-]{1,110}\.json', key), 'Invalid store key.')
        return key

    @staticmethod
    def _check_file(fd):
        info = os.fstat(fd)
        _require(stat.S_ISREG(info.st_mode) and stat.S_IMODE(info.st_mode) == 0o600
                 and info.st_uid == os.geteuid() and info.st_nlink == 1 and info.st_size <= 2_000_000,
                 'Store record identity or private permissions changed.')

    def read(self, key):
        self._check_directory()
        try:
            fd = os.open(self._key(key), os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=self.fd)
        except FileNotFoundError:
            return None
        try:
            self._check_file(fd)
            with os.fdopen(fd, 'rb', closefd=False) as stream:
                return _json(stream.read(2_000_001))
        finally:
            os.close(fd)

    def create(self, key, value):
        self._check_directory()
        raw = canonical_bytes(value)
        _require(len(raw) <= 2_000_000, 'Store record exceeds bound.')
        fd = os.open(self._key(key), os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                     0o600, dir_fd=self.fd)
        try:
            self._check_file(fd)
            with os.fdopen(fd, 'wb', closefd=False) as stream:
                stream.write(raw)
                stream.flush()
                os.fsync(fd)
            os.fsync(self.fd)
        finally:
            os.close(fd)

    def close(self):
        if self.fd is not None:
            os.close(self.fd)
            self.fd = None


def _workflow_id(value):
    _require(type(value) is str and re.fullmatch(r'[A-Fa-f0-9]{16,64}', value), 'Invalid workflow ID.')
    return value


def _id(record):
    values = [record[key] for key in ('id', 'ID', 'agentId') if key in record]
    _require(bool(values) and len(set(values)) == 1, 'Workflow ID missing or ambiguous.')
    return _workflow_id(values[0])


def _published(value):
    _require(type(value) in (bool, int) and value in (0, 1), 'Invalid published state.')
    return bool(value)


class RegistrationExecutor:
    def __init__(self, *, client, store, scope_check):
        self.client, self.store, self.scope_check = client, store, scope_check

    @staticmethod
    def _key(digest, suffix):
        return digest + '-' + suffix + '.json'

    def _record(self, digest, suffix, value):
        self.store.create(self._key(digest, suffix), {
            'schema_version': 1, 'plan_sha256': digest,
            'recorded_at_utc': datetime.now(timezone.utc).isoformat(), **value,
        })

    def _intent(self, plan, digest, role, operation):
        record = self.store.read(self._key(digest, role + '-' + operation + '-intent'))
        if record is None:
            return None
        _require(isinstance(record, dict) and record.get('plan_sha256') == digest
                 and record.get('scope') == 'registration-write-intent' and record.get('role') == role,
                 'Existing intent does not match this plan.')
        if operation == 'create':
            _require(record.get('method') == 'POST' and record.get('path') == '/v1/agents'
                     and record.get('document_sha256') == plan['roles'][role]['document_sha256'],
                     'Existing create intent differs.')
        else:
            workflow_id = _workflow_id(record.get('workflow_id'))
            _require(record.get('method') == 'PUT'
                     and record.get('path') == '/v1/agents/' + workflow_id + '/publish'
                     and record.get('graph_sha256') == GRAPH_SHA256[role], 'Existing publish intent differs.')
        return record

    def _guard(self, plan, digest):
        _require(self.scope_check() == SCOPE, 'Fresh VM, compartment or region guard failed.')
        target = plan['legacy_target']
        opaf = target['opaf']
        _require(self.client.origin + '/agentFactory' == opaf['base_url']
                 and self.client.pin == opaf['certificate_sha256'], 'OPAF origin or certificate differs.')
        request = {'job_id': 'fox-' + digest[:20], 'source_hash': digest}
        for role in ROLES:
            observed = self.client.observe_environment(opaf['roles'][role], request,
                                                       role_name=role, target_profile=_copy(target))
            _require(observed['target_profile_sha256'] == LEGACY_TARGET_SHA256
                     and observed['workflow'] == {**opaf['roles'][role], 'published': True}
                     and observed['opaf_version'] == target['tested_versions']['opaf']
                     and observed['opaf'] == {k: opaf[k] for k in (
                         'base_url', 'certificate_sha256', 'model_authentication', 'version_number', 'build_id')},
                     'Observed legacy environment differs.')
        registered = self.client._request('GET', '/v1/agentBuilderGetRegisteredLLMS')['data']
        _require(isinstance(registered, list), 'Invalid registered-model list.')
        for connection in CONNECTIONS.values():
            _require(sum(isinstance(row, dict) and row.get('value') == connection for row in registered) == 1,
                     'Registered OCI model connection missing or ambiguous.')
        login = self.client._request('GET', '/v1/loginValidation', login=True)['data']
        user_ids = [login[k] for k in ('USER_ID', 'userId', 'user_id') if k in login]
        _require(user_ids and all(type(value) is str for value in user_ids)
                 and len(set(user_ids)) == 1 and re.fullmatch(r'[A-Za-z0-9_.:@-]{1,128}', user_ids[0]),
                 'Authenticated user ID missing or ambiguous.')
        return user_ids[0]

    def _lookup(self, plan, role):
        listing = self.client._request('GET', '/v1/agents')
        container = listing.get('data', listing)
        _require(isinstance(container, dict) and isinstance(container.get('items'), list), 'Invalid agent listing.')
        items = container['items']
        for metadata in (listing, container):
            _require(not metadata.get('hasMore') and not metadata.get('next') and not metadata.get('nextPage'),
                     'Partial agent listing; reconcile manually.')
            for field in ('total', 'totalCount'):
                if field in metadata:
                    _require(type(metadata[field]) is int and metadata[field] == len(items), 'Partial agent listing.')
        _require(all(isinstance(item, dict) for item in items), 'Invalid agent listing item.')
        matches = [item for item in items if item.get('name') == NAMES[role]]
        _require(len(matches) <= 1, 'Duplicate registration names; no overwrite or replay.')
        if not matches:
            return None
        workflow_id = _id(matches[0])
        old_ids = {record['workflow_id'].upper() for record in plan['legacy_target']['opaf']['roles'].values()}
        _require(workflow_id.upper() not in old_ids, 'New role aliases a legacy workflow.')
        current = self.client._request('GET', '/v1/agents/' + workflow_id)['data']
        if any(key in current for key in ('id', 'ID', 'agentId')):
            _require(_id(current) == workflow_id, 'Agent readback ID differs.')
        document = plan['roles'][role]['document']
        _require(all(current.get(key) == document[key] for key in (*READBACK_HEADERS, 'data')),
                 'Existing registration conflicts with exact reviewed graph or headers.')
        _require(canonical_hash(current['data']) == plan['roles'][role]['graph_sha256']
                 and canonical_hash({key: current[key] for key in READBACK_HEADERS})
                 == plan['roles'][role]['readback_header_sha256'],
                 'Existing registration canonical graph or header digest differs.')
        if 'category' in current:
            _require(canonical_bytes(current['category']) == canonical_bytes(document['category']),
                     'Existing registration category differs from the submitted header.')
        observed_document = {key: current[key] for key in (*READBACK_HEADERS, 'data')}
        if 'category' in current:
            observed_document['category'] = current['category']
        return {
            'workflow_id': workflow_id, 'name': NAMES[role], 'published': _published(current['published']),
            'graph_sha256': canonical_hash(current['data']),
            'header_sha256': canonical_hash({key: current[key] for key in READBACK_HEADERS}),
            'header_fields_hashed': list(READBACK_HEADERS),
            'submitted_header_sha256': plan['roles'][role]['request_header_sha256'],
            'category_observation': 'returned_and_matched' if 'category' in current else 'not_returned_submitted_only',
            'observed_record_sha256': canonical_hash(current),
            'document': observed_document,
        }

    def _read_candidates(self, plan):
        records = {role: self._lookup(plan, role) for role in ROLES}
        ids = [record['workflow_id'].upper() for record in records.values() if record]
        _require(len(ids) == len(set(ids)), 'Candidate roles share a workflow ID.')
        return records

    def inspect(self, plan, *, expected_plan_sha256=None):
        """GET-only remote inspection, no journal mutation or execution claim."""
        digest = validate_plan(plan, expected_plan_sha256)
        self._guard(plan, digest)
        roles = self._read_candidates(plan)
        journal = {}
        for suffix in ('claim', 'attention', 'complete', 'reconciled'):
            record = self.store.read(self._key(digest, suffix))
            journal[suffix] = record is not None
        return {'scope': 'fox-project-opaf-registration-inspection-v1', 'plan_sha256': digest,
                'remote_methods': ['GET'], 'execution_receipt': False, 'roles': roles,
                'journal': journal, 'automatic_replay_allowed': False}

    def apply(self, plan, *, expected_plan_sha256, explicit_apply=False):
        """Single attempt only. Durable intent always precedes each POST or PUT."""
        _require(explicit_apply is True, 'Explicit registration authorization is required.')
        digest = validate_plan(plan, expected_plan_sha256)
        _require(self.store.read(self._key(digest, 'claim')) is None
                 and self.store.read(self._key(digest, 'reconciled')) is None,
                 'Plan already attempted or reconciled; inspect only, never replay.')
        self._guard(plan, digest)
        _require(all(value is None for value in self._read_candidates(plan).values()),
                 'Candidate already exists; inspect and explicitly reconcile, never overwrite.')
        # Atomic create-only claim is also the cross-process one-shot lock.
        self._record(digest, 'claim', {'scope': 'registration-claim', 'plan': plan})
        return self._perform(plan, digest, continuation=False)

    def _perform(self, plan, digest, *, continuation):
        known = {}
        used_201_reconciliation = False
        try:
            for role in ROLES:
                user_id = self._guard(plan, digest)
                current = self._read_candidates(plan)
                for previous, workflow_id in known.items():
                    _require(current[previous] is not None and current[previous]['workflow_id'] == workflow_id
                             and current[previous]['published'], 'Previously registered role changed.')
                if continuation and self._intent(plan, digest, role, 'create') is not None:
                    existing = current[role]
                    _require(existing is not None, 'Attempted create remains unconfirmed; never replay POST.')
                    original = self.store.read(self._key(digest, role + '-create-outcome'))
                    if original is not None:
                        _require(original.get('plan_sha256') == digest
                                 and original['readback']['workflow_id'] == existing['workflow_id'],
                                 'Previously created workflow identity changed.')
                    self._record(digest, role + '-create-reconciled', {
                        'scope': 'registration-explicit-continuation-readback',
                        'execution_receipt': False, 'readback': existing,
                    })
                    workflow_id = existing['workflow_id']
                    publish_intent = self._intent(plan, digest, role, 'publish')
                    if publish_intent is not None:
                        _require(publish_intent['workflow_id'] == workflow_id and existing['published'],
                                 'Attempted publish remains unconfirmed; never replay PUT.')
                        self._record(digest, role + '-publish-reconciled', {
                            'scope': 'registration-explicit-continuation-readback',
                            'execution_receipt': False, 'readback': existing,
                        })
                        known[role] = workflow_id
                        continue
                    _require(not existing['published'], 'Role was published outside the recorded attempt; inspect only.')
                    self._publish(plan, digest, role, workflow_id, known)
                    known[role] = workflow_id
                    continue
                _require(current[role] is None, 'Candidate appeared without a create intent; inspect only.')
                _require(self.store.read(self._key(digest, role + '-create-intent')) is None
                         and self.store.read(self._key(digest, role + '-publish-intent')) is None,
                         'Operation intent already exists; never replay.')
                payload = {**_copy(plan['roles'][role]['document']), 'user_id': user_id}
                self._record(digest, role + '-create-intent', {
                    'scope': 'registration-write-intent', 'role': role, 'method': 'POST', 'path': '/v1/agents',
                    'document_sha256': plan['roles'][role]['document_sha256'],
                    'authenticated_user_id_sha256': sha256(user_id.encode()),
                })
                response_id = None
                outcome = 'http_200_response'
                try:
                    response = self.client._request('POST', '/v1/agents', payload)
                except Exception as error:
                    # Existing OpafClient discards the 201 body and raises this exact
                    # fixed message. This is a known positive HTTP status, not a timeout.
                    acknowledged = (getattr(error, 'status_code', None) == 201 or str(error) ==
                        'OPAF request did not complete (HTTP 201). No automatic retry was attempted.')
                    if not acknowledged:
                        raise
                    outcome = 'http_201_acknowledged_exact_readback_required'
                    used_201_reconciliation = True
                else:
                    _require(isinstance(response, dict), 'Unsupported create response; inspect only.')
                    response_id = _id(response.get('data', response))
                created = self._lookup(plan, role)
                _require(created is not None and (response_id is None or response_id == created['workflow_id']),
                         'Creation not confirmed by exact unique readback; inspect only.')
                _require(not created['published'], 'New workflow unexpectedly published; inspect only.')
                workflow_id = created['workflow_id']
                _require(workflow_id.upper() not in {item.upper() for item in known.values()}, 'Role IDs are not distinct.')
                self._record(digest, role + '-create-outcome', {'scope': 'registration-create-readback',
                             'response_classification': outcome, 'readback': created})
                self._publish(plan, digest, role, workflow_id, known)
                known[role] = workflow_id
            self._guard(plan, digest)
            final = self._read_candidates(plan)
            _require(all(final[role] is not None and final[role]['workflow_id'] == known[role]
                         and final[role]['published'] for role in ROLES), 'Final registration readback differs.')
            receipt = {
                'scope': ('fox-project-opaf-registration-continuation-v1' if continuation
                          else 'fox-project-opaf-registration-execution-v1'), 'plan_sha256': digest,
                'status': ('COMPLETE_WITH_EXPLICIT_CONTINUATION' if continuation else
                           'COMPLETE_WITH_CREATE_READBACK_RECONCILIATION' if used_201_reconciliation else 'COMPLETE'),
                'execution_receipt': not continuation, 'model_invocation': False, 'profile_activation': False,
                'legacy_target_sha256': LEGACY_TARGET_SHA256, 'roles': final,
            }
            if continuation:
                receipt['prior_process_exit'] = 'not_inferred'
            self._record(digest, 'complete', receipt)
            return receipt
        except Exception:
            # Never persist an exception string: vendor errors can contain secrets.
            try:
                self._record(digest, 'continuation-attention' if continuation else 'attention', {'scope': 'registration-attention',
                             'status': 'INCOMPLETE_INSPECT_REQUIRED', 'automatic_replay_allowed': False})
            except Exception:
                pass  # The durable claim/intents still prohibit all subsequent apply.
            raise RegistrationError('Registration incomplete. Inspect existing objects and journal; no automatic replay.') from None

    def _publish(self, plan, digest, role, workflow_id, known):
        self._guard(plan, digest)
        before_publish = self._read_candidates(plan)
        _require(before_publish[role] is not None and before_publish[role]['workflow_id'] == workflow_id
                 and not before_publish[role]['published'], 'Created role changed before publish.')
        for previous, previous_id in known.items():
            _require(before_publish[previous] is not None
                     and before_publish[previous]['workflow_id'] == previous_id
                     and before_publish[previous]['published'], 'Previously registered role changed.')
        path = '/v1/agents/' + workflow_id + '/publish'
        self._record(digest, role + '-publish-intent', {'scope': 'registration-write-intent',
                     'role': role, 'method': 'PUT', 'path': path, 'workflow_id': workflow_id,
                     'graph_sha256': GRAPH_SHA256[role]})
        self.client._request('PUT', path, {})
        published = self._lookup(plan, role)
        _require(published is not None and published['workflow_id'] == workflow_id and published['published'],
                 'Publish not confirmed; inspect only.')
        self._record(digest, role + '-publish-outcome', {'scope': 'registration-publish-readback', 'readback': published})

    def continue_unattempted(self, plan, *, expected_plan_sha256, explicit_continue=False):
        """One explicit continuation, never replaying an attempted POST or PUT.

        Requires the previous call's durable incomplete marker, so it cannot race
        an ongoing apply or silently resume a killed process. Existing exact
        objects are GET-confirmed and explicitly labeled reconciled. Only phases
        without an intent may write. Another incomplete continuation stops here;
        a fresh operator decision is required, not a new plan or generic retry.
        """
        _require(explicit_continue is True, 'Explicit continuation authorization is required.')
        digest = validate_plan(plan, expected_plan_sha256)
        claim = self.store.read(self._key(digest, 'claim'))
        attention = self.store.read(self._key(digest, 'attention'))
        _require(isinstance(claim, dict) and claim.get('plan_sha256') == digest
                 and canonical_hash(claim.get('plan')) == digest
                 and isinstance(attention, dict) and attention.get('plan_sha256') == digest
                 and attention.get('status') == 'INCOMPLETE_INSPECT_REQUIRED',
                 'No confirmed incomplete attempt to continue.')
        _require(all(self.store.read(self._key(digest, suffix)) is None
                     for suffix in ('complete', 'reconciled', 'continuation-claim')),
                 'Attempt is complete, reconciled or already continued; inspect only.')
        self.inspect(plan, expected_plan_sha256=digest)
        self._record(digest, 'continuation-claim', {'scope': 'registration-explicit-continuation',
                     'automatic_replay_allowed': False, 'prior_process_exit': 'not_inferred'})
        return self._perform(plan, digest, continuation=True)

    def reconcile_completion(self, plan, *, expected_plan_sha256, explicit_reconcile=False):
        """GET-only remote reconciliation; never resumes an incomplete operation.

        Can record already-published exact objects, including pre-existing objects.
        This distinct local receipt does not assert that a prior script succeeded.
        An unpublished/missing role needs a separately reviewed operator decision;
        this module intentionally offers no generic resume or publish endpoint.
        """
        _require(explicit_reconcile is True, 'Explicit reconciliation authorization is required.')
        digest = validate_plan(plan, expected_plan_sha256)
        observation = self.inspect(plan, expected_plan_sha256=digest)
        _require(all(record is not None and record['published'] for record in observation['roles'].values()),
                 'Registration remains incomplete; no writes or replay were performed.')
        receipt = {'scope': 'fox-project-opaf-registration-reconciliation-v1', 'plan_sha256': digest,
                   'status': 'CONFIRMED_EXISTING_PUBLISHED_OBJECTS', 'execution_receipt': False,
                   'prior_process_exit': 'not_inferred', 'remote_methods': ['GET'],
                   'model_invocation': False, 'profile_activation': False, 'roles': observation['roles'],
                   'prior_claim_present': observation['journal']['claim']}
        self._record(digest, 'reconciled', receipt)
        return receipt
