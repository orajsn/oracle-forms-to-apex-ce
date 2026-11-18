"""Direct OCI Python SDK inference; instance principals, one call, no retries.

SDK/service bodies and credentials never enter exception messages. A network
error remains uncertain to the durable caller; this class never retries it.
Injected SDK/client objects are for offline contract tests only.
"""
from datetime import datetime, timezone
from copy import deepcopy
import json
import re
import uuid

from .design_provider import DIRECT, PROMPTS, direct_config
from .genai_prompts import PROMPTS as TEXTS, prompt_hash
from .opaf import OpafError, canonical_hash, parse_model_message
from .provider_timing import ProviderTiming
from .provider_receipts import ProviderReceiptError


def _now():
    return datetime.now(timezone.utc).isoformat()


def _service_failure(sdk, failure):
    """Selected SDK error metadata only; never its message or full headers."""
    try:
        service_error = sdk.exceptions.ServiceError
        if not isinstance(failure, service_error):
            return None
        status, code = failure.status, failure.code
        request_id = failure.headers.get('opc-request-id')
        if (type(status) is not int or not 400 <= status <= 599
                or not isinstance(code, str) or not re.fullmatch(r'[A-Za-z0-9_.:-]{1,200}', code)
                or not (request_id is None or isinstance(request_id, str) and len(request_id) <= 512)):
            return None
        return {'body': {'scope': 'fox-oci-service-error-v1', 'code': code},
                'status': status, 'request_id': request_id}
    except Exception:
        return None


class OciGenAiClient:
    def __init__(self, target, *, client=None, sdk=None):
        self.config = direct_config(target)
        self.target = target
        try:
            if sdk is None:
                import oci as sdk
            self.sdk = sdk
            self.client = client
        except ImportError:
            raise OpafError('OCI SDK is unavailable; install the packaged inference dependency.') from None

    def _client(self):
        if self.client is None:
            try:
                signer = self.sdk.auth.signers.InstancePrincipalsSecurityTokenSigner()
                self.client = self.sdk.generative_ai_inference.GenerativeAiInferenceClient(
                    config={}, signer=signer, service_endpoint=self.config['endpoint'],
                    retry_strategy=self.sdk.retry.NoneRetryStrategy(), timeout=(10, 600))
            except Exception:
                raise OpafError('OCI instance principal inference configuration is unavailable.') from None
        return self.client

    def observe_environment(self, role, identity, *, role_name, target_profile):
        if (canonical_hash(target_profile) != canonical_hash(self.target)
                or self.config['roles'].get(role_name) != role):
            raise OpafError('Direct model differs from its approved target.')
        # Config observation only, not proof of live availability or inference.
        return {'schema_version': 2, 'scope': 'fox-design-model-environment-v2',
            'provider': DIRECT, 'trust_boundary': 'authenticated_fox_executor_not_vendor_attestation',
            'job_id': identity['job_id'], 'role': role_name,
            'source_manifest_sha256': identity['source_hash'],
            'target_profile_sha256': canonical_hash(target_profile), 'observed_at_utc': _now(),
            'endpoint': self.config['endpoint'], 'region': self.target['oci']['region'],
            'compartment_id': self.target['oci']['compartment_id'], 'authentication': 'instance_principal',
            'sdk_version': self.sdk.__version__, 'model': role['model'],
            'prompt_version': PROMPTS[role_name], 'prompt_sha256': prompt_hash(role_name)}

    def invoke(self, role, request):
        return self._invoke(role, request)

    def invoke_prepared(self, role, request, identity, *, role_name, target_profile, before_invoke,
                        receipt_store=None):
        """Observe configured metadata, persist intent, then one non-retried chat."""
        if not callable(before_invoke):
            raise OpafError('A before-invocation intent callback is required.')
        timing = ProviderTiming(DIRECT)
        environment = self.observe_environment(role, identity, role_name=role_name, target_profile=target_profile)
        timing.mark('environment_seconds')
        try:
            # Initialize auth/SDK and validate/serialize before durable intent:
            # setup failures have not submitted an uncertain inference.
            self._client()
            prepared = self._prepare_request(role, request)
        except Exception:
            raise OpafError('Direct OCI inference setup failed before submission.') from None
        timing.mark('setup_seconds')
        binding = canonical_hash([role, request, identity, target_profile, self.target])
        try:
            before_invoke(deepcopy(environment))
        except Exception:
            raise OpafError('Model intent callback did not complete; no model request was submitted.') from None
        if canonical_hash([role, request, identity, target_profile, self.target]) != binding:
            raise OpafError('Prepared model inputs changed before invocation.')
        lead = (datetime.fromisoformat(_now()) - datetime.fromisoformat(environment['observed_at_utc'])).total_seconds()
        if not -5 <= lead <= 120:
            raise OpafError('Prepared model environment expired before invocation.')
        timing.mark('before_invoke_seconds')
        receipt_binding = self._receipt_binding(role, request, identity, role_name,
                                                target_profile, prepared[2]) if receipt_store is not None else None
        output, invocation = self._invoke(role, request, timing=timing, prepared=prepared,
            receipt_store=receipt_store, receipt_binding=receipt_binding, environment=environment)
        from .design_provider import validate_environment
        validate_environment(environment, target_profile, role_name, identity, invocation)
        return output, invocation, environment, timing.finish()

    def _receipt_binding(self, role, request, identity, role_name, target_profile, wire_hash):
        return {'schema_version': 1, 'provider': DIRECT, 'job_id': identity['job_id'],
            'source_manifest_sha256': identity['source_hash'], 'identity_sha256': canonical_hash(identity),
            'target_profile_sha256': canonical_hash(target_profile), 'client_target_sha256': canonical_hash(self.target),
            'role': role_name, 'model': role['model'], 'role_sha256': canonical_hash(role),
            'prompt_version': PROMPTS[role_name], 'prompt_sha256': prompt_hash(role_name),
            'request_sha256': canonical_hash(request), 'wire_request_sha256': wire_hash}

    def recover_prepared(self, role, request, identity, *, role_name, target_profile, receipt_store):
        """Explicit read/parse only, returning (output, invocation, environment).

        Caller must independently recheck current source/owner permission before
        adopting anything. A receipt is evidence, never authorization or business
        acceptance. This method never initializes authentication or calls chat;
        SDK request serialization only recomputes the exact original wire hash.
        No historical intent/result files are changed, and no timing is invented.
        """
        response_read = False
        try:
            if (canonical_hash(target_profile) != canonical_hash(self.target)
                    or self.config['roles'].get(role_name) != role):
                raise ValueError()
            name, _, wire_hash = self._prepare_request(role, request)
            binding = self._receipt_binding(role, request, identity, role_name, target_profile, wire_hash)
            intent, response = receipt_store.read(binding)
            response_read = True
            output, invocation = self._parse_response(role, request, name=name, wire_hash=wire_hash,
                client_request_id=intent['client_request_id'], started=intent['started_at_utc'],
                completed=response['completed_at_utc'], body=response['body'],
                status=response['status'], request_id=response['request_id'])
            from .design_provider import validate_environment
            validate_environment(intent['environment'], target_profile, role_name, identity, invocation)
            return output, invocation, intent['environment']
        except ProviderReceiptError:
            raise
        except Exception:
            if response_read:
                raise OpafError('Captured OCI response did not seal valid structured output; reconcile without replay.') from None
            raise OpafError('OCI response recovery inputs are unavailable or invalid; reconcile without replay.') from None

    def _prepare_request(self, role, request):
        name = next(n for n in PROMPTS if role == self.config['roles'][n])
        encoded = json.dumps(request, ensure_ascii=False, allow_nan=False, separators=(',', ':'))
        if len(encoded.encode('utf-8')) > 650_000:
            raise ValueError()
        m = self.sdk.generative_ai_inference.models
        details = m.ChatDetails(compartment_id=self.target['oci']['compartment_id'],
            serving_mode=m.OnDemandServingMode(model_id=role['model']),
            chat_request=m.GenericChatRequest(api_format='GENERIC', is_stream=False,
                num_generations=1, max_tokens=16000, temperature=0,
                messages=[m.SystemMessage(content=[m.TextContent(text=TEXTS[name])]),
                          m.UserMessage(content=[m.TextContent(text=encoded)])]))
        return name, details, canonical_hash(self.sdk.util.to_dict(details))

    def _invoke(self, role, request, *, timing=None, prepared=None, receipt_store=None,
                receipt_binding=None, environment=None):
        response_captured = False
        service_error_captured = False
        try:
            name, details, wire_hash = self._prepare_request(role, request) if prepared is None else prepared
            client_request_id = 'fox-' + uuid.uuid4().hex
            started = _now()
            if receipt_store is not None:
                receipt_key = receipt_store.begin(receipt_binding, client_request_id=client_request_id,
                    started_at_utc=started, environment=deepcopy(environment))
            if timing is not None:
                timing.begin_request()
            try:
                response = self._client().chat(details, opc_request_id=client_request_id,
                    retry_strategy=self.sdk.retry.NoneRetryStrategy())
            except Exception as failure:
                details_received = _service_failure(self.sdk, failure) if receipt_store is not None else None
                if details_received is not None:
                    receipt_store.capture(receipt_key, completed_at_utc=_now(), **details_received)
                    service_error_captured = True
                raise
            completed = _now()
            if timing is not None:
                timing.mark('request_seconds')
            body = self.sdk.util.to_dict(response.data)
            request_id = response.headers.get('opc-request-id')
            if receipt_store is not None:
                receipt_store.capture(receipt_key, body=body, status=response.status,
                    request_id=request_id, completed_at_utc=completed)
                response_captured = True
            return self._parse_response(role, request, name=name, wire_hash=wire_hash,
                client_request_id=client_request_id, started=started, completed=completed,
                body=body, status=response.status, request_id=request_id)
        except ProviderReceiptError:
            raise
        except Exception:
            if service_error_captured:
                raise OpafError('OCI service error metadata was captured; reconcile without replay.') from None
            if response_captured:
                raise OpafError('Captured OCI response did not seal valid structured output; reconcile without replay.') from None
            raise OpafError('Direct OCI inference did not seal valid structured output; reconcile without replay.') from None

    @staticmethod
    def _parse_response(role, request, *, name, wire_hash, client_request_id, started,
                        completed, body, status, request_id):
        if len(json.dumps(body, ensure_ascii=False).encode('utf-8')) > 2_000_000:
            raise ValueError()
        result = body['chat_response']
        choices = result['choices']
        if (status != 200 or body.get('model_id') != role['model']
                or not isinstance(body.get('model_version'), str) or not body['model_version']
                or len(body['model_version']) > 200
                or result.get('api_format') != 'GENERIC' or len(choices) != 1
                or choices[0].get('finish_reason', '').lower() != 'stop'
                or not isinstance(request_id, str) or not request_id):
            raise ValueError()
        message = choices[0]['message']
        content = message['content']
        if (message.get('role') != 'ASSISTANT' or not content
                or any(c.get('type') != 'TEXT' or not isinstance(c.get('text'), str) for c in content)
                or message.get('tool_calls')):
            raise ValueError()
        output = parse_model_message(''.join(c['text'] for c in content))
        invocation = {'schema_version': 2, 'provider': DIRECT, 'role': name,
            'model': body['model_id'], 'model_version': body['model_version'], 'prompt_version': PROMPTS[name], 'prompt_sha256': prompt_hash(name),
            'request_id': request_id, 'client_request_id': client_request_id,
            'request_sha256': canonical_hash(request), 'wire_request_sha256': wire_hash,
            'response_sha256': canonical_hash(body), 'started_at_utc': started, 'completed_at_utc': completed}
        return output, invocation
