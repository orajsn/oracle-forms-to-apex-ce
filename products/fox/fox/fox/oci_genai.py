"""Direct OCI Python SDK inference; instance principals, one call, no retries.

SDK/service bodies and credentials never enter exception messages. A network
error remains uncertain to the durable caller; this class never retries it.
Injected SDK/client objects are for offline contract tests only.
"""
from datetime import datetime, timezone
from copy import deepcopy
import json
import uuid

from .design_provider import DIRECT, PROMPTS, direct_config
from .genai_prompts import PROMPTS as TEXTS, prompt_hash
from .opaf import OpafError, canonical_hash, parse_model_message
from .provider_timing import ProviderTiming


def _now():
    return datetime.now(timezone.utc).isoformat()


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

    def invoke_prepared(self, role, request, identity, *, role_name, target_profile, before_invoke):
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
        output, invocation = self._invoke(role, request, timing=timing, prepared=prepared)
        from .design_provider import validate_environment
        validate_environment(environment, target_profile, role_name, identity, invocation)
        return output, invocation, environment, timing.finish()

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

    def _invoke(self, role, request, *, timing=None, prepared=None):
        try:
            name, details, wire_hash = self._prepare_request(role, request) if prepared is None else prepared
            client_request_id = 'fox-' + uuid.uuid4().hex
            started = _now()
            if timing is not None:
                timing.begin_request()
            response = self._client().chat(details, opc_request_id=client_request_id,
                retry_strategy=self.sdk.retry.NoneRetryStrategy())
            completed = _now()
            if timing is not None:
                timing.mark('request_seconds')
            body = self.sdk.util.to_dict(response.data)
            if len(json.dumps(body, ensure_ascii=False).encode('utf-8')) > 2_000_000:
                raise ValueError()
            result = body['chat_response']
            choices = result['choices']
            request_id = response.headers.get('opc-request-id')
            if (response.status != 200 or body.get('model_id') != role['model']
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
        except Exception:
            raise OpafError('Direct OCI inference did not seal valid structured output; reconcile without replay.') from None
