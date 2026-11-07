"""Explicit existing-listener integration; runtime proof requires a real callback."""
import os

from .prototype_authority_client import PrototypeAuthorityClient
from .prototype_gateway import PrototypeGateway


def build_prototype_gateway(settings, *, authority_url, authority_origin, runtime_verifier=None):
    if runtime_verifier is not None and not callable(runtime_verifier):
        raise ValueError('Explicit runtime verifier must be callable')
    authorizer = PrototypeAuthorityClient(settings, authority_url=authority_url,
                                          authority_origin=authority_origin)
    return PrototypeGateway(settings, authorize=authorizer, runtime_verifier=runtime_verifier)


def configured_prototype_gateway(settings, *, runtime_verifier=None, environ=None):
    env = os.environ if environ is None else environ
    enabled = env.get('FOX_PROTOTYPE_AUTHORITY_ENABLED', '')
    if enabled in ('', '0'):
        return None
    if enabled != '1':
        raise ValueError('FOX_PROTOTYPE_AUTHORITY_ENABLED must explicitly be 1')
    bridge = env.get('FOX_PROTOTYPE_RUNTIME_BRIDGE_ENABLED', '')
    if bridge not in ('', '0', '1'):
        raise ValueError('FOX_PROTOTYPE_RUNTIME_BRIDGE_ENABLED must explicitly be 1')
    if bridge == '1':
        if runtime_verifier is not None:
            raise ValueError('Choose one explicit runtime executor')
        from .prototype_runtime_bridge import PrototypeRuntimeBridge
        runtime_verifier = PrototypeRuntimeBridge(settings.jobs_root,
            expected_worker_sha256=env.get('FOX_PROTOTYPE_RUNTIME_WORKER_SHA256', ''))
    return build_prototype_gateway(settings,
        authority_url=env.get('FOX_PROTOTYPE_AUTHORITY_URL', ''),
        authority_origin=env.get('FOX_PROTOTYPE_AUTHORITY_ORIGIN', ''),
        runtime_verifier=runtime_verifier)
