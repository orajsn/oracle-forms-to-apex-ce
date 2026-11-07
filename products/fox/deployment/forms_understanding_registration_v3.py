"""Additive two-role v3 registration using the existing create-only protocol."""
from copy import deepcopy
from deployment import forms_understanding_registration as base
from deployment.forms_understanding_profiles_v3 import build_candidates

ROLES = ('baseline43', 'reviewer43')
MODELS = {role: 'xai.grok-4.3' for role in ROLES}
SCOPE, ENDPOINT = base.SCOPE, base.ENDPOINT
PLAN_SCOPE = 'fox-forms-understanding-registration-v3'
RegistrationError, canonical_hash = base.RegistrationError, base.canonical_hash


def build_registration_plan(candidates, existing_profile):
    fresh = build_candidates()
    base._require(canonical_hash(candidates) == canonical_hash(fresh), 'Candidates differ from bundled resources.')
    return {'schema_version': 1, 'scope': PLAN_SCOPE, 'oci': deepcopy(SCOPE),
            'model_invocation': False, 'profile_activation': False,
            'existing_profile': base._profile(existing_profile), 'candidates': fresh}


def validate_plan(plan, expected_plan_sha256=None):
    try:
        rebuilt = build_registration_plan(plan['candidates'], plan['existing_profile'])
        digest = canonical_hash(rebuilt)
        base._require(canonical_hash(plan) == digest, 'Registration plan changed.')
        base._require(expected_plan_sha256 is None or expected_plan_sha256 == digest, 'Reviewed plan hash changed.')
        return digest
    except RegistrationError:
        raise
    except Exception:
        raise RegistrationError('Invalid v3 registration plan.') from None


class RegistrationExecutor(base.RegistrationExecutor):
    def _roles(self):
        return ROLES

    def _validated_plan(self, plan, expected_hash):
        return validate_plan(plan, expected_hash)

    def _receipt_scope(self):
        return PLAN_SCOPE
