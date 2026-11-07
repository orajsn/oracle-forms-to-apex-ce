"""Add only a reviewer; require and preserve the already published v3 mapper."""
from copy import deepcopy
from deployment import forms_understanding_registration as base
from deployment.forms_understanding_profiles_v4 import build_candidates

SCOPE = base.SCOPE
PLAN_SCOPE = 'fox-forms-understanding-registration-v4'
ROLES = ('baseline43', 'reviewer43')
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
        base._require(canonical_hash(plan) == digest and
                      (expected_plan_sha256 is None or expected_plan_sha256 == digest), 'Reviewed registration plan changed.')
        return digest
    except RegistrationError:
        raise
    except Exception:
        raise RegistrationError('Invalid reviewer-only registration plan.') from None


class RegistrationExecutor(base.RegistrationExecutor):
    def _roles(self):
        return ROLES

    def _validated_plan(self, plan, expected_hash):
        return validate_plan(plan, expected_hash)

    def _receipt_scope(self):
        return PLAN_SCOPE

    def _guard(self, plan):
        originals = super()._guard(plan)
        mapper = self._candidates(plan)['baseline43']
        base._require(mapper is not None and mapper['published'] is True, 'Existing published v3 mapper required.')
        return originals

    def act(self, plan, *, role, operation, expected_plan_sha256, explicit_apply=False):
        base._require(role == 'reviewer43', 'Only the new reviewer may be registered.')
        return super().act(plan, role=role, operation=operation,
                           expected_plan_sha256=expected_plan_sha256, explicit_apply=explicit_apply)
