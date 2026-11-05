"""Additive v2 registration adapter; no CLI, credentials or automatic live action.

Trusted Python code binds fresh v2 candidate resources to the original scope
guards. The v1 executor supplies its one-write/create-only journal protocol and
all original graph, model, publication, identity and no-replay checks unchanged.
Only plan validation and receipt scope differ; no product profile is activated.
"""
from __future__ import annotations

from copy import deepcopy

from deployment import forms_understanding_registration as v1
from deployment.forms_understanding_profiles_v2 import build_candidates


ROLES = v1.ROLES
MODELS = v1.MODELS
SCOPE = v1.SCOPE
ENDPOINT = v1.ENDPOINT
PLAN_SCOPE = 'fox-forms-understanding-registration-v2'
RegistrationError = v1.RegistrationError
canonical_hash = v1.canonical_hash


def build_registration_plan(candidates, existing_profile):
    """Rebuild bundled v2 candidates; never trust caller-provided digests alone."""
    try:
        fresh = build_candidates()
        v1._require(canonical_hash(candidates) == canonical_hash(fresh),
                    'Candidates differ from freshly rebuilt resources.')
        return {'schema_version': 1, 'scope': PLAN_SCOPE, 'oci': deepcopy(SCOPE),
                'model_invocation': False, 'profile_activation': False,
                'existing_profile': v1._profile(existing_profile), 'candidates': deepcopy(fresh)}
    except RegistrationError:
        raise
    except Exception:
        raise RegistrationError('Invalid registration inputs.') from None


def validate_plan(plan, expected_plan_sha256=None):
    try:
        rebuilt = build_registration_plan(plan['candidates'], plan['existing_profile'])
        v1._require(canonical_hash(plan) == canonical_hash(rebuilt), 'Registration plan was altered.')
        digest = canonical_hash(rebuilt)
        if expected_plan_sha256 is not None:
            v1._require(type(expected_plan_sha256) is str and digest == expected_plan_sha256,
                        'Reviewed registration hash differs.')
        return digest
    except RegistrationError:
        raise
    except Exception:
        raise RegistrationError('Invalid registration plan.') from None


class RegistrationExecutor(v1.RegistrationExecutor):
    """The same guarded executor, restricted to freshly rebuilt v2 plans."""

    def _validated_plan(self, plan, expected_hash):
        return validate_plan(plan, expected_hash)

    def _receipt_scope(self):
        return PLAN_SCOPE
