"""Pure preparation of project QA inputs from exact private clean evidence.

No SQL, browser, credential lookup or filesystem work occurs here. Preparing a
target is not a claim that browser verification passed. The independent project
proof reader remains the only authority for technical promotion.
"""
from . import contracts as c
from . import project_contracts as pc
from fox.native_qa_plan import qa_plan_sha256
from fox.native_verification import ORDS
from fox.native_verification_policy import BoundVerificationPolicy, validate_allocation_receipt
from fox.project_qa_plan import derive_project_qa_plan, derive_project_qa_profile
from fox.project_verification import _validate_clean

HANDOFF = ('package.zip', 'native-project-spec.json', 'source-to-apex.json',
           'allocate.evidence.json', 'verification-profile.json',
           'verify.evidence.json', 'runtime-credentials.json')


def prepare_inputs(plan_raw, files, *, operator_code_sha256):
    """Derive every form's target/profile; reject omitted or changed evidence."""
    c._require(type(files) is dict and set(files) == set(HANDOFF)
               and all(type(raw) is bytes and raw for raw in files.values()), 'Project handoff members differ.')
    plan = pc.validate_plan(plan_raw, operator_code_sha256=operator_code_sha256)
    package = pc.load_package(files['package.zip'], plan['binding']['package_sha256'])
    pc.validate_plan(plan_raw, package=package)
    c._require(files['native-project-spec.json'] == package['project_raw']
               and files['source-to-apex.json'] == package['trace_raw'], 'Project handoff source bytes differ.')
    allocation_raw = files['allocate.evidence.json']
    pc.validate_allocation(allocation_raw, plan)
    expected_policy = c.canonical_bytes(pc.make_verification_profile(plan, allocation_raw))
    c._require(files['verification-profile.json'] == expected_policy, 'Project handoff policy differs.')
    policy = BoundVerificationPolicy(expected_policy)
    validate_allocation_receipt(allocation_raw, policy)
    qa_plan = derive_project_qa_plan(package['project'], c.digest(package['project_raw']),
                                   package['trace'], c.digest(package['trace_raw']))
    binding = {key: plan['binding'][key] for key in ('job_id', *pc.HASH_KEYS)}
    binding.update(verification_profile_sha256=c.digest(expected_policy),
                   allocation_receipt_sha256=c.digest(allocation_raw))
    imported = c.load_json(files['verify.evidence.json'])
    _validate_clean(imported, package['project'], qa_plan, binding, policy,
                    package['binding']['original_parsing_schema'])
    c._require(imported.get('authenticated_runtime_passed') is False
               and imported.get('human_acceptance_recorded') is False,
               'Clean import must not claim browser or human acceptance.')
    accounts = c.load_json(files['runtime-credentials.json'])
    c._require(set(accounts) == {'username', 'password', 'second_username', 'second_password'}
               and all(type(v) is str and 0 < len(v) <= 1024 for v in accounts.values())
               and accounts['username'] == 'FOX_QA_A' and accounts['second_username'] == 'FOX_QA_B'
               and accounts['password'] != accounts['second_password'], 'Two allocator runtime identities are required.')
    profile_raw = c.canonical_bytes(derive_project_qa_profile(package['project'], qa_plan))
    target = {'schema_version': 1, 'scope': 'fox-project-qa-target-v1', **binding,
              'target': policy.target, 'url': ORDS + '/r/'
              + policy.target['workspace'].lower() + '/' + policy.target['application_alias'].lower() + '/',
              'profile_sha256': c.digest(profile_raw), 'import_receipt_sha256': c.digest(files['verify.evidence.json']),
              'test_plan_sha256': qa_plan_sha256(qa_plan), 'synthetic_qa_approved': True}
    return {'profile.json': profile_raw, 'target.json': c.canonical_bytes(target)}
