"""Prepare a JSN current-pair C/R/plan, never activate or replay anything.

The source bundle and independently pinned current installation are checked
before importing or writing. Existing configuration/keys/state remain intact.
Only --apply creates a new private configuration directory; no container,
service, model, SQL or OCI state-changing operation is exposed.

--hosted-forms-queue explicitly authorizes a private queue on the existing /data
mount. Repeat the option on later upgrades; no environment variable enables it.
"""
from __future__ import annotations
import argparse
from copy import deepcopy
import importlib.util
import json
import os
from pathlib import Path
import sys

sys.dont_write_bytecode=True
spec=importlib.util.spec_from_file_location('upgrade_candidate_preparer',Path(__file__).with_name('activate_project_release.py'))
A=importlib.util.module_from_spec(spec);spec.loader.exec_module(A)
CONFIG_ROOT=Path('/home/opc/.config/fox-project-runtime')


def compose(configuration,root,images):
    """Pure declaration composition plus measured source reads, not authority."""
    from qa.operator import runtime_provider as runtime,product_verifier as verifier
    from forms2apex.target_profile import load_target_profile,target_profile_sha256
    root=Path(root)
    A.need(verifier.ROOT==root and Path(runtime.__file__).parent==root/'qa/operator',
           'NEW_SOURCE_NAMESPACE_REQUIRED')
    old=runtime.configuration_document(A.canonical(configuration),expected_sha256=A.sha(A.canonical(configuration)))
    runtime.validated_image_pins(images)
    A.need(old['schema_version']==2 and all(images[role]!=old['images'][role] for role in ('fox','converter')),
           'DISTINCT_CURRENT_PAIRED_RELEASE_REQUIRED')
    target=load_target_profile(root/'deployment/target-profile.jsn-project-v2.json')
    new=deepcopy(old)
    new.update(provider_sha256=A.sha(A.read(root/'qa/operator/runtime_provider.py')),
        target_profile=target,target_profile_sha256=target_profile_sha256(target),
        converter_root=str(root/'converter'),images=dict(images),
        converter_sources={name:A.sha(A.read(root/'converter'/name)) for name in runtime._SOURCE_FILES})
    raw=A.canonical(new);digest=A.sha(raw)
    runtime.configuration_document(raw,expected_sha256=digest)
    profile=root/'deployment/project-opaf-profile-v2.json'
    manifest=verifier.build_manifest({'schema_version':3,'scope':'fox-product-verifier-operator-config-v3',
        'enabled':True,'images':dict(images),'hosted_runtime_configuration_sha256':digest,
        'opaf_profile':{'path':'deployment/project-opaf-profile-v2.json','sha256':A.sha(A.read(profile)),
            'target_profile_sha256':new['target_profile_sha256']}},hosted_configuration=raw)
    # No secret, state or interpreter migration is implied by a new release.
    for key in ('owner_uid','python','state_root','admin_secret_file','public_mount_roots'):
        A.need(new[key]==old[key],'PRIVATE_ACCESS_OR_STATE_BOUNDARY_CHANGED')
    return raw,A.canonical(manifest)


def prepare(bundle_sha256,current_installation,*,apply=False,hosted_forms_queue=None):
    A.need(type(apply)is bool and type(bundle_sha256)is str and A.SHA.fullmatch(bundle_sha256),
           'EXACT_SOURCE_BUNDLE_REQUIRED')
    if hosted_forms_queue is not None:A.hosted_queue_path(hosted_forms_queue)
    A.host_identity()
    root=Path('/home/opc/.local/share/fox-project-builds')/bundle_sha256/'bundle'
    root,runtime,bridge,verifier=A.source_namespace(root,bundle_sha256)
    current=A.CurrentBaseline({'schema_version':2,'current_installation':current_installation})
    current.scope();before=A.baseline(current);A.validate_bound_sources(before)
    signature=A.baseline_signature(before)
    images={}
    for role in ('fox','converter'):
        receipt=A.parse(A.read(root.parent/(role+'-build-complete.json'),private=True))
        A.need(receipt.get('status')=='BUILT_NOT_ACTIVATED' and receipt.get('exit_code')==0
            and receipt.get('source_bundle_sha256')==bundle_sha256 and receipt.get('baseline_unchanged') is True,
            'COMPLETED_BOUND_IMAGE_BUILD_REQUIRED')
        reference=receipt.get('image')
        A.need(type(reference)is str and reference.startswith('sha256:') and A.SHA.fullmatch(reference[7:]),
            'BOUND_IMAGE_ID_REQUIRED')
        image=A.parse(A.command(['/usr/bin/podman','image','inspect',reference]))[0]
        A.need('sha256:'+image['Id'].removeprefix('sha256:')==reference
            and image['Architecture']=='amd64' and image['Os']=='linux'
            and image.get('Labels',{}).get('com.oracle.jsn.fox.source-bundle')==bundle_sha256,
            'BUILT_IMAGE_SOURCE_BINDING_CHANGED')
        images[role]=reference
    c,r=compose(current.configuration,root,images)
    destination=CONFIG_ROOT/bundle_sha256
    helper=A.read(Path(A.__file__).resolve())
    plan={'schema_version':2,'scope':A.UPGRADE_SCOPE,'source_bundle_sha256':bundle_sha256,
        'bundle_root':str(root),'provider':{'path':str(destination/'provider.json'),'sha256':A.sha(c)},
        'release':{'path':str(destination/'release.json'),'sha256':A.sha(r)},
        'current_installation':dict(current_installation),'helper_sha256':A.sha(helper)}
    if hosted_forms_queue is not None:plan['hosted_forms_queue']=hosted_forms_queue
    raw=A.canonical(plan);digest=A.sha(raw);A.plan_document(raw,digest)
    A.need(not destination.exists() and not destination.is_symlink(),'CONFIGURATION_ATTEMPT_EXISTS_INSPECT_NO_REPLAY')
    current.scope()
    A.need(A.baseline_signature(A.baseline(current))==signature,'CURRENT_RUNTIME_CHANGED_DURING_PREPARATION')
    result={'status':'UPGRADE_DECLARED_NOT_PREPARED','source_bundle_sha256':bundle_sha256,
        'provider_sha256':A.sha(c),'release_sha256':A.sha(r),'plan_sha256':digest,
        'current_installation_sha256':current_installation['sha256'],'configuration_directory':str(destination),
        'target_profile_sha256':A.parse(c)['target_profile_sha256'],'images':images,
        'files_written':False,'containers_started':False,'services_changed':False,'automatic_replay_permitted':False}
    if hosted_forms_queue is not None:result['hosted_forms_queue']=hosted_forms_queue
    if not apply:return result
    A.host_identity();current.scope()
    if not CONFIG_ROOT.exists():
        A.private_dir(CONFIG_ROOT.parent);CONFIG_ROOT.mkdir(mode=0o700);A.sync(CONFIG_ROOT.parent)
    A.private_dir(CONFIG_ROOT)
    destination.mkdir(mode=0o700);A.sync(CONFIG_ROOT)
    A.create_file(destination/'prepare-intent.json',A.canonical(result))
    for name,content in (('provider.json',c),('release.json',r),('activation-plan.json',raw),
            ('activate_project_release-'+A.sha(helper)+'.py',helper)):
        A.create_file(destination/name,content)
    current.scope()
    A.need(A.baseline_signature(A.baseline(current))==signature,'CURRENT_RUNTIME_CHANGED_DURING_PREPARATION')
    result.update(status='UPGRADE_CONFIGURATION_PREPARED_NOT_ACTIVATED',files_written=True)
    A.create_file(destination/'prepare-complete.json',A.canonical(result))
    return result


def main():
    os.umask(0o077)
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source-bundle-sha256',required=True)
    parser.add_argument('--current-installation',required=True)
    parser.add_argument('--current-installation-sha256',required=True)
    parser.add_argument('--hosted-forms-queue',help='Explicit private /data/native-preparations[-suffix] queue; requires a separately configured host processor')
    parser.add_argument('--apply',action='store_true')
    args=parser.parse_args()
    value=prepare(args.source_bundle_sha256,{'path':args.current_installation,
        'sha256':args.current_installation_sha256},apply=args.apply,hosted_forms_queue=args.hosted_forms_queue)
    print(json.dumps(value,sort_keys=True))


if __name__=='__main__':
    try:main()
    except Exception as error:
        print(json.dumps({'status':'NOT_PREPARED','code':str(error) if type(error)is A.ActivationError
            else 'UPGRADE_PREPARATION_UNCONFIRMED','automatic_replay_permitted':False}))
        raise SystemExit(1)
