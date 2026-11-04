"""Create an ignored, nonsecret legacy profile for offline source tests only.

No connection, credentials, target selection, service or model operation occurs.
Existing configured files are never overwritten. Defaults to inspection only.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import os
from pathlib import Path
import stat
import sys

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'converter'))
from forms2apex.target_profile import load_target_profile,select_target_profile


class TestProfileError(ValueError):
    """Bounded local diagnostics, never configuration contents."""


def need(value,code):
    if not value:raise TestProfileError(code)


def ordinary(path):
    for item in (path,*path.parents):
        info=item.lstat()
        need(not stat.S_ISLNK(info.st_mode) and not getattr(info,'st_file_attributes',0)&0x400,
             'TEST_PROFILE_LINK_FORBIDDEN')
    need(path.resolve()==path,'TEST_PROFILE_CANONICAL_PATH_REQUIRED')


def prepare(root=ROOT,*,apply=False):
    need(type(apply) is bool,'TEST_PROFILE_EXPLICIT_MODE_REQUIRED')
    root=Path(root).absolute();ordinary(root)
    deployment=root/'deployment';ordinary(deployment)
    source=deployment/'target-profile.jsn.json';ordinary(source)
    need(load_target_profile(source)==select_target_profile('jsn-native-beta-v1'),
         'REGISTERED_LEGACY_TEST_SOURCE_REQUIRED')
    target=load_target_profile(source);opaf=target['opaf']
    profile={'schema_version':1,'profile_id':'native-table-form-v1',
        'opaf_base_url':opaf['base_url'],'certificate_sha256':opaf['certificate_sha256'],
        **opaf['roles']}
    raw=(json.dumps(profile,sort_keys=True,indent=2)+'\n').encode()
    destination=deployment/'native-beta-profile.json'
    if os.path.lexists(destination):
        ordinary(destination);info=destination.lstat()
        need(stat.S_ISREG(info.st_mode) and info.st_nlink==1 and info.st_size<=32768,
             'EXISTING_PROFILE_REQUIRES_REVIEW')
        need(destination.read_bytes()==raw,'EXISTING_PROFILE_REQUIRES_REVIEW')
        status='TEST_PROFILE_UNCHANGED'
    elif apply:
        with os.fdopen(os.open(destination,os.O_WRONLY|os.O_CREAT|os.O_EXCL|
                getattr(os,'O_NOFOLLOW',0),0o600),'wb') as stream:
            stream.write(raw);stream.flush();os.fsync(stream.fileno())
        status='TEST_PROFILE_CREATED'
    else:status='TEST_PROFILE_MISSING_NOT_CREATED'
    return {'status':status,'profile_sha256':hashlib.sha256(raw).hexdigest(),
        'test_configuration_only':True,'connection_tested':False,'conversion_ready':False}


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source-root',default=str(ROOT));parser.add_argument('--apply',action='store_true')
    args=parser.parse_args()
    try:print(json.dumps(prepare(args.source_root,apply=args.apply),sort_keys=True))
    except Exception as error:
        print(json.dumps({'status':'NOT_PREPARED','code':str(error) if type(error) is TestProfileError
                         else 'TEST_PROFILE_INPUT_CHECK_FAILED'}));raise SystemExit(1)
