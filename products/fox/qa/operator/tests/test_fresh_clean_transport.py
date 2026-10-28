"""Real private C3/R4/F program compilation; external OCI/Podman are synthetic.

Synthetic A/containers/child results test the transport, not admission or an
Oracle install. The original clean phase engine and production execution fence
are not replaced by a second implementation or a passing ready flag.
"""
import base64
from contextlib import redirect_stdout
from copy import deepcopy
import io
import json
import os
from pathlib import Path
import runpy
import subprocess
import sys
import tempfile
import unittest
import urllib.request
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[3]
POSIX=os.name=='posix' and hasattr(os,'geteuid') and os.geteuid()>0
SECRET='SyntheticAdminOnly9!'


def new_private_path(path):
    if path.exists():return
    new_private_path(path.parent)
    path.mkdir(mode=0o700)


def scenario(name,original):
    support=runpy.run_path(str(original/'qa/operator/tests/test_fresh_backend.py'))
    with tempfile.TemporaryDirectory(prefix='fct-') as temporary:
        parent=Path(temporary);parent.chmod(0o700);source=parent/'release'
        support['copy_source_closure'](original,source)
        fixture=support['Fixture'](parent,source)
        if name=='alternate':
            config=deepcopy(fixture.values['provider'])
            config['runtime']['roles']['fox']['name']='fox-fresh-alternate'
            config['runtime']['roles']['converter']['name']='forms2apex-fresh-alternate'
            config['runtime']['roles']['converter']['user']='20002:20003'
            fixture.put('provider',Path(fixture.refs['provider']['path']),config)
            release=deepcopy(fixture.values['release']);release['hosted_runtime_configuration_sha256']=fixture.refs['provider']['sha256']
            fixture.put('release',Path(fixture.refs['release']['path']),release)
        result=fixture.call();backend=result['backend_initialization']
        from qa.operator import runtime_provider as runtime, fresh_clean_transport as transport
        from qa.operator import clean_install as native,project_clean_install as project,fresh_remote as observer
        config=fixture.values['provider'];release_ref=fixture.refs['release']
        for role in config['runtime']['roles'].values():
            for mount in role['mounts']:
                path=Path(mount['source'])
                if not path.exists():new_private_path(path)
        new_private_path(Path(config['admin_secret_file']).parent)
        runtime.configure_fresh(fixture.refs['provider'],release_ref,backend,layout=fixture.layout)
        provider=runtime.selected_hosted()
        admission={'schema_version':1,'scope':'fox-fresh-live-admission-v1','installation_id':fixture.identity,
            'storage_completion_sha256':fixture.refs['completion']['sha256'],
            'app_projection_sha256':fixture.refs['projection']['sha256'],
            'provider_configuration_sha256':fixture.refs['provider']['sha256'],'release_sha256':release_ref['sha256'],
            'backend_initialization_sha256':backend['sha256'],'admission_sha256':'a'*64,
            'installation_sha256':'b'*64,'live_observation_sha256':'c'*64,'observed_at_utc':'2027-01-01T00:00:00Z',
            'transition':'INITIAL_TO_NORMAL','automatic_replay_permitted':False}
        if name!='fenced':
            path=fixture.public/'live-admission.json';path.write_bytes(support['canonical'](admission));path.chmod(0o600)
        projection=provider.runtime_projection();containers=[]
        for index,(role,wanted) in enumerate(config['runtime']['roles'].items(),1):
            env=observer.fox_environment(config,release_ref,backend) if role=='fox' else observer.converter_environment(config,release_ref,backend) if role=='converter' else {}
            containers.append({'Id':str(index)*64,'Name':'/'+wanted['name'],'Image':wanted['image'],
                'Config':{'User':wanted['user'],'Env':[key+'='+value for key,value in env.items()]},
                'State':{'Running':True},'HostConfig':{'ReadonlyRootfs':wanted['read_only_rootfs'],
                    'Tmpfs':{'/tmp':'rw,noexec,nosuid,nodev,size=64m,mode=1777'} if role=='fox' else {}},
                'Mounts':[{'Type':'bind','Source':x['source'],'Destination':x['destination'],'RW':not x['read_only']} for x in wanted['mounts']]})
        target=config['target_profile']['oci'];scope={key:target[key] for key in ('instance_id','database_id','compartment_id')}
        built={kind:transport.program(kind) for kind in ('source','native','project')}
        before=support['snapshot'](parent)
        if name=='routing':
            for cli in (native,project):
                calls=[]
                def stop(program,packet):calls.append(program);raise RuntimeError('SYNTHETIC_CAPTURE_ONLY')
                with patch.object(cli,'ssh_json',side_effect=stop):
                    try:cli.fetch_source('fox-'+'a'*20,'a'*64,scope)
                    except RuntimeError as error:assert str(error)=='SYNTHETIC_CAPTURE_ONLY'
                    else:raise AssertionError('NO_TRANSPORT_CALL')
                assert calls==[built['source']]
            assert support['snapshot'](parent)==before
            return {'status':'PASSED'}
        if name=='provider_fence':
            for kind in built:
                with patch.object(subprocess,'run',side_effect=AssertionError('NO_FRESH_HOST_LAUNCH')):
                    try:provider.execute_host(built[kind],b'{}',timeout=1)
                    except runtime.ProviderError as error:assert str(error)=='FRESH_BOUND_TRANSPORT_AND_ADMISSION_REQUIRED'
                    else:raise AssertionError('UNAUTHORIZED_FRESH_EXECUTION')
            assert support['snapshot'](parent)==before
            return {'status':'PASSED'}
        for kind in built:
            packet={'cli_scope':scope}
            if kind=='source':
                packet.update(fox_image=config['images']['fox'],reader_b64=base64.b64encode(native.SOURCE_CODE.encode()).decode(),
                              job_id='fox-'+'a'*20,package_sha256='a'*64)
            else:
                code=native.EXECUTOR_CODE if kind=='native' else project.EXECUTOR_CODE
                digest=fixture.values['release']['clean_operator_code_sha256'] if kind=='native' else fixture.values['release']['project']['clean_operator_code_sha256']
                packet.update(image=config['images']['converter'],executor_b64=base64.b64encode(code.encode()).decode(),
                    operator_code_sha256=digest,command='apply',apply=True,phase='allocate',admin_password=SECRET)
            calls=[]; inspections=[0]; measured=deepcopy(containers)
            if name=='wrong_environment':
                for item in measured:
                    item['Config']['Env']=[x for x in item['Config']['Env'] if not x.startswith(('FOX_FRESH_PROVIDER_SHA256=','F2A_FRESH_PROVIDER_SHA256='))]
            if name=='wrong_code':packet['reader_b64' if kind=='source' else 'executor_b64']=base64.b64encode(b'print("not trusted")').decode()
            if name=='wrong_image':packet['fox_image' if kind=='source' else 'image']='sha256:'+'f'*64
            def podman(args,**options):
                assert args[0]=='/usr/bin/podman'
                if args[1:3]==['inspect','--']:
                    inspections[0]+=1
                    rows=deepcopy(measured)
                    if name=='post_identity' and inspections[0]>1:rows[0]['Id']='f'*64
                    return subprocess.CompletedProcess(args,0,json.dumps(rows).encode(),b'')
                assert args[1]=='--remote=false'
                if args[2:4]==['inspect','--']:
                    rows=[x for x in measured if x['Id']==args[4]]
                    return subprocess.CompletedProcess(args,0,json.dumps(rows).encode(),b'')
                assert args[2:6]==['exec','-i','--user',config['runtime']['roles']['fox' if kind=='source' else 'converter']['user']]
                child_id=args[12]
                assert child_id in {x['Id'] for x in measured}
                assert args[-4:-1]==['-I','-B','-c'] and SECRET not in repr(args)
                program,body=options['input'].split(b'\n',1)
                assert base64.b64decode(program).decode()==(native.SOURCE_CODE if kind=='source' else native.EXECUTOR_CODE if kind=='native' else project.EXECUTOR_CODE)
                assert json.loads(body)==packet
                calls.append(child_id)
                if name=='child_error':return subprocess.CompletedProcess(args,1,SECRET.encode(),SECRET.encode())
                return subprocess.CompletedProcess(args,0,b'{"status":"SYNTHETIC_CHILD_BOUNDARY_ONLY"}',b'')
            metadata={'id':target['instance_id'],'compartmentId':target['compartment_id'],'canonicalRegionName':target['region']}
            output=io.StringIO()
            with patch.dict(os.environ,provider._environment(),clear=True), \
                 patch.object(sys,'stdin',io.TextIOWrapper(io.BytesIO(json.dumps(packet).encode()))), \
                 patch.object(urllib.request,'urlopen',return_value=io.BytesIO(json.dumps(metadata).encode())), \
                 patch.object(subprocess,'run',side_effect=podman),redirect_stdout(output):
                exec(compile(built[kind],'<actual-fresh-clean-host>','exec'),{})
            response=json.loads(output.getvalue());assert SECRET not in output.getvalue()
            if name in ('normal','alternate'):
                assert response=={'status':'SYNTHETIC_CHILD_BOUNDARY_ONLY'} and len(calls)==1
                assert calls[0]==containers[0 if kind=='source' else 1]['Id']
            else:
                assert response=={'status':'STOPPED','code':'FRESH_CLEAN_TRANSPORT_OUTCOME_UNCONFIRMED_NO_REPLAY','automatic_replay_permitted':False}
                assert len(calls)==(1 if name in ('child_error','post_identity') else 0)
        assert support['snapshot'](parent)==before
        return {'status':'PASSED'}


class FreshCleanHostTests(unittest.TestCase):
    def run_case(self,name):
        if not POSIX:self.skipTest('actual nonroot POSIX owner/source/files required')
        program='import json,runpy,sys;m=runpy.run_path(sys.argv[1]);print(json.dumps(m["scenario"](sys.argv[2],m["ROOT"])))'
        result=subprocess.run([sys.executable,'-I','-B','-c',program,str(Path(__file__).resolve()),name],
                              stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=120)
        self.assertEqual(result.returncode,0,result.stdout.decode()+result.stderr.decode())
        self.assertEqual(json.loads(result.stdout),{'status':'PASSED'})


for _name in ('normal','alternate','routing','provider_fence','fenced','wrong_environment','wrong_code','wrong_image','child_error','post_identity'):
    setattr(FreshCleanHostTests,'test_'+_name,lambda self,name=_name:self.run_case(name))
