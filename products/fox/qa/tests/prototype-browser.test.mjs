/** Pure synthetic request checks; importing runner never launches Playwright. */
import test from 'node:test';
import assert from 'node:assert/strict';
import {allowedRequest,validatePacket,assertUnexpired,run,ORIGIN} from '../run-prototype.mjs';
import {sha256,canonicalQaPlan} from '../lib/contracts.mjs';

const packet=()=>{
  const source='a'.repeat(64),files={'run-prototype.mjs':'b'.repeat(64),'lib/contracts.mjs':'c'.repeat(64)};
  return {binding:{schema_version:1,scope:'fox-native-blueprint-runtime-v1',profile_id:'native-blueprint-prototype-v1',
    workspace:'FORMS2APEX_POC',application_id:12345,application_alias:'F2A_FOX_TEST',project_id:'synthetic',source_binding:source},
    spec:{profile_id:'native-blueprint-prototype-v1',project_id:'synthetic',source_binding:source,
      blocks:[{sequence:1,source_block_id:'block1',classification:'control',native_component:'page-items'}]},
    pages:[{page_id:1,source_block_id:'block1',checks:['render','native_items']}],
    credential_authority:{scope:'fox-prototype-runtime-credentials-target-v1',workspace:'FORMS2APEX_POC',ords_origin:ORIGIN,
      db_name:'ASZ8EQWFM8UNCA2_JSNF2APEX'},url:ORIGIN+'/ords/r/forms2apex_poc/f2a_fox_test/',
    image_id:'sha256:'+'d'.repeat(64),runner_files:files,code_sha256:sha256(canonicalQaPlan(files)),
    data_retention:'synthetic_test_rows_retained',deadline_at_utc:new Date(Date.now()+405_000).toISOString(),
    request_deadline_at_utc:new Date(Date.now()+480_000).toISOString()};
};
const request=(url,method='GET',body=null)=>({url:()=>url,method:()=>method,resourceType:()=> 'document',postData:()=>body,
  headers:()=>({'content-type':'application/x-www-form-urlencoded'})});

test('new-profile page plan and original credential target are mandatory',()=>{
  assert.equal(validatePacket(packet()).binding.application_id,12345);
  const old=packet();old.binding.profile_id='native-project-v1';assert.throws(()=>validatePacket(old));
  const missing=packet();missing.pages=[];assert.throws(()=>validatePacket(missing));
  const clean=packet();clean.credential_authority.workspace='FRESH_OTHER';assert.throws(()=>validatePacket(clean));
});
test('network routing rejects other apps external hosts unbound POST and malformed bodies',()=>{
  const value=packet();
  assert.equal(allowedRequest(request(value.url),value),true);
  assert.equal(allowedRequest(request(ORIGIN+'/ords/r/forms2apex_poc/other/'),value),false);
  assert.equal(allowedRequest(request('https://example.test/'),value),false);
  const endpoint=ORIGIN+'/ords/wwv_flow.accept';
  assert.equal(allowedRequest(request(endpoint,'POST','p_flow_id=12345&p_flow_step_id=1'),value),true);
  for(const body of ['p_flow_id=999&p_flow_step_id=1','p_flow_id=12345&p_flow_step_id=2',
    'p_flow_id=12345&p_flow_id=12345&p_flow_step_id=1','p_flow_id=12345&p_flow_step_id=%GG'])
    assert.equal(allowedRequest(request(endpoint,'POST',body),value),false);
});

test('expired or missing absolute expiry rejects every POST without network execution',()=>{
  const value=packet(),endpoint=ORIGIN+'/ords/wwv_flow.accept';
  const post=request(endpoint,'POST','p_flow_id=12345&p_flow_step_id=1');
  const expiry=Date.parse(value.deadline_at_utc);
  assert.equal(allowedRequest(post,value,expiry-1),true);
  assert.equal(allowedRequest(post,value,expiry),false);
  assert.equal(allowedRequest(post,value,expiry+1),false);
  for(const path of ['/ords/wwv_flow.ajax','/ords/wwv_flow.show'])
    assert.equal(allowedRequest(request(ORIGIN+path,'POST','p_flow_id=12345&p_flow_step_id=9999'),value,expiry),false);
  delete value.deadline_at_utc;
  assert.equal(allowedRequest(post,value),false);
  assert.throws(()=>validatePacket(value),/expiry/);
});

test('request expiry cannot be extended by the browser packet',()=>{
  const value=packet();
  value.deadline_at_utc=new Date(Date.parse(value.request_deadline_at_utc)+1).toISOString();
  assert.throws(()=>assertUnexpired(value),/expiry/);
});

test('APEX message and dialog scripts require exact app binding and script GET',()=>{
  const value=packet();
  for(const path of ['/ords/wwv_flow.js_messages','/ords/wwv_flow.js_dialogs']){
    const make=(query,method='GET',type='script')=>({...request(ORIGIN+path+query,method),resourceType:()=>type});
    assert.equal(allowedRequest(make('?p_app_id=12345&p_lang=en&p_version=26.1&p_nls_settings=x'),value),true);
    for(const query of ['', '?p_app_id=999', '?p_app_id=12345&p_app_id=12345',
      '?p_app_id=12345&unknown=x', '?p_app_id=12345&p_lang=%GG'])
      assert.equal(allowedRequest(make(query),value),false);
    assert.equal(allowedRequest(make('?p_app_id=12345','POST'),value),false);
    assert.equal(allowedRequest(make('?p_app_id=12345','GET','document'),value),false);
    assert.equal(allowedRequest(make('?p_app_id=12345'),value,Date.parse(value.deadline_at_utc)),false);
  }
  assert.equal(allowedRequest(request(ORIGIN+'/ords/r/apex/authentication-scheme-login/change-end-user-password'),value),false);
});

test('expired packet cannot launch even a synthetic browser',async()=>{
  const value=packet();value.deadline_at_utc='2026-01-01T00:00:00.000Z';
  let launches=0;
  await assert.rejects(run(value,{}, {launch:async()=>{launches++;throw Error('Forbidden synthetic browser launch');}}),/expiry/);
  assert.equal(launches,0);
});
