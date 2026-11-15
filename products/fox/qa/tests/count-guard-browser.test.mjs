/** Actual local Edge with authored APEX DOM and intercepted synthetic network.
 * No Oracle/server/provider connection, SQL or business acceptance is proved. */
import test from 'node:test';
import assert from 'node:assert/strict';
import {createRequire} from 'node:module';
import {spawnSync} from 'node:child_process';
import {mkdtempSync,mkdirSync,writeFileSync,readFileSync} from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import {COUNT_PROFILE,COUNT_CHECKS,FAILURE,SUCCESS,validateCountFixture,exerciseCountGuard,consumeCountSubmission} from '../lib/count-guard.mjs';
import {allowedRequest,validatePacket,assertUnexpired,submitCountGuardAndWait,run,ORIGIN} from '../run-count-guard-v1.mjs';
import {sha256,canonicalQaPlan} from '../lib/contracts.mjs';

const hash=value=>sha256(canonicalQaPlan(value));
const product=path.resolve(import.meta.dirname,'../..');
const evidenceRoot=process.env.FOX_QA_EVIDENCE??path.join(os.tmpdir(),'fox-count-qa');
mkdirSync(evidenceRoot,{recursive:true});
const evidence=mkdtempSync(path.join(evidenceRoot,'count-browser-'));
const artifact=(name,value)=>writeFileSync(path.join(evidence,name),typeof value==='string'?value:canonicalQaPlan(value),{flag:'wx'});

function packet(){
  const ids={owner_block:'owner',detail_block:'detail',bind_block:'owner',bind_item:'bind',key_item:'key',value_item:'value'};
  const spec={schema_version:3,profile_id:COUNT_PROFILE,project_id:'synthetic-count-browser',source_binding:'a'.repeat(64),
    input_validation_policy:'forms-required-inputs-v1',count_guard:{source_objects:ids,partial_scope_consent:true,
      policy_id:'forms-null-zero-count-guard-v1',scope:'isolated_pre_action_validation_only',source_rule_sha256:'e'.repeat(64)},
    blocks:[{sequence:1,source_block_id:'owner',name:'MASTER',classification:'database',native_component:'form',table_name:'F2A_OWNER',
      fields:[{source_item_id:'bind',name:'GROUP_KEY',data_type:'VARCHAR2',length:80,value_required:true,in_edit_form:true,widget:'text'}]},
    {sequence:2,source_block_id:'detail',name:'DETAIL',classification:'database',native_component:'report',table_name:'F2A_DETAIL',
      fields:[{source_item_id:'key',name:'GROUP_KEY',data_type:'VARCHAR2',length:80,value_required:false,in_edit_form:false,widget:'text'},
        {source_item_id:'value',name:'AMOUNT',data_type:'NUMBER',value_required:false,in_edit_form:false,widget:'number'},
        {source_item_id:'other',name:'OTHER',data_type:'VARCHAR2',length:80,value_required:false,in_edit_form:false,widget:'text'}]}]};
  const job='synthetic-browser-check',seed=hash([job,spec.project_id,spec.source_binding,spec.count_guard]);
  const plan={schema_version:1,scope:'fox-count-guard-synthetic-fixture-v1',job_id:job,project_id:spec.project_id,
    source_binding:spec.source_binding,rendering_spec_sha256:hash(spec),source_rule_sha256:spec.count_guard.source_rule_sha256,
    table_name:'F2A_DETAIL',source_block_id:'detail',key_column:'GROUP_KEY',value_column:'AMOUNT',key_type:'VARCHAR2',page_id:1,
    key_item:'P1_FOX_COUNT_GUARD_KEY',request:'FOX_COUNT_GUARD_CHECK',other_columns:['OTHER'],
    cases:['null','zero','positive','negative'].map((name,i)=>({case:name,key:`FCG${seed.slice(0,12).toUpperCase()}${i}`,
      value:[null,0,2,-1][i],expected_blocked:i<2})),data_mode:'synthetic_qa_only',rows_retained:true};
  const fixture={plan,plan_sha256:hash(plan),prepared:true,request_sha256:'b'.repeat(64),fixture_sql_sha256:'c'.repeat(64),
    rows:plan.cases.map((row,i)=>({case:row.case,primary_key:String(i+100)}))};
  const files=Object.fromEntries(['run-count-guard-v1.mjs','lib/contracts.mjs','lib/count-guard.mjs']
    .map(name=>[name,sha256(readFileSync(path.join(product,'qa',name)))]));
  return {binding:{schema_version:1,scope:'fox-native-blueprint-runtime-v1',profile_id:COUNT_PROFILE,job_id:job,
    project_id:spec.project_id,source_binding:spec.source_binding,count_guard_fixture_sha256:hash(fixture),
    workspace:'FORMS2APEX_POC',application_id:12345,application_alias:'F2A_SYNTHETIC_BROWSER_CHECK'},
    spec,count_guard_fixture:fixture,pages:[{page_id:1,source_block_id:'owner',checks:['render','report_columns','search','detail_navigation',...COUNT_CHECKS]},
      {page_id:2,source_block_id:'owner',checks:['render','native_items','create','update','synthetic_records_accounted','additional_required_input_validation']},
      {page_id:3,source_block_id:'detail',checks:['render','report_columns','search']}],
    credential_authority:{scope:'fox-prototype-runtime-credentials-target-v1',workspace:'FORMS2APEX_POC',ords_origin:ORIGIN,
      db_name:'ASZ8EQWFM8UNCA2_JSNF2APEX',username_sha256:sha256('synthetic-count-user')},
    url:ORIGIN+'/ords/r/forms2apex_poc/f2a_synthetic_browser_check/',image_id:'sha256:'+'f'.repeat(64),
    runner_files:files,code_sha256:hash(files),data_retention:'synthetic_test_rows_retained',
    deadline_at_utc:new Date(Date.now()+400_000).toISOString(),request_deadline_at_utc:new Date(Date.now()+480_000).toISOString()};
}

test('v3 reconstructs exact fixture and seven checks without making report-only detail editable',()=>{
  assert.equal(sha256(readFileSync(path.join(product,'qa/run-prototype.mjs'))),
    '4c9c6f5492a96294dbdd611a95995a5dbf6aab8dd1231fa532b1bffbd0536add',
    'Historical completed-flow runner bytes must not be replaced by the v3 driver');
  const value=packet();assert.equal(validatePacket(value),value);
  assert.deepEqual(validateCountFixture(value).plan,value.count_guard_fixture.plan);
  assert.equal(COUNT_CHECKS.length,7);assert.equal(COUNT_CHECKS.at(-1),'count_guard_no_approval_request');
  assert.equal(value.spec.blocks[1].native_component,'report');
  assert.equal(value.pages[1].checks.includes('additional_required_input_validation'),true);
  for(const change of [p=>delete p.count_guard_fixture,p=>p.binding.count_guard_fixture_sha256='0'.repeat(64),
    p=>p.count_guard_fixture.plan.project_id='other',p=>p.count_guard_fixture.rows[1].primary_key='100',
    p=>p.count_guard_fixture.plan.cases[2].value=0,p=>p.pages[0].checks.pop(),
    p=>p.spec.blocks[0].fields[0].value_required='true']){
    const changed=packet();change(changed);
    // Even a coherently re-hashed altered receipt must fail independent plan
    // reconstruction, not just the outer checksum comparison.
    if(changed.count_guard_fixture&&changed.binding.count_guard_fixture_sha256!=='0'.repeat(64)){
      changed.count_guard_fixture.plan_sha256=hash(changed.count_guard_fixture.plan);
      changed.binding.count_guard_fixture_sha256=hash(changed.count_guard_fixture);
    }
    assert.throws(()=>validatePacket(changed));
  }
  for(const profile of ['native-blueprint-prototype-v1','native-blueprint-prototype-required-v1']){
    const changed=packet();changed.binding.profile_id=changed.spec.profile_id=profile;
    assert.throws(()=>validatePacket(changed),/Unbound runtime target/);
  }
});

test('Python converter fixture hash and independent browser plan are identical',{skip:!process.env.FOX_TEST_PYTHON},()=>{
  const source=`import sys,json\nsys.path[:0]=['converter','converter/tests']\nfrom test_count_guard_integration import request_and_import\nfrom forms2apex.prototype_package import runtime_binding,expected_runtime_pages\nr,i,a=request_and_import()\nprint(json.dumps({'spec':r['rendering_spec'],'binding':runtime_binding(r,i,a),'pages':expected_runtime_pages(r['rendering_spec']),'count_guard_fixture':r['prior_receipts']['prepare_schema']['count_guard_fixture']}))`;
  const result=spawnSync(process.env.FOX_TEST_PYTHON,['-B','-c',source],{cwd:product,encoding:'utf8'});
  assert.equal(result.status,0,result.stderr);const actual=JSON.parse(result.stdout);
  const value={...packet(),...actual};value.url=ORIGIN+'/ords/r/forms2apex_poc/'+actual.binding.application_alias.toLowerCase()+'/';
  assert.equal(validatePacket(value),value);
  artifact('python-contract.json',{fixture_sha256:hash(actual.count_guard_fixture),plan_sha256:hash(actual.count_guard_fixture.plan),
    runner_files:value.runner_files,code_sha256:value.code_sha256});
});

test('missing stale or expired v3 fixture cannot launch any browser',async()=>{
  for(const change of [p=>delete p.count_guard_fixture,p=>p.spec.source_binding='stale',
    p=>p.deadline_at_utc='2026-01-01T00:00:00.000Z']){
    const value=packet();change(value);let launched=0;
    await assert.rejects(run(value,{}, {launch:async()=>{launched++;throw Error('MUST_NOT_LAUNCH');}}));
    assert.equal(launched,0);
  }
});

const request=body=>({url:()=>ORIGIN+'/ords/wwv_flow.accept',method:()=> 'POST',postData:()=>body,
  resourceType:()=> 'document',headers:()=>({'content-type':'application/x-www-form-urlencoded'})});
test('check-only network fence refuses Save approval duplicate and wrong app/page requests',()=>{
  const value=packet(),base='p_flow_id=12345&p_flow_step_id=1&p_request=';
  assert.equal(allowedRequest(request(base+'FOX_COUNT_GUARD_CHECK'),value,Date.now(),1),true);
  for(const body of [base+'SAVE',base+'APPROVE',base,base+'FOX_COUNT_GUARD_CHECK&p_request=SAVE',
    'p_flow_id=999&p_flow_step_id=1&p_request=FOX_COUNT_GUARD_CHECK',
    'p_flow_id=12345&p_flow_step_id=2&p_request=FOX_COUNT_GUARD_CHECK'])
    assert.equal(allowedRequest(request(body),value,Date.now(),1),false);
  assert.equal(allowedRequest(request(base+'FOX_COUNT_GUARD_CHECK'),value,Date.parse(value.deadline_at_utc),1),false);
});

test('per-case submission intent is exact and consumed once, never by wrong missing or duplicate keys',()=>{
  const intent={key_item:'P1_FOX_COUNT_GUARD_KEY',key:'FCG_SYNTHETIC',submitted:false};
  const target={n:intent.key_item,v:intent.key},json=JSON.stringify({pageItems:{itemsToSubmit:[target]}});
  const bodyFor=(items,extras={})=>new URLSearchParams({p_json:JSON.stringify({pageItems:{itemsToSubmit:items}}),...extras}).toString();
  for(const body of ['',intent.key_item+'=FCG_SYNTHETIC',bodyFor([]),bodyFor([{...target,v:'wrong'}]),bodyFor([target,target]),
    bodyFor([{...target,v:['FCG_SYNTHETIC']}]),bodyFor([target],{[intent.key_item]:intent.key}),
    'p_json='+encodeURIComponent('{"pageItems":{},"pageItems":{"itemsToSubmit":[]}}'),
    'p_json='+encodeURIComponent(json.slice(0,-1)),bodyFor([{...target,unknown:true}])]){
    assert.equal(consumeCountSubmission(request(body),intent),false);assert.equal(intent.submitted,false);
  }
  const chunked=new URLSearchParams();chunked.append('p_json',json.slice(0,10));chunked.append('p_json',json.slice(10));
  assert.equal(consumeCountSubmission(request(chunked.toString()),intent),true);
  assert.equal(consumeCountSubmission(request(bodyFor([target])),intent),false);
});

test('actual local headless browser: four native check submissions and fail-closed outcomes',async t=>{
  const require=createRequire(process.env.FOX_TEST_NODE_PACKAGES?path.join(process.env.FOX_TEST_NODE_PACKAGES,'../package.json'):import.meta.url);
  const {chromium}=require('playwright');
  const browser=await chromium.launch({channel:'msedge',headless:true});
  artifact('local-browser-runtime.json',{scope:'LOCAL_INSTALLED_TOOLS_NOT_DEPLOYED_RUNNER',
    playwright_version:require('playwright/package.json').version,browser_version:browser.version(),channel:'msedge',
    node_version:process.version});
  try{
    for(const mode of ['success','chunked-json','conflict','unexpected-error','failed-response','unknown','wrong-request','wrong-page','wrong-account','expiry',
      'wrong-key','duplicate-key','missing-group','duplicate-post']){
      await t.test(mode,async()=>{
        const value=packet(),plan=value.count_guard_fixture.plan,context=await browser.newContext();
        const posts=[],blocked=[],records=[];let expired=false,unsafe=false,intent=null;
        // Minimal authored reproduction of Oracle 26.1.6 browserSubmit's
        // pageItems -> ordered p_json hidden fields, not a native APEX server.
        const script=`const key=this.elements.${plan.key_item};let items=[{n:'${plan.key_item}',v:key.value}];
          ${mode==='wrong-key'?"items[0].v='other-group';":mode==='duplicate-key'?'items.push({...items[0]});':mode==='missing-group'?'items=[];':''}
          const raw=JSON.stringify({pageItems:{itemsToSubmit:items,protected:'${mode==='chunked-json'?'x'.repeat(8200):''}',rowVersion:'',formRegionChecksums:[]}});
          key.removeAttribute('name');for(let i=0;i<raw.length;i+=8000){const hidden=document.createElement('input');hidden.type='hidden';hidden.name='p_json';hidden.value=raw.slice(i,i+8000);this.appendChild(hidden);}
          ${mode==='duplicate-post'?"fetch(this.action,{method:'POST',body:new URLSearchParams(new FormData(this))}).catch(()=>{})":''}`;
        const document=(message='',extra='',app='12345',user='synthetic-count-user')=>`<!doctype html><html><body>
          <input name="p_flow_id" value="${app}"><input name="p_flow_step_id" value="1">
          <span class="t-Button-label">${user}</span><form method="POST" action="/ords/wwv_flow.accept" onsubmit="${script}">
          <input name="p_flow_id" value="12345"><input name="p_flow_step_id" value="${mode==='wrong-page'?'3':'1'}">
          <input name="p_request" value="${mode==='wrong-request'?'SAVE':'FOX_COUNT_GUARD_CHECK'}">
          <input name="P1_FOX_COUNT_GUARD_KEY"><button>Check null or zero values only</button></form>
          ${message?`<div>${message}</div>`:''}${extra}</body></html>`;
        // Both app/page hidden fields must be unique as on the actual APEX document.
        const html=(...args)=>document(...args).replace('<input name="p_flow_id" value="12345"><input name="p_flow_step_id" value="1">','');
        await context.route('**/*',async route=>{
          const req=route.request();
          if(!allowedRequest(req,value,expired?Date.parse(value.deadline_at_utc):Date.now(),1)
            ||req.method()==='POST'&&!consumeCountSubmission(req,intent)){
            unsafe=true;
            blocked.push({method:req.method(),url:req.url()});return route.abort('blockedbyclient');
          }
          if(req.method()==='POST'){
            const body=new URLSearchParams(req.postData()),json=JSON.parse(body.getAll('p_json').join(''));
            const row=plan.cases.find(row=>row.key===json.pageItems.itemsToSubmit.find(item=>item.n===plan.key_item)?.v);
            posts.push({case:row?.case,request:body.get('p_request')});
            if(mode==='unknown')return route.abort('failed');
            const message=row.expected_blocked?FAILURE:SUCCESS;
            const extra=mode==='conflict'?`<div>${row.expected_blocked?SUCCESS:FAILURE}</div>`:
              mode==='unexpected-error'?'<div class="t-Alert--danger">Unrelated failure</div>':'';
            return route.fulfill({status:mode==='failed-response'?500:200,contentType:'text/html',
              body:html(message,extra,mode==='wrong-page'?'999':'12345')});
          }
          await route.fulfill({status:200,contentType:'text/html',body:html('', '', '12345',mode==='wrong-account'?'other-user':'synthetic-count-user')});
        });
        const page=await context.newPage();page.setDefaultTimeout(300);page.setDefaultNavigationTimeout(1000);
        const guard=()=>{assertUnexpired(value,expired?Date.parse(value.deadline_at_utc):Date.now());assert.equal(unsafe,false,'Unsafe browser state');};
        const identity=async id=>{guard();assert.equal(await page.locator('[name="p_flow_id"]').first().inputValue(),'12345');
          assert.equal(await page.locator('[name="p_flow_step_id"]').first().inputValue(),String(id));};
        const account=async()=>assert.equal(sha256((await page.locator('.t-Button-label').innerText()).toLowerCase()),value.credential_authority.username_sha256);
        const callbacks={guard,navigate:async()=>{guard();await page.goto(value.url+'block_1');},identity,account,
          act:async action=>{guard();return action();},record:async row=>{records.push(row);if(mode==='expiry')expired=true;},
          submit:async(pageId,action,row)=>{
            intent={key_item:plan.key_item,key:row.key,submitted:false};
            await submitCountGuardAndWait(page,{applicationId:12345,pageId,action,timeout:400});
            guard();assert.equal(intent.submitted,true);intent=null;
          }};
        try{
          if(['success','chunked-json'].includes(mode)){
            const checks=await exerciseCountGuard(page,value,callbacks);
            assert.deepEqual(checks,Object.fromEntries(COUNT_CHECKS.map(name=>[name,true])));
            assert.deepEqual(posts,plan.cases.map(row=>({case:row.case,request:plan.request})));
            assert.equal(records.length,4);assert.equal(blocked.length,0);
            await page.screenshot({path:path.join(evidence,mode==='success'?'four-cases-success.png':'chunked-json-success.png')});
          }else{
            await assert.rejects(exerciseCountGuard(page,value,callbacks));
            assert.ok(posts.length<=1,'No automatic retry after any failure');assert.ok(records.length<=1);
            if(['wrong-request','wrong-page','wrong-account','expiry','wrong-key','duplicate-key','missing-group'].includes(mode))assert.equal(posts.length,0);
            await page.screenshot({path:path.join(evidence,mode+'.png')}).catch(()=>{});
          }
          artifact(mode+'.json',{scope:'LOCAL_AUTHORED_APEX_DOM_NETWORK_NOT_ORACLE',mode,posts,blocked,records,
            fixture_sha256:value.binding.count_guard_fixture_sha256,business_behavior_accepted:false});
        }finally{await context.close();}
      });
    }
  }finally{await browser.close();}
});
