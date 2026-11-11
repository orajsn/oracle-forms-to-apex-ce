/** Pure synthetic request checks; importing runner never launches Playwright. */
import test from 'node:test';
import assert from 'node:assert/strict';
import {allowedRequest,validatePacket,assertUnexpired,assertAdditionalRequiredInputRejected,sourceNavigationUrl,resetNativeReport,
  submitAndWaitForPage,closeRejectedNewRecord,run,ORIGIN} from '../run-prototype.mjs';
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

const requiredPacket=()=>{
  const value=packet();
  value.binding.profile_id=value.spec.profile_id='native-blueprint-prototype-required-v1';
  value.spec.schema_version=2;value.spec.input_validation_policy='forms-required-inputs-v1';
  value.spec.blocks=[{sequence:1,source_block_id:'block1',classification:'database',native_component:'form',
    fields:[{source_item_id:'item1',name:'FIELD1',in_edit_form:true,widget:'text',value_required:true},
      {source_item_id:'item2',name:'FIELD2',in_edit_form:true,widget:'number',value_required:false}]}];
  value.pages=[{page_id:1,source_block_id:'block1',checks:['render','report_columns','search','detail_navigation']},
    {page_id:2,source_block_id:'block1',checks:['render','native_items','create','update','synthetic_records_accounted',
      'additional_required_input_validation']}];
  return value;
};

test('required profile has an exact version policy and independent additional runtime check',()=>{
  assert.equal(validatePacket(requiredPacket()).spec.schema_version,2);
  for(const change of [value=>value.spec.schema_version=1,
    value=>value.spec.input_validation_policy='other',value=>delete value.spec.input_validation_policy,
    value=>value.pages[1].checks.pop(),value=>value.spec.profile_id='native-blueprint-prototype-v1']){
    const value=requiredPacket();change(value);assert.throws(()=>validatePacket(value));
  }
});

test('required profile refuses nonboolean flags and noneditable/report/control/display required targets',()=>{
  for(const flag of [null,undefined,1,0,'true','false',{},[]]){
    const value=requiredPacket();value.spec.blocks[0].fields[0].value_required=flag;
    assert.throws(()=>validatePacket(value),/item policy/);
  }
  for(const change of [block=>block.native_component='report',block=>block.classification='control',
    block=>block.fields[0].in_edit_form=false,block=>block.fields[0].widget='display']){
    const value=requiredPacket();change(value.spec.blocks[0]);assert.throws(()=>validatePacket(value),/item policy/);
  }
});

function requiredProbe({initial='',after='',errors=1,valueMissing=false}={}){
  let submitted=false,waited=false;
  const input={inputValue:async()=>submitted?after:initial,evaluate:async()=>valueMissing};
  const page={locator:selector=>selector.startsWith('[name=')?input:{count:async()=>errors},
    waitForLoadState:async mode=>{assert.equal(mode,'networkidle');waited=true;}};
  return {page,submit:async()=>{submitted=true;},observed:()=>({submitted,waited})};
}

test('negative required probe needs a matching field rejection before continuation',async()=>{
  for(const options of [{errors:1},{errors:0,valueMissing:true}]){
    const probe=requiredProbe(options);let guards=0;
    await assertAdditionalRequiredInputRejected(probe.page,'P2_FIELD1',probe.submit,()=>{guards++;});
    assert.deepEqual(probe.observed(),{submitted:true,waited:true});assert.equal(guards,1);
  }
  const missing=requiredProbe({errors:0});
  await assert.rejects(assertAdditionalRequiredInputRejected(missing.page,'P2_FIELD1',missing.submit,()=>{}),/not rejected/);
  const nonempty=requiredProbe({initial:'A'});
  await assert.rejects(assertAdditionalRequiredInputRejected(nonempty.page,'P2_FIELD1',nonempty.submit,()=>{}),/must be empty/);
  assert.equal(nonempty.observed().submitted,false);
  const changed=requiredProbe({after:'A'});
  await assert.rejects(assertAdditionalRequiredInputRejected(changed.page,'P2_FIELD1',changed.submit,()=>{}),/unexpectedly changed/);
});

test('negative required probe never ignores a failed no-POST or freshness fence',async()=>{
  const probe=requiredProbe();
  await assert.rejects(assertAdditionalRequiredInputRejected(probe.page,'P2_FIELD1',probe.submit,
    ()=>{throw Error('Unexpected POST blocked before DML');}),/POST blocked/);
});

function navigationPage(elements){
  // Synthetic DOM query model: ensure the actual helper requests both exact
  // roles including hidden elements, then intersects with real href anchors.
  function locator(selected){return {
    selected,
    or:other=>locator([...new Set([...selected,...other.selected])]),
    and:other=>locator(selected.filter(element=>other.selected.includes(element))),
    evaluateAll:async callback=>callback(selected)
  };}
  return {
    getByRole:(role,options)=>{
      assert.equal(options.exact,true);assert.equal(options.includeHidden,true);
      return locator(elements.filter(element=>element.role===role&&element.name===options.name));
    },
    locator:selector=>{
      assert.equal(selector,'a[href]');
      return locator(elements.filter(element=>element.tag==='a'&&element.hasHref));
    }
  };
}
const navElement=(href,overrides={})=>({tag:'a',hasHref:true,role:'treeitem',name:'SOURCE_BLOCK',hidden:true,href,...overrides});
const navBlock={name:'SOURCE_BLOCK',sequence:1,source_block_id:'synthetic-block'};

test('source navigation accepts standard hidden APEX treeitems and existing visible links without clicking',async()=>{
  for(const shape of [{role:'treeitem',hidden:true},{role:'treeitem',hidden:false},{role:'link',hidden:false},{role:'link',hidden:true}]){
    const value=packet(),href=value.url+'block_1?session=synthetic';
    assert.equal(await sourceNavigationUrl(navigationPage([navElement(href,shape)]),navBlock,value),href);
  }
});

test('source navigation deduplicates the same URL but rejects distinct bound URL collisions',async()=>{
  const value=packet(),href=value.url+'block_1?session=synthetic';
  assert.equal(await sourceNavigationUrl(navigationPage([navElement(href),navElement(href,{role:'link'})]),navBlock,value),href);
  await assert.rejects(sourceNavigationUrl(navigationPage([navElement(href),navElement(value.url+'block_1?session=different')]),navBlock,value),/missing or ambiguous/);
});

test('source navigation never substitutes foreign apps wrong pages wrong names or non-anchor tree controls',async()=>{
  const value=packet(),valid=value.url+'block_1';
  const rejected=[navElement('https://example.test/block_1'),navElement(ORIGIN+'/ords/r/forms2apex_poc/other/block_1'),
    navElement(value.url+'block_2'),navElement(valid,{name:'SOURCE_BLOCK other'}),
    navElement(valid,{tag:'div'}),navElement(valid,{hasHref:false}),navElement('javascript:alert(1)'),
    navElement(ORIGIN+'/ords/f?p=999:1:synthetic'),navElement(ORIGIN+'/ords/f?p=12345:3:synthetic')];
  for(const element of rejected)
    await assert.rejects(sourceNavigationUrl(navigationPage([element]),navBlock,value),/missing or ambiguous/);
  assert.equal(await sourceNavigationUrl(navigationPage([...rejected,navElement(valid)]),navBlock,value),valid);
});

test('source navigation retains numeric f?p page matching and absolute expiry guards',async()=>{
  const value=packet(),href=ORIGIN+'/ords/f?p=12345:1:synthetic';
  assert.equal(await sourceNavigationUrl(navigationPage([navElement(href)]),navBlock,value),href);
  value.deadline_at_utc='2026-01-01T00:00:00.000Z';
  await assert.rejects(sourceNavigationUrl(navigationPage([navElement(href)]),navBlock,value),/missing or ambiguous/);
});

function resetPage({badName=null,badCount=0}={}){
  const clicks=[],waits=[],phases=[];let settled=0,guards=0;
  const page={getByRole:(role,{name,exact})=>{
    assert.equal(exact,true);
    const expectedRole=['Actions','Apply'].includes(name)?'button':'menuitem';assert.equal(role,expectedRole);
    return {
      waitFor:async({state})=>{
        waits.push(name+':'+state);
        if(name==='Report')assert.ok(clicks.includes('Actions'));
        if(name==='Reset')assert.ok(clicks.includes('Report'),'Report must be clicked before Reset becomes visible');
        if(name==='Apply')assert.ok(clicks.includes('Reset'));
      },
      count:async()=>name===badName?badCount:1,
      click:async()=>{clicks.push(name);},
      hover:async()=>{throw Error('Hover must not be used to activate the Report submenu');}
    };
  }};
  return {page,clicks,waits,phases,options:{act:async action=>{guards++;return action();},
    settled:async()=>{settled++;},onPhase:phase=>phases.push(phase)},observed:()=>({settled,guards})};
}

test('native report reset clicks Report and waits for visible unique Reset before confirmation',async()=>{
  const value=resetPage();await resetNativeReport(value.page,value.options);
  assert.deepEqual(value.clicks,['Actions','Report','Reset','Apply']);
  assert.deepEqual(value.waits,['Actions:visible','Report:visible','Reset:visible','Apply:visible','Apply:hidden']);
  assert.deepEqual(value.observed(),{settled:1,guards:4});
  assert.deepEqual(value.phases,['RESET_ACTIONS','RESET_REPORT_SUBMENU','RESET_MENUITEM','RESET_CONFIRMATION','RESET_SETTLE']);
});

test('native report reset rejects every missing or ambiguous control without a fallback',async()=>{
  for(const name of ['Actions','Report','Reset','Apply'])for(const count of [0,2]){
    const value=resetPage({badName:name,badCount:count});
    await assert.rejects(resetNativeReport(value.page,value.options),/missing or ambiguous/);
    assert.equal(value.clicks.includes(name),false);assert.equal(value.observed().settled,0);
  }
});

test('native report reset never ignores a revoked target or write fence',async()=>{
  const value=resetPage();let guards=0;
  value.options.act=async action=>{if(++guards===3)throw Error('SYNTHETIC_TARGET_REVOKED');return action();};
  await assert.rejects(resetNativeReport(value.page,value.options),/SYNTHETIC_TARGET_REVOKED/);
  assert.deepEqual(value.clicks,['Actions','Report']);assert.equal(value.observed().settled,0);
  assert.equal(value.phases.at(-1),'RESET_MENUITEM');
});

function submitPage({app='12345',pageId='2',destinationApp='12345',destinationPage='1',delay=5}={}){
  let registered=false,actions=0;
  const page={locator:selector=>({inputValue:async()=>selector.includes('p_flow_id')?app:pageId}),
    waitForFunction:(predicate,args,{timeout})=>{
      registered=true;
      return new Promise((resolve,reject)=>{
        const timer=setTimeout(()=>{clearInterval(poll);reject(Error('SYNTHETIC_DESTINATION_TIMEOUT'));},timeout);
        const poll=setInterval(()=>{
          const before=globalThis.document;
          globalThis.document={querySelector:selector=>({value:selector.includes('p_flow_id')?app:pageId})};
          try{if(predicate(args)){clearInterval(poll);clearTimeout(timer);resolve();}}
          finally{globalThis.document=before;}
        },1);
      });
    }};
  const options={applicationId:12345,fromPageId:2,toPageId:1,timeout:30,action:async()=>{
    assert.equal(registered,true,'Destination waiter must be registered before click');actions++;
    setTimeout(()=>{app=destinationApp;pageId=destinationPage;},delay);
  }};
  return {page,options,observed:()=>({registered,actions,app,pageId})};
}

test('positive native submit waits for deferred exact destination DOM, not an already-idle form',async()=>{
  for(const button of ['Create','Save Changes']){
    const value=submitPage();await submitAndWaitForPage(value.page,value.options);
    assert.deepEqual(value.observed(),{registered:true,actions:1,app:'12345',pageId:'1'},button);
  }
});

test('positive native submit rejects wrong source app/page or already-arrived destination before clicking',async()=>{
  for(const source of [{app:'999'},{pageId:'3'},{pageId:'1'}]){
    const value=submitPage(source);
    await assert.rejects(submitAndWaitForPage(value.page,value.options),/Wrong app\/page/);
    assert.equal(value.observed().actions,0);assert.equal(value.observed().registered,false);
  }
});

test('positive native submit never accepts a wrong destination app/page or retries after timeout',async()=>{
  for(const destination of [{destinationApp:'999'},{destinationPage:'3'},{destinationPage:'2'}]){
    const value=submitPage(destination);
    await assert.rejects(submitAndWaitForPage(value.page,value.options),/SYNTHETIC_DESTINATION_TIMEOUT/);
    assert.equal(value.observed().actions,1);
  }
});

test('positive native submit preserves a revoked action guard without clicking',async()=>{
  const value=submitPage();
  value.options.action=async()=>{throw Error('SYNTHETIC_GUARD_REVOKED');};
  await assert.rejects(submitAndWaitForPage(value.page,value.options),/SYNTHETIC_GUARD_REVOKED/);
  assert.equal(value.observed().actions,0);
});

test('positive native submit requires a bounded timeout and distinct valid page IDs',async()=>{
  for(const timeout of [0,-1,Infinity,45001]){
    const value=submitPage();value.options.timeout=timeout;
    await assert.rejects(submitAndWaitForPage(value.page,value.options),/Invalid native submit destination/);
    assert.equal(value.observed().registered,false);assert.equal(value.observed().actions,0);
  }
});

test('negative required probe can return to a report with retained rows, without clearing or counting them',async()=>{
  const calls=[],existingRows=[{key:'1',marker:'FPQ-prior-retained'}];let pageId='2',fence=true;
  const probe=requiredProbe();await assertAdditionalRequiredInputRejected(probe.page,'P2_FIELD1',probe.submit,()=>{});
  const page={locator:selector=>{
    if(selector==='input[name="p_flow_id"]')return {inputValue:async()=> '12345'};
    if(selector==='input[name="p_flow_step_id"]')return {inputValue:async()=>pageId};
    assert.equal(selector,'input[name="P2_FOX_ROW_ID"]');return {inputValue:async()=>''};
  },waitForFunction:async()=>{
    await new Promise(resolve=>setTimeout(resolve,1));assert.equal(pageId,'1');
  },getByRole:(role,{name,exact})=>{
    assert.equal(role,'button');assert.equal(name,'Cancel');assert.equal(exact,true);
    return {click:async()=>{assert.equal(fence,true);calls.push('cancel');pageId='1';}};
  }};
  await closeRejectedNewRecord(page,{applicationId:12345,formPage:2,identity:async id=>{calls.push('page:'+id);},
    account:async()=>{calls.push('account');},act:async action=>action(),
    settled:async()=>{calls.push('settled');},clearFence:()=>{fence=false;calls.push('release');},
    reset:async()=>{assert.equal(fence,false);calls.push('reset');}});
  assert.deepEqual(calls,['page:2','account','cancel','settled','page:1','account','release','reset']);
  assert.deepEqual(existingRows,[{key:'1',marker:'FPQ-prior-retained'}]);
});

test('negative probe still rejects a nonempty new-row key before any return action',async()=>{
  let actions=0;
  const page={locator:()=>({inputValue:async()=> '99'}),getByRole:()=>{actions++;throw Error('Must not act');}};
  await assert.rejects(closeRejectedNewRecord(page,{applicationId:12345,formPage:2,identity:async()=>{},account:async()=>{},
    act:async action=>action(),settled:async()=>{},reset:async()=>{},clearFence:()=>{}}),/acquired a row identity/);
  assert.equal(actions,0);
});

test('late negative POST during Cancel or report-account verification is aborted and can never become PASSED',async()=>{
  for(const lateAt of ['cancel','report-account']){
    let pageId='2',fence=true,unsafe=false,forwarded=0,aborted=0,passed=false,resets=0;
    const latePost=()=>{if(fence){aborted++;unsafe=true;}else forwarded++;};
    const guard=()=>{if(unsafe)throw Error('SYNTHETIC_UNSAFE_ABORT');};
    const page={locator:selector=>({inputValue:async()=>selector.includes('p_flow_id')?'12345':selector.includes('p_flow_step_id')?pageId:''}),
      waitForFunction:async()=>{await new Promise(resolve=>setTimeout(resolve,1));assert.equal(pageId,'1');},
      getByRole:()=>({click:async()=>{if(lateAt==='cancel')latePost();pageId='1';}})};
    await assert.rejects((async()=>{
      await closeRejectedNewRecord(page,{applicationId:12345,formPage:2,identity:async()=>{},
        account:async()=>{if(pageId==='1'&&lateAt==='report-account')latePost();},
        act:async action=>{guard();return action();},settled:async()=>{guard();},
        clearFence:()=>{guard();fence=false;},reset:async()=>{resets++;}});
      passed=true;
    })(),/SYNTHETIC_UNSAFE_ABORT/);
    assert.equal(aborted,1);assert.equal(forwarded,0);assert.equal(unsafe,true);
    assert.equal(fence,true);assert.equal(passed,false);assert.equal(resets,0);
  }
});

test('failed Cancel destination wait never releases the negative no-POST fence',async()=>{
  let fence=true,resets=0;
  const page={locator:selector=>({inputValue:async()=>selector.includes('p_flow_id')?'12345':selector.includes('p_flow_step_id')?'2':''}),
    waitForFunction:async()=>{throw Error('SYNTHETIC_CANCEL_TIMEOUT');},getByRole:()=>({click:async()=>{}})};
  await assert.rejects(closeRejectedNewRecord(page,{applicationId:12345,formPage:2,identity:async()=>{},account:async()=>{},
    act:async action=>action(),settled:async()=>{},clearFence:()=>{fence=false;},reset:async()=>{resets++;}}),/SYNTHETIC_CANCEL_TIMEOUT/);
  assert.equal(fence,true);assert.equal(resets,0);
});
