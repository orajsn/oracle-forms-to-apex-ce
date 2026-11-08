import {test} from 'node:test';
import assert from 'node:assert/strict';
import {mkdir} from 'node:fs/promises';
import {createRequire} from 'node:module';
import {fileURLToPath} from 'node:url';
import path from 'node:path';

const root=fileURLToPath(new URL('../',import.meta.url)),require=createRequire(import.meta.url);
test('saved context-screen mapping waits for independent review without repeating mapping',{skip:process.env.FOX_UI_BROWSER!=='1',timeout:60000},async()=>{
 const runtime=createRequire(path.join(process.env.FOX_TEST_NODE_MODULES,'../package.json'));
 const {chromium}=runtime('playwright'),{build}=require('esbuild'),out=path.resolve(process.env.FOX_TEST_EVIDENCE_DIR);
 await mkdir(out,{recursive:true});
 const h='a'.repeat(64),binding='b'.repeat(64),target='c'.repeat(64),proof='d'.repeat(64),run='fox-'+'e'.repeat(20);
 const fixture={schema_version:1,scope:'fox-prototype-mapping-epoch-v1',project_id:'p',run_id:run,source_hash:h,source_binding:binding,selected_source_set_id:'ss',target_profile_sha256:target,approved_chunk_hashes:{one:h},epoch_number:6,predecessor_sha256:binding,checkpoint_sha256:h,eligible:true,reason:'The saved mapping can be independently reviewed after a technical projection.',ai_approved_focuses:8,source_checked_focuses:8,repair_focus_id:'focus-7',projection_focus_id:'focus-8',source_fact_violations:0,planned_corrective_operations:['review_saved_projection'],remaining_focus_count:18,continue_remaining_run:true,epoch_recorded:false,strategy:'context-screen-projection-v1',expected_screen_projection_sha256:proof,saved_mapping_focuses:1,saved_mapping_source_checked:true,pending_review_focus_id:'focus-9',unstarted_focus_count:17,projected_context_screens:1,new_corrective_model_calls:1,repeated_mapper_calls:0,repeated_reviewer_calls:0};
 const assessment={source_hash:h,source_binding:binding,selected_source_set_id:'ss',target_profile_sha256:target,conversion_configured:true,source_count:1,code_unit_count:2,chunks:[{id:'one',sha256:h,bytes:1},{id:'two',sha256:binding,bytes:2}],scope_notice:'Prototype scope'};
 const code=`import React from 'react';import{createRoot}from'react-dom/client';import Prototype from './web/PrototypeConversion';import './web/style.css';import './web/projectWorkbench.css';let source={project_id:'p',source_hash:'${h}',selected_source_set_id:'ss'},unknown=false;const root=createRoot(document.getElementById('root'));window.change=()=>{source={...source,source_hash:'${binding}'};render()};window.unknown=()=>{unknown=true;render()};function render(){root.render(<div className="fox-workbench"><Prototype projectId="p" source={source} activeRun={{id:'${run}',project_id:'p',source_hash:'${h}',state:'ATTENTION'}} busy={false} unknownOutcome={unknown} hasRun={true} execute={async fn=>{try{await fn()}catch{}return false}} onRefresh={async()=>({status:'confirmed'})}/></div>)}render();`;
 const built=await build({stdin:{contents:code,resolveDir:root,loader:'tsx'},bundle:true,write:false,outfile:'preview.js',format:'iife',platform:'browser',logLevel:'silent'});
 const browser=await chromium.launch({channel:'msedge',headless:true});
 try{
  const page=await browser.newPage({viewport:{width:1440,height:900}});let plan={...fixture},gets=0,posts=0,body,hold=false,release,held,heldEntered,mode='unknown';
  const beginHold=()=>{hold=true;let timer;const entered=new Promise(resolve=>{heldEntered=resolve;});return Promise.race([entered,new Promise((_,reject)=>{timer=setTimeout(()=>reject(new Error("Held request did not arrive")),10000);})]).finally(()=>clearTimeout(timer));};
  await page.route('**/*',async route=>{
   const url=route.request().url();
   if(url==='http://localhost/')return route.fulfill({contentType:'text/html',body:'<div id="root"></div>'});
   if(url.endsWith('/review-correction'))return route.fulfill({json:{eligible:false,correction_recorded:false}});
   if(url.endsWith('/mapping-epochs/next')){gets++;if(hold)await new Promise(r=>{release=r;heldEntered();});return route.fulfill({json:plan});}
   if(url.endsWith('/prototype-assessment'))return route.fulfill({json:assessment});
   if(url.endsWith('/mapping-epochs')){posts++;body=route.request().postDataJSON();if(mode==='unknown')return route.abort();return route.fulfill({status:202,json:{id:run,state:'QUEUED',continued:true,epoch_number:6,conversion_profile:'native-blueprint-prototype-v1'}});}
   return route.abort();
  });
  await page.route('**/dsc-identity-repair',route=>route.fulfill({json:{schema_version:1,scope:'fox-prototype-dsc-identity-repair-v1',project_id:'p',run_id:run,source_hash:h,source_binding:'b'.repeat(64),selected_source_set_id:'ss',target_profile_sha256:'c'.repeat(64),approved_chunk_hashes:{one:h},eligible:false,identity_repair_recorded:false,reason:'Check existing repairs.',next_action:'check_existing_repairs'}}));
  await page.route('**/candidate-format-continuation',route=>route.fulfill({json:{schema_version:1,scope:'fox-prototype-candidate-format-continuation-v1',project_id:'p',run_id:run,id:run,state:'ATTENTION',source_hash:h,source_binding:'b'.repeat(64),selected_source_set_id:'ss',target_profile_sha256:'c'.repeat(64),approved_chunk_hashes:{one:h},eligible:false,continuation_recorded:false,business_behavior_accepted:false,reason:'Check existing repairs.',next_action:'check_existing_repairs'}}));
  const boot=async()=>{await page.goto('http://localhost/');await page.addStyleTag({content:built.outputFiles.find(f=>f.path.endsWith('.css')).text});await page.addScriptTag({content:built.outputFiles.find(f=>f.path.endsWith('.js')).text});};
  const check=async()=>{await page.getByRole('button',{name:'Check repair plan'}).click();await page.getByRole('heading',{name:'Review saved mapping and continue'}).waitFor();};
  const scope=async()=>{await page.getByRole('button',{name:'Review prototype scope'}).click();await page.getByText('Prototype scope',{exact:true}).waitFor();};
  const boxes=()=>page.getByRole('group',{name:'Confirm before processing'}).getByRole('checkbox');
  const action=()=>page.getByRole('button',{name:'Review saved mapping and continue'});
  await boot();assert.equal(gets,0);assert.equal(posts,0);await scope();held=beginHold();
  await page.getByRole('button',{name:'Check repair plan'}).click();await page.waitForFunction(()=>document.body.textContent.includes('Checking repair plan'));
  for(const box of await boxes().all())assert.equal(await box.isDisabled(),true);
  await held;release();hold=false;await page.getByRole('heading',{name:'Review saved mapping and continue'}).waitFor();
  assert.equal(await page.getByText(/completed mapping and reviews will not run again/).count(),1);
  assert.equal(await page.getByText(/An APEX file is not ready yet/).count(),1);
  assert.equal(await page.getByText('One saved mapping passed source checks and is awaiting independent review. 17 sections have not started yet.').count(),1);
  assert.equal(await page.getByText(/Independent review comes first/).count(),1);
  assert.equal(await page.getByRole('button',{name:'Check saved progress'}).count(),0);
  assert.equal(await page.getByRole('button',{name:'Check recovery options'}).count(),0);
  assert.equal(await action().isDisabled(),true);assert.equal(await page.getByLabel(/one ·/).isChecked(),true);assert.equal(await page.getByLabel(/one ·/).isDisabled(),true);
  for(const box of await boxes().all())assert.equal(await box.isChecked(),false);
  await page.getByText('Saved mapping evidence',{exact:true}).click();
  await page.screenshot({path:path.join(out,'context-screen-epoch-desktop.png'),fullPage:true});
  await page.setViewportSize({width:390,height:844});assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth>innerWidth),false);
  await page.screenshot({path:path.join(out,'context-screen-epoch-mobile.png'),fullPage:true});
  const approvals=await boxes().all();await approvals[0].check();await approvals[1].check();assert.equal(await action().isDisabled(),true);await approvals[2].check();
  await action().click();await page.waitForTimeout(150);assert.equal(posts,1);assert.equal(await action().isDisabled(),true);assert.equal(await page.getByRole('button',{name:'Check repair plan'}).isDisabled(),true);
  assert.deepEqual(body,{source_hash:h,source_binding:binding,expected_current_source_set_id:'ss',target_profile_sha256:target,approved_chunk_hashes:{one:h},approved_redacted_source:true,approved_external_ai:true,approved_prototype_scope:true,checkpoint_sha256:h,expected_epoch_number:6,expected_predecessor_sha256:binding,expected_screen_projection_sha256:proof});
  await page.evaluate(()=>window.unknown());assert.equal(await page.getByRole('button',{name:'Check repair plan'}).count(),0);
  // These are authored API replies, not hosted proof-adoption evidence.
  const invalid=[{expected_screen_projection_sha256:undefined},{expected_screen_projection_sha256:'bad'},{epoch_number:2},{epoch_number:3},{epoch_number:4},{epoch_number:5},{epoch_number:7},{strategy:'unknown'},{saved_mapping_focuses:0},{saved_mapping_focuses:true},{saved_mapping_source_checked:false},{saved_mapping_source_checked:1},{pending_review_focus_id:''},{pending_review_focus_id:'x'.repeat(129)},{unstarted_focus_count:-1},{unstarted_focus_count:true},{unstarted_focus_count:16},{projected_context_screens:0},{projected_context_screens:true},{new_corrective_model_calls:0},{new_corrective_model_calls:true},{repeated_mapper_calls:1},{repeated_reviewer_calls:1},{ai_approved_focuses:9},{source_checked_focuses:9},{source_fact_violations:1},{planned_corrective_operations:[]},{planned_corrective_operations:['mapper_repair']},{expected_clause_proof_sha256:binding},{analysis_role:{}},{new_clause_analysis_calls:0},{repeated_clause_review_calls:0},{expected_container_proof_sha256:binding},{container_corrections:1},{corrective_projection_review_calls:1},{expected_partition_proof_sha256:binding},{reused_review_focuses:1}];
  for(const patch of invalid){plan={...fixture,...patch};await boot();await page.getByRole('button',{name:'Check repair plan'}).click();await page.getByRole('alert').waitFor();assert.equal(await action().count(),0);assert.equal(posts,1);}
  plan={...fixture};await boot();held=beginHold();await page.getByRole('button',{name:'Check repair plan'}).click();await page.waitForFunction(()=>document.body.textContent.includes('Checking repair plan'));await held;await page.evaluate(()=>window.change());release();hold=false;await page.waitForTimeout(100);assert.equal(await action().count(),0);
  await boot();await check();assessment.target_profile_sha256=binding;await scope();await page.getByText('The source or target changed. Check the repair plan again.').waitFor();assert.equal(await action().count(),0);assessment.target_profile_sha256=target;
  await boot();plan={...fixture,eligible:false,epoch_recorded:true};await check();assert.equal(await action().count(),0);assert.equal(await page.getByRole('button',{name:'Check saved progress'}).count(),0);assert.equal(posts,1);
  plan={...fixture};await boot();mode='success';await check();await scope();for(const box of await boxes().all())await box.check();await action().click();await page.getByText('Check the saved run status before taking any further action. Do not submit again.').waitFor();assert.equal(posts,2);assert.equal(await action().isDisabled(),true);
 }finally{await browser.close();}
});
