import {test} from 'node:test';
import assert from 'node:assert/strict';
import {mkdir} from 'node:fs/promises';
import {createRequire} from 'node:module';
import {fileURLToPath} from 'node:url';
import path from 'node:path';

const root=fileURLToPath(new URL('../',import.meta.url)),require=createRequire(import.meta.url);
test('epoch requests have bounded budgets and uncertain submissions cannot replay',{skip:process.env.FOX_UI_BROWSER!=='1',timeout:60000},async()=>{
 const runtime=createRequire(path.join(process.env.FOX_TEST_NODE_MODULES,'../package.json'));
 const {chromium}=runtime('playwright'),{build}=require('esbuild'),out=path.resolve(process.env.FOX_TEST_EVIDENCE_DIR);
 await mkdir(out,{recursive:true});
 const h='a'.repeat(64),binding='b'.repeat(64),target='c'.repeat(64),proof='d'.repeat(64),run='fox-'+'e'.repeat(20);
 const plan={schema_version:1,scope:'fox-prototype-mapping-epoch-v1',project_id:'p',run_id:run,source_hash:h,source_binding:binding,selected_source_set_id:'ss',target_profile_sha256:target,approved_chunk_hashes:{one:h},epoch_number:5,predecessor_sha256:binding,checkpoint_sha256:h,eligible:true,reason:'A reviewed correction is available.',ai_approved_focuses:8,source_checked_focuses:8,repair_focus_id:'focus-7',projection_focus_id:'focus-8',source_fact_violations:0,planned_corrective_operations:[],remaining_focus_count:18,continue_remaining_run:true,epoch_recorded:false,strategy:'retained-compact-review-v1',expected_partition_proof_sha256:proof,reused_review_focuses:1,new_corrective_model_calls:0,repeated_mapper_calls:0,repeated_reviewer_calls:0};
 const assessment={source_hash:h,source_binding:binding,selected_source_set_id:'ss',target_profile_sha256:target,conversion_configured:true,source_count:1,code_unit_count:1,chunks:[{id:'one',sha256:h,bytes:1}],scope_notice:'Prototype scope'};
 const code=`import React from 'react';import{createRoot}from'react-dom/client';import Prototype from './web/PrototypeConversion';import './web/style.css';import './web/projectWorkbench.css';createRoot(document.getElementById('root')).render(<div className="fox-workbench"><Prototype projectId="p" source={{project_id:'p',source_hash:'${h}',selected_source_set_id:'ss'}} activeRun={{id:'${run}',project_id:'p',source_hash:'${h}',state:'ATTENTION'}} busy={false} unknownOutcome={false} hasRun={true} execute={async fn=>{try{await fn()}catch{}return false}} onRefresh={async()=>({status:'confirmed'})}/></div>);`;
 const built=await build({stdin:{contents:code,resolveDir:root,loader:'tsx'},bundle:true,write:false,outfile:'preview.js',format:'iife',platform:'browser',logLevel:'silent'});
 const browser=await chromium.launch({channel:'msedge',headless:true});
 try{
  const page=await browser.newPage({viewport:{width:1440,height:900}});
  await page.route('http://localhost/',route=>route.fulfill({contentType:'text/html',body:'<div id="root"></div>'}));
  await page.goto('http://localhost/');
  await page.evaluate(({plan,assessment})=>{
   const nativeSetTimeout=window.setTimeout;window.budgets=[];window.pending=[];window.requests=[];
   window.setTimeout=(fn,ms,...args)=>{if(ms===15000||ms===45000||ms===60000){window.budgets.push(ms);window.pending.push(fn);return nativeSetTimeout(fn,ms,...args);}return nativeSetTimeout(fn,ms,...args);};
   window.fetch=(url,options)=>{window.requests.push({url,method:options.method,body:options.body});if(url.endsWith('/prototype-assessment'))return Promise.resolve(new Response(JSON.stringify(assessment)));if(url.endsWith('/dsc-identity-repair'))return Promise.resolve(new Response(JSON.stringify({schema_version:1,scope:'fox-prototype-dsc-identity-repair-v1',project_id:'p',run_id:plan.run_id,source_hash:plan.source_hash,source_binding:plan.source_binding,selected_source_set_id:'ss',target_profile_sha256:plan.target_profile_sha256,approved_chunk_hashes:{one:plan.source_hash},eligible:false,identity_repair_recorded:false,reason:'Check existing repairs.',next_action:'check_existing_repairs'})));if(url.endsWith('/review-correction'))return Promise.resolve(new Response(JSON.stringify({eligible:false,correction_recorded:false})));if(url.endsWith('/mapping-epochs/next')&&window.planMode==='success')return Promise.resolve(new Response(JSON.stringify(plan)));return new Promise((resolve,reject)=>options.signal.addEventListener('abort',()=>reject(new DOMException('Aborted','AbortError')),{once:true}));};
  },{plan,assessment});
  await page.addStyleTag({content:built.outputFiles.find(f=>f.path.endsWith('.css')).text});
  await page.addScriptTag({content:built.outputFiles.find(f=>f.path.endsWith('.js')).text});
  const boxes=()=>page.getByRole('group',{name:'Confirm before processing'}).getByRole('checkbox');
  await page.getByRole('button',{name:'Review prototype scope'}).click();await page.getByText('Prototype scope',{exact:true}).waitFor();
  assert.deepEqual(await page.evaluate(()=>window.budgets),[15000]);
  await page.getByRole('button',{name:'Check repair plan'}).click();await page.getByText('Checking repair plan…').waitFor();
  await page.waitForFunction(()=>window.budgets.length===4);
  assert.deepEqual(await page.evaluate(()=>window.budgets),[15000,60000,60000,45000]);
  assert.deepEqual((await page.evaluate(()=>window.requests)).slice(1).map(r=>r.url.split('/').pop()),['dsc-identity-repair','review-correction','next']);
  for(const box of await boxes().all())assert.equal(await box.isDisabled(),true);
  assert.equal(await page.getByRole('button',{name:'Continue remaining sections'}).count(),0);
  assert.equal((await page.evaluate(()=>window.requests)).filter(r=>r.method==='POST').length,0);
  await page.screenshot({path:path.join(out,'waiting-desktop.png'),fullPage:true});
  await page.setViewportSize({width:390,height:844});assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth>innerWidth),false);
  await page.screenshot({path:path.join(out,'waiting-mobile.png'),fullPage:true});
  await page.evaluate(()=>window.pending[3]());
  await page.getByText('Checking the repair plan timed out. No processing was started. Check the plan again or ask your operator for help.').waitFor();
  await page.evaluate(()=>{window.planMode='success'});
  await page.getByRole('button',{name:'Check repair plan'}).click();await page.getByRole('heading',{name:'Continue remaining sections'}).waitFor();
  for(const box of await boxes().all())await box.check();
  await page.getByRole('button',{name:'Continue remaining sections'}).click();
  await page.waitForFunction(()=>window.requests.some(r=>r.method==='POST'));
  assert.deepEqual(await page.evaluate(()=>window.budgets),[15000,60000,60000,45000,60000,60000,45000,45000]);
  const post=(await page.evaluate(()=>window.requests)).find(r=>r.method==='POST');assert.equal(Object.keys(JSON.parse(post.body)).length,12);
  await page.evaluate(()=>window.pending[7]());
  await page.getByText('Check the saved run status before taking any further action. Do not submit again.').waitFor();
  assert.equal(await page.getByRole('button',{name:'Continue remaining sections'}).isDisabled(),true);
  assert.equal((await page.evaluate(()=>window.requests)).filter(r=>r.method==='POST').length,1);
  await page.screenshot({path:path.join(out,'uncertain-mobile.png'),fullPage:true});
 }finally{await browser.close();}
});
