import {test} from 'node:test';
import assert from 'node:assert/strict';
import {mkdir} from 'node:fs/promises';
import {createRequire} from 'node:module';
import {fileURLToPath} from 'node:url';
import path from 'node:path';

const root=fileURLToPath(new URL('../',import.meta.url)),require=createRequire(import.meta.url);
test('progress is read-only, source-bound, conservative and responsive',{skip:process.env.FOX_UI_BROWSER!=='1',timeout:60000},async()=>{
 const runtime=createRequire(path.join(process.env.FOX_TEST_NODE_MODULES,'../package.json'));
 const {chromium}=runtime('playwright'),{build}=require('esbuild');
 const out=path.resolve(process.env.FOX_TEST_EVIDENCE_DIR);await mkdir(out,{recursive:true});
 const code=`import React from 'react';import{createRoot}from'react-dom/client';import Prototype from './web/PrototypeConversion';import './web/style.css';import './web/projectWorkbench.css';let source={project_id:'p',source_hash:'${'a'.repeat(64)}',selected_source_set_id:'ss-1'};let run={id:'fox-${'a'.repeat(20)}',project_id:'p',source_hash:source.source_hash,state:'PROCESSING',message:''};const root=createRoot(document.getElementById('root'));window.change=()=>{source={...source,source_hash:'${'b'.repeat(64)}'};render()};function render(){root.render(<div className="fox-workbench"><Prototype projectId="p" source={source} activeRun={run} busy={false} unknownOutcome={false} hasRun={true} execute={async()=>false}/></div>)}render();`;
 const built=await build({stdin:{contents:code,resolveDir:root,loader:'tsx'},bundle:true,write:false,outfile:'preview.js',format:'iife',platform:'browser',logLevel:'silent'});
 const js=built.outputFiles.find(f=>f.path.endsWith('.js')).text,css=built.outputFiles.find(f=>f.path.endsWith('.css')).text;
 const browser=await chromium.launch({channel:'msedge',headless:true});
 try{
  const page=await browser.newPage({viewport:{width:1440,height:900}}),calls=[];
  const value={schema_version:1,scope:'fox-prototype-progress-v1',project_id:'p',run_id:'fox-'+ 'a'.repeat(20),source_hash:'a'.repeat(64),state:'PROCESSING',observed_at_utc:'2026-11-12T05:00:00Z',current_stage:'validate',stages:['mapping','validate','prepare_schema','import','verify_runtime','export'].map((id,i)=>({id,status:i===0?'recorded':i===1?'working':'not_observed'})),message:'safe',progress_available:true,advisory:true,technically_verified:false,business_behavior_accepted:false};
  let mode='good';
  await page.route('**/*',async route=>{if(route.request().url()==='http://localhost/')return route.fulfill({contentType:'text/html',body:'<div id="root"></div>'});calls.push([route.request().method(),route.request().url()]);if(route.request().url().endsWith('/progress'))return route.fulfill({contentType:'application/json',body:JSON.stringify(mode==='bad'?{...value,source_hash:'b'.repeat(64)}:mode==='stale'?{...value,state:'GENERATED'}:mode==='unavailable'?{...value,progress_available:false}:mode==='order'?{...value,stages:value.stages.map((s,i)=>({...s,status:i===0?'working':i===1?'recorded':'not_observed'})),current_stage:'mapping'}:mode==='stage'?{...value,current_stage:'mapping'}:value)});return route.abort();});
  await page.goto('http://localhost/');await page.addStyleTag({content:css});await page.addScriptTag({content:js});
  const widget=page.getByRole('region',{name:'Prototype progress'}),refresh=widget.getByRole('button',{name:'Refresh progress'});
  await widget.getByText('Working',{exact:true}).waitFor();assert.equal(await widget.locator('li').count(),6);assert.equal(await widget.getByText('Recorded',{exact:true}).count(),1);assert.equal(await widget.getByText('Not yet recorded',{exact:true}).count(),4);assert.match(await widget.innerText(),/not proof of technical verification or business acceptance/i);
  await widget.screenshot({path:path.join(out,'progress-desktop.png')});
  await page.setViewportSize({width:390,height:844});assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth>innerWidth),false);await widget.screenshot({path:path.join(out,'progress-mobile.png')});
  mode='bad';await refresh.focus();await page.keyboard.press('Enter');await widget.getByText(/Progress is unavailable/).waitFor();assert.equal(await widget.locator('li').count(),0);
  mode='stale';await refresh.click();await widget.getByText(/Progress is unavailable/).waitFor();assert.equal(await widget.locator('li').count(),0);
  mode='unavailable';await refresh.click();await widget.getByText(/Progress is unavailable/).waitFor();assert.equal(await widget.locator('li').count(),0);
  mode='order';await refresh.click();await widget.getByText(/Progress is unavailable/).waitFor();assert.equal(await widget.locator('li').count(),0);
  mode='stage';await refresh.click();await widget.getByText(/Progress is unavailable/).waitFor();assert.equal(await widget.locator('li').count(),0);
  mode='good';await refresh.click();await widget.getByText('Working',{exact:true}).waitFor();
  await page.evaluate(()=>{window.savedFetch=window.fetch;window.fetch=(url,options)=>url.endsWith('/progress')?new Promise(resolve=>{window.releaseProgress=()=>resolve(new Response(JSON.stringify({schema_version:1,scope:'fox-prototype-progress-v1',project_id:'p',run_id:'fox-'+ 'a'.repeat(20),source_hash:'a'.repeat(64),state:'PROCESSING',observed_at_utc:'2026-11-12T05:00:00Z',current_stage:'mapping',stages:['mapping','validate','prepare_schema','import','verify_runtime','export'].map(id=>({id,status:'recorded'})),message:'safe',progress_available:true,advisory:true,technically_verified:false,business_behavior_accepted:false}),{status:200,headers:{'Content-Type':'application/json'}}));}):window.savedFetch(url,options);});
  await refresh.click();await widget.getByText('Checking recorded progress…').waitFor();await page.evaluate(()=>window.change());await widget.waitFor({state:'detached'});await page.evaluate(()=>window.releaseProgress());assert.equal(await widget.count(),0);
  assert.equal(calls.length,7);assert.ok(calls.every(([method,url])=>method==='GET'&&url.endsWith('/progress')));
 }finally{await browser.close();}
});
