import {test} from 'node:test';
import assert from 'node:assert/strict';
import {mkdir} from 'node:fs/promises';
import {createRequire} from 'node:module';
import {fileURLToPath} from 'node:url';
import path from 'node:path';

const root=fileURLToPath(new URL('../',import.meta.url)),require=createRequire(import.meta.url);
test('package output and optional recorded timing are source-bound', {skip:process.env.FOX_UI_BROWSER!=='1',timeout:60000},async()=>{
 const runtime=createRequire(path.join(process.env.FOX_TEST_NODE_MODULES,'../package.json'));
 const {chromium}=runtime('playwright'),{build}=require('esbuild');
 const out=path.resolve(process.env.FOX_TEST_EVIDENCE_DIR);await mkdir(out,{recursive:true});
 const code=`import React from 'react';import{createRoot}from'react-dom/client';import Prototype from './web/PrototypeConversion';import './web/style.css';import './web/projectWorkbench.css';let source={project_id:'p',source_hash:'${'a'.repeat(64)}',selected_source_set_id:'ss-1'};const run={id:'fox-${'a'.repeat(20)}',project_id:'p',source_hash:source.source_hash,state:'GENERATED'};const root=createRoot(document.getElementById('root'));window.change=()=>{source={...source,source_hash:'${'b'.repeat(64)}'};render()};function render(){root.render(<div className="fox-workbench"><Prototype projectId="p" source={source} activeRun={run} busy={false} unknownOutcome={false} hasRun={true} execute={async()=>false}/></div>)}render();`;
 const built=await build({stdin:{contents:code,resolveDir:root,loader:'tsx'},nodePaths:process.env.FOX_UI_DEPS?[process.env.FOX_UI_DEPS]:[],bundle:true,write:false,outfile:'preview.js',format:'iife',platform:'browser',logLevel:'silent'});
 const js=built.outputFiles.find(f=>f.path.endsWith('.js')).text,css=built.outputFiles.find(f=>f.path.endsWith('.css')).text;
 const browser=await chromium.launch({channel:'msedge',headless:true});
 try{
  const page=await browser.newPage({viewport:{width:1440,height:900}}),base='/api/projects/p/prototype-runs/fox-'+ 'a'.repeat(20);let timing=true;
  const output={schema_version:1,scope:'fox-apexlang-package-output-v1',project_id:'p',run_id:'fox-'+ 'a'.repeat(20),source_hash:'a'.repeat(64),selected_source_set_id:'ss-1',source_binding:'c'.repeat(64),status:'APEX_GENERATED',download_path:base+'/download',business_behavior_accepted:false,clean_schema_install_passed:false,package_reimport_passed:false,delivery_mode:'apexlang_package',package_format:'apexlang_zip',format_validated:true,technically_verified:false,runtime_verified:false,import_verified:false,compatibility:{mmd_version:'26.1.0+3102',target_compatibility:'Requires a matching APEXlang compiler and compatible APEX release.',declared_target_profile:{profile_id:'synthetic',versions:{apex:'26.1.6',apexlang_mmd:'26.1.0+3102'},evidence:'configuration_only_not_import_tested'}},prerequisites:['Compatible SQLcl and Java'],omissions:[{source_object_id:'FORM1',reason:'Trigger requires review'}]};
  const progress={schema_version:1,scope:'fox-prototype-progress-v1',project_id:'p',run_id:output.run_id,source_hash:output.source_hash,state:'GENERATED',observed_at_utc:'2026-11-12T05:00:00Z',current_stage:null,stages:['mapping','render','validate','package'].map(id=>({id,status:'recorded'})),message:'safe',progress_available:true,advisory:true,technically_verified:false,business_behavior_accepted:false,delivery_mode:'apexlang_package'};
  await page.route('**/*',route=>route.request().url()==='http://localhost/'?route.fulfill({contentType:'text/html',body:'<div id="root"></div>'}):route.request().url().endsWith('/output')?route.fulfill({json:output}):route.request().url().endsWith('/progress')?route.fulfill({json:{...progress,timing:timing?{available:true,scope:'fox-provider-timing-summary-v1',provider_calls:2,request_seconds:12.5}:{available:true,scope:'fox-provider-timing-summary-v1',provider_calls:2,request_seconds:-1}}}):route.abort());
  await page.goto('http://localhost/');await page.addStyleTag({content:css});await page.addScriptTag({content:js});
  await page.getByText('Recorded AI request time: 12.5 seconds across 2 calls. This is not whole-job time.').waitFor();
  await page.getByRole('button',{name:'View prototype output'}).click();const link=page.getByRole('link',{name:'Download APEX package'});await link.waitFor();assert.equal(await link.getAttribute('href'),base+'/download');await page.getByText('FORM1: Trigger requires review').waitFor();await page.getByText(/Declared APEX target: 26\.1\.6 \(configuration only/).waitFor();await page.getByText(/Generated MMD version: 26\.1\.0\+3102/).waitFor();
  await page.screenshot({path:path.join(out,'package-desktop.png'),fullPage:true});await page.setViewportSize({width:390,height:844});assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth>innerWidth),false);await page.screenshot({path:path.join(out,'package-mobile.png'),fullPage:true});
  timing=false;await page.getByRole('button',{name:'Refresh progress'}).click();await page.getByText('Recorded AI request timing is unavailable.').waitFor();await page.evaluate(()=>window.change());assert.equal(await link.count(),0);
 }finally{await browser.close();}
});
