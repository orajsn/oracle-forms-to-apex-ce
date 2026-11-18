import {test} from 'node:test';
import assert from 'node:assert/strict';
import {mkdir} from 'node:fs/promises';
import {createRequire} from 'node:module';
import {fileURLToPath} from 'node:url';
import path from 'node:path';
const root=fileURLToPath(new URL('../',import.meta.url)),require=createRequire(import.meta.url);
test('saved output remains pending past 30 seconds, binds to source, and handles errors',{skip:process.env.FOX_UI_BROWSER!=='1',timeout:60000},async()=>{
 const runtime=createRequire(path.join(process.env.FOX_TEST_NODE_MODULES,'../package.json')),{chromium}=runtime('playwright'),{build}=require('esbuild');
 const out=path.resolve(process.env.FOX_TEST_EVIDENCE_DIR);await mkdir(out,{recursive:true});
 const code=`import React from 'react';import{createRoot}from'react-dom/client';import Prototype from './web/PrototypeConversion';import './web/style.css';import './web/projectWorkbench.css';let source={project_id:'p',source_hash:'${'a'.repeat(64)}',selected_source_set_id:'ss-1'};const run={id:'fox-${'a'.repeat(20)}',project_id:'p',source_hash:source.source_hash,state:'GENERATED'};const root=createRoot(document.getElementById('root'));window.change=()=>{source={...source,source_hash:'${'b'.repeat(64)}'};render()};function render(){root.render(<div className="fox-workbench"><Prototype exportOnly projectId="p" source={source} activeRun={run} busy={false} unknownOutcome={false} hasRun={true} execute={async()=>false}/></div>)}render();`;
 const built=await build({stdin:{contents:code,resolveDir:root,loader:'tsx'},bundle:true,write:false,outfile:'preview.js',format:'iife',platform:'browser',logLevel:'silent'}),js=built.outputFiles.find(f=>f.path.endsWith('.js')).text,css=built.outputFiles.find(f=>f.path.endsWith('.css')).text;
 const browser=await chromium.launch({channel:'msedge',headless:true});
 const base='/api/projects/p/prototype-runs/fox-'+ 'a'.repeat(20),output={schema_version:1,scope:'fox-apexlang-package-output-v1',project_id:'p',run_id:'fox-'+ 'a'.repeat(20),source_hash:'a'.repeat(64),selected_source_set_id:'ss-1',source_binding:'c'.repeat(64),status:'APEX_GENERATED',download_path:base+'/download',business_behavior_accepted:false,clean_schema_install_passed:false,package_reimport_passed:false,delivery_mode:'apexlang_package',package_format:'apexlang_zip',format_validated:true,technically_verified:false,runtime_verified:false,import_verified:false,compatibility:{mmd_version:'26.1',target_compatibility:'Compatible compiler required.'},prerequisites:[],omissions:[]};
 try{for(const scenario of ['delayed','stale','error','timeout']){
  const page=await browser.newPage({viewport:{width:1100,height:800}});await page.clock.install();let release,seen,requests=0,posts=0;const waiting=new Promise(resolve=>{release=resolve}),requested=new Promise(resolve=>{seen=resolve});
  await page.route('**/*',async route=>{const req=route.request();if(req.method()==='POST')posts++;if(req.url()==='http://localhost/')return route.fulfill({contentType:'text/html',body:'<div id="root"></div>'});if(req.url().endsWith('/output')){requests++;seen();if(scenario==='error')return route.fulfill({status:503,json:{detail:'Saved output verification is unavailable.'}});await waiting;try{return await route.fulfill({json:output});}catch{return;}}return route.abort();});
  await page.goto('http://localhost/');await page.addStyleTag({content:css});await page.addScriptTag({content:js});await page.getByRole('button',{name:'View prototype output'}).click();await requested;
  if(scenario==='error'){await page.getByRole('alert').getByText('Saved output verification is unavailable.').waitFor();assert.equal(await page.getByRole('link',{name:'Download APEX package'}).count(),0);}
  else {const button=page.getByRole('button',{name:'Checking prototype output…'});assert.equal(await button.isDisabled(),true);await page.getByRole('status').filter({hasText:'Verifying saved output. This can take several minutes. The generated package is preserved.'}).waitFor();assert.equal(requests,1);
   if(scenario==='timeout'){await page.clock.fastForward(600000);await page.getByRole('alert').getByText(/Checking prototype output timed out/).waitFor();assert.equal(await page.getByRole('link',{name:'Download APEX package'}).count(),0);release();}
   else if(scenario==='delayed'){await page.clock.fastForward(31000);assert.equal(await button.isDisabled(),true);assert.equal(await page.getByRole('alert').count(),0);await page.screenshot({path:path.join(out,'saved-output-waiting.png'),fullPage:true});release();const link=page.getByRole('link',{name:'Download APEX package'});await link.waitFor();assert.equal(await link.getAttribute('href'),base+'/download');}
   else {await page.evaluate(()=>window.change());release();await page.waitForTimeout(100);assert.equal(await page.getByRole('link',{name:'Download APEX package'}).count(),0);assert.equal(await page.getByText('Output details do not match the current source or are unavailable. Refresh the project or ask your operator for help.').count(),1);}
  }
  assert.equal(requests,1);assert.equal(posts,0);await page.close();
 }}finally{await browser.close();}
});
