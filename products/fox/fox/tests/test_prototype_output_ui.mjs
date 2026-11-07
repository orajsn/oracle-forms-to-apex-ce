import {test} from 'node:test';
import assert from 'node:assert/strict';
import {mkdir} from 'node:fs/promises';
import {createRequire} from 'node:module';
import {fileURLToPath} from 'node:url';
import path from 'node:path';

const root=fileURLToPath(new URL('../',import.meta.url)),require=createRequire(import.meta.url);
test('generated prototype output is source-bound and never navigates to an arbitrary URL',{skip:process.env.FOX_UI_BROWSER!=='1',timeout:60000},async()=>{
 const runtime=createRequire(path.join(process.env.FOX_TEST_NODE_MODULES,'../package.json'));
 const {chromium}=runtime('playwright'),{build}=require('esbuild');
 const out=path.resolve(process.env.FOX_TEST_EVIDENCE_DIR);await mkdir(out);
 const code=`import React from 'react';import{createRoot}from'react-dom/client';import Prototype from './web/PrototypeConversion';import './web/style.css';import './web/projectWorkbench.css';let source={project_id:'p',source_hash:'${'a'.repeat(64)}',selected_source_set_id:'ss-1'};let run={id:'fox-${'a'.repeat(20)}',project_id:'p',source_hash:source.source_hash,state:'GENERATED',message:'Generated'};const root=createRoot(document.getElementById('root'));window.change=()=>{source={...source,source_hash:'${'b'.repeat(64)}'};render()};function render(){root.render(<div className="fox-workbench"><Prototype projectId="p" source={source} activeRun={run} busy={false} unknownOutcome={false} hasRun={true} execute={async()=>false}/></div>)}render();`;
 const built=await build({stdin:{contents:code,resolveDir:root,loader:'tsx'},bundle:true,write:false,outfile:'preview.js',format:'iife',platform:'browser',logLevel:'silent'});
 const js=built.outputFiles.find(f=>f.path.endsWith('.js')).text,css=built.outputFiles.find(f=>f.path.endsWith('.css')).text;
 const browser=await chromium.launch({channel:'msedge',headless:true});
 try{const page=await browser.newPage({viewport:{width:1440,height:900}});let mode='bad',calls=0,release;
  const base='/api/projects/p/prototype-runs/fox-'+ 'a'.repeat(20);
  const response={schema_version:1,scope:'fox-generated-prototype-output-v1',project_id:'p',run_id:'fox-'+ 'a'.repeat(20),source_hash:'a'.repeat(64),selected_source_set_id:'ss-1',source_binding:'c'.repeat(64),status:'APEX_GENERATED',download_path:base+'/download',business_behavior_accepted:false,clean_schema_install_passed:false,package_reimport_passed:false};
  await page.route('**/*',async route=>{if(route.request().url()==='http://localhost/')return route.fulfill({contentType:'text/html',body:'<div id="root"></div>'});if(route.request().url().endsWith('/output')){calls++;if(mode==='held')await new Promise(r=>release=r);return route.fulfill({contentType:'application/json',body:JSON.stringify({...response,download_path:mode==='bad'?'https://example.com/evil':response.download_path})});}return route.abort();});
  await page.goto('http://localhost/');await page.addStyleTag({content:css});await page.addScriptTag({content:js});
  const view=page.getByRole('button',{name:'View prototype output'}),link=page.getByRole('link',{name:'Download generated prototype'});
  assert.equal(calls,0);await view.click();await page.getByRole('alert').waitFor();assert.equal(await link.count(),0);assert.equal(calls,1);
  mode='ok';await view.click();await link.waitFor();assert.equal(await link.getAttribute('href'),base+'/download');assert.equal(calls,2);
  await page.screenshot({path:path.join(out,'generated-desktop.png'),fullPage:true});await page.setViewportSize({width:390,height:844});assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth>innerWidth),false);await page.screenshot({path:path.join(out,'generated-mobile.png'),fullPage:true});
  mode='held';await view.click();await page.waitForFunction(()=>document.body.textContent.includes('Checking prototype output'));await page.evaluate(()=>window.change());release();await page.getByText(/do not match the current source/).waitFor();assert.equal(await link.count(),0);assert.equal(calls,3);
 }finally{await browser.close();}
});
