import {test} from 'node:test';
import assert from 'node:assert/strict';
import {createRequire} from 'node:module';
import {mkdir} from 'node:fs/promises';
import path from 'node:path';
import {fileURLToPath} from 'node:url';

const root=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'..');
const modules=process.env.FOX_TEST_NODE_MODULES;
const browserModules=process.env.FOX_TEST_BROWSER_MODULES;
const output=process.env.FOX_UI_ARTIFACT_DIR;

test('checkbox draft receipt is validated and displayed safely', {timeout:90000}, async()=>{
 const {build}=createRequire(path.join(modules,'../package.json'))('esbuild');
 const {chromium}=createRequire(path.join(browserModules,'../package.json'))('playwright');
 await mkdir(output,{recursive:true});
 const entry=`import React from 'react';
  import {createRoot} from 'react-dom/client';
  import Mapping from './web/XmlMappingConversion';
  import './web/style.css';
  createRoot(document.getElementById('root')).render(<div className="fox-workbench">
   <Mapping projectId="${'a'.repeat(32)}" source={{project_id:'${'a'.repeat(32)}',source_hash:'${'b'.repeat(64)}',selected_source_set_id:'ss-${'c'.repeat(32)}'}} busy={false}/>
  </div>);`;
 const built=await build({absWorkingDir:root,stdin:{contents:entry,resolveDir:root,loader:'tsx'},
  bundle:true,write:false,outfile:'fixture.js',nodePaths:[modules],format:'iife'});
 const js=built.outputFiles.find(f=>f.path.endsWith('.js')).text;
 const css=built.outputFiles.find(f=>f.path.endsWith('.css')).text;
 const executablePath=process.env.FOX_TEST_BROWSER_EXECUTABLE;
 const channel=process.env.FOX_TEST_BROWSER_CHANNEL;
 const browser=await chromium.launch({headless:true,...(executablePath?{executablePath}:{channel:channel||'msedge'})});
 try{
  const page=await browser.newPage({viewport:{width:1200,height:900}});
  const errors=[];
  page.on('pageerror',e=>errors.push(e.message));
  await page.route('**/*',r=>r.fulfill({contentType:'text/html',body:'<div id="root"></div>'}));
  await page.goto('http://localhost');
  await page.evaluate(()=>{
   const pid='a'.repeat(32),hash='b'.repeat(64),sid='ss-'+'c'.repeat(32);
   const rid='fox-'+'d'.repeat(20),binding='e'.repeat(64);
   const report={schema_version:1,scope:'fox-source-discrepancies-v1',source_binding:binding,
    summary:{total_units:0,generated_units:0,encoded_unwired_units:0,unimplemented_units:0,
     dependency_groups:0,dependency_references:0},
    units:[],dependencies:[],runtime_verified:false,business_behavior_accepted:false};
   window.run={id:rid,request_id:'123e4567-e89b-42d3-a456-426614174000',project_id:pid,
    source_hash:hash,selected_source_set_id:sid,state:'GENERATED',message:'Synthetic saved run',
    created:1,updated:2,conversion_profile:'xml-mapping-v1',format_validated:true,
    generated_units:0,unsupported_units:0,total_units:0,current_source:true,
    download_url:`/api/projects/${pid}/xml-mapping/runs/${rid}/download`,package_sha256:binding,
    runtime_verified:false,business_behavior_accepted:false,discrepancies:report};
   window.receipt={member:'fox-package/checkbox-drafts.json',sha256:binding,
    groups:[{source_unit_id:'unit',source_unit_sha256:binding,source_block_id:'block',
     source_block_name:'<img src=x>',controller:'SCHEDULE',dependents:['MONDAY','TUESDAY'],
     page_id:8100,page_file:'pages/p8100-draft.apx',reset_on_manual_off:true}],
    gaps:[{source_unit_id:'other',reason:'CHECKBOX_GROUP_UNSUPPORTED'}],
    generated_group_count:1,gap_count:1,scope:'synthetic_session_draft_only',
    converted_code_unit_count:0,exact_checked_unchecked_only:true,null_other_values_accepted:false,
    original_access_rights_proven:false,record_entry_initialization_implemented:false,
    durable_synthetic_save:false,customer_table_writes:false,runtime_verified:false,business_accepted:false};
   window.fetch=async()=>new Response(JSON.stringify({project_id:pid,source_hash:hash,
    selected_source_set_id:sid,source_binding:binding,catalog_sha256:binding,available:true,
    reason:null,source_count:1,code_unit_count:0,scope_notice:'Synthetic fixture',runs:[window.run]}));
  });
  await page.addStyleTag({content:css});
  await page.addScriptTag({content:js});
  await page.getByText('Source behavior and conversion progress').waitFor();
  assert.equal(await page.getByText(/Checkbox draft behavior/).count(),0);
  const refresh=()=>page.getByRole('button',{name:'Refresh mapping status'}).click();
  await page.evaluate(()=>{window.run.checkbox_drafts=window.receipt});
  await refresh();
  const summary=page.getByText('Checkbox draft behavior (1 group)');
  await summary.focus();
  await page.keyboard.press('Enter');
  await page.getByText(/Turning it off manually clears/).waitFor();
  await page.getByText(/source behavior could not be safely mapped/).waitFor();
  assert.equal(await page.locator('img').count(),0);
  await page.screenshot({path:path.join(output,'checkbox-desktop.png'),fullPage:true});
  await page.setViewportSize({width:390,height:844});
  assert.ok(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth+2));
  await page.screenshot({path:path.join(output,'checkbox-mobile.png'),fullPage:true});
  await page.evaluate(()=>{window.run.checkbox_drafts.runtime_verified=true});
  await refresh();
  await page.getByRole('alert').waitFor();
  assert.equal(await page.getByRole('link',{name:'Download native APEXlang package'}).count(),0);
  assert.deepEqual(errors,[]);
 }finally{
  await browser.close();
 }
});
