import {test} from 'node:test';
import assert from 'node:assert/strict';
import {readFile,writeFile,mkdir} from 'node:fs/promises';
import {execFileSync,spawn} from 'node:child_process';
import {createRequire} from 'node:module';
import {createInterface} from 'node:readline';
import {once} from 'node:events';
import {fileURLToPath} from 'node:url';
import path from 'node:path';
import React from 'react';
import {renderToStaticMarkup} from 'react-dom/server';
import ts from 'typescript';
const require=createRequire(import.meta.url),root=fileURLToPath(new URL('../',import.meta.url)),product=path.dirname(root);
const python=process.env.FOX_TEST_PYTHON??path.join(root,'.venv',process.platform==='win32'?'Scripts/python.exe':'bin/python');
const code=String.raw`
import json,runpy
g=runpy.run_path('tests/test_dependency_guidance.py')
from fox.source_requests import build_source_requests
first=g['form']();second=g['src']('history.xml',first['text'].replace('Name="ORDER_ENTRY"','Name="ORDER_HISTORY"'))
base=[first,second,g['ddl'](),g['spec']()]
result={}
for name,files in [('missing',base),('complete',base+[g['body']()]),('wrong',[first,g['ddl'](),g['spec']('CANCEL_ORDER'),g['body']('CANCEL_ORDER')])]:
 p=g['assess'](files);result[name]={'plan':p,'requests':build_source_requests(p),'files':files}
print(json.dumps(result))
`;
const fixture=JSON.parse(execFileSync(python,['-B','-c',code],{cwd:root,encoding:'utf8',timeout:15000,maxBuffer:2000000}));
function load(name,imports={}){
 const raw=execFileSync(process.execPath,['-e','process.stdout.write(require("fs").readFileSync(process.argv[1],"utf8"))',path.join(root,'web',name)],{encoding:'utf8'});
 const js=ts.transpileModule(raw,{fileName:name,compilerOptions:{target:ts.ScriptTarget.ES2022,module:ts.ModuleKind.CommonJS,jsx:ts.JsxEmit.ReactJSX,esModuleInterop:true}}).outputText;
 const m={exports:{}};new Function('require','module','exports',js)(n=>Object.hasOwn(imports,n)?imports[n]:n.endsWith('.css')?{}:require(n),m,m.exports);return m.exports;
}
const api=load('sourceRequests.ts'),panel=load('SourceRequestPanel.tsx',{'./sourceRequests':api}).default;
test('real producer groups a shared body but preserves both callers',()=>{
 const row=fixture.missing,list=api.readSourceRequests(row.requests,row.plan),group=list.groups.find(g=>g.kind==='package');
 assert.equal(list.counts.requests,1);assert.equal(group.form_count,2);assert.equal(group.reference_count,2);
 const html=renderToStaticMarkup(React.createElement(panel,{value:row.requests,plan:row.plan,onAddFiles:()=>{}}));
 assert.match(html,/1 grouped source request across 2 forms/);assert.match(html,/ORDER_ENTRY/);assert.match(html,/ORDER_HISTORY/);
 assert.match(html,/\.pkb/);assert.doesNotMatch(html,/\.pks/);
 assert.match(html,new RegExp('source_hash='+row.plan.source_hash));
});
test('supplied source and wrong routine do not establish converted behavior',()=>{
 const row=fixture.complete,list=api.readSourceRequests(row.requests,row.plan);
 assert.equal(list.counts.requests,0);assert.equal(row.plan.can_generate,false);
 const html=renderToStaticMarkup(React.createElement(panel,{value:row.requests,plan:row.plan,onAddFiles:()=>{}}));
 assert.match(html,/mapping not verified/);assert.doesNotMatch(html,/Copy request/);
 const wrong=api.readSourceRequests(fixture.wrong.requests,fixture.wrong.plan);
 assert.equal(wrong.groups.find(g=>g.kind==='package').state,'ROUTINE_UNCONFIRMED');
});
test('stale bindings, dropped callers, false actions and cross-form references are rejected',()=>{
 const row=fixture.missing;
 for(const mutate of [r=>r.source_hash='0'.repeat(64),r=>r.project_id='another-project',
  r=>r.groups.pop(),r=>r.groups[0].references[0].module_id='unknown',r=>r.groups[0].form_count=99,
  r=>r.groups[0].actions=['invented action'],r=>r.groups[0].references.push(r.groups[0].references[0])]){
  const value=structuredClone(row.requests);mutate(value);assert.throws(()=>api.readSourceRequests(value,row.plan));
 }
});
test('copy text contains caller evidence, not raw trigger code',()=>{
 const row=fixture.missing,group=api.readSourceRequests(row.requests,row.plan).groups.find(g=>g.kind==='package');
 const plan=structuredClone(row.plan);for(const f of plan.forms)for(const d of f.dependencies)d.evidence='RAW_CODE_MARKER';
 const text=api.sourceRequestText(group,plan);assert.match(text,/Approve order/);assert.match(text,/ORDER_HISTORY/);
 assert.doesNotMatch(text,/RAW_CODE_MARKER/);assert.match(text,/not proof of translated APEX behavior/);
});
test('actual UI and local API: add one missing body, retain both forms and reject old export',{
 skip:process.env.FOX_UI_BROWSER!=='1',timeout:90000,
},async()=>{
 const packageRoot=process.env.FOX_TEST_NODE_MODULES;assert.ok(packageRoot);
 const {chromium}=createRequire(path.join(packageRoot,'../package.json'))('playwright');
 const out=path.join(product,'work',process.env.FOX_SOURCE_REQUEST_ARTIFACT??`source-request-flow-${Date.now()}`);
 assert.ok(out.startsWith(path.join(product,'work')+path.sep));await mkdir(path.dirname(out),{recursive:true});await mkdir(out);
 const child=spawn(python,['-B','tests/serve_source_requests_test.py','--root',out],{cwd:root,stdio:['pipe','pipe','pipe'],windowsHide:true});
 let log='';child.stderr.on('data',v=>{log+=v.toString();});
 const line=await Promise.race([once(createInterface({input:child.stdout}),'line').then(([v])=>v),new Promise((_,reject)=>setTimeout(()=>reject(new Error('Test server did not report an origin')),15000).unref())]);
 const {origin}=JSON.parse(line);assert.match(origin,/^http:\/\/127\.0\.0\.1:\d+$/);
 let browser,context,page;const errors=[];
 try{
  for(let n=0;n<100;n++){try{const response=await fetch(origin+'/api/health');if(response.ok)break;}catch{}await new Promise(resolve=>setTimeout(resolve,100));}
  browser=await chromium.launch({channel:'msedge',headless:true});context=await browser.newContext({viewport:{width:1440,height:1100}});page=await context.newPage();page.setDefaultTimeout(12000);page.on('pageerror',e=>errors.push(e.message));
  await page.goto(origin);await page.getByLabel('Username',{exact:true}).fill('source-flow-test');await page.getByLabel('Password',{exact:true}).fill('synthetic-source-flow-only');await page.getByRole('button',{name:'Sign in',exact:true}).click();
  await page.getByRole('button',{name:'New project',exact:true}).click();await page.getByLabel('Customer / organization',{exact:true}).fill('Synthetic source QA');await page.getByLabel('Project name',{exact:true}).fill('Shared dependency flow');await page.getByRole('button',{name:'Create project',exact:true}).click();
  await page.getByRole('heading',{name:'Add all the forms for this application',exact:true}).waitFor();
  const upload=async files=>{await page.getByLabel('Readable files, without a preparation manifest',{exact:true}).check();await page.getByLabel('Choose project source files',{exact:true}).setInputFiles(files.map(f=>({name:f.name,mimeType:'text/plain',buffer:Buffer.from(f.text)})));await page.getByRole('button',{name:'Upload and assess',exact:true}).click();await page.getByRole('heading',{name:'Review every form',exact:true}).waitFor();};
  await upload(fixture.missing.files);await page.getByRole('button',{name:'3 Resolve',exact:true}).click();
  const card=page.getByRole('article',{name:'Source request ORDER_API',exact:true});await card.getByText('Show all affected callers',{exact:true}).click();
  await card.getByText('ORDER_HISTORY',{exact:true}).waitFor();assert.equal(await card.getByText('ORDER_ENTRY',{exact:true}).count(),1);
  const projects=await (await context.request.get(origin+'/api/projects')).json();const id=projects[0].id;
  const before=await (await context.request.get(origin+'/api/projects/'+id)).json();assert.equal(before.source_requests.counts.requests,1);
  const oldLink=await page.getByRole('link',{name:'Download request list',exact:true}).getAttribute('href');const exported=await context.request.get(origin+oldLink);assert.equal(exported.status(),200);await writeFile(path.join(out,'request-before.txt'),await exported.text());
  await page.getByRole('region',{name:'Source requests across forms',exact:true}).screenshot({path:path.join(out,'missing-desktop.png')});
  await page.setViewportSize({width:390,height:844});assert.ok(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth+2));await page.getByRole('region',{name:'Source requests across forms',exact:true}).screenshot({path:path.join(out,'missing-mobile.png')});
  await card.getByRole('button',{name:'Add requested source',exact:true}).click();await upload([fixture.complete.files.find(f=>f.name==='order_api.pkb')]);await page.getByRole('button',{name:'3 Resolve',exact:true}).click();
  await page.getByText('No outstanding source requests reported',{exact:true}).waitFor();
  const after=await (await context.request.get(origin+'/api/projects/'+id)).json();assert.equal(after.id,id);assert.equal(after.project_plan.forms.length,2);assert.equal(after.project_plan.can_generate,false);assert.equal(after.source_requests.counts.requests,0);assert.notEqual(before.inventory.source_hash,after.inventory.source_hash);
  assert.equal((await context.request.get(origin+oldLink)).status(),409);assert.equal(after.runs.length,0);assert.equal(after.inventory.files.length,5);
  await page.getByRole('region',{name:'Source requests across forms',exact:true}).screenshot({path:path.join(out,'available-mobile.png')});assert.ok(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth+2));
  assert.deepEqual(errors,[]);await writeFile(path.join(out,'result.json'),JSON.stringify({passed:true,actual_api:true,actual_local_sqlite:true,backend_simulated:false,synthetic_source:true,oracle_executed:false,model_executed:false,human_acceptance_recorded:false,project_id:id,before_hash:before.inventory.source_hash,after_hash:after.inventory.source_hash,form_count:2,request_count_before:1,request_count_after:0,old_export_rejected:true},null,2));
 }catch(error){await page?.screenshot({path:path.join(out,'failure.png'),fullPage:true}).catch(()=>{});await writeFile(path.join(out,'failure.json'),JSON.stringify({passed:false,error:String(error.message),oracle_executed:false,model_executed:false}));throw error;}
 finally{await context?.close();await browser?.close();child.stdin.end('STOP\n');await Promise.race([once(child,'exit'),new Promise(resolve=>setTimeout(()=>{child.kill();resolve();},15000).unref())]);await writeFile(path.join(out,'server.log'),log);}
});
