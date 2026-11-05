import {test} from 'node:test';
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import {createRequire} from 'node:module';
import React from 'react';
import {renderToStaticMarkup} from 'react-dom/server';
import ts from 'typescript';

const require=createRequire(import.meta.url);
async function load(name){
 const source=await readFile(new URL('../web/'+name,import.meta.url),'utf8');
 const code=ts.transpileModule(source,{fileName:name,compilerOptions:{target:ts.ScriptTarget.ES2022,module:ts.ModuleKind.CommonJS,
  jsx:ts.JsxEmit.ReactJSX,esModuleInterop:true}}).outputText,module={exports:{}};
 new Function('require','module','exports',code)(require,module,module.exports);return module.exports;
}
const drafts=await load('PartialDraftPanel.tsx'),handoff=await load('ApexHandoff.tsx'),setup=await load('SetupReadiness.tsx');
const render=(component,props)=>renderToStaticMarkup(React.createElement(component,props));
const scope={scope:'fox-partial-draft-v1',project_id:'project-one',parent_source_hash:'a'.repeat(64),parent_plan_sha256:'b'.repeat(64),
 draft_sha256:'c'.repeat(64),derived_source_hash:'d'.repeat(64),selected_source_set_id:'ss-'+'1'.repeat(32),parent_source_set_id:'ss-'+'2'.repeat(32),
 available:true,warning:'Partial demo only.',next_action:'Review scope.',included_forms:[{form_name:'Orders',draft_form_name:'Orders - Draft',source_name:'orders.xml',components:['Native report','Native form']}],
 omitted_forms:[{form_name:'Missing details',source_name:'details.xml',reason:'Authoritative DDL missing.'}],
 omissions:[{form_name:'Orders',code:'MISSING_DEPENDENCY',message:'ORDER_API body is missing.',required_action:'Upload the package body.',draft_disposition:'Not implemented.',source_location:{form:'Orders',button:'Submit',trigger:'WHEN-BUTTON-PRESSED',code_line:1}}]};

test('draft scope is source/project bound and renders honest omissions',()=>{
 assert.ok(drafts.readDraftScope(scope,'project-one','d'.repeat(64)));
 assert.ok(drafts.readDraftScope(scope,'project-one','a'.repeat(64),true));
 assert.equal(drafts.readDraftScope(scope,'other','d'.repeat(64)),null);
 assert.equal(drafts.readDraftScope(scope,'project-one','a'.repeat(64)),null);
 const html=render(drafts.DraftScopeSummary,{value:scope,projectId:'project-one',sourceHash:'d'.repeat(64),onOriginal:()=>{}});
 assert.match(html,/1 forms included.*1 forms omitted/);assert.match(html,/Submit.*WHEN-BUTTON-PRESSED/);
 assert.match(html,/Not implemented/);assert.match(html,/Return to original sources/);
 assert.match(html,/not a merge/);assert.doesNotMatch(html,/Business accepted/);
});
test('preview shows omissions and next actions before requesting acceptance',()=>{
 const html=render(drafts.ScopeContents,{scope,showOmissions:true});
 assert.match(html,/<details open=""/);assert.match(html,/ORDER_API body is missing/);
 assert.match(html,/Next: Upload the package body/);
});
for(const mutate of [value=>{value.available=false;},value=>{value.included_forms=[];},value=>{value.omissions[0].required_action={bad:true};},
 value=>{value.omissions[0].source_location.code_line=-1;},value=>{value.parent_source_set_id='../other';}]){
 test('malformed draft data cannot become a trusted scope',()=>{
  const value=structuredClone(scope);mutate(value);assert.equal(drafts.readDraftScope(value,'project-one','d'.repeat(64)),null);
 });
}
test('scope and readiness content is escaped instead of rendered as HTML',()=>{
 const value=structuredClone(scope);value.included_forms[0].form_name='<script>alert(1)</script>';
 const html=render(drafts.DraftScopeSummary,{value,projectId:'project-one',sourceHash:'d'.repeat(64)});
 assert.match(html,/&lt;script&gt;/);assert.doesNotMatch(html,/<script>/);
 const readiness=render(setup.default,{configuration:{conversion_configured:true,configuration_scope:'Configuration only.',
  configuration_checks:[{code:'INTERNAL_CONVERTER',ready:true,message:'Configuration present.'}]},onCheck:async()=>({})});
 assert.match(readiness,/connection not tested here/);assert.match(readiness,/Not checked in this view/);
 assert.match(readiness,/does not mean those checks passed/);
});
test('APEX handoff reads actual recorded versions and never invents compatibility',()=>{
 let html=render(handoff.default,{evidence:{}});
 assert.match(html,/Not established in this evidence/);assert.doesNotMatch(html,/26\.1/);
 html=render(handoff.default,{evidence:{technical_verification:{scope:'fox-project-technical-verification-v1',
  observed_versions:{apex:'26.1.6',database:'23.26.4.1.0',sqlcl:'26.1.2.0'}}}});
 assert.match(html,/26\.1\.6/);assert.match(html,/23\.26\.4\.1\.0/);
 assert.match(html,/new application ID/);assert.match(html,/not a promise/);
});
