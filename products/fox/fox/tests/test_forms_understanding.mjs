// Presentation tests use synthetic Forms XML and the actual local facts extractor.
import {test} from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {execFileSync} from 'node:child_process';
import React from 'react';
import {renderToStaticMarkup} from 'react-dom/server';
import ts from 'typescript';
const compile=(source,name)=>ts.transpileModule(source,{fileName:name,compilerOptions:{module:ts.ModuleKind.ESNext,target:ts.ScriptTarget.ES2022,jsx:ts.JsxEmit.React}}).outputText;
const data=source=>'data:text/javascript;base64,'+Buffer.from(source).toString('base64');
const helperURL=data(compile(readFileSync(new URL('../web/formsFactsPresentation.ts',import.meta.url),'utf8'),'formsFactsPresentation.ts'));
const api=await import(helperURL);
const component=compile(readFileSync(new URL('../web/FormsUnderstanding.tsx',import.meta.url),'utf8'),'FormsUnderstanding.tsx')
 .replace("from 'react'",'from '+JSON.stringify(import.meta.resolve('react')))
 .replace("from './formsFactsPresentation'",'from '+JSON.stringify(helperURL))
 .replace("import './formsUnderstanding.css';",'');
const {FormsUnderstanding}=await import(data(component));
const source='<Module><FormModule Name="SYNTHETIC"><Block Name="DATA" DatabaseBlock="true"><Item Name="ID" DatabaseItem="true"/><Trigger Name="WHEN-VALIDATE-ITEM" TriggerText="BEGIN NULL; END;"/></Block><Block Name="CONTROL" DatabaseBlock="false"><Item Name="ACTION" DatabaseItem="false"/></Block></FormModule></Module>';
const run=(xml=source)=>JSON.parse(execFileSync(process.env.FOX_TEST_PYTHON||'python',['-c',`import json,sys; from fox.forms_facts import assess_forms_xml; print(json.dumps(assess_forms_xml('synthetic.xml',sys.stdin.buffer.read())))`],{input:xml,encoding:'utf8'}));
const render=(facts,selectedSource,understanding)=>renderToStaticMarkup(React.createElement(FormsUnderstanding,{facts,selectedSource,understanding}));
test('actual synthetic extractor output displays local evidence without source code',()=>{
 const facts=run(),expected=facts.source,view=api.readFormsFacts(facts,expected),html=render(facts,expected);
 assert.equal(view.blocks.length,2);assert.equal(view.totals.items,2);assert.match(html,/Not run/);assert.match(html,/DATA/);assert.match(html,/CONTROL/);assert.match(html,/XML location/);assert.doesNotMatch(html,/BEGIN NULL|ready to convert|download/i);
});
test('stale source and malformed inventory fail closed',()=>{
 const facts=run(),expected=facts.source;
 assert.match(render(facts,{...expected,sha256:'f'.repeat(64)}),/no longer matches/);
 for(const change of [v=>v.totals.items++,v=>v.blocks[0].location.path='/bad raw SQL',v=>v.items[0].block_id='missing',v=>v.safety.code_executed=true]){
  const changed=structuredClone(facts);change(changed);assert.throws(()=>api.readFormsFacts(changed,expected));assert.match(render(changed,expected),/no longer matches/);
 }
});
test('status belongs to the selected source and is separate from generation',()=>{
 const facts=run(),expected=facts.source;
 assert.match(render(facts,expected,{state:'working',source_sha256:expected.sha256}),/In progress/);
 assert.match(render(facts,expected,{state:'reviewed',source_sha256:expected.sha256}),/Review recorded/);
 assert.match(render(facts,expected,{state:'reviewed',source_sha256:'f'.repeat(64)}),/no longer matches/);
 assert.match(render(null,null),/No source facts yet/);
});
test('actual unknown wrapper paths retain blocks and show uninterpreted finding',()=>{
 const facts=run('<FormModule Name="A"><Extension><Block Name="B"><Item Name="I"/></Block></Extension></FormModule>');
 const view=api.readFormsFacts(facts,facts.source),html=render(facts,facts.source);
 assert.equal(view.blocks.length,1);assert.equal(view.blocks[0].items.length,1);
 assert.match(view.blocks[0].location.path,/\/\*\[position\(\)=1\]\/Block\[1\]/);
 assert.match(html,/XML elements that the local inventory could not interpret/);
 for(const replacement of ['*[position()=0]','*[position()=01]','*[position() =1]','*[position()=1 or 1=1]','*[1]']){
  const altered=structuredClone(facts),block=altered.blocks[0];block.location.path=block.location.path.replace('*[position()=1]',replacement);
  const object=altered.objects.find(item=>item.id===block.id);object.location.path=block.location.path;
  assert.throws(()=>api.readFormsFacts(altered,facts.source));
 }
});
