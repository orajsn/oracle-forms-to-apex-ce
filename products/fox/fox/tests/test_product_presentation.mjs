// Presentation-only tests using installed TypeScript and React. No browser/API.
import {test} from 'node:test';
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import React from 'react';
import {renderToStaticMarkup} from 'react-dom/server';
import ts from 'typescript';

const helper=await readFile(new URL('../web/productPresentation.ts',import.meta.url),'utf8');
const compiled=ts.transpileModule(helper,{compilerOptions:{module:ts.ModuleKind.ESNext,target:ts.ScriptTarget.ES2022}}).outputText;
const {presentSourceFindings,presentReviewer}=await import('data:text/javascript;base64,'+Buffer.from(compiled).toString('base64'));
const ui=await readFile(new URL('../web/main.tsx',import.meta.url),'utf8');
function component(name,next){
 const source=ui.slice(ui.indexOf('function '+name+'('),ui.indexOf('function '+next+'('));
 assert.ok(source.startsWith('function '+name+'('));
 const js=ts.transpileModule(source,{fileName:'presentation.tsx',compilerOptions:{module:ts.ModuleKind.ESNext,target:ts.ScriptTarget.ES2022,jsx:ts.JsxEmit.React}}).outputText;
 return new Function('React','presentSourceFindings','presentReviewer','ArrowRight',js+'\nreturn '+name+';')(React,presentSourceFindings,presentReviewer,()=>null);
}
const SourceOverview=component('SourceOverview','SourceEligibility');
const SourceEligibility=component('SourceEligibility','ReviewerFeedback');
const ReviewerFeedback=component('ReviewerFeedback','verifiedLabSummary');
const markup=(Component,props)=>renderToStaticMarkup(React.createElement(Component,props));
const blocker=(overrides={})=>({code:'BUSINESS_CODE_REVIEW_REQUIRED',message:'Map the trigger before conversion.',source:'blocked.xml',evidence:'trigger:WHEN-NEW-FORM-INSTANCE',...overrides});
function inventory(overrides={}){
 return {files:[{file:'source.xml'}],missing_count:0,issues:[],conversion_eligible:true,conversion_blockers:[],
  conversion_source_bytes:500,max_conversion_bytes:300000,forms_source_files:['source.xml'],
  native_assessment:{state:'READY',blockers:[],unsupported:[],native_form:null,scope_note:'Synthetic scope only.'},...overrides};
}
const blocked=()=>inventory({native_assessment:{state:'BLOCKED',blockers:[blocker()],unsupported:[{...blocker(),status:'UNCONVERTED_REVIEW_REQUIRED'}],native_form:null,scope_note:'Synthetic scope only.'}});

test('blocked native source with zero assessment issues shows one actionable blocker',()=>{
 const value=blocked(),summary=presentSourceFindings(value);
 assert.equal(summary.assessmentFindingCount,0);
 assert.equal(summary.blockerCount,1);
 assert.equal(summary.blockerCountLabel,'1');
 assert.equal(summary.detailsIncomplete,false);
 const html=markup(SourceOverview,{inventory:value,acceptedCount:0,onReview:()=>{}});
 assert.match(html,/<strong>1<\/strong><span>Conversion blockers<\/span>/);
 assert.match(html,/0 assessment findings \(separate\)/);
 assert.match(html,/Review conversion blockers/);
 assert.doesNotMatch(html,/Remediation items/);
 const details=markup(SourceEligibility,{inventory:value});
 assert.equal((details.match(/Map the trigger before conversion/g)||[]).length,1);
 assert.match(details,/blocked\.xml · trigger:WHEN-NEW-FORM-INSTANCE/);
 assert.match(details,/Action required/);
});
test('happy source reports zero blockers without pretending assessment findings block conversion',()=>{
 const value=inventory({issues:[{title:'Review client behavior'}]}),summary=presentSourceFindings(value);
 assert.equal(summary.blockerCount,0);
 assert.equal(summary.assessmentFindingCount,1);
 assert.equal(summary.detailsIncomplete,false);
 const html=markup(SourceOverview,{inventory:value,acceptedCount:2,onReview:()=>{}});
 assert.match(html,/<strong>0<\/strong><span>Conversion blockers<\/span>/);
 assert.match(html,/1 assessment findings \(separate\)/);
 assert.match(html,/<strong>2<\/strong><span>Accepted packages<\/span>/);
 assert.doesNotMatch(html,/Review conversion blockers/);
 assert.match(markup(SourceEligibility,{inventory:value}),/Source checks passed/);
});
test('exact duplicated entries collapse across producers and unsupported mirror is not counted',()=>{
 const item=blocker(),value=inventory({conversion_blockers:[item,{...item}],
  native_assessment:{state:'BLOCKED',blockers:[{...item}],unsupported:[{...item}],native_form:null}});
 assert.equal(presentSourceFindings(value).blockerCount,1);
});
test('multi-source blockers expand consistently and overlap with singular sources deduplicates',()=>{
 const value=inventory({conversion_blockers:[blocker({source:undefined,sources:['a.xml','b.xml','a.xml']})],
  native_assessment:{state:'BLOCKED',blockers:[blocker({source:'a.xml'})],native_form:null}});
 const summary=presentSourceFindings(value);
 assert.equal(summary.blockerCount,2);
 assert.deepEqual(summary.blockers.map(item=>item.source),['a.xml','b.xml']);
 const html=markup(SourceEligibility,{inventory:value});
 assert.equal((html.match(/Map the trigger before conversion/g)||[]).length,2);
 assert.match(html,/a\.xml/);assert.match(html,/b\.xml/);
});
test('different source names evidence and messages remain separate actionable blockers',()=>{
 const value=inventory({conversion_blockers:[
  blocker(),blocker({source:'BLOCKED.xml'}),blocker({evidence:'trigger:OTHER'}),
  blocker({message:'Review the required field mapping.'}),blocker({code:'OTHER_RULE'}),
 ]});
 const summary=presentSourceFindings(value);
 assert.equal(summary.blockerCount,5);
 assert.equal(new Set(summary.blockers.map(item=>item.key)).size,5);
});
test('same native code/source/item can have multiple distinct required fixes',()=>{
 const value=inventory({native_assessment:{state:'BLOCKED',native_form:null,blockers:[
  blocker({code:'ITEM_BEHAVIOR_REVIEW_REQUIRED',evidence:'CODE',message:'Map the item type.'}),
  blocker({code:'ITEM_BEHAVIOR_REVIEW_REQUIRED',evidence:'CODE',message:'Map the query-only behavior.'}),
  blocker({code:'ITEM_BEHAVIOR_REVIEW_REQUIRED',evidence:'CODE',message:'Resolve required/nullability mismatch.'}),
 ]}});
 assert.equal(presentSourceFindings(value).blockerCount,3);
});
test('unrelated general and native restrictions are not semantically merged',()=>{
 const value=inventory({conversion_blockers:[blocker({code:'BUSINESS_DML_REVIEW_REQUIRED'})],
  native_assessment:{state:'BLOCKED',blockers:[blocker()],native_form:null}});
 assert.equal(presentSourceFindings(value).blockerCount,2);
});
for(const value of [null,{},inventory({conversion_blockers:null}),inventory({conversion_eligible:false}),
 inventory({conversion_eligible:null}),inventory({conversion_eligible:undefined}),inventory({conversion_eligible:'true'}),
 inventory({conversion_profile:'native-table-form-v1',native_assessment:null}),
 inventory({native_assessment:{state:'BLOCKED',blockers:[]}})]){
 test('missing blocker data is unavailable rather than an invented zero',()=>{
  const summary=presentSourceFindings(value);
  assert.equal(summary.detailsIncomplete,true);
  assert.equal(summary.blockerCountLabel,'Unavailable');
 });
}
test('malformed details preserve valid blockers and visibly mark the count incomplete',()=>{
 const value=inventory({conversion_blockers:[blocker(),null,{code:'X',message:{raw:'never stringify'}}]});
 const summary=presentSourceFindings(value);
 assert.equal(summary.blockerCountLabel,'1+');
 const html=markup(SourceEligibility,{inventory:value});
 assert.match(html,/blocker count may be incomplete/);
 assert.doesNotMatch(html,/never stringify|\[object Object\]/);
});
test('summary does not mutate producer data or change its eligibility flags',()=>{
 const value=blocked(),before=JSON.stringify(value);
 presentSourceFindings(value);
 assert.equal(JSON.stringify(value),before);
 assert.equal(value.conversion_eligible,true);
 assert.equal(value.native_assessment.state,'BLOCKED');
});
test('review blocker action selects Sources without an API call',()=>{
 let selected=null;
 const tree=SourceOverview({inventory:blocked(),acceptedCount:0,onReview:tab=>{selected=tab;}});
 function find(node){
  if(!React.isValidElement(node))return null;
  if(node.type==='button')return node;
  for(const child of React.Children.toArray(node.props.children)){const result=find(child);if(result)return result;}
  return null;
 }
 const button=find(tree);assert.ok(button);button.props.onClick();assert.equal(selected,'Sources');
});

test('reviewer string notes render as ordinary text with known verdict labels',()=>{
 assert.deepEqual(presentReviewer({verdict:'approve',notes:'Checks are consistent.'}),{verdict:'Approved by the reviewer',notes:['Checks are consistent.'],notesStyle:'paragraph',notice:null});
 const html=markup(ReviewerFeedback,{reviewer:{verdict:'reject',notes:'Review the mapping.'}});
 assert.match(html,/Not approved by the reviewer/);assert.match(html,/<p>Review the mapping\.<\/p>/);
});
test('reviewer string-array notes become bullets, not serialized JSON',()=>{
 const html=markup(ReviewerFeedback,{reviewer:{verdict:'approve',notes:['First check passed.','Second check passed.']}});
 assert.match(html,/<ul><li>First check passed\.<\/li><li>Second check passed\.<\/li><\/ul>/);
 assert.doesNotMatch(html,/\[&quot;|First check passed\.",/);
});
for(const notes of ['', '   ', []]){
 test('empty notes get neutral explicit feedback',()=>{
  const html=markup(ReviewerFeedback,{reviewer:{verdict:'approve',notes}});
  assert.match(html,/No reviewer notes recorded/);
  assert.doesNotMatch(html,/<ul>|undefined|\[object Object\]/);
 });
}
test('legacy missing notes do not invent content or approval',()=>{
 const feedback=presentReviewer({});
 assert.equal(feedback.verdict,'Reviewer verdict unavailable');
 assert.equal(feedback.notice,'No reviewer notes recorded.');
});
for(const notes of [null,42,true,{private:'Do not stringify'},[['nested']]]){
 test('malformed notes have an honest fallback rather than raw objects',()=>{
  const html=markup(ReviewerFeedback,{reviewer:{verdict:'approve',notes}});
  assert.match(html,/unsupported format/);
  assert.doesNotMatch(html,/Do not stringify|nested|\[object Object\]|\{&quot;/);
 });
}
test('mixed note arrays retain readable entries and disclose omitted unsupported values',()=>{
 const feedback=presentReviewer({verdict:'approve',notes:['Visible note.',{hidden:'unknown'},'',12]});
 assert.deepEqual(feedback.notes,['Visible note.']);
 assert.match(feedback.notice,/Some reviewer notes/);
 const html=markup(ReviewerFeedback,{reviewer:{verdict:'approve',notes:['Visible note.',{}]}});
 assert.match(html,/<li>Visible note\.<\/li>/);assert.match(html,/unsupported format/);
});
test('unknown verdict never becomes approved',()=>{
 for(const verdict of ['APPROVE','pending',{},42,null]){
  const feedback=presentReviewer({verdict,notes:[]});
  assert.notEqual(feedback.verdict,'Approved by the reviewer');
  assert.match(feedback.verdict,/unavailable|Unrecognized/);
 }
});
test('actual React components escape source messages reviewer verdicts and notes',()=>{
 const attack='<img src=x onerror=alert(1)>';
 const reviewer=markup(ReviewerFeedback,{reviewer:{verdict:attack,notes:['</li><script>alert(1)</script>']}});
 assert.doesNotMatch(reviewer,/<img|<script>/);
 assert.match(reviewer,/&lt;img/);assert.match(reviewer,/&lt;script&gt;/);
 const details=markup(SourceEligibility,{inventory:inventory({conversion_blockers:[blocker({message:attack,source:'<source>'})]})});
 assert.doesNotMatch(details,/<img|<source>/);assert.match(details,/&lt;img/);assert.match(details,/&lt;source&gt;/);
});
test('conversion consent technical acceptance and download gates remain unchanged',()=>{
 assert.match(ui,/const ready=inventory\.conversion_eligible&&\(!native\|\|native\.state==='READY'\)/);
 assert.match(ui,/disabled=\{busy\|\|!session\.conversion_configured\|\|!consent\.every\(Boolean\)\|\|!detail\.inventory\.conversion_eligible\|\|\(session\.conversion_profile==='native-table-form-v1'&&detail\.inventory\.native_assessment\?\.state!=='READY'\)\}/);
 for(const field of ['approved_redacted_source:consent[0]','approved_external_ai:consent[1]','approved_prototype_scope:consent[2]'])assert.ok(ui.includes(field));
 assert.match(ui,/\['REVIEW_REQUIRED','VERIFIED'\]\.includes\(r\.state\)&&r\.source_hash===detail\.inventory\.source_hash&&<Acceptance/);
 assert.match(ui,/r\.state==='ACCEPTED'&&r\.downloadable/);
 assert.match(ui,/disabled=\{busy\|\|!tested\|\|!reviewed\|\|!notes\.trim\(\)\}/);
 assert.doesNotMatch(ui,/JSON\.stringify\(evidence\.reviewer/);
 assert.doesNotMatch(ui,/dangerouslySetInnerHTML/);
});
