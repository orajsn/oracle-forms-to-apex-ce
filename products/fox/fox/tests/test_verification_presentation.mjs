// Read-only public-status presentation. No queue, operator, browser or API calls.
import {test} from 'node:test';
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import React from 'react';
import {renderToStaticMarkup} from 'react-dom/server';
import ts from 'typescript';

const helper=await readFile(new URL('../web/verificationPresentation.ts',import.meta.url),'utf8');
const compiled=ts.transpileModule(helper,{compilerOptions:{module:ts.ModuleKind.ESNext,target:ts.ScriptTarget.ES2022}}).outputText;
const {presentVerificationStatus}=await import('data:text/javascript;base64,'+Buffer.from(compiled).toString('base64'));
const ui=await readFile(new URL('../web/main.tsx',import.meta.url),'utf8');
const componentSource=ui.slice(ui.indexOf('function ManagedVerificationStatus('),ui.indexOf('function Acceptance('));
assert.ok(componentSource.startsWith('function ManagedVerificationStatus('));
const componentJS=ts.transpileModule(componentSource,{fileName:'verification.tsx',compilerOptions:{module:ts.ModuleKind.ESNext,target:ts.ScriptTarget.ES2022,jsx:ts.JsxEmit.React}}).outputText;
const ManagedVerificationStatus=new Function('React','presentVerificationStatus',componentJS+'\nreturn ManagedVerificationStatus;')(React,presentVerificationStatus);
const status=(state='queued',operator_contact='recent')=>({
 configured:state!=='disabled',state,operator_contact:state==='disabled'?'not_reported':operator_contact,
 operator_last_seen_at_utc:null,queue_updated_at_utc:null,message:'Ignored server message.',
});
const view=value=>presentVerificationStatus('QA_REQUIRED',value);
const html=(value,runState='QA_REQUIRED')=>renderToStaticMarkup(React.createElement(ManagedVerificationStatus,{run:{state:runState,verification_status:value}}));

for(const [state,label] of [
 ['queued','Queued for verification'],['running','Verification attempt started'],
 ['attention','Operator attention required'],['not_queued','Not yet queued for verification'],
 ['unavailable','Verification status unavailable'],['disabled','Managed verification not configured'],
]){
 test('renders truthful managed status '+state,()=>{
  const value=view(status(state));assert.equal(value.state,state);assert.equal(value.label,label);
  const rendered=html(status(state));assert.match(rendered,/Managed verification status/);assert.ok(rendered.includes(label));
  assert.doesNotMatch(rendered,/<button|<form|<input|Ignored server message/);
 });
}
test('running only means an attempt started and never claims ongoing execution',()=>{
 const value=view(status('running'));
 assert.match(value.message,/attempt has started/);
 assert.match(value.message,/result has not yet been recorded/);
 assert.match(value.message,/does not confirm that the attempt is still running/);
 const rendered=html(status('running'));
 assert.match(rendered,/not this specific run/);
 assert.match(rendered,/does not prove that this attempt is still active/);
 assert.doesNotMatch(rendered,/operator is online|currently running|currently active|Verification completed|Technical checks passed/);
});
for(const state of ['queued','running']){
 for(const contact of ['recent','stale','not_reported','unknown']){
  test(state+' handles operator contact '+contact,()=>{
   const value=view(status(state,contact));
   assert.equal(value.operatorContact,contact);
   assert.equal(value.contactOperator,contact!=='recent');
   if(contact==='recent'){
    assert.equal(value.action,null);assert.match(value.contactMessage,/Latest reported/);
   }else assert.match(value.action,/Contact the FOX operator/);
   if(contact==='stale')assert.doesNotMatch(value.contactMessage,/offline|stopped|failed/);
   if(contact==='not_reported')assert.match(value.contactMessage,/No operator contact has been reported/);
  });
 }
}
for(const state of ['attention','not_queued','unavailable','disabled']){
 test(state+' asks for operator attention even if contact was recent',()=>{
  assert.equal(view(status(state,'recent')).contactOperator,true);
  assert.match(view(status(state,'recent')).action,/Contact the FOX operator/);
 });
}
test('attention explains reconciliation and no automatic retry without exposing controls',()=>{
 const rendered=html(status('attention'));
 assert.match(rendered,/needs operator reconciliation/);assert.match(rendered,/will not be retried automatically/);
 assert.doesNotMatch(rendered,/<button|Retry verification|Run QA|claim_token/);
});
for(const timestamp of ['2026-10-17T14:12:34Z','2026-10-17T14:12:34+00:00','2026-10-17T14:12:34.123456+00:00']){
 test('valid optional UTC last contact is explicit: '+timestamp,()=>{
  const value={...status('running','stale'),operator_last_seen_at_utc:timestamp};
  const presented=view(value);assert.equal(presented.lastSeen.value,timestamp);
  assert.equal(presented.lastSeen.label,'2026-10-17 14:12:34 UTC');
  const rendered=html(value);assert.match(rendered,/<time dateTime=/);assert.match(rendered,/Last recorded contact/);
 });
}
for(const timestamp of [undefined,null]){
 test('missing optional last-seen does not invent a timestamp',()=>{
  const value=view({...status(),operator_last_seen_at_utc:timestamp});
  assert.equal(value.operatorContact,'recent');assert.equal(value.lastSeen,null);
  assert.doesNotMatch(html({...status(),operator_last_seen_at_utc:timestamp}),/<time|Invalid Date/);
 });
}
for(const timestamp of ['',42,{},'<img src=x onerror=alert(1)>','2026-02-30T12:00:00Z','2026-10-17T24:00:00Z','2026-10-17T14:00:00+07:00','2026-10-17T14:00:00','2026-10-17T14:00:00Z\n']){
 test('malformed timestamp is hidden and contact becomes unknown',()=>{
  const supplied={...status(),operator_last_seen_at_utc:timestamp},value=view(supplied);
  assert.equal(value.lastSeen,null);assert.equal(value.operatorContact,'unknown');assert.equal(value.contactOperator,true);
  const rendered=html(supplied);assert.doesNotMatch(rendered,/<time|<img|Invalid Date/);
 });
}
for(const contact of ['unknown','not_reported']){
 test('does not attach an unrelated timestamp to '+contact+' contact',()=>{
  const value=view({...status('queued',contact),operator_last_seen_at_utc:'2026-10-17T14:12:34Z'});
  assert.equal(value.lastSeen,null);assert.equal(value.operatorContact,contact);
 });
}
for(const supplied of [undefined,null,[],{},'running',
 {configured:'true',state:'running'},{configured:false,state:'queued'},
 {configured:true,state:'disabled'},{configured:true,state:'completed'},
 {configured:true,state:'VERIFIED'},{configured:true,state:{private:'token'}},
]){
 test('absent inconsistent or malformed public status is unavailable, never successful',()=>{
  const value=view(supplied);assert.equal(value.state,'unavailable');assert.equal(value.operatorContact,'unknown');
  assert.equal(value.contactOperator,true);assert.equal(value.lastSeen,null);
  assert.doesNotMatch(JSON.stringify(value),/private|token|VERIFIED|completed/);
 });
}
test('disabled is accepted only for explicit configured false',()=>{
 assert.equal(view(status('disabled')).state,'disabled');
 assert.equal(view({configured:0,state:'disabled'}).state,'unavailable');
 assert.equal(view({...status('disabled'),operator_contact:'recent',operator_last_seen_at_utc:'2026-10-17T14:12:34Z'}).lastSeen,null);
});
test('unknown contact values do not echo details or imply liveness',()=>{
 for(const contact of ['online','recent\n',{},false]){
  const value=view(status('running',contact));assert.equal(value.operatorContact,'unknown');
  assert.equal(value.contactOperator,true);assert.doesNotMatch(JSON.stringify(value),/online|recent\\n/);
 }
});
test('never renders raw server messages unknown fields claim tokens or private paths',()=>{
 const value={...status('running','unknown'),message:'PRIVATE-MESSAGE-MARKER',
  claim_token:'PRIVATE-CLAIM-MARKER',operator_id:'PRIVATE-OPERATOR-MARKER',path:'C:/PRIVATE-PATH-MARKER',
  queue_updated_at_utc:'PRIVATE-QUEUE-MARKER',approved:true,downloadable:true};
 const rendered=html(value);
 for(const marker of ['PRIVATE-MESSAGE-MARKER','PRIVATE-CLAIM-MARKER','PRIVATE-OPERATOR-MARKER','PRIVATE-PATH-MARKER','PRIVATE-QUEUE-MARKER'])assert.ok(!rendered.includes(marker));
 assert.doesNotMatch(rendered,/Accepted APEX package|Accept tested package|Run QA|Retry verification/);
});
for(const runState of ['VERIFIED','ACCEPTED','REVIEW_REQUIRED','QUEUED','PROCESSING','ATTENTION',null]){
 test('managed queue status is not a proof or control for run state '+runState,()=>{
  assert.equal(presentVerificationStatus(runState,status('running')),null);
  assert.equal(html(status('running'),runState),'');
 });
}
test('source snapshot is not mutated or interpreted as permission',()=>{
 const value={...status('running'),claim_token:'SECRET'},before=JSON.stringify(value);
 presentVerificationStatus('QA_REQUIRED',value);assert.equal(JSON.stringify(value),before);
 assert.doesNotMatch(helper,/fetch\(|\.claim_token|\.message\b|JSON\.stringify/);
});
test('existing product rendering and consent proof acceptance download gates remain intact',()=>{
 assert.match(ui,/import \{presentSourceFindings,presentReviewer\} from '\.\/productPresentation'/);
 assert.match(ui,/\{r\.state==='QA_REQUIRED'&&<ManagedVerificationStatus run=\{r\}\/>\}/);
 assert.doesNotMatch(ui,/No action or test-tool setup is required from you/);
 assert.match(componentSource,/do not need to install or run test tools/);
 assert.doesNotMatch(componentSource,/api\(|fetch\(|onClick|onChange|<button|<form|<input|claim_token/);
 assert.match(ui,/const labVerified=verifiedLabSummary\(run,technical\)/);
 assert.match(ui,/\['REVIEW_REQUIRED','VERIFIED'\]\.includes\(r\.state\)&&r\.source_hash===detail\.inventory\.source_hash&&<Acceptance/);
 assert.match(ui,/r\.state==='ACCEPTED'&&r\.downloadable/);
 assert.match(ui,/disabled=\{busy\|\|!tested\|\|!reviewed\|\|!notes\.trim\(\)\}/);
 assert.match(ui,/!consent\.every\(Boolean\)\|\|!detail\.inventory\.conversion_eligible/);
});
