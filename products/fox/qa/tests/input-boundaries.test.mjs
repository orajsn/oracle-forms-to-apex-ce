import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {runInNewContext} from 'node:vm';
import {fillNativeQaValue,probeNativeQaMaximumLength} from '../lib/contracts.mjs';

function input(limit,{initial='A',attribute=String(limit),property=limit,transform=null,ignoreClear=false,cap=limit,wrongFocus=false,partialSelection=false}={}) {
  let value=initial,active=true,start=value.length,end=value.length;const fills=[],keys=[],clicks=[];
  return{fills,keys,clicks,getAttribute:async name=>{assert.equal(name,'maxlength');return attribute;},
    evaluate:async fn=>{const element={maxLength:property,value,selectionStart:start,selectionEnd:end,tagName:'INPUT',id:'TEXT_VALUE'};
      return runInNewContext(`(${fn.toString()})(element)`,{element,document:{activeElement:active?element:{tagName:'BUTTON',id:'other'}}});},
    inputValue:async()=>value,click:async()=>{clicks.push('click');active=!wrongFocus;start=end=value.length;},
    press:async key=>{keys.push(key);if(key==='ControlOrMeta+A'){active=!wrongFocus;start=partialSelection?value.length:0;end=value.length;}
      else if(key==='Backspace'){if(active&&!ignoreClear&&start===0&&end===value.length){value='';start=end=0;}}
      else if(key==='Tab')active=false;else assert.fail('Unexpected key');},
    fill:async next=>{fills.push(next);active=true;value=transform?transform(next,value):next.slice(0,cap);start=end=value.length;}};
}
const column=limit=>({name:'TEXT_VALUE',data_type:'VARCHAR2',max_length:limit});
for(const limit of [1,20,100,4000]){
  test(`valid VARCHAR2(${limit}) replacement clears and exactly rereads every deterministic phase`,async()=>{
    const field=input(limit,{transform:(next,old)=>next.slice(0,Math.max(0,limit-old.length))});
    for(const value of ['A','B','C','D','E','F'])await fillNativeQaValue(field,column(limit),value);
    assert.deepEqual(field.fills,['A','B','C','D','E','F']);
    assert.equal(field.clicks.length,6);assert.deepEqual(field.keys,Array(6).fill(['ControlOrMeta+A','Backspace','Tab']).flat());
  });
  test(`VARCHAR2(${limit}) boundary and overlength are tested from verified empty state`,async()=>{
    const field=input(limit,{transform:(next,old)=>next.slice(0,Math.max(0,limit-old.length))});
    const probe=await probeNativeQaMaximumLength(field,column(limit));
    assert.deepEqual(field.fills,['X'.repeat(limit),'X'.repeat(limit+1)]);
    assert.equal(field.clicks.length,2);assert.deepEqual(field.keys,Array(2).fill(['ControlOrMeta+A','Backspace','Tab']).flat());
    assert.equal(probe.actual,'X'.repeat(limit));assert.equal(probe.evidence.mode,'browser_maxlength');
    assert.equal(probe.evidence.exact_boundary_input_accepted,true);assert.equal(probe.evidence.server_validation_proven,false);
  });
}
for(const [name,options] of [['missing attribute',{attribute:null}],['different attribute',{attribute:'99'}],['different property',{property:99}],
  ['noncanonical attribute',{attribute:'100.0'}]])test(`text input rejects ${name} before changing it`,async()=>{
  const field=input(100,options);await assert.rejects(()=>fillNativeQaValue(field,column(100),'B'));assert.deepEqual(field.fills,[]);
});
test('failed explicit clear prevents a subsequent value fill',async()=>{
  const field=input(100,{ignoreClear:true});await assert.rejects(()=>fillNativeQaValue(field,column(100),'B'));assert.deepEqual(field.fills,[]);
  assert.deepEqual(field.keys,['ControlOrMeta+A','Backspace','Tab']);
});
for(const [name,options] of [['wrong focus',{wrongFocus:true}],['partial selection',{partialSelection:true}]])test(`${name} blocks Backspace before input can change`,async()=>{
  const field=input(100,options);await assert.rejects(()=>fillNativeQaValue(field,column(100),'B'),/full active selection/);
  assert.deepEqual(field.keys,['ControlOrMeta+A']);assert.deepEqual(field.fills,[]);assert.equal(await field.inputValue(),'A');
});
test('unexpected valid-value or overlength transformation remains a failure',async()=>{
  const malformed=input(100,{transform:next=>next===''?'':next+'!'});await assert.rejects(()=>fillNativeQaValue(malformed,column(100),'B'));
  const shortened=input(100,{transform:next=>next.length>100?'X'.repeat(99):next});await assert.rejects(()=>probeNativeQaMaximumLength(shortened,column(100)));
});
test('a smaller effective input capacity fails exact-boundary proof rather than passing as a cap',async()=>{
  const field=input(100,{cap:99});await assert.rejects(()=>probeNativeQaMaximumLength(field,column(100)));
  assert.deepEqual(field.fills,['X'.repeat(100)]);
});
test('uncapped exact overlength remains a separate APEX rejection path, never a proven server claim',async()=>{
  const field=input(100,{cap:1000});const probe=await probeNativeQaMaximumLength(field,column(100));
  assert.equal(probe.actual,'X'.repeat(101));assert.equal(probe.evidence.mode,'apex_validation');assert.equal(probe.evidence.server_validation_proven,false);
});
test('NUMBER and DATE retain exact input intent without text-limit assumptions',async()=>{
  for(const [data_type,value] of [['NUMBER','4'],['DATE','2026-01-04']]){
    const field=input(100);await fillNativeQaValue(field,{name:'VALUE_COL',data_type},value);assert.deepEqual(field.fills,[value]);
  }
});
test('all v2 valid fills and both concurrency writers use strict replacement helper',()=>{
  const source=readFileSync(new URL('../run-native.mjs',import.meta.url),'utf8');
  assert.match(source,/for\(const column of profile.fields\)await fillNativeQaValue\(field\(page,column\),column,values\[column.name\]\)/);
  assert.match(source,/fillNativeQaValue\(field\(a.page,editField\),editField,winning\[editField.name\]\)/);
  assert.match(source,/fillNativeQaValue\(field\(b.page,editField\),editField,stale\[editField.name\]\)/);
  assert.match(source,/probe=await probeNativeQaMaximumLength\(input,column\)/);
});
