// LOCAL SYNTHETIC BROWSER MODEL ONLY. These exercise executed case flow and
// receipt compatibility, not Oracle, SQLcl, Playwright or deployed APEX proof.
import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync,existsSync} from 'node:fs';
import {execFileSync} from 'node:child_process';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {canonicalQaPlan,sha256,deriveNativeQaValues} from '../lib/contracts.mjs';
import {deriveProjectQaArtifacts,PROJECT_OBSERVATION_SCOPE} from '../lib/project-profile.mjs';
import {createProjectRuntimeResult,executeProjectCases,validateProjectObservation} from '../lib/project-runtime.mjs';
import {parseProjectPagination,ProjectBrowserDriver} from '../lib/project-browser.mjs';

const fixture=new URL('../../converter/tests/fixtures/project_v1/two-forms-aligned/',import.meta.url);
const hash=value=>sha256(canonicalQaPlan(value));
function binding({shared=false}={}) {
  const project=JSON.parse(readFileSync(new URL('native-project-spec.json',fixture)));
  const trace=JSON.parse(readFileSync(new URL('source-to-apex.json',fixture)));
  if(shared) {
    project.forms[1].native_form=structuredClone(project.forms[0].native_form);
    const second=trace.forms[1],first=trace.forms[0];
    second.table_name=first.table_name;second.schema_contract_sha256=first.schema_contract_sha256;
    second.native_spec_sha256=first.native_spec_sha256;
    second.items=first.items.map(item=>({...item,item:item.item.replace('P2_','P4_')}));
    trace.tables=[{...trace.tables.find(table=>table.table_name===first.table_name),module_ids:project.forms.map(form=>form.module_id)}];
    trace.rendering_spec_sha256=hash(project);
  }
  const artifacts=deriveProjectQaArtifacts(Buffer.from(JSON.stringify(project)),Buffer.from(JSON.stringify(trace)));
  return {...artifacts,target:{target:{application_id:99001}},targetReceiptSha256:'a'.repeat(64),inputSha256:{},
    accounts:{primary:{username:'FOX_QA_A',password:'local-model-primary'},secondary:{username:'FOX_QA_B',password:'local-model-secondary'},twoIndependentAccounts:true}};
}

class SyntheticBrowserModel {
  constructor(binding,fault={}) {
    this.binding=binding;this.fault=fault;this.tables=Object.fromEntries(binding.plan.tables.map(table=>[table.table_name,new Map()]));
    this.sessions={primary:{},secondary:{}};this.events=[];this.next=90071992547409931234567890123456789010n;
  }
  async start(){this.events.push('two-isolated-logins');}
  async close(){this.closed=true;}
  redact(error){return error.message;}
  hasUnexpectedDialog(){return false;}
  formNative(form){return this.binding.project.forms.find(item=>item.module_id===form.module_id).native_form;}
  async navigate(name,form){this.sessions[name]={form,kind:'report'};this.events.push(['navigate',name,form.module_id,form.report_page_id]);}
  async context(name,form,kind) {
    const state=this.sessions[name];assert.equal(state.form.module_id,form.module_id);assert.equal(state.kind,kind);
    return {application_id:99001,page_id:this.fault.wrongPage&&form===this.binding.plan.forms[1]?2:form[kind==='report'?'report_page_id':'form_page_id'],
      page_item_names:kind==='report'?[]:form.items.map(item=>item.item)};
  }
  async createPage(name,form){this.sessions[name]={form,kind:'form',key:null,values:{}};this.events.push(['createPage',form.module_id]);}
  async fill(name,form,values){assert.equal(this.sessions[name].form.module_id,form.module_id);this.sessions[name].values=structuredClone(values);return structuredClone(values);}
  async cancel(name,form){this.events.push(['cancel',name,form.module_id]);await this.navigate(name,form);return this.context(name,form,'report');}
  async saved(name,form){assert.equal(this.sessions[name].error,undefined);await this.navigate(name,form);return this.context(name,form,'report');}
  async openRecord(name,form,native,key) {
    const record=this.tables[form.table_name].get(key);assert.ok(record);
    this.sessions[name]={form,kind:'form',key,values:structuredClone(record.values),version:record.version};
    this.events.push(['open',name,form.module_id,key]);
  }
  async readRecord(name,form){const state=this.sessions[name];assert.equal(state.form.module_id,form.module_id);return {primary_key:state.key,values:structuredClone(state.values)};}
  async probe(name,form,column,attempted,kind) {
    const actual=kind==='maximum_length'?attempted.slice(0,column.length):attempted;
    this.sessions[name].values[column.name]=actual;this.events.push(['probe',form.module_id,column.name,kind]);return actual;
  }
  async submit(name,form,button,expected,key,beforeClick) {
    const state=this.sessions[name],native=this.formNative(form);assert.deepEqual(state.values,expected);assert.equal(state.key,key);
    await beforeClick(structuredClone(state.values));this.events.push(['submit',name,form.module_id,button]);
    const bad=native.columns.filter(column=>!column.primary_key).some(column=>
      !column.nullable&&state.values[column.name]===''||['not-a-number','not-a-date'].includes(state.values[column.name]));
    if(bad&&!this.fault.acceptInvalid){state.error='validation';return;}
    if(button==='Create') {
      const identity=String(this.next++);this.tables[form.table_name].set(identity,{values:structuredClone(expected),version:1});
      if(this.fault.extraRow)this.tables[form.table_name].set(String(this.next++),{values:structuredClone(expected),version:1});
    } else {
      const record=this.tables[form.table_name].get(key);
      if(record.version!==state.version&&!this.fault.acceptStale){state.error='stale';return;}
      record.values=structuredClone(expected);record.version++;
    }
  }
  async rejected(name,form,{stale=false}={}){assert.equal(this.sessions[name].form.module_id,form.module_id);return this.sessions[name].error===(stale?'stale':'validation');}
  async search(name,form,native,key) {
    await this.navigate(name,form);return {primary_keys:this.tables[form.table_name].has(key)?[key]:[],context:await this.context(name,form,'report')};
  }
  async observeTable(name,form) {
    await this.navigate(name,form);
    let records=[...this.tables[form.table_name]].map(([primary_key,record])=>({primary_key,values:structuredClone(record.values)}));
    if(this.fault.resetShared&&form===this.binding.plan.forms[1]){this.tables[form.table_name].clear();records=[];}
    const pages=records.length?records.map(row=>[row.primary_key]):[[]];
    return {observation_scope:PROJECT_OBSERVATION_SCOPE,records,pagination:{page_primary_keys:pages,
      reported_total_rows:this.fault.wrongTotal?records.length+1:records.length,terminal_next_page_enabled:false}};
  }
}

async function execute(options={},fault={}) {
  const input=binding(options),driver=new SyntheticBrowserModel(input,fault),result=createProjectRuntimeResult(input,'SYNTHETIC-MODEL-NOT-ORACLE-VERIFIED');
  let dispatches=0,persisted=0;
  await executeProjectCases(input,driver,result,{persist:async()=>{persisted++;},beginAttempt:async()=>{dispatches++;}});
  return {input,driver,result,dispatches,persisted};
}

function pythonVerify(input,result) {
  const root=fileURLToPath(new URL('../../',import.meta.url));
  const candidate=path.join(root,'fox','.venv',process.platform==='win32'?'Scripts':'bin',process.platform==='win32'?'python.exe':'python');
  const python=existsSync(candidate)?candidate:(process.platform==='win32'?'python':'python3');
  const script="import json,sys\nsys.path.insert(0,sys.argv[1])\nfrom fox.project_qa_plan import validate_project_qa_result\nv=json.load(sys.stdin)\nr=validate_project_qa_result(v['result'],v['project'],v['plan'],99001)\nprint(len(r))";
  return execFileSync(python,['-I','-B','-c',script,path.join(root,'fox')],{input:JSON.stringify({result,project:input.project,plan:input.plan}),encoding:'utf8',timeout:15000});
}

for(const shared of [false,true])test(`synthetic executed ${shared?'shared':'distinct'} table project serializes Python-verifiable case observations (NOT Oracle verified)`,async()=>{
  const {input,driver,result,dispatches,persisted}=await execute({shared});
  assert.equal(result.status,'PASSED');assert.equal(dispatches,1);assert.ok(persisted>30);assert.equal(driver.closed,true);
  assert.equal(pythonVerify(input,result).trim(),'2');assert.equal(result.forms.length,2);
  for(const [index,form] of result.forms.entries()) {
    assert.equal(form.tests.length,14);assert.equal(form.status,'PASSED');
    assert.equal(form.tests.find(item=>item.name==='create').evidence.rendered_contexts[0].page_id,index*2+2);
    assert.deepEqual(form.tests.find(item=>item.name==='concurrent_edit').evidence.account_identity_sha256,
      ['fox_qa_a','fox_qa_b'].map(sha256));
  }
  if(shared){assert.equal(result.forms[1].row_tracking.baseline_records.length,1);assert.equal(Object.values(result.final_table_records)[0].length,2);
    assert.equal(result.forms[1].row_tracking.final_pagination.page_primary_keys.length,2);}
  assert.ok(JSON.stringify(result).includes('90071992547409931234567890123456789010'));
  assert.ok(!JSON.stringify(result).includes('local-model-primary'));
  assert.ok(driver.events.filter(event=>Array.isArray(event)&&event[0]==='submit').length>5);
});

for(const [name,fault,shared] of [
  ['wrong module page',{wrongPage:true},false],['accepted invalid input',{acceptInvalid:true},false],
  ['accepted stale update',{acceptStale:true},false],['unexpected extra insert',{extraRow:true},false],
  ['unmeasured total',{wrongTotal:true},false],['shared-table reset',{resetShared:true},true],
])test(`synthetic fault ${name} stops and never emits a passing project`,async()=>{
  const {result,driver}=await execute({shared},fault);assert.equal(result.status,'FAILED');assert.equal(driver.closed,true);
  assert.ok(result.failure);assert.notEqual(result.dispatch_state,'ATTEMPT_COMPLETED');
});

test('dispatch denial prevents the first possible submission',async()=>{
  const input=binding(),driver=new SyntheticBrowserModel(input),result=createProjectRuntimeResult(input,'test');
  await executeProjectCases(input,driver,result,{beginAttempt:async()=>{throw new Error('already attempted');}});
  assert.equal(result.status,'FAILED');assert.equal(result.write_attempts.length,0);
  assert.equal(driver.events.filter(event=>Array.isArray(event)&&event[0]==='submit').length,0);
});

test('durable-output failure still closes every authenticated browser context',async()=>{
  const input=binding(),driver=new SyntheticBrowserModel(input),result=createProjectRuntimeResult(input,'test');
  await assert.rejects(executeProjectCases(input,driver,result,{persist:async()=>{throw new Error('synthetic full disk');}}));
  assert.equal(driver.closed,true);assert.equal(result.write_attempts.length,0);
});

test('case engine does not mutate selected package plan/profile/spec',async()=>{
  const input=binding(),before=canonicalQaPlan(input),driver=new SyntheticBrowserModel(input),result=createProjectRuntimeResult(input,'test');
  await executeProjectCases(input,driver,result);assert.equal(canonicalQaPlan(input),before);
});

test('measured pagination allows one page, multiple-page range and visible empty report only',()=>{
  assert.deepEqual(parseProjectPagination({labels:['1 - 15 of 31'],nextControls:[true],noData:false},['1']),{total:31,nextEnabled:true});
  assert.deepEqual(parseProjectPagination({labels:['31 - 31 of 31'],nextControls:[],noData:false},['31']),{total:31,nextEnabled:false});
  assert.deepEqual(parseProjectPagination({labels:[],nextControls:[],noData:true},[]),{total:0,nextEnabled:false});
  for(const observation of [
    {labels:[],nextControls:[],noData:false},{labels:['1 - 15 of more than 15'],nextControls:[true],noData:false},
    {labels:['1 - 15 of 31'],nextControls:[true,true],noData:false},{labels:['1 - 15 of 31','1 - 15 of 32'],nextControls:[true],noData:false},
  ])assert.throws(()=>parseProjectPagination(observation,['1']));
});

test('complete observation rejects duplicate, numeric, omitted and unterminated keys',()=>{
  const base={observation_scope:PROJECT_OBSERVATION_SCOPE,records:[{primary_key:'9007199254740993',values:{A:'B'}}],
    pagination:{page_primary_keys:[['9007199254740993']],reported_total_rows:1,terminal_next_page_enabled:false}};
  assert.deepEqual(validateProjectObservation(base),['9007199254740993']);
  for(const change of [o=>o.records[0].primary_key=9007199254740993,o=>o.pagination.page_primary_keys.push(['9007199254740993']),
    o=>o.pagination.page_primary_keys=[[]],o=>o.pagination.terminal_next_page_enabled=true]) {
    const changed=structuredClone(base);change(changed);assert.throws(()=>validateProjectObservation(changed));
  }
});

test('real adapter target guard rejects another app and credentials even on the allowed origin',()=>{
  const input=binding();input.targetUrl='https://asz8eqwfm8unca2-jsnf2apex.adb.us-ashburn-1.oraclecloudapps.com/ords/r/fox_qa_261025_1234abcd/f2a_qa_261025_1234abcd/';
  const driver=new ProjectBrowserDriver({binding:input,result:{},chromium:{}});
  assert.equal(driver.assertUrl(input.targetUrl+'form_2?session=123').origin,new URL(input.targetUrl).origin);
  assert.throws(()=>driver.assertUrl(input.targetUrl.replace('f2a_qa_261025_1234abcd','other_app')));
  assert.throws(()=>driver.assertUrl(input.targetUrl.replace('https://','https://secret@')));
  assert.throws(()=>driver.assertUrl(new URL('/ords/f?p=123:1:555',input.targetUrl).href));
});
