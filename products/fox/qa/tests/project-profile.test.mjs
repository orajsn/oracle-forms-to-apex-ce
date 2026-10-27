// Authored synthetic fixture/observations only; no browser, database or models.
import test from 'node:test';
import assert from 'node:assert/strict';
import {execFileSync} from 'node:child_process';
import {existsSync,readFileSync} from 'node:fs';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {canonicalQaPlan,sha256} from '../lib/contracts.mjs';
import {
  PROJECT_OBSERVATION_SCOPE,assertProjectFormBaseline,createProjectRowLedger,
  deriveProjectQaArtifacts,deriveProjectQaPlan,deriveProjectQaProfile,retainProjectFormRow,
} from '../lib/project-profile.mjs';

const root = fileURLToPath(new URL('../../',import.meta.url));
const fixture = new URL('../../converter/tests/fixtures/project_v1/two-forms-aligned/',import.meta.url);
const originalProjectRaw = readFileSync(new URL('native-project-spec.json',fixture));
const originalTraceRaw = readFileSync(new URL('source-to-apex.json',fixture));
const originalProject = JSON.parse(originalProjectRaw), originalTrace = JSON.parse(originalTraceRaw);
const clone = value => structuredClone(value);
const hash = value => sha256(canonicalQaPlan(value));

function mappingFor(project) {
  // Author the expected mapping from the declared deterministic allocation.
  // Fake schema SQL digests are structural fixture metadata, not import proof.
  const tables = new Map();
  const forms = project.forms.map((form,index) => {
    const native = form.native_form, reportPage = index*2+1, formPage = index*2+2;
    const schema = {profile_id:native.profile_id,data_mode:native.data_mode,table_name:native.table_name,
      supported_operations:['query','insert','update'],columns:native.columns.map(column => ({
        ...Object.fromEntries(Object.entries(column).filter(([key]) => key!=='label')),
        primary_key:column.primary_key??false,identity:column.identity??false,
      }))};
    if (!tables.has(native.table_name)) tables.set(native.table_name,{table_name:native.table_name,
      schema_contract_sha256:hash(schema),schema_sql_sha256:'a'.repeat(64),module_ids:[]});
    tables.get(native.table_name).module_ids.push(form.module_id);
    return {module_id:form.module_id,form_name:form.form_name,source_name:form.source_name,source_sha256:form.source_sha256,
      report_page_id:reportPage,form_page_id:formPage,report_alias:`FORM_${index+1}`,form_alias:`EDIT_${index+1}`,
      report_file:`pages/p${String(reportPage).padStart(5,'0')}-form_${index+1}.apx`,
      form_file:`pages/p${String(formPage).padStart(5,'0')}-edit_${index+1}.apx`,table_name:native.table_name,
      schema_contract_sha256:hash(schema),native_spec_sha256:hash(native),
      items:native.columns.map(column => ({column:column.name,item:`P${formPage}_${column.name}`}))};
  });
  return {...clone(originalTrace),schema_version:1,scope:'fox-native-project-render-trace-v1',application_count:1,form_count:forms.length,
    project_name:project.project_name,source_manifest_sha256:project.source_manifest_sha256,
    rendering_spec_sha256:hash(project),forms,tables:[...tables.keys()].sort().map(table => tables.get(table))};
}

function inputs(project=originalProject, trace=originalTrace) {
  const projectRaw=Buffer.from(JSON.stringify(project)),traceRaw=Buffer.from(JSON.stringify(trace));
  return {project:clone(project),trace:clone(trace),projectRaw,traceRaw,
    projectHash:sha256(projectRaw),traceHash:sha256(traceRaw)};
}
const derive = value => deriveProjectQaPlan(value.project,value.projectHash,value.trace,value.traceHash);

function sharedInputs() {
  const project=clone(originalProject);
  project.forms[1].native_form=clone(project.forms[0].native_form);
  project.forms[1].native_form.columns[1].label='Alternative customer name';
  return inputs(project,mappingFor(project));
}

test('two-form authored renderer fixture derives complete dynamic page and item coverage',()=>{
  const {plan,profile}=deriveProjectQaArtifacts(originalProjectRaw,originalTraceRaw);
  assert.equal(plan.application_count,1);
  assert.equal(plan.form_count,2);
  assert.deepEqual(plan.forms.map(form=>[form.report_page_id,form.form_page_id,form.item_prefix]),[[1,2,'P2_'],[3,4,'P4_']]);
  assert.equal(plan.forms[1].primary_key.item_name,'P4_ORDER_ID');
  assert.deepEqual(profile.forms[1].native_profile.fields.map(field=>field.name),['TITLE','AMOUNT','DUE_DATE','STATUS']);
  assert.equal(plan.forms[0].cases.find(item=>item.name==='invalid_number').applicable,false);
  assert.equal(plan.forms[1].cases.find(item=>item.name==='invalid_number').applicable,true);
  assert.equal(plan.forms[1].cases.find(item=>item.name==='invalid_date').applicable,true);
  assert.equal(plan.human_acceptance_recorded,false);
  assert.equal(plan.delete_or_reset_allowed,false);
});

test('exact packaged bytes are bound without substituting canonical reserialization',()=>{
  const left=deriveProjectQaArtifacts(originalProjectRaw,originalTraceRaw);
  const changedProject=Buffer.from(JSON.stringify(originalProject,null,2));
  const right=deriveProjectQaArtifacts(changedProject,originalTraceRaw);
  assert.notEqual(left.plan.project_spec_sha256,right.plan.project_spec_sha256);
  assert.equal(left.plan.project_spec_sha256,sha256(originalProjectRaw));
  assert.equal(left.plan.source_to_apex_sha256,sha256(originalTraceRaw));
  assert.deepEqual(left.plan.forms,right.plan.forms);
});

test('shared physical table retains two independent form plans and display labels',()=>{
  const data=sharedInputs(),plan=derive(data),profile=deriveProjectQaProfile(data.project,plan);
  assert.equal(plan.tables.length,1);
  assert.deepEqual(plan.tables[0].module_ids,data.project.forms.map(form=>form.module_id));
  assert.equal(plan.forms.length,2);
  assert.equal(plan.forms[0].cases.length,14);
  assert.equal(plan.forms[1].cases.length,14);
  assert.notEqual(profile.forms[0].native_profile.fields[0].label,profile.forms[1].native_profile.fields[0].label);
  assert.equal(profile.forms[1].primary_key_item,'P4_CUSTOMER_ID');
});

test('derivation and profile leave every supplied object unchanged',()=>{
  const data=sharedInputs(),before={...clone(data),projectRaw:Buffer.from(data.projectRaw),traceRaw:Buffer.from(data.traceRaw)};
  const plan=derive(data);deriveProjectQaProfile(data.project,plan);
  assert.deepEqual(data,before);
});

const invalidCases = [
  ['missing project form',d=>d.project.forms.pop()],
  ['duplicate module',d=>d.project.forms[1].module_id=d.project.forms[0].module_id],
  ['reordered modules',d=>d.project.forms.reverse()],
  ['missing mapped form',d=>d.trace.forms.pop()],
  ['duplicate mapped form',d=>d.trace.forms[1]=clone(d.trace.forms[0])],
  ['wrong report page',d=>d.trace.forms[1].report_page_id=1],
  ['wrong form page',d=>d.trace.forms[1].form_page_id=2],
  ['report filename differing from alias',d=>d.trace.forms[0].report_file='pages/p00001-form-1.apx'],
  ['form filename differing from alias',d=>d.trace.forms[0].form_file='pages/p00002-edit-1.apx'],
  ['hardcoded second form prefix',d=>d.trace.forms[1].items[0].item='P2_ORDER_ID'],
  ['missing mapped item',d=>d.trace.forms[1].items.pop()],
  ['orphaned table',d=>d.trace.tables.push(clone(d.trace.tables[0]))],
  ['missing physical table',d=>d.trace.tables.pop()],
  ['missing table module',d=>d.trace.tables[1].module_ids=[]],
  ['wrong table schema hash',d=>d.trace.tables[0].schema_contract_sha256='f'.repeat(64)],
  ['wrong source digest',d=>d.trace.forms[0].source_sha256='e'.repeat(64)],
  ['wrong embedded spec digest',d=>d.trace.forms[0].native_spec_sha256='e'.repeat(64)],
  ['wrong rendering spec digest',d=>d.trace.rendering_spec_sha256='e'.repeat(64)],
  ['missing exact project digest',d=>d.projectHash=null],
  ['malformed exact trace digest',d=>d.traceHash='bad'],
  ['more than one application',d=>d.trace.application_count=2],
  ['boolean application count',d=>d.trace.application_count=true],
  ['legacy conversion profile',d=>d.project.profile_id='native-table-form-v1'],
  ['unknown project field',d=>d.project.omit_second_form=true],
  ['unknown trace field',d=>d.trace.storage_mapping={}],
  ['legacy trace with project identity',d=>d.trace.project_id='not-version-one'],
  ['render trace claiming runtime proof',d=>d.trace.runtime_verified=true],
  ['render trace missing its false approval marker',d=>delete d.trace.reviewer_approval_verified],
  ['unknown template field',d=>d.trace.template.approval=true],
  ['changed navigation policy',d=>d.trace.template.navigation_policy='business_flow'],
];
for (const [name,mutate] of invalidCases) test(`rejects ${name}`,()=>{
  const data=inputs();mutate(data);assert.throws(()=>derive(data));
});

test('conflicting shared-table metadata cannot pass with a matching trace',()=>{
  const data=sharedInputs();data.project.forms[1].native_form.columns[1].length=99;
  data.trace=mappingFor(data.project);
  assert.throws(()=>derive(data),/conflicting schemas/);
});

test('profile rejects missing or reordered module coverage',()=>{
  const data=inputs(),plan=derive(data);
  const missing=clone(plan);missing.forms.pop();assert.throws(()=>deriveProjectQaProfile(data.project,missing));
  const reordered=clone(plan);reordered.forms.reverse();assert.throws(()=>deriveProjectQaProfile(data.project,reordered));
});

test('exact byte parser rejects duplicate keys, malformed UTF-8 and decimal metadata tokens',()=>{
  const text=originalProjectRaw.toString();
  assert.throws(()=>deriveProjectQaArtifacts(Buffer.from(text.replace('"schema_version":1','"schema_version":1,"schema_version":1')),originalTraceRaw));
  assert.throws(()=>deriveProjectQaArtifacts(originalProjectRaw,Buffer.from('{"forms":[],"forms":[]}')));
  assert.throws(()=>deriveProjectQaArtifacts(Buffer.from([0xff]),originalTraceRaw));
  assert.throws(()=>deriveProjectQaArtifacts(Buffer.from(text.replace('"length":100','"length":100.0')),originalTraceRaw));
  assert.throws(()=>deriveProjectQaArtifacts(originalProjectRaw,Buffer.from(originalTraceRaw.toString().replace('"form_page_id":4','"form_page_id":4.0'))));
  assert.throws(()=>deriveProjectQaArtifacts(Buffer.from(text.replace('"schema_version":1','"schema_version":1.0')),originalTraceRaw));
  assert.throws(()=>deriveProjectQaArtifacts(originalProjectRaw,Buffer.from(originalTraceRaw.toString().replace('"max_forms":50','"max_forms":5e1'))));
  assert.throws(()=>deriveProjectQaArtifacts(Buffer.alloc(2_000_001),originalTraceRaw));
});

test('JavaScript plan and profile match independent Python for distinct and shared table vectors',()=>{
  const vectors=[inputs(),sharedInputs()];
  const optional=sharedInputs();
  for(const form of optional.project.forms) {
    form.native_form.columns[1].nullable=true;
    delete form.native_form.columns[1].identity;delete form.native_form.columns[1].primary_key;
    delete form.native_form.supported_operations;
  }
  optional.trace=mappingFor(optional.project);vectors.push(inputs(optional.project,optional.trace));
  const pythonCandidate=path.join(root,'fox','.venv',process.platform==='win32'?'Scripts':'bin',process.platform==='win32'?'python.exe':'python');
  const python=existsSync(pythonCandidate)?pythonCandidate:(process.platform==='win32'?'python':'python3');
  const script=`import json,sys\nsys.path.insert(0,sys.argv[1])\nfrom fox.project_qa_plan import derive_project_qa_plan,derive_project_qa_profile\nresult=[]\nfor v in json.load(sys.stdin):\n p=derive_project_qa_plan(v['project'],v['projectHash'],v['trace'],v['traceHash'])\n result.append({'plan':p,'profile':derive_project_qa_profile(v['project'],p)})\nprint(json.dumps(result,ensure_ascii=False))`;
  const pythonResult=JSON.parse(execFileSync(python,['-I','-B','-c',script,path.join(root,'fox')],{
    input:JSON.stringify(vectors.map(({project,trace,projectHash,traceHash})=>({project,trace,projectHash,traceHash}))),
    encoding:'utf8',timeout:15_000,maxBuffer:2_000_000,
  }));
  const jsResult=vectors.map(value=>{const plan=derive(value);return{plan,profile:deriveProjectQaProfile(value.project,plan)};});
  assert.deepEqual(jsResult,pythonResult);
});

function ledgerFixture() {
  const data=sharedInputs(),plan=derive(data),ledger=createProjectRowLedger(data.project,plan);
  const key='90071992547409931234567890123456789012';
  const secondKey='90071992547409931234567890123456789013';
  const row={primary_key:key,values:{CUSTOMER_NAME:'D'}};
  const secondRow={primary_key:secondKey,values:{CUSTOMER_NAME:'D'}};
  const observation={observation_scope:PROJECT_OBSERVATION_SCOPE,baseline_records:[],
    retained_primary_key:{name:'CUSTOMER_ID',value:key},final_records:[row]};
  return {...data,plan,ledger,key,secondKey,row,secondRow,observation};
}

test('ledger preserves exact 38-digit keys and every shared-table row without resetting',()=>{
  const f=ledgerFixture(),before=clone(f.ledger);
  assert.deepEqual(assertProjectFormBaseline(f.ledger,f.project,f.plan,f.plan.execution_order[0],
    {observation_scope:PROJECT_OBSERVATION_SCOPE,records:[]}),[]);
  const first=retainProjectFormRow(f.ledger,f.project,f.plan,f.plan.execution_order[0],f.observation);
  assert.deepEqual(f.ledger,before);
  assert.deepEqual(assertProjectFormBaseline(first,f.project,f.plan,f.plan.execution_order[1],
    {observation_scope:PROJECT_OBSERVATION_SCOPE,records:[f.row]}),[f.key]);
  const final=retainProjectFormRow(first,f.project,f.plan,f.plan.execution_order[1],{
    observation_scope:PROJECT_OBSERVATION_SCOPE,baseline_records:[f.row],
    retained_primary_key:{name:'CUSTOMER_ID',value:f.secondKey},final_records:[f.secondRow,f.row]});
  assert.equal(final.next_form_index,2);
  assert.equal(final.tables.FOX_NATIVE_CUSTOMERS.length,2);
  assert.equal(typeof final.tables.FOX_NATIVE_CUSTOMERS[0].primary_key,'string');
  final.tables.FOX_NATIVE_CUSTOMERS[1].values.CUSTOMER_NAME='changed copy';
  assert.equal(first.tables.FOX_NATIVE_CUSTOMERS[0].values.CUSTOMER_NAME,'D');
});

test('ledger rejects rows not proved by the clean empty starting context',()=>{
  const f=ledgerFixture();
  assert.throws(()=>assertProjectFormBaseline(f.ledger,f.project,f.plan,f.plan.execution_order[0],
    {observation_scope:PROJECT_OBSERVATION_SCOPE,records:[f.row]}));
});

for(const [name,change] of [
  ['number-coerced primary key',o=>o.retained_primary_key.value=9007199254740992],
  ['leading-zero primary key',o=>o.retained_primary_key.value='01'],
  ['scientific primary key',o=>o.retained_primary_key.value='1e10'],
  ['numeric row key',o=>o.final_records[0].primary_key=1],
  ['unexpected extra row',o=>o.final_records.push({primary_key:'2',values:{CUSTOMER_NAME:'A'}})],
  ['duplicated row key',o=>o.final_records.push(clone(o.final_records[0]))],
  ['missing editable field',o=>o.final_records[0].values={}],
  ['numeric editable value',o=>o.final_records[0].values.CUSTOMER_NAME=4],
  ['unapproved null',o=>o.final_records[0].values.CUSTOMER_NAME=null],
  ['visible-page-only observation',o=>o.observation_scope='visible_rows'],
]) test(`ledger rejects ${name}`,()=>{
  const f=ledgerFixture();change(f.observation);
  assert.throws(()=>retainProjectFormRow(f.ledger,f.project,f.plan,f.plan.execution_order[0],f.observation));
});

test('ledger rejects omitted, modified and reset earlier rows, reused identity and wrong module order',()=>{
  const f=ledgerFixture(),module=f.plan.execution_order;
  assert.throws(()=>retainProjectFormRow(f.ledger,f.project,f.plan,module[1],f.observation));
  const first=retainProjectFormRow(f.ledger,f.project,f.plan,module[0],f.observation);
  const second={observation_scope:PROJECT_OBSERVATION_SCOPE,baseline_records:[f.row],
    retained_primary_key:{name:'CUSTOMER_ID',value:f.secondKey},final_records:[f.row,f.secondRow]};
  for(const mutate of [o=>o.baseline_records=[],o=>o.final_records.shift(),
    o=>o.final_records[0].values.CUSTOMER_NAME='not preserved',
    o=>o.retained_primary_key.value=f.key]) {
    const changed=clone(second);mutate(changed);
    assert.throws(()=>retainProjectFormRow(first,f.project,f.plan,module[1],changed));
  }
  assert.throws(()=>retainProjectFormRow(first,f.project,f.plan,module[0],f.observation));
});
