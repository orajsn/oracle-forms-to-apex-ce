/** Pure project QA metadata and retained-row helpers.
 *
 * This is deliberately separate from historical native v1/v2 contracts. A
 * derivable plan is not source completeness, execution permission or proof of
 * runtime success. Callers must bind duplicate-key-safe parsed package bytes,
 * establish clean import independently, and execute every form's cases.
 */
import {
  canonicalPrimaryKey, canonicalQaPlan, check, deriveNativeQaPlan,
  deriveNativeQaProfile, isHash, parseUniqueJson, samePrimaryKeySet,
  sha256, validateNativeQaSpec,
} from './contracts.mjs';

export const PROJECT_PROFILE_ID = 'native-project-v1';
export const PROJECT_PLAN_SCOPE = 'fox-project-qa-plan-v1';
export const PROJECT_OBSERVATION_SCOPE = 'all_rows_not_visible_page_subset';
const ROOT_FIELDS = ['schema_version','profile_id','data_mode','project_name','source_manifest_sha256','forms'];
const FORM_FIELDS = ['module_id','form_name','source_name','source_sha256','native_form'];
const TRACE_FIELDS = ['schema_version','scope','application_count','form_count','project_name',
  'source_manifest_sha256','rendering_spec_sha256','forms','tables','template','source_completeness_verified',
  'reviewer_approval_verified','sqlcl_validated','imported','runtime_verified','human_acceptance_recorded'];
const STORAGE_FIELDS = ['schema_version','scope','project_id','source_table_name',
  'source_schema_sha256','identity_sha256','target_table_name'];
const record = value => value !== null && typeof value === 'object' && !Array.isArray(value);
const exactFields = (value, fields) => record(value) && Object.keys(value).length === fields.length
  && fields.every(key => Object.hasOwn(value, key));
const same = (left, right) => canonicalQaPlan(left) === canonicalQaPlan(right);
const canonicalHash = value => sha256(canonicalQaPlan(value));

// Python source contracts order Unicode names by scalar, not UTF-16 code unit.
const sourceNameOrder = (left,right) => {
  const a=[...left],b=[...right];
  for(let i=0;i<Math.min(a.length,b.length);i++) {
    const difference=a[i].codePointAt(0)-b[i].codePointAt(0);if(difference)return difference;
  }
  return a.length-b.length;
};
// Unicode default case folding preserves dotless i and uses uppercase Cherokee.
const sourceNameFold = value => [...value].map(char => char==='\u0131'?char:
  /[\u13a0-\u13f5\u13f8-\u13fd\uab70-\uabbf]/u.test(char)?char.toUpperCase():
    char.toLowerCase().toUpperCase().toLowerCase()).join('');

function validateProjectStorage(project) {
  check(typeof project.project_id==='string'&&/^[A-Za-z0-9][A-Za-z0-9_.-]{0,79}(?![^])/.test(project.project_id),
    'Project storage requires a stable canonical project identity');
  const targets=new Map(),identities=new Map(),sources=new Map(),sourceHashes=new Map();
  for(const form of project.forms) {
    const native=validateNativeQaSpec(form.native_form),mapping=form.storage_mapping;
    check(exactFields(native,['profile_id','data_mode','table_name','columns','supported_operations'])
      &&native.columns.every(column=>exactFields(column,['name','label','data_type','nullable','primary_key','identity',
        ...(column.data_type==='VARCHAR2'?['length']:[])])),
    'Project storage requires the complete explicit structural schema');
    check(exactFields(mapping,STORAGE_FIELDS)&&mapping.schema_version===1
      &&mapping.scope==='fox-project-storage-v1'&&mapping.project_id===project.project_id,
    'Project storage mapping version or project binding differs');
    // Reuse the exact identifier/exclusion validator without permitting a source
    // table to become the runtime target. A temporary column validates the name.
    validateNativeQaSpec({...native,columns:[
      {name:mapping.source_table_name,label:'Source identity',data_type:'NUMBER',nullable:false,primary_key:true,identity:true},
      {name:mapping.source_table_name==='FOX_STORAGE_CHECK'?'FOX_STORAGE_CHECK_ALT':'FOX_STORAGE_CHECK',
        label:'Storage check',data_type:'NUMBER',nullable:true,primary_key:false,identity:false},
    ]});
    const sourceSchema={...native,table_name:mapping.source_table_name,
      columns:native.columns.map(column=>Object.fromEntries(Object.entries(column).filter(([key])=>key!=='label')))};
    const identity={schema_version:1,scope:'fox-project-storage-v1',project_id:project.project_id,
      source_table_name:mapping.source_table_name,source_schema_sha256:canonicalHash(sourceSchema)};
    const identityHash=canonicalHash(identity),target='FOX_NATIVE_'+identityHash.slice(0,19).toUpperCase();
    check(same(mapping,{...identity,identity_sha256:identityHash,target_table_name:target})&&native.table_name===target,
      'Project storage mapping does not match the original structural schema');
    for(const [seen,key,value] of [[targets,target,identityHash],[identities,identityHash,identity],
      [sources,mapping.source_table_name,identity.source_schema_sha256]]) {
      check(!seen.has(key)||same(seen.get(key),value),'Project storage identities collide or disagree');seen.set(key,value);
    }
    check(Array.isArray(form.ddl_sources)&&form.ddl_sources.length>0,
      'Project storage requires original DDL source references');
    const names=[];
    for(const ref of form.ddl_sources) {
      check(exactFields(ref,['name','sha256'])&&typeof ref.name==='string'&&[...ref.name].length>=1
        &&[...ref.name].length<=180&&ref.name.toLowerCase().endsWith('.sql')&&!/[\\/:\u0000-\u001f]/u.test(ref.name)
        &&!ref.name.includes('..')&&!/[\uD800-\uDFFF]/u.test(ref.name)&&isHash(ref.sha256),
      'Project DDL references must preserve safe original source names and hashes');
      names.push(ref.name);
    }
    check(same(names,[...names].sort(sourceNameOrder))&&new Set(names.map(sourceNameFold)).size===names.length,
      'Project DDL references must be unique and ordered by original filename');
    for(const source of [{name:form.source_name,sha256:form.source_sha256},...form.ddl_sources]) {
      check(typeof source.name==='string','Project original source name is invalid');
      const key=sourceNameFold(source.name);
      check(!sourceHashes.has(key)||same(sourceHashes.get(key),source),
        'Project original source filenames have conflicting byte identities');sourceHashes.set(key,source);
    }
  }
}

function schemaContract(spec) {
  return {profile_id:spec.profile_id,data_mode:spec.data_mode,table_name:spec.table_name,
    supported_operations:['query','insert','update'],columns:spec.columns.map(column => ({
      ...Object.fromEntries(Object.entries(column).filter(([key]) => key !== 'label')),
      primary_key:column.primary_key ?? false,identity:column.identity ?? false,
    }))};
}

/** Independently derive all modules/pages/items and every physical table.
 * projectSpecSha256 and traceSha256 identify the exact packaged files; nested
 * native_spec_sha256 values identify canonical embedded objects, not files.
 */
export function deriveProjectQaPlan(project, projectSpecSha256, trace, traceSha256) {
  const mapped=project?.schema_version===2;
  check(exactFields(project,[...ROOT_FIELDS,...(mapped?['project_id']:[])]) && [1,2].includes(project.schema_version)
    && project.profile_id === PROJECT_PROFILE_ID && project.data_mode === 'synthetic_test_only',
  'Project QA requires the explicit supported synthetic project specification');
  check([projectSpecSha256,traceSha256,project.source_manifest_sha256].every(isHash),
    'Exact project specification and trace byte hashes are required');
  const forms = project.forms;
  check(Array.isArray(forms) && forms.length >= 1 && forms.length <= 50
    && forms.every(form => exactFields(form,[...FORM_FIELDS,...(mapped?['ddl_sources','storage_mapping']:[])])),
  'Project QA must include every supported form');
  if(mapped)validateProjectStorage(project);
  const ids = forms.map(form => form.module_id);
  check(ids.every(id => typeof id === 'string' && /^form-[a-f0-9]{20}(?![^])/.test(id))
    && new Set(ids).size === ids.length && same(ids,[...ids].sort()),
  'Project modules must be unique and in canonical order');
  check(exactFields(trace,[...TRACE_FIELDS,...(mapped?['project_id']:[])])
    && trace.scope === `fox-native-project-render-trace-v${mapped?2:1}`
    && trace.schema_version === project.schema_version && (!mapped||trace.project_id===project.project_id)
    && trace.application_count === 1 && trace.form_count === forms.length
    && trace.project_name === project.project_name && trace.source_manifest_sha256 === project.source_manifest_sha256
    && trace.rendering_spec_sha256 === canonicalHash(project)
    && Array.isArray(trace.forms) && trace.forms.length === forms.length,
  'Project trace is incomplete or bound to another specification');
  const template=trace.template;
  check(exactFields(template,['template_id','sha256','profile_id','data_mode','max_forms','navigation_policy','home_policy'])
    &&template.template_id==='sqlcl-26.1.2-fox-project-v1'&&isHash(template.sha256)
    &&template.profile_id===PROJECT_PROFILE_ID&&template.data_mode==='synthetic_test_only'&&template.max_forms===50
    &&template.navigation_policy==='stable_module_id_order_not_inferred_business_flow'
    &&template.home_policy==='first_report_not_a_business_start_claim'
    &&['source_completeness_verified','reviewer_approval_verified','sqlcl_validated','imported',
      'runtime_verified','human_acceptance_recorded'].every(key=>trace[key]===false),
  'Project render trace must retain its exact non-execution template context');

  const plans = [], tables = new Map(), schemas = new Map(), storageTables = new Map();
  for (const [index, form] of forms.entries()) {
    check(isHash(form.source_sha256), 'A form lacks its exact source identity');
    const native = validateNativeQaSpec(form.native_form), nativeHash = canonicalHash(native);
    const base = deriveNativeQaPlan(native,nativeHash);
    const reportPage = 2 * index + 1, formPage = 2 * index + 2;
    const schema = schemaContract(native), schemaHash = canonicalHash(schema), table = native.table_name;
    check(!schemas.has(table) || same(schemas.get(table),schema),
      'Forms sharing a physical table have conflicting schemas');
    schemas.set(table,schema);
    const expectedMapping = {
      module_id:form.module_id,form_name:form.form_name,source_name:form.source_name,source_sha256:form.source_sha256,
      report_page_id:reportPage,form_page_id:formPage,report_alias:`FORM_${index+1}`,form_alias:`EDIT_${index+1}`,
      report_file:`pages/p${String(reportPage).padStart(5,'0')}-form_${index+1}.apx`,
      form_file:`pages/p${String(formPage).padStart(5,'0')}-edit_${index+1}.apx`,
      table_name:table,schema_contract_sha256:schemaHash,native_spec_sha256:nativeHash,
      items:native.columns.map(column => ({column:column.name,item:`P${formPage}_${column.name}`})),
      ...(mapped?{ddl_sources:form.ddl_sources,storage_mapping:form.storage_mapping}:{}),
    };
    check(same(trace.forms[index],expectedMapping),
      'A form trace has missing or mismatched pages, items or source bindings');
    if (!tables.has(table)) tables.set(table,{table_name:table,schema_contract_sha256:schemaHash,module_ids:[]});
    tables.get(table).module_ids.push(form.module_id);
    if(mapped) {
      if(!storageTables.has(table))storageTables.set(table,{storage_mapping:form.storage_mapping,ddl:new Map()});
      const stored=storageTables.get(table);
      check(same(stored.storage_mapping,form.storage_mapping),'Project shared storage mapping differs');
      for(const ref of form.ddl_sources)stored.ddl.set(ref.name,ref.sha256);
    }
    plans.push({module_id:form.module_id,form_name:form.form_name,source_name:form.source_name,source_sha256:form.source_sha256,
      table_name:table,native_spec_sha256:nativeHash,schema_contract_sha256:schemaHash,
      report_page_id:reportPage,form_page_id:formPage,report_alias:`FORM_${index+1}`,form_alias:`EDIT_${index+1}`,
      item_prefix:`P${formPage}_`,items:expectedMapping.items,
      primary_key:{...base.primary_key,item_name:`P${formPage}_${base.primary_key.name}`},
      row_tracking:{mode:'retained_table_baseline_then_observed_pk',delete_or_reset_allowed:false},
      edit_field:base.edit_field,cases:base.cases});
  }
  const expectedTables = [...tables.keys()].sort().map(table => tables.get(table));
  check(Array.isArray(trace.tables) && trace.tables.length === expectedTables.length,
    'Project trace does not cover each distinct physical table');
  for (const [index, table] of expectedTables.entries()) {
    const storage=storageTables.get(table.table_name);
    const expected={...table,...(mapped?{storage_mapping:storage.storage_mapping,
      ddl_sources:[...storage.ddl.keys()].sort(sourceNameOrder).map(name=>({name,sha256:storage.ddl.get(name)}))}:{})};
    const actual = trace.tables[index];
    check(exactFields(actual,[...Object.keys(expected),'schema_sql_sha256'])
      && Object.entries(expected).every(([key,value]) => same(actual[key],value)) && isHash(actual.schema_sql_sha256),
    'Project trace has orphaned, duplicate or conflicting physical tables');
  }
  return {schema_version:1,scope:PROJECT_PLAN_SCOPE,profile_id:PROJECT_PROFILE_ID,data_mode:'synthetic_test_only',
    source_manifest_sha256:project.source_manifest_sha256,project_spec_sha256:projectSpecSha256,
    source_to_apex_sha256:traceSha256,application_count:1,form_count:plans.length,forms:plans,tables:expectedTables,
    execution_order:ids,table_observation_scope:PROJECT_OBSERVATION_SCOPE,
    delete_or_reset_allowed:false,human_acceptance_recorded:false};
}

/** Deterministic values and dynamic selectors; no per-form omit/override path. */
export function deriveProjectQaProfile(project, plan) {
  check(Array.isArray(project?.forms) && Array.isArray(plan?.forms) && project.forms.length === plan.forms.length,
    'Project profile form coverage differs');
  const forms = project.forms.map((form,index) => {
    const expected = plan.forms[index];
    check(form.module_id === expected.module_id, 'Project profile module identity differs');
    return {module_id:form.module_id,report_page_id:expected.report_page_id,form_page_id:expected.form_page_id,
      item_prefix:expected.item_prefix,primary_key_item:expected.primary_key.item_name,
      native_profile:deriveNativeQaProfile(form.native_form)};
  });
  return {schema_version:1,scope:'fox-project-qa-profile-v1',profile_id:PROJECT_PROFILE_ID,
    test_plan_sha256:canonicalHash(plan),forms};
}

/** Parse and bind exact bytes before deriving a plan; do not hash reserialization. */
export function deriveProjectQaArtifacts(projectRaw, traceRaw) {
  const bounded = raw => check(raw instanceof Uint8Array && raw.byteLength > 0 && raw.byteLength <= 2_000_000,
    'Project QA inputs must be bounded exact bytes');
  bounded(projectRaw); bounded(traceRaw);
  const parse = raw => parseUniqueJson(raw,{onNumber:(lexeme,keysPath) => {
    if (['schema_version','application_count','max_forms','length','form_count','form_page_id','report_page_id'].includes(keysPath.at(-1))) {
      check(/^(?:0|[1-9][0-9]*)(?![^])/.test(lexeme) && Number.isSafeInteger(Number(lexeme)),
        'Project integer metadata must use an exact safe integer JSON token');
    }
  }});
  const project = parse(projectRaw), trace = parse(traceRaw);
  const plan = deriveProjectQaPlan(project,sha256(projectRaw),trace,sha256(traceRaw));
  return {project,trace,plan,profile:deriveProjectQaProfile(project,plan)};
}

function indexRecords(records, native) {
  validateNativeQaSpec(native);
  check(Array.isArray(records),'Complete observed row records are required');
  const fields = native.columns.filter(column => column.primary_key !== true), indexed = new Map();
  for (const row of records) {
    check(exactFields(row,['primary_key','values']), 'Observed row record is malformed');
    const key = canonicalPrimaryKey(row.primary_key);
    check(!indexed.has(key) && exactFields(row.values,fields.map(column => column.name)),
      'Observed row keys or field coverage is incomplete');
    for (const field of fields) check(typeof row.values[field.name] === 'string'
      || row.values[field.name] === null && field.nullable,
    'Observed values must preserve exact strings or declared nulls');
    indexed.set(key,row.values);
  }
  return indexed;
}

function sameRecords(left, right) {
  return samePrimaryKeySet([...left.keys()],[...right.keys()])
    && [...left].every(([key,values]) => same(values,right.get(key)));
}

function projectLedgerContext(ledger, project, plan, moduleId) {
  check(ledger?.scope === 'fox-project-row-ledger-v1' && ledger.test_plan_sha256 === canonicalHash(plan)
    && Number.isSafeInteger(ledger.next_form_index) && ledger.next_form_index >= 0
    && ledger.next_form_index < plan.forms.length && plan.execution_order[ledger.next_form_index] === moduleId
    && exactFields(ledger.tables,plan.tables.map(table => table.table_name)),
  'The project row ledger is stale, incomplete or out of order');
  const expected = plan.forms[ledger.next_form_index], form = project.forms[ledger.next_form_index];
  check(form.module_id === moduleId && form.native_form.table_name === expected.table_name
    && canonicalHash(form.native_form) === expected.native_spec_sha256,
  'The project row ledger has a different module or native specification');
  return {expected,native:form.native_form,baseline:indexRecords(ledger.tables[expected.table_name],form.native_form)};
}

/** Start only after the operator proves a clean import. This performs no I/O. */
export function createProjectRowLedger(project, plan) {
  deriveProjectQaProfile(project,plan);
  check(plan.scope === PROJECT_PLAN_SCOPE && Array.isArray(plan.tables) && plan.tables.length > 0,
    'An independently derived project plan is required');
  return {scope:'fox-project-row-ledger-v1',test_plan_sha256:canonicalHash(plan),next_form_index:0,
    tables:Object.fromEntries(plan.tables.map(table => [table.table_name,[]]))};
}

/** Validate the entire table before the next form, including prior forms' rows. */
export function assertProjectFormBaseline(ledger, project, plan, moduleId, observation) {
  const {native,baseline} = projectLedgerContext(ledger,project,plan,moduleId);
  check(observation?.observation_scope === PROJECT_OBSERVATION_SCOPE
    && sameRecords(indexRecords(observation.records,native),baseline),
  'Runtime lost or changed retained rows, or observed only a visible page subset');
  return [...baseline.keys()];
}

/** Retain exactly one newly observed identity and preserve every baseline row.
 * Returns a new ledger, never mutating inputs. This helper alone proves neither
 * case execution nor expected new-row business values; the independent Python
 * project receipt reader checks those before technical verification.
 */
export function retainProjectFormRow(ledger, project, plan, moduleId, observation) {
  const {expected,native,baseline} = projectLedgerContext(ledger,project,plan,moduleId);
  assertProjectFormBaseline(ledger,project,plan,moduleId,
    {observation_scope:observation?.observation_scope,records:observation?.baseline_records});
  const primaryKey = observation?.retained_primary_key;
  check(exactFields(primaryKey,['name','value']) && primaryKey.name === expected.primary_key.name,
    'The retained row does not use the mapped primary key');
  const key = canonicalPrimaryKey(primaryKey.value);
  check(!baseline.has(key),'The retained identity already existed before this form');
  const final = indexRecords(observation.final_records,native);
  check(samePrimaryKeySet([...final.keys()],[...baseline.keys(),key])
    && [...baseline].every(([oldKey,values]) => same(values,final.get(oldKey))),
  'Runtime modified or deleted a retained row, or created unexpected rows');
  return {...ledger,next_form_index:ledger.next_form_index+1,
    tables:{...structuredClone(ledger.tables),[expected.table_name]:structuredClone(observation.final_records)}};
}
