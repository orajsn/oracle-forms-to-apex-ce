// Authored local synthetic byte-binding tests. No Oracle, browser or cloud run.
import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {canonicalQaPlan,sha256,SCOPE} from '../lib/contracts.mjs';
import {crc32} from '../lib/package-evidence.mjs';
import {deriveProjectQaArtifacts} from '../lib/project-profile.mjs';
import {inspectProjectPackageBytes,validateProjectRunnerInputs,loadProjectRunnerInputs} from '../lib/project-runner-inputs.mjs';

const bytes=value=>Buffer.from(JSON.stringify(value));
const hash=value=>sha256(canonicalQaPlan(value));
const NOW=Date.parse('2026-10-25T04:00:00Z');
const fixtureRoot=new URL('../../converter/tests/fixtures/project_v1/two-forms-aligned/',import.meta.url);
const mappedFixtureRoot=new URL('../../converter/tests/fixtures/project_v2/mapped-source/',import.meta.url);
const INSTANCE='ocid1.instance.oc1.iad.anuwcljtc7x6gxic5w37qsyp3rst64betkt4uk2pdcrtmy3okspcpbv77qea';

function zip(entries) {
  const locals=[],centrals=[];let offset=0;
  for(const [name,data] of entries) {
    const nameBytes=Buffer.from(name),local=Buffer.alloc(30),central=Buffer.alloc(46),crc=crc32(data);
    local.writeUInt32LE(0x04034b50);local.writeUInt16LE(20,4);local.writeUInt32LE(crc,14);
    local.writeUInt32LE(data.length,18);local.writeUInt32LE(data.length,22);local.writeUInt16LE(nameBytes.length,26);
    central.writeUInt32LE(0x02014b50);central.writeUInt16LE(20,4);central.writeUInt16LE(20,6);
    central.writeUInt32LE(crc,16);central.writeUInt32LE(data.length,20);central.writeUInt32LE(data.length,24);
    central.writeUInt16LE(nameBytes.length,28);central.writeUInt32LE(offset,42);
    locals.push(local,nameBytes,data);centrals.push(central,nameBytes);offset+=local.length+nameBytes.length+data.length;
  }
  const directory=Buffer.concat(centrals),end=Buffer.alloc(22);end.writeUInt32LE(0x06054b50);
  end.writeUInt16LE(entries.length,8);end.writeUInt16LE(entries.length,10);end.writeUInt32LE(directory.length,12);end.writeUInt32LE(offset,16);
  return Buffer.concat([...locals,directory,end]);
}
function fixture({mapped=false,mutatePackage=()=>{},mutatePolicy=()=>{},mutateClean=()=>{},mutateTarget=()=>{},mutateProfile=()=>{},mutateCredentials=()=>{}}={}) {
  const sourceFixture=mapped?mappedFixtureRoot:fixtureRoot;
  const project=JSON.parse(readFileSync(new URL('native-project-spec.json',sourceFixture)));
  const trace=JSON.parse(readFileSync(new URL('source-to-apex.json',sourceFixture)));
  const files=[...new Map(project.forms.flatMap(f=>[{packaged_name:f.source_name,sha256:f.source_sha256},
    ...(mapped?f.ddl_sources.map(ref=>({packaged_name:ref.name,sha256:ref.sha256})):[])])
    .map(file=>[file.packaged_name,file])).values()];
  project.source_manifest_sha256=sha256(files.map(f=>`${f.packaged_name}:${f.sha256}`).sort().join('\n'));
  trace.source_manifest_sha256=project.source_manifest_sha256;trace.rendering_spec_sha256=hash(project);
  const release={job_id:'fox-'+'1'.repeat(20),conversion_profile:'native-project-v1',application_count:1,form_count:2,
    source_manifest_sha256:project.source_manifest_sha256,application_id:999,application_alias:'F2A_GENERATED',
    reviewer_approved:true,reviewer_execution_verified:true,sqlcl_valid:true,import_passed:true,runtime_smoke_passed:true,
    package_reimport_passed:true,business_acceptance_required:true,human_acceptance_recorded:false,
    authenticated_runtime_passed:false,clean_schema_install_passed:false,forms:trace.forms,
    artifact_binding:{project_trace_sha256:sha256(bytes(trace))},package_reimport:{application_id:1000,application_alias:'F2A_REIMPORT'}};
  const members=new Map([
    ['native-project-spec.json',bytes(project)],['source-to-apex.json',bytes(trace)],
    ['schema/01_synthetic_schema.sql',Buffer.from('-- Synthetic local schema placeholder, not executable proof')],
    ['sql/f999.sql',Buffer.from('-- Synthetic local SQL placeholder, not executable proof\n'.repeat(30))],
    ['evidence/release-evidence.json',bytes(release)],['evidence/target-profile.json',bytes({database:{parsing_schema:'FORMS2APEX_POC'}})],
    ['evidence/source-manifest.json',bytes({job_id:release.job_id,source_manifest_sha256:project.source_manifest_sha256,native_project:project,files})],
  ]);
  if(mapped)members.set('schema/storage-mapping.json',bytes({schema_version:1,scope:'fox-project-storage-package-v1',
    project_id:project.project_id,data_mode:'synthetic_test_only',source_manifest_sha256:project.source_manifest_sha256,
    data_migration_included:false,mappings:trace.tables.map(table=>({storage_mapping:table.storage_mapping,
      ddl_sources:table.ddl_sources,module_ids:table.module_ids}))}));
  mutatePackage(members);
  const manifest=Object.fromEntries([...members].map(([name,raw])=>[name,sha256(raw)]));
  members.set('manifest.json',bytes(manifest));
  const packageRaw=zip([...members]);
  const projectRaw=members.get('native-project-spec.json'),traceRaw=members.get('source-to-apex.json');
  const {plan,profile}=deriveProjectQaArtifacts(projectRaw,traceRaw);
  const target={...Object.fromEntries(['compartment_id','database_id','region','db_name'].map(k=>[k,SCOPE[k]])),
    workspace:'FOX_QA_261025_1234ABCD',parsing_schema:'FOX_QA_261025_1234ABCD',workspace_id:'900719925474099312345',
    application_id:2000,application_alias:'F2A_QA_261025_1234ABCD'};
  const versions={apex:'26.1.5',sqlcl:'26.1.2.0',database:'23.26.4.1.0',mmd:'26.1.0+3102'};
  const allocation={schema_version:1,scope:'fox-clean-allocation-v2',passed:true,plan_sha256:'f'.repeat(64),allocated_at_utc:'2026-10-25T03:00:00Z',
    binding:{job_id:release.job_id,source_manifest_sha256:project.source_manifest_sha256,package_sha256:sha256(packageRaw)},
    target:{...target,instance_id:INSTANCE},observed_versions:versions,
    fresh_namespace:{workspace_created_fresh:true,schema_created_fresh:true,application_count:0,user_object_count:0}};
  const allocationRaw=bytes(allocation);
  const verification={schema_version:1,scope:'fox-native-verification-profile-v2',policy_id:'jsn-clean-native-v2',
    binding:{...allocation.binding,allocation_receipt_sha256:sha256(allocationRaw)},target,expected_versions:versions,max_evidence_age_seconds:86400};
  mutatePolicy(verification);
  const verificationRaw=bytes(verification),binding={...allocation.binding,project_spec_sha256:sha256(projectRaw),source_to_apex_sha256:sha256(traceRaw),
    schema_script_sha256:manifest['schema/01_synthetic_schema.sql'],sql_sha256:manifest['sql/f999.sql'],
    verification_profile_sha256:sha256(verificationRaw),allocation_receipt_sha256:sha256(allocationRaw)};
  const clean={schema_version:1,scope:'fox-project-clean-package-install-v1',profile_id:'native-project-v1',...binding,target,
    observed_versions:versions,started_at_utc:'2026-10-25T03:01:00Z',finished_at_utc:'2026-10-25T03:05:00Z',
    before_install:{application_ids:[],user_object_count:0},after_install:{application_ids:[2000],physical_tables:plan.tables.map(t=>t.table_name),unexpected_schema_dependency_count:0},
    table_metadata:plan.tables.map(t=>{
      const native=project.forms.find(f=>f.native_form.table_name===t.table_name).native_form;
      return {table_name:t.table_name,schema:target.parsing_schema,row_count:0,primary_keys:[],unexpected_schema_dependency_count:0,
        columns:native.columns.map(c=>({name:c.name,data_type:c.data_type,nullable:c.nullable,char_length:c.data_type==='VARCHAR2'?c.length:0,identity:c.identity??false})),
        primary_key:{columns:[native.columns.find(c=>c.primary_key).name],status:'ENABLED',validated:'VALIDATED'}};
    }),module_metadata:plan.forms.map(f=>Object.fromEntries(['module_id','table_name','report_page_id','form_page_id','items'].map(k=>[k,f[k]]))),
    page_ids:[0,1,2,3,4,9999],navigation:plan.forms.map(f=>({module_id:f.module_id,report_page_id:f.report_page_id})),
    original_parsing_schema:'FORMS2APEX_POC',original_schema_reference_count:0};
  mutateClean(clean);mutateProfile(profile);
  const importRaw=bytes(clean),profileRaw=bytes(profile);
  const receipt={schema_version:1,scope:'fox-project-qa-target-v1',...binding,target,
    url:`${SCOPE.origin}/ords/r/${target.workspace.toLowerCase()}/${target.application_alias.toLowerCase()}/`,
    profile_sha256:sha256(profileRaw),import_receipt_sha256:sha256(importRaw),test_plan_sha256:hash(plan),synthetic_qa_approved:true};
  mutateTarget(receipt);
  const credentials={username:'FOX_QA_A',password:'SyntheticPrimaryOnly9!',second_username:'FOX_QA_B',second_password:'SyntheticSecondaryOnly8!'};
  mutateCredentials(credentials);
  return {targetRaw:bytes(receipt),profileRaw,projectRaw,traceRaw,importRaw,verificationRaw,allocationRaw,packageRaw,credentialRaw:bytes(credentials)};
}

test('synthetic project input bytes bind exact target, every module and both QA identities',()=>{
  const input=fixture(),bound=validateProjectRunnerInputs(input,{now:NOW});
  assert.equal(bound.plan.form_count,2);assert.equal(bound.target.target.application_id,2000);
  assert.equal(bound.plan.forms[1].form_page_id,4);assert.equal(bound.accounts.secondary.username,'FOX_QA_B');
  assert.equal(bound.targetReceiptSha256,sha256(input.targetRaw));
  assert.equal(bound.inputSha256.project_spec_sha256,sha256(input.projectRaw));
  assert.equal(bound.packageEvidence.package_sha256,sha256(input.packageRaw));
});

test('mapped package envelope binds original DDL refs and physical QA targets without changing receipt scope',()=>{
  // The specs/trace are actual renderer fixtures. ZIP receipts and SQL are
  // explicitly authored structural observations, not database execution proof.
  const input=fixture({mapped:true}),bound=validateProjectRunnerInputs(input,{now:NOW});
  assert.equal(bound.project.schema_version,2);
  assert.equal(bound.target.scope,'fox-project-qa-target-v1');
  assert.equal(bound.plan.scope,'fox-project-qa-plan-v1');
  assert.ok(bound.plan.tables.every(table=>/^FOX_NATIVE_[A-F0-9]{19}$/.test(table.table_name)));
  assert.equal(bound.inputSha256.project_spec_sha256,sha256(input.projectRaw));
  assert.equal(bound.inputSha256.source_to_apex_sha256,sha256(input.traceRaw));
  assert.equal(bound.packageEvidence.members.has('schema/storage-mapping.json'),true);
});

for(const [name,mutatePackage] of [
  ['missing mapped artifact',m=>m.delete('schema/storage-mapping.json')],
  ['different mapped project',m=>{const v=JSON.parse(m.get('schema/storage-mapping.json'));v.project_id='other-project';m.set('schema/storage-mapping.json',bytes(v));}],
  ['invented migration permission',m=>{const v=JSON.parse(m.get('schema/storage-mapping.json'));v.data_migration_included=true;m.set('schema/storage-mapping.json',bytes(v));}],
  ['missing mapped physical table',m=>{const v=JSON.parse(m.get('schema/storage-mapping.json'));v.mappings.pop();m.set('schema/storage-mapping.json',bytes(v));}],
  ['altered mapped DDL digest',m=>{const v=JSON.parse(m.get('schema/storage-mapping.json'));v.mappings[0].ddl_sources[0].sha256='a'.repeat(64);m.set('schema/storage-mapping.json',bytes(v));}],
  ['unknown mapped artifact field',m=>{const v=JSON.parse(m.get('schema/storage-mapping.json'));v.approved=true;m.set('schema/storage-mapping.json',bytes(v));}],
  ['omitted original DDL source',m=>{const v=JSON.parse(m.get('evidence/source-manifest.json'));v.files=v.files.filter(file=>!file.packaged_name.endsWith('.sql'));m.set('evidence/source-manifest.json',bytes(v));}],
])test(`mapped package rejects ${name} after ZIP manifest rehash`,()=>{
  assert.throws(()=>validateProjectRunnerInputs(fixture({mapped:true,mutatePackage}),{now:NOW}));
});

test('legacy package cannot silently opt into the mapped storage artifact',()=>{
  assert.throws(()=>validateProjectRunnerInputs(fixture({mutatePackage:m=>m.set('schema/storage-mapping.json',bytes({}))}),{now:NOW}));
});

for(const [name,options] of [
  ['wrong region',{mutatePolicy:v=>v.target.region='eu-frankfurt-1'}],
  ['personal workspace',{mutatePolicy:v=>v.target.workspace='FORMS2APEX_POC'}],
  ['invalid allocation date',{mutatePolicy:v=>{v.target.workspace='FOX_QA_260231_1234ABCD';v.target.parsing_schema=v.target.workspace;v.target.application_alias='F2A_QA_260231_1234ABCD';}}],
  ['different application',{mutateTarget:v=>v.target.application_id=2001}],
  ['wrong URL',{mutateTarget:v=>v.url='https://example.invalid/'}],
  ['unapproved writes',{mutateTarget:v=>v.synthetic_qa_approved=false}],
  ['native legacy scope',{mutateTarget:v=>v.scope='fox-native-qa-target-v2'}],
  ['omitted profile form',{mutateProfile:v=>v.forms.pop()}],
  ['hardcoded P2 second form',{mutateProfile:v=>v.forms[1].item_prefix='P2_'}],
  ['nonempty clean namespace',{mutateClean:v=>v.before_install.user_object_count=1}],
  ['retained data on clean import',{mutateClean:v=>v.table_metadata[0].row_count=1}],
  ['wrong nullable metadata',{mutateClean:v=>v.table_metadata[0].columns[1].nullable=true}],
  ['missing physical table',{mutateClean:v=>v.table_metadata.pop()}],
  ['missing module items',{mutateClean:v=>v.module_metadata[1].items.pop()}],
  ['missing navigation',{mutateClean:v=>v.navigation.pop()}],
  ['original schema dependency',{mutateClean:v=>v.original_schema_reference_count=1}],
  ['future clean import',{mutateClean:v=>v.finished_at_utc='2026-10-26T00:00:00Z'}],
  ['impossible clean timestamp',{mutateClean:v=>v.finished_at_utc='2026-02-30T00:00:00Z'}],
  ['stale clean import',{mutateClean:v=>{v.started_at_utc='2026-10-23T00:00:00Z';v.finished_at_utc='2026-10-23T01:00:00Z';}}],
  ['unsupported active versions',{mutatePolicy:v=>v.expected_versions.apex='99.1'}],
  ['non-test personal identity',{mutateCredentials:v=>v.username='person@example.invalid'}],
  ['acceptance identity',{mutateCredentials:v=>v.second_username='FOX_ACCEPTANCE'}],
  ['same account',{mutateCredentials:v=>v.second_username='fox_qa_a'}],
  ['incomplete second identity',{mutateCredentials:v=>delete v.second_password}],
  ['unknown credential field',{mutateCredentials:v=>v.token='SECRET_NEVER_PRINT'}],
  ['wrong package source',{mutatePackage:m=>{const v=JSON.parse(m.get('evidence/source-manifest.json'));v.files.pop();m.set('evidence/source-manifest.json',bytes(v));}}],
  ['unreviewed package',{mutatePackage:m=>{const v=JSON.parse(m.get('evidence/release-evidence.json'));v.reviewer_execution_verified=false;m.set('evidence/release-evidence.json',bytes(v));}}],
])test(`rejects ${name} before browser startup`,()=>{
  assert.throws(()=>validateProjectRunnerInputs(fixture(options),{now:NOW}));
});

test('exact mounted bytes cannot be replaced by semantically identical JSON',()=>{
  for(const name of ['projectRaw','traceRaw','profileRaw','importRaw','verificationRaw','allocationRaw','targetRaw']) {
    const input=fixture();input[name]=Buffer.from(input[name].toString()+'\n');
    if(name==='targetRaw')assert.equal(validateProjectRunnerInputs(input,{now:NOW}).targetReceiptSha256,sha256(input.targetRaw));
    else assert.throws(()=>validateProjectRunnerInputs(input,{now:NOW}));
  }
});

test('credential parser errors cannot disclose supplied secret values',()=>{
  const input=fixture();input.credentialRaw=Buffer.from('{"password":"SECRET_NEVER_PRINT",invalid}');
  assert.throws(()=>validateProjectRunnerInputs(input,{now:NOW}),error=>!error.message.includes('SECRET_NEVER_PRINT'));
  assert.throws(()=>loadProjectRunnerInputs({FOX_QA_TARGET_RECEIPT:'SECRET_NEVER_PRINT'}),error=>!error.message.includes('SECRET_NEVER_PRINT'));
});

test('bounded ZIP reader rejects altered payload, duplicate paths and unsafe paths',()=>{
  const raw=fixture().packageRaw,changed=Buffer.from(raw);changed[100]^=1;
  assert.throws(()=>inspectProjectPackageBytes(changed));
  assert.throws(()=>inspectProjectPackageBytes(zip([['same',Buffer.from('a')],['same',Buffer.from('b')]])));
  assert.throws(()=>inspectProjectPackageBytes(zip([['../escape',Buffer.from('a')]])));
  assert.throws(()=>inspectProjectPackageBytes(Buffer.alloc(8_000_001)));
});

test('duplicate JSON keys cannot be hidden in any mounted document',()=>{
  for(const name of ['targetRaw','profileRaw','verificationRaw','allocationRaw','importRaw','credentialRaw']) {
    const input=fixture(),old=input[name].toString();input[name]=Buffer.from('{"duplicate":1,"duplicate":2,'+old.slice(1));
    assert.throws(()=>validateProjectRunnerInputs(input,{now:NOW}));
  }
});

test('decimal and exponent metadata tokens cannot hide behind JS number coercion',()=>{
  for(const token of ['1.0','1e0'])for(const name of ['targetRaw','profileRaw','verificationRaw','allocationRaw','importRaw','projectRaw','traceRaw']) {
    const input=fixture();input[name]=Buffer.from(input[name].toString().replace('"schema_version":1',`"schema_version":${token}`));
    assert.throws(()=>validateProjectRunnerInputs(input,{now:NOW}));
  }
});

test('rebound decimal page and row metadata still fails before any browser action',()=>{
  for(const [name,from,to,targetHash] of [
    ['profileRaw','"form_page_id":4','"form_page_id":4e0','profile_sha256'],
    ['importRaw','"row_count":0','"row_count":0.0','import_receipt_sha256'],
    ['importRaw','"page_ids":[0,1,2,3,4,9999]','"page_ids":[0,1,2,3,4.0,9999]','import_receipt_sha256'],
  ]) {
    const input=fixture(),text=input[name].toString();assert.ok(text.includes(from));
    input[name]=Buffer.from(text.replace(from,to));
    const target=JSON.parse(input.targetRaw);target[targetHash]=sha256(input[name]);input.targetRaw=bytes(target);
    assert.throws(()=>validateProjectRunnerInputs(input,{now:NOW}));
  }
});
