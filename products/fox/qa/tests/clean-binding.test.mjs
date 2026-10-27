import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync,mkdtempSync,writeFileSync,mkdirSync,rmSync} from 'node:fs';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {spawnSync} from 'node:child_process';
import {deflateRawSync} from 'node:zlib';
import {SCOPE,CLEAN_WORKSPACE,CLEAN_WORKSPACE_ID,sha256,validateTarget} from '../lib/contracts.mjs';
import {crc32,inspectPackageBytes} from '../lib/package-evidence.mjs';

const profileRaw=readFileSync(new URL('../profiles/native-beta-clean.json',import.meta.url));
const profile=JSON.parse(profileRaw),profileHash=sha256(profileRaw);
const spec={profile_id:'native-table-form-v1',data_mode:'synthetic_test_only',table_name:'FOX_NATIVE_BETA',supported_operations:['query','insert','update'],
  columns:[{name:'ID',label:'ID',data_type:'NUMBER',nullable:false,identity:true,primary_key:true},
    ...profile.fields.map(field=>({name:field.name,label:field.label,data_type:field.data_type,nullable:!field.required,primary_key:false,identity:false,
      ...(field.max_length?{length:field.max_length}:{})}))]};
const nativeRaw=Buffer.from(JSON.stringify(spec));
const hashChar=char=>char.repeat(64);

function zip(entries,{method=8}={}) {
  const locals=[],centrals=[];let offset=0;
  for(const [name,value,mode=0x8000] of entries){
    const nameBytes=Buffer.from(name),content=Buffer.from(value),packed=method===8?deflateRawSync(content):content,crc=crc32(content);
    const header=Buffer.alloc(30);header.writeUInt32LE(0x04034b50);header.writeUInt16LE(20,4);header.writeUInt16LE(method,8);
    header.writeUInt32LE(crc,14);header.writeUInt32LE(packed.length,18);header.writeUInt32LE(content.length,22);header.writeUInt16LE(nameBytes.length,26);
    locals.push(header,nameBytes,packed);
    const central=Buffer.alloc(46);central.writeUInt32LE(0x02014b50);central.writeUInt16LE(20,4);central.writeUInt16LE(20,6);central.writeUInt16LE(method,10);
    central.writeUInt32LE(crc,16);central.writeUInt32LE(packed.length,20);central.writeUInt32LE(content.length,24);central.writeUInt16LE(nameBytes.length,28);
    central.writeUInt32LE((mode<<16)>>>0,38);central.writeUInt32LE(offset,42);centrals.push(central,nameBytes);offset+=30+nameBytes.length+packed.length;
  }
  const directory=Buffer.concat(centrals),end=Buffer.alloc(22);end.writeUInt32LE(0x06054b50);end.writeUInt16LE(entries.length,8);end.writeUInt16LE(entries.length,10);
  end.writeUInt32LE(directory.length,12);end.writeUInt32LE(offset,16);return Buffer.concat([...locals,directory,end]);
}
function packageBytes({extra=[],releaseChange={},manifestChange={},method=8}={}){
  const release={job_id:'fox-11111111111111111111',application_id:123,source_manifest_sha256:hashChar('a'),reviewer_approved:true,sqlcl_valid:true,import_passed:true,...releaseChange};
  const entries=[['native-form-spec.json',nativeRaw],['schema/01_synthetic_schema.sql','create table FOX_NATIVE_BETA (ID number);'],['sql/f123.sql','-- conventional export fixture'],
    ['evidence/release-evidence.json',JSON.stringify(release)],...extra];
  const manifest=Object.fromEntries(entries.map(([name,value])=>[name,sha256(Buffer.from(value))]));Object.assign(manifest,manifestChange);
  return zip([...entries,['manifest.json',JSON.stringify(manifest)]],{method});
}
function fixture(){
  const packageEvidence=inspectPackageBytes(packageBytes());
  const imported={schema_version:1,scope:'fox-clean-package-install-v1',passed:true,...SCOPE,
    job_id:'fox-11111111111111111111',workspace:CLEAN_WORKSPACE,workspace_id:CLEAN_WORKSPACE_ID,parsing_schema:CLEAN_WORKSPACE,
    application_id:179000001,application_alias:'F2A_CLEAN_UNIT',application_url:`${SCOPE.origin}/ords/r/${CLEAN_WORKSPACE.toLowerCase()}/f2a_clean_unit/`,
    table_name:profile.table_name,profile_id:profile.profile_id,
    clean_install:{passed:true,workspace_created_fresh:true,schema_created_fresh:true,before_install:{passed:true,application_count:0,user_object_count:0},after_install:{passed:true,application_count:1,native_table_count:1}},
    observed_versions:{apex:'26.1.5',sqlcl:'26.1.2.132',database:'23.26.0.0.0'},
    no_original_schema_dependencies:{passed:true,original_schema:'FORMS2APEX_POC',reference_count:0}};
  const target={schema_version:1,...SCOPE,synthetic_qa_approved:true,application_id:imported.application_id,alias:imported.application_alias,url:imported.application_url,
    workspace:CLEAN_WORKSPACE,workspace_id:CLEAN_WORKSPACE_ID,parsing_schema:CLEAN_WORKSPACE,table_name:profile.table_name,clean_install:true,job_id:imported.job_id,profile_sha256:profileHash};
  for(const key of ['package_sha256','sql_sha256','native_spec_sha256','schema_script_sha256','source_manifest_sha256']) target[key]=imported[key]=packageEvidence[key];
  const artifacts={nativeSpec:{value:structuredClone(spec),sha256:sha256(nativeRaw)},importReceipt:{value:imported,sha256:sha256(JSON.stringify(imported))},packageEvidence};
  target.import_receipt_sha256=artifacts.importReceipt.sha256;
  return {target,artifacts,profile:structuredClone(profile)};
}
function valid(f){return validateTarget(f.target,f.profile,profileHash,f.artifacts.packageEvidence.package_sha256,f.artifacts);}

test('standard independent CRC vector is correct',()=>assert.equal(crc32(Buffer.from('123456789')),0xcbf43926));
test('stored and deflated complete release packages have verified evidence',()=>{
  for(const method of [0,8]){const value=inspectPackageBytes(packageBytes({method}));assert.equal(value.native_spec_sha256,sha256(nativeRaw));assert.equal(value.member_count,5);}
});
test('exact fixed clean workspace is bound to all mounted evidence',()=>{
  const result=valid(fixture());assert.equal(result.cleanInstallBound,true);assert.equal(result.nativeSpecBound,true);assert.equal(result.importReceiptBound,true);
});
for(const name of ['package_sha256','sql_sha256','native_spec_sha256','schema_script_sha256','source_manifest_sha256']){
  test(`rejects mismatched clean import ${name}`,()=>{const f=fixture();f.artifacts.importReceipt.value[name]=hashChar('f');assert.throws(()=>valid(f));});
  test(`rejects mismatched target ${name}`,()=>{const f=fixture();f.target[name]=hashChar('f');assert.throws(()=>valid(f));});
}
for(const name of ['nativeSpec','importReceipt','packageEvidence'])test(`requires actual mounted ${name}`,()=>{const f=fixture();delete f.artifacts[name];assert.throws(()=>valid(f));});
test('changed native/import file bytes are rejected even if JSON fields look valid',()=>{
  for(const name of ['nativeSpec','importReceipt']){const f=fixture();f.artifacts[name].sha256=hashChar('f');assert.throws(()=>valid(f));}
});
test('large workspace ID is bound as exact string, never rounded JS number',()=>{
  for(const value of [Number(CLEAN_WORKSPACE_ID),'22042420337195496',null]){
    const f=fixture();f.target.workspace_id=value;f.artifacts.importReceipt.value.workspace_id=value;assert.throws(()=>valid(f));
  }
});
for(const [name,value] of [['application_id',123],['application_alias','F2A_OTHER'],['application_url','https://example.test/'],
  ['workspace','FORMS2APEX_POC'],['parsing_schema','FORMS2APEX_POC'],['compartment_id','other'],['database_id','other'],['region','ap-singapore-1'],
  ['db_name','OTHER'],['passed','true'],['scope','other'],['job_id','fox-22222222222222222222'],['table_name','FOX_NATIVE_OTHER'],['profile_id','other']]){
  test(`rejects foreign or weak clean import identity ${name}`,()=>{const f=fixture();f.artifacts.importReceipt.value[name]=value;assert.throws(()=>valid(f));});
}
test('clean workspace cannot be enabled by a generic workspace edit or missing clean flag',()=>{
  for(const change of [{workspace:'OTHER'},{workspace:'FOX_QA_261017B'},{clean_install:false},{clean_install:'true'},{parsing_schema:'OTHER'},{workspace:'FORMS2APEX_POC'}]){
    const f=fixture();Object.assign(f.target,change);assert.throws(()=>valid(f));
  }
});
test('fresh/empty/exact one-install evidence uses strict booleans and numeric counts',()=>{
  for(const mutate of [p=>p.passed='true',p=>p.workspace_created_fresh=false,p=>p.schema_created_fresh=1,
    p=>p.before_install.passed=false,p=>p.before_install.application_count=1,p=>p.before_install.user_object_count='0',
    p=>p.after_install.passed=false,p=>p.after_install.application_count=2,p=>p.after_install.native_table_count=0]){
    const f=fixture();mutate(f.artifacts.importReceipt.value.clean_install);assert.throws(()=>valid(f));
  }
});
test('requires observed compatible versions and zero original-schema references',()=>{
  for(const mutate of [p=>p.observed_versions.apex='24.2',p=>p.observed_versions.apex='26.1.BAD',p=>p.observed_versions.sqlcl=['26.1.2'],p=>p.observed_versions.sqlcl='25.1',p=>p.observed_versions.database='',p=>p.observed_versions.database='unknown',
    p=>p.no_original_schema_dependencies.passed='true',p=>p.no_original_schema_dependencies.reference_count=1,p=>p.no_original_schema_dependencies.original_schema='OTHER']){
    const f=fixture();mutate(f.artifacts.importReceipt.value);assert.throws(()=>valid(f));
  }
});
test('profile must match all exact mounted native columns and labels',()=>{
  for(const mutate of [p=>p.fields[0].label='Title',p=>p.fields[0].max_length=101,p=>p.fields[1].required=false,p=>p.fields.pop(),p=>p.table_name='FOX_NATIVE_OTHER',
    p=>p.database_constraints.push({field:'STATUS',invalid_value:'INVALID',expected_error:'check constraint'})]){const f=fixture();mutate(f.profile);assert.throws(()=>valid(f));}
});
for(const [name,mode] of [['../escape',0x8000],['/absolute',0x8000],['safe/../escape',0x8000],['safe\\escape',0x8000],['link',0xa000],['native-form-spec.JSON',0x8000],['sql/other.sql',0x8000]]){
  test(`rejects unsafe or duplicate ZIP member ${name}`,()=>assert.throws(()=>inspectPackageBytes(packageBytes({extra:[[name,'x',mode]]}))));
}
test('rejects missing or altered manifest member hashes',()=>assert.throws(()=>inspectPackageBytes(packageBytes({manifestChange:{'sql/f123.sql':hashChar('f')}}))));
test('rejects non-boolean package release evidence',()=>assert.throws(()=>inspectPackageBytes(packageBytes({releaseChange:{reviewer_approved:'true'}}))));
for(const applicationId of ['123',[123],true,null,0,-1,1.5,9007199254740993]) {
  test(`rejects noninteger package application identity ${JSON.stringify(applicationId)}`,()=>{
    assert.throws(()=>inspectPackageBytes(packageBytes({releaseChange:{application_id:applicationId}})));
  });
}
test('package string identity rejects coerced hashes and terminal line breaks',()=>{
  for(const sourceHash of [hashChar('a')+'\n',[hashChar('a')]])assert.throws(()=>inspectPackageBytes(packageBytes({releaseChange:{source_manifest_sha256:sourceHash}})));
  assert.throws(()=>inspectPackageBytes(packageBytes({extra:[['extra.txt\n','unsafe name']]})));
});
test('rejects malformed ZIP directory encryption overlap sizes and CRC',()=>{
  for(const mutate of [b=>b[b.length-22]=0,b=>b.writeUInt16LE(1,b.length-18),b=>b.writeUInt16LE(201,b.length-12),
    b=>b.writeUInt16LE(1,b.readUInt32LE(b.length-6)+8),b=>b.writeUInt32LE(0xffffffff,b.readUInt32LE(b.length-6)+24),
    b=>b.writeUInt32LE(1,b.readUInt32LE(b.length-6)+42),b=>b[40]^=1]){
    const bytes=packageBytes();mutate(bytes);assert.throws(()=>inspectPackageBytes(bytes));
  }
});
test('clean CLI creates exact receipt once and refuses overwrite',()=>{
  const qaRoot=fileURLToPath(new URL('../',import.meta.url)),directory=mkdtempSync(path.join(qaRoot,'.test-clean-'));
  try {
    const f=fixture();
    const files={profile:path.join(directory,'profile.json'),spec:path.join(directory,'native.json'),package:path.join(directory,'package.zip'),import:path.join(directory,'import.json'),output:path.join(directory,'target.json')};
    writeFileSync(files.profile,profileRaw);writeFileSync(files.spec,nativeRaw);writeFileSync(files.package,packageBytes());writeFileSync(files.import,JSON.stringify(f.artifacts.importReceipt.value));
    const args=[fileURLToPath(new URL('../prepare-target.mjs',import.meta.url)),'--clean-install','--workspace',CLEAN_WORKSPACE,'--parsing-schema',CLEAN_WORKSPACE,
      '--profile',files.profile,'--native-spec',files.spec,'--package',files.package,'--import-receipt',files.import,'--application-id',String(f.target.application_id),
      '--alias',f.target.alias,'--output',files.output,'--approve-synthetic-writes'];
    const first=spawnSync(process.execPath,args,{encoding:'utf8'});assert.equal(first.status,0,first.stderr);
    const receipt=JSON.parse(readFileSync(files.output));assert.equal(receipt.workspace_id,CLEAN_WORKSPACE_ID);assert.equal(receipt.import_receipt_sha256,sha256(readFileSync(files.import)));
    assert.equal(receipt.native_spec_sha256,sha256(nativeRaw));assert.equal(receipt.clean_install,true);
    const original=readFileSync(files.output);const repeated=spawnSync(process.execPath,args,{encoding:'utf8'});assert.equal(repeated.status,2);assert.deepEqual(readFileSync(files.output),original);
  } finally {rmSync(directory,{recursive:true,force:true});}
});
test('runner rejects mismatched mounted spec before loading credentials or Playwright',()=>{
  const qaRoot=fileURLToPath(new URL('../',import.meta.url)),directory=mkdtempSync(path.join(qaRoot,'.test-mount-'));
  try {
    const f=fixture(),profilePath=path.join(directory,'profile.json'),targetPath=path.join(directory,'target.json'),specPath=path.join(directory,'native.json'),packagePath=path.join(directory,'package.zip'),importPath=path.join(directory,'import.json'),output=path.join(directory,'results');
    writeFileSync(profilePath,profileRaw);writeFileSync(targetPath,JSON.stringify(f.target));writeFileSync(packagePath,packageBytes());writeFileSync(importPath,JSON.stringify(f.artifacts.importReceipt.value));
    writeFileSync(specPath,JSON.stringify({...spec,table_name:'FOX_NATIVE_WRONG'}));mkdirSync(output);
    const child=spawnSync(process.execPath,[fileURLToPath(new URL('../run-native.mjs',import.meta.url))],{encoding:'utf8',env:{...process.env,DEBUG:'',PWDEBUG:'',
      FOX_QA_TARGET_RECEIPT:targetPath,FOX_QA_PROFILE:profilePath,FOX_QA_NATIVE_SPEC:specPath,FOX_QA_IMPORT_RECEIPT:importPath,FOX_QA_PACKAGE:packagePath,FOX_QA_OUTPUT_DIR:output,
      FOX_QA_CREDENTIAL_FILE:path.join(directory,'MUST_NOT_BE_READ.json')}});
    assert.equal(child.status,2,child.stderr);const compact=JSON.parse(child.stdout.trim()),report=JSON.parse(readFileSync(compact.result_file));
    assert.match(report.failure,/Mounted native_spec bytes/);assert.equal(report.write_attempts.length,0);assert.equal(report.tests.find(test=>test.name==='login').status,'NOT_RUN');
  } finally {rmSync(directory,{recursive:true,force:true});}
});
