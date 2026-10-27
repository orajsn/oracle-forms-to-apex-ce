import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {SCOPE,sha256,validateTarget,validateCredentials,allowedRequest,safeMessage,outcome,decimalCents,formatCents} from '../lib/contracts.mjs';

const raw=readFileSync(new URL('../profiles/native-261016.json',import.meta.url));
const profile=JSON.parse(raw);
const hash=sha256(raw);
function receipt() {return {schema_version:1,...SCOPE,synthetic_qa_approved:true,application_id:261016002,
  alias:'F2A_NATIVE_261016B',workspace:'FORMS2APEX_POC',url:`${SCOPE.origin}/ords/r/forms2apex_poc/f2a_native_261016b/`,
  table_name:profile.table_name,profile_sha256:hash,package_sha256:null,source_manifest_sha256:null,native_spec_sha256:null,import_receipt_sha256:null};}
test('valid explicit synthetic target is accepted without claiming a package binding',()=>{
  assert.equal(validateTarget(receipt(),profile,hash).packageBound,false);
});
test('actual package digest is required when declared',()=>{
  const value=receipt(); value.package_sha256='a'.repeat(64);
  assert.throws(()=>validateTarget(value,profile,hash),/package bytes/i);
  assert.equal(validateTarget(value,profile,hash,'a'.repeat(64)).packageBound,true);
});
for(const [field,value] of [['compartment_id','other'],['database_id','other'],['region','ap-singapore-1'],
  ['workspace','CUSTOMER'],['synthetic_qa_approved',false],['application_id',0],['profile_sha256','b'.repeat(64)],
  ['table_name','CUSTOMER_TABLE'],['native_spec_sha256','not-a-hash'],['alias','OTHER']]) {
  test(`rejects wrong or absent scope: ${field}`,()=>assert.throws(()=>validateTarget({...receipt(),[field]:value},profile,hash)));
}
for(const url of ['https://example.com/','http://asz8eqwfm8unca2-jsnf2apex.adb.us-ashburn-1.oraclecloudapps.com/',
  `${SCOPE.origin}/ords/r/forms2apex_poc/other/`,`${SCOPE.origin}/ords/r/forms2apex_poc/f2a_native_261016b/?session=secret`,
  `https://someone:password@${new URL(SCOPE.origin).host}/ords/r/forms2apex_poc/f2a_native_261016b/`]) {
  test('rejects unsafe/mismatched application URL '+url.replace(/someone:.+@/,'[REDACTED]@'),()=>assert.throws(()=>validateTarget({...receipt(),url},profile,hash)));
}
test('production and ambiguous metadata are rejected',()=>{
  for(const change of [{data_mode:'production'},{marker_field:'MISSING'},{edit_field:'TITLE'},{database_constraints:null}])
    assert.throws(()=>validateTarget(receipt(),{...profile,...change},hash));
});
test('duplicate accessible labels fail closed',()=>{
  const value=structuredClone(profile);value.fields[1].label=value.fields[0].label;
  assert.throws(()=>validateTarget(receipt(),value,hash),/unique/);
});
test('allows only pinned APEX origin and read-only official APEX static CDN',()=>{
  assert.equal(allowedRequest(`${SCOPE.origin}/ords/wwv_flow.accept`,'POST'),true);
  assert.equal(allowedRequest('https://static.oracle.com/cdn/apex/26.1/a.js'),true);
  assert.equal(allowedRequest('https://static.oracle.com/cdn/apex/26.1/a.js','POST'),false);
  for(const url of ['https://example.com','http://169.254.169.254/opc/v2/instance/','file:///run/secrets/apex.json',
    'https://static.oracle.com/other','https://static.oracle.com.evil.test/cdn/apex/a.js','not a url'])
    assert.equal(allowedRequest(url),false);
});
test('failure text does not leak username password or session URL',()=>{
  const value=safeMessage(new Error('fill demo-secret for qa@example.test at https://target.test/?session=123'),['demo-secret','qa@example.test']);
  assert.doesNotMatch(value,/demo-secret|qa@example.test|session=123/);
});
test('NOT_RUN is not success, optional gaps remain separate',()=>{
  assert.equal(outcome([{status:'NOT_RUN',required:true}]),'INCOMPLETE');
  assert.equal(outcome([{status:'PASSED',required:true},{status:'NOT_RUN',required:false}]),'PASSED');
  assert.equal(outcome([{status:'FAILED',required:true}]),'FAILED');
  assert.equal(outcome([{status:'PASSED',required:true},{status:'FAILED',required:false}]),'FAILED');
});
test('edit arithmetic uses exact bounded decimal cents',()=>{
  assert.equal(formatCents(decimalCents('42.58')+10000),'142.58');
  assert.equal(decimalCents('42.5'),decimalCents('42.50'));
  assert.equal(formatCents(decimalCents('-0.25')),'-0.25');
  assert.throws(()=>decimalCents('9007199254740992'));
  assert.throws(()=>decimalCents('0.00001'));
});
test('entrypoint never enables tracing video or stored authentication',()=>{
  const source=readFileSync(new URL('../run-native.mjs',import.meta.url),'utf8');
  for(const pattern of [/\.tracing\.start\(/,/recordVideo\s*:/,/recordHar\s*:/,/\.storageState\(/,/ignoreHTTPSErrors:\s*true/]) assert.doesNotMatch(source,pattern);
  assert.match(source,/independent_browser_contexts:2/);
  assert.match(source,/CREATE_SUBMITTED_OUTCOME_NOT_YET_CONFIRMED/);
  assert.match(source,/browserErrorCase\.status=result\.browser_errors\.length\?'FAILED':'PASSED'/);
});
test('supports one account without claiming two independent users',()=>{
  const value=validateCredentials({username:'QA_A',password:'test-only-a'});
  assert.equal(value.twoIndependentAccounts,false);assert.equal(value.secondary,null);
});
test('supports a complete independent secondary account',()=>{
  const value=validateCredentials({username:'QA_A',password:'test-only-a',second_username:'QA_B',second_password:'test-only-b'});
  assert.equal(value.twoIndependentAccounts,true);assert.equal(value.secondary.username,'QA_B');
});
test('refuses partial same-user and unrelated secondary credential payloads',()=>{
  for(const change of [{second_username:'QA_B'},{second_password:'test-only-b'},
    {second_username:'qa_a',second_password:'test-only-b'},{token:'not-accepted'}])
    assert.throws(()=>validateCredentials({username:'QA_A',password:'test-only-a',...change}));
});
test('redacts both accounts in errors',()=>{
  const raw='QA_A test-only-a QA_B test-only-b';
  assert.equal(safeMessage(raw,['QA_A','test-only-a','QA_B','test-only-b']),'[REDACTED] [REDACTED] [REDACTED] [REDACTED]');
});
