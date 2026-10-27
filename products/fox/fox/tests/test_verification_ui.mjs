// Exercise the exact pure display predicate from the rendered React component.
import {test} from 'node:test';
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import ts from 'typescript';
const ui=await readFile(new URL('../web/main.tsx',import.meta.url),'utf8');
const source=ui.slice(ui.indexOf('function verifiedLabSummary('),ui.indexOf('function RunEvidence('))+'\nexport {verifiedLabSummary};';
const compiled=ts.transpileModule(source,{compilerOptions:{module:ts.ModuleKind.ESNext,target:ts.ScriptTarget.ES2022}}).outputText;
const {verifiedLabSummary}=await import(`data:text/javascript;base64,${Buffer.from(compiled).toString('base64')}`);
const tests=['login','create','search_positive','search_negative','reread','edit_save','cancel_edit','cancel_create','required_fields','invalid_number','invalid_date','maximum_length','concurrent_edit','browser_runtime_errors'];
const run={id:'fox-'+'a'.repeat(20),state:'VERIFIED',source_hash:'b'.repeat(64)};
const proof=(version=1)=>({schema_version:version,scope:`fox-native-technical-verification-v${version}`,policy_id:version===2?'jsn-clean-native-v2':'jsn-clean-native-beta-20261017-v1',job_id:run.id,source_manifest_sha256:run.source_hash,package_sha256:'c'.repeat(64),authenticated_runtime_passed:true,clean_schema_install_passed:true,required_tests:[...tests],...(version===2?{test_plan:{schema_version:1,scope:'fox-native-qa-plan-v2',cases:tests.map(name=>({name,applicable:true}))}}:{})});
test('historical v1 retains its required-check presentation',()=>{
 assert.deepEqual(verifiedLabSummary(run,proof()),{passed:14,notApplicable:null});
 assert.deepEqual(verifiedLabSummary({...run,state:'ACCEPTED'},proof()),{passed:14,notApplicable:null});
});
for(const absent of [[],['invalid_number','invalid_date','maximum_length'],['required_fields','invalid_number','invalid_date','maximum_length']])test(`v2 distinguishes ${absent.length} N/A cases without counting them as passes`,()=>{
 const value=proof(2);value.test_plan.cases.forEach(item=>{item.applicable=!absent.includes(item.name);});value.required_tests=value.required_tests.filter(name=>!absent.includes(name));
 assert.deepEqual(verifiedLabSummary(run,value),{passed:14-absent.length,notApplicable:absent.length});
});
for(const version of [1,2])test(`v${version} retains exact state/job/hash/technical checks`,()=>{
 for(const state of ['QA_REQUIRED','REVIEW_REQUIRED','PROCESSING'])assert.equal(verifiedLabSummary({...run,state},proof(version)),null);
 for(const patch of [{scope:'unknown'},{schema_version:true},{job_id:'other'},{source_manifest_sha256:'f'.repeat(64)},{package_sha256:'bad'},{package_sha256:'c'.repeat(64)+'\n'},{authenticated_runtime_passed:false},{clean_schema_install_passed:false},{required_tests:[]},{required_tests:[1]},{required_tests:['login','login']}])assert.equal(verifiedLabSummary(run,{...proof(version),...patch}),null);
});
test('malformed v2 applicability cannot present a successful summary',()=>{
 for(const mutate of [v=>v.policy_id='other',v=>delete v.test_plan,v=>v.test_plan.schema_version=2,v=>v.test_plan.scope='other',v=>v.test_plan.cases.pop(),v=>v.test_plan.cases[0].applicable=0,v=>v.test_plan.cases[1].name='login',v=>v.test_plan.cases[0].applicable=false,v=>v.required_tests.pop()]){const value=proof(2);mutate(value);assert.equal(verifiedLabSummary(run,value),null);}
});
test('render keeps human acceptance separate and reports explicit N/A count',()=>{
 assert.match(ui,/const labVerified=verifiedLabSummary\(run,technical\)/);
 assert.match(ui,/applicable browser checks passed; \$\{labVerified.notApplicable\} not applicable/);
 assert.match(ui,/Your business-flow review and acceptance are still separate/);
 assert.match(ui,/\['REVIEW_REQUIRED','VERIFIED'\]\.includes\(r.state\)&&r.source_hash===detail.inventory.source_hash&&<Acceptance/);
 assert.match(ui,/r.state==='ACCEPTED'&&r.downloadable/);
});
