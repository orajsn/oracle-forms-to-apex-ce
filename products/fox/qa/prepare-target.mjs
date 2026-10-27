import {readFileSync,writeFileSync,existsSync} from 'node:fs';
import path from 'node:path';
import {parseArgs} from 'node:util';
import {SCOPE,sha256,readJson,validateTarget,check,deriveNativeQaProfile,deriveNativeQaPlan,canonicalQaPlan} from './lib/contracts.mjs';
import {readPackageEvidence} from './lib/package-evidence.mjs';

// No credentials accepted. This creates an operator assertion, not cloud/DB discovery proof.
const {values}=parseArgs({options:{
  profile:{type:'string'},'application-id':{type:'string'},alias:{type:'string'},output:{type:'string'},
  package:{type:'string'},'native-spec':{type:'string'},'source-manifest':{type:'string'},'import-receipt':{type:'string'},
  workspace:{type:'string',default:'FORMS2APEX_POC'},'parsing-schema':{type:'string'},'clean-install':{type:'boolean',default:false},
  'approve-synthetic-writes':{type:'boolean',default:false},
  'verification-profile':{type:'string'},'profile-output':{type:'string'},
},allowPositionals:false,strict:true});
try {
  check(values['approve-synthetic-writes'],'Pass --approve-synthetic-writes only for the approved JSN synthetic application');
  check(path.isAbsolute(values.output??'')&&!existsSync(values.output),'Output must be a new absolute file path');
  const v2=Boolean(values['verification-profile']);
  if(v2) {
    check(values['clean-install']&&!values.profile&&!values['application-id']&&!values.alias&&!values['source-manifest']&&!values['parsing-schema']&&values.workspace==='FORMS2APEX_POC','V2 identity comes only from the exact operator profile; do not supply identity overrides');
    check(path.isAbsolute(values['profile-output']??'')&&!existsSync(values['profile-output'])&&values['profile-output']!==values.output,'V2 requires a separate new absolute profile output');
    const verificationProfile=readJson(values['verification-profile']),nativeSpec=readJson(values['native-spec'],1048576,{nativeSpec:true}),importReceipt=readJson(values['import-receipt']);
    const packageEvidence=readPackageEvidence(values.package),approved=verificationProfile.value;
    const profile=deriveNativeQaProfile(nativeSpec.value),profileRaw=JSON.stringify(profile,null,2)+'\n';
    const target=approved.target??{},plan=deriveNativeQaPlan(nativeSpec.value,nativeSpec.sha256);
    const receipt={schema_version:2,...SCOPE,synthetic_qa_approved:true,clean_install:true,job_id:approved.binding?.job_id,
      application_id:target.application_id,alias:target.application_alias,workspace:target.workspace,workspace_id:target.workspace_id,parsing_schema:target.parsing_schema,
      url:`${SCOPE.origin}/ords/r/${String(target.workspace).toLowerCase()}/${String(target.application_alias).toLowerCase()}/`,table_name:profile.table_name,
      profile_sha256:sha256(profileRaw),verification_profile_sha256:verificationProfile.sha256,allocation_receipt_sha256:approved.binding?.allocation_receipt_sha256,
      native_spec_sha256:nativeSpec.sha256,import_receipt_sha256:importReceipt.sha256,test_plan_sha256:sha256(canonicalQaPlan(plan))};
    for(const key of ['package_sha256','sql_sha256','schema_script_sha256','source_manifest_sha256'])receipt[key]=packageEvidence[key];
    validateTarget(receipt,profile,receipt.profile_sha256,packageEvidence.package_sha256,{nativeSpec,importReceipt,packageEvidence,verificationProfile});
    writeFileSync(values['profile-output'],profileRaw,{mode:0o600,flag:'wx'});
    writeFileSync(values.output,JSON.stringify(receipt,null,2)+'\n',{mode:0o600,flag:'wx'});
    console.log(JSON.stringify({target_receipt:values.output,qa_profile:values['profile-output'],application_id:receipt.application_id,clean_install_bound:true,test_plan_sha256:receipt.test_plan_sha256}));
  } else {
  check(!values['profile-output'],'Profile output is only valid with a v2 verification profile');
  const profile=readJson(values.profile);
  const hash=file=>file?sha256(readFileSync(file)):null;
  const applicationId=Number(values['application-id']); const alias=values.alias;
  const clean=values['clean-install'],workspace=values.workspace,parsingSchema=values['parsing-schema']??workspace;
  check(!clean||!values['source-manifest'],'Clean source identity comes from packaged release evidence, not a manifest file byte hash');
  const nativeSpec=values['native-spec']?readJson(values['native-spec']):null;
  const importReceipt=values['import-receipt']?readJson(values['import-receipt']):null;
  const packageEvidence=clean?readPackageEvidence(values.package):null;
  const receipt={schema_version:1,compartment_id:SCOPE.compartment_id,database_id:SCOPE.database_id,region:SCOPE.region,db_name:SCOPE.db_name,
    synthetic_qa_approved:true,application_id:applicationId,alias,workspace,parsing_schema:parsingSchema,clean_install:clean,
    url:`${SCOPE.origin}/ords/r/${workspace.toLowerCase()}/${String(alias).toLowerCase()}/`,table_name:profile.value.table_name,
    profile_sha256:profile.sha256,package_sha256:packageEvidence?.package_sha256??hash(values.package),native_spec_sha256:nativeSpec?.sha256??null,
    source_manifest_sha256:packageEvidence?.source_manifest_sha256??hash(values['source-manifest']),import_receipt_sha256:importReceipt?.sha256??null};
  if(clean)Object.assign(receipt,{job_id:packageEvidence.releaseEvidence.job_id,workspace_id:importReceipt?.value.workspace_id,
    sql_sha256:packageEvidence.sql_sha256,schema_script_sha256:packageEvidence.schema_script_sha256});
  validateTarget(receipt,profile.value,profile.sha256,receipt.package_sha256,{nativeSpec,importReceipt,packageEvidence});
  writeFileSync(values.output,JSON.stringify(receipt,null,2)+'\n',{mode:0o600,flag:'wx'});
  console.log(JSON.stringify({target_receipt:values.output,application_id:applicationId,package_bound:receipt.package_sha256!==null,clean_install_bound:clean}));
  }
} catch(error) {console.error(error.message);process.exitCode=2;}
