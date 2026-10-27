/** Read-only preflight for the project browser runner.
 *
 * Hashes bind operator-owned mounted bytes; they are not vendor signatures.
 * The operator must first run the independent Python package/source verifier.
 * This module neither provisions targets/accounts nor performs network I/O.
 */
import {readFileSync,lstatSync} from 'node:fs';
import {inflateRawSync} from 'node:zlib';
import path from 'node:path';
import {SCOPE,check,sha256,isHash,parseUniqueJson,canonicalQaPlan,validateCredentials} from './contracts.mjs';
import {crc32} from './package-evidence.mjs';
import {deriveProjectQaArtifacts,PROJECT_PROFILE_ID} from './project-profile.mjs';

const INSTANCE='ocid1.instance.oc1.iad.anuwcljtc7x6gxic5w37qsyp3rst64betkt4uk2pdcrtmy3okspcpbv77qea';
const VERSIONS={apex:'26.1.5',sqlcl:'26.1.2.0',database:'23.26.4.1.0',mmd:'26.1.0+3102'};
const FIXED_KEYS=['compartment_id','database_id','region','db_name'];
const object=v=>v!==null&&typeof v==='object'&&!Array.isArray(v);
const exact=(v,keys)=>object(v)&&Object.keys(v).length===keys.length&&keys.every(k=>Object.hasOwn(v,k));
const same=(a,b)=>canonicalQaPlan(a)===canonicalQaPlan(b);
const hash=v=>sha256(canonicalQaPlan(v));
const bounded=(v,max)=>check(Buffer.isBuffer(v)&&v.length>0&&v.length<=max,'Mounted project input must contain bounded exact bytes');
const utc=value=>{
  check(typeof value==='string'&&/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?(?:Z|\+00:00)(?![^])/.test(value)
    &&Number.isFinite(Date.parse(value))&&Number(value.slice(0,4))>=1
    &&new Date(Date.parse(value)).toISOString().slice(0,19)===value.slice(0,19),
    'Project evidence timestamp is not explicit valid UTC');
  return Date.parse(value);
};

/** Narrow in-memory ZIP32 envelope audit; never extract or execute package files. */
export function inspectProjectPackageBytes(bytes) {
  bounded(bytes,8_000_000);
  check(bytes.length>=22,'Project package ZIP is truncated');
  const end=bytes.length-22;
  check(bytes.readUInt32LE(end)===0x06054b50&&bytes.readUInt16LE(end+20)===0,'Project package ZIP end record is invalid');
  const count=bytes.readUInt16LE(end+10),directorySize=bytes.readUInt32LE(end+12),directoryOffset=bytes.readUInt32LE(end+16);
  check(bytes.readUInt16LE(end+4)===0&&bytes.readUInt16LE(end+6)===0&&bytes.readUInt16LE(end+8)===count
    &&count>0&&count<=500&&directoryOffset+directorySize===end,'Project package ZIP directory is invalid');
  const members=new Map(),names=new Set(),intervals=[],entries=[];
  let cursor=directoryOffset,total=0;
  for(let index=0;index<count;index++) {
    check(cursor+46<=end&&bytes.readUInt32LE(cursor)===0x02014b50,'Project package ZIP central record is invalid');
    const flags=bytes.readUInt16LE(cursor+8),method=bytes.readUInt16LE(cursor+10),crc=bytes.readUInt32LE(cursor+16);
    const compressed=bytes.readUInt32LE(cursor+20),size=bytes.readUInt32LE(cursor+24),nameLength=bytes.readUInt16LE(cursor+28);
    const extra=bytes.readUInt16LE(cursor+30),comment=bytes.readUInt16LE(cursor+32),disk=bytes.readUInt16LE(cursor+34);
    const mode=bytes.readUInt32LE(cursor+38)>>>16,offset=bytes.readUInt32LE(cursor+42);
    check((flags&~0x800)===0&&[0,8].includes(method)&&disk===0,'Project package ZIP feature is unsupported');
    check(size<=8_000_000&&compressed<=8_000_000&&(total+=size)<=20_000_000,'Project package ZIP expansion exceeds its bound');
    check(cursor+46+nameLength+extra+comment<=end,'Project package ZIP member bounds are invalid');
    const nameBytes=bytes.subarray(cursor+46,cursor+46+nameLength),name=new TextDecoder('utf-8',{fatal:true}).decode(nameBytes);
    check(/^[A-Za-z0-9_.\/-]+(?![^])/.test(name)&&!name.startsWith('/')&&!name.endsWith('/')
      &&!name.split('/').some(part=>!part||part==='.'||part==='..'),'Project package ZIP path is unsafe');
    check(!names.has(name.toLowerCase())&&[0,0x8000].includes(mode&0xf000),'Project package ZIP has duplicate or nonregular members');
    names.add(name.toLowerCase());
    check(offset+30<=directoryOffset&&bytes.readUInt32LE(offset)===0x04034b50,'Project package ZIP local record is invalid');
    const localName=bytes.readUInt16LE(offset+26),localExtra=bytes.readUInt16LE(offset+28),dataStart=offset+30+localName+localExtra;
    check(bytes.readUInt16LE(offset+6)===flags&&bytes.readUInt16LE(offset+8)===method&&bytes.readUInt32LE(offset+14)===crc
      &&bytes.readUInt32LE(offset+18)===compressed&&bytes.readUInt32LE(offset+22)===size,'Project package ZIP local and central records differ');
    check(dataStart+compressed<=directoryOffset&&nameBytes.equals(bytes.subarray(offset+30,offset+30+localName)),
      'Project package ZIP payload or local path differs');
    intervals.push([offset,dataStart+compressed]);entries.push({name,dataStart,compressed,size,method,crc});
    cursor+=46+nameLength+extra+comment;
  }
  check(cursor===end,'Project package ZIP contains unexpected central data');
  intervals.sort((a,b)=>a[0]-b[0]);let previous=0;
  for(const [start,finish] of intervals){check(start===previous,'Project package ZIP hides or overlaps payload data');previous=finish;}
  check(previous===directoryOffset,'Project package ZIP contains unexpected payload data');
  for(const entry of entries) {
    const packed=bytes.subarray(entry.dataStart,entry.dataStart+entry.compressed);
    const raw=entry.method===0?packed:inflateRawSync(packed,{maxOutputLength:Math.max(1,entry.size)});
    check(raw.length===entry.size&&crc32(raw)===entry.crc,'Project package member length or CRC differs');
    members.set(entry.name,raw);
  }
  const json=name=>{check(members.has(name),'Required project package evidence is missing');return parseUniqueJson(members.get(name));};
  const manifest=json('manifest.json');
  check(exact(manifest,[...members.keys()].filter(name=>name!=='manifest.json')),'Project package manifest coverage differs');
  for(const [name,raw] of members)if(name!=='manifest.json')check(isHash(manifest[name])&&manifest[name]===sha256(raw),'Project package member hash differs');
  const release=json('evidence/release-evidence.json'),historical=json('evidence/target-profile.json');
  check(Number.isSafeInteger(release.application_id)&&release.application_id>0,'Project package export application is invalid');
  const sqlMember=`sql/f${release.application_id}.sql`,sqlNames=[...members.keys()].filter(name=>name.startsWith('sql/'));
  check(same(sqlNames,[sqlMember])&&members.get(sqlMember)?.length>=1000&&members.has('schema/01_synthetic_schema.sql'),
    'Project package requires its actual conventional export and schema script');
  const projectRaw=members.get('native-project-spec.json'),traceRaw=members.get('source-to-apex.json');
  const derived=deriveProjectQaArtifacts(projectRaw,traceRaw),{project,trace,plan}=derived;
  if(project.schema_version===2) {
    const expected={schema_version:1,scope:'fox-project-storage-package-v1',project_id:project.project_id,
      data_mode:'synthetic_test_only',source_manifest_sha256:project.source_manifest_sha256,data_migration_included:false,
      mappings:trace.tables.map(table=>({storage_mapping:table.storage_mapping,
        ddl_sources:table.ddl_sources,module_ids:table.module_ids}))};
    check(same(json('schema/storage-mapping.json'),expected),
      'Project packaged storage mapping differs from the exact source-bound rendering');
  } else check(!members.has('schema/storage-mapping.json'),
    'Project legacy package cannot silently acquire mapped storage semantics');
  check(release.conversion_profile===PROJECT_PROFILE_ID&&release.application_count===1&&release.form_count===project.forms.length
    &&release.source_manifest_sha256===project.source_manifest_sha256&&/^fox-[a-f0-9]{20}(?![^])/.test(release.job_id)
    &&['reviewer_approved','reviewer_execution_verified','sqlcl_valid','import_passed','runtime_smoke_passed','package_reimport_passed','business_acceptance_required'].every(k=>release[k]===true)
    &&['human_acceptance_recorded','authenticated_runtime_passed','clean_schema_install_passed'].every(k=>release[k]===false),
    'Project package profile, source or generation gates differ');
  check(same(release.forms,trace.forms)&&release.artifact_binding?.project_trace_sha256===manifest['source-to-apex.json'],
    'Project package form mapping is not bound to the released trace');
  const source=json('evidence/source-manifest.json');
  check(source.job_id===release.job_id&&source.source_manifest_sha256===project.source_manifest_sha256
    &&same(source.native_project,project)&&Array.isArray(source.files)&&source.files.length>0,
    'Project package selected source manifest differs');
  const sources=new Map();
  for(const file of source.files) {
    check(typeof file.packaged_name==='string'&&/^[A-Za-z0-9_.\/-]+(?![^])/.test(file.packaged_name)
      &&!sources.has(file.packaged_name)&&isHash(file.sha256),'Project source manifest has invalid or duplicate identities');
    sources.set(file.packaged_name,file.sha256);
  }
  check(sha256([...sources.keys()].sort().map(name=>`${name}:${sources.get(name)}`).join('\n'))===project.source_manifest_sha256
    &&project.forms.every(form=>sources.get(form.source_name)===form.source_sha256
      &&(project.schema_version!==2||form.ddl_sources.every(ref=>sources.get(ref.name)===ref.sha256))),
    'Project package omitted or changed selected source identities');
  check(object(historical.database)&&typeof historical.database.parsing_schema==='string',
    'Project package original parsing schema is unavailable');
  return {...derived,manifest,release,historical,members,package_sha256:sha256(bytes),sql_sha256:manifest[sqlMember],
    schema_script_sha256:manifest['schema/01_synthetic_schema.sql'],sql_member:sqlMember};
}

function validatePolicy(verification,allocation,allocationRaw) {
  check(exact(verification,['schema_version','scope','policy_id','binding','target','expected_versions','max_evidence_age_seconds'])
    &&verification.schema_version===1&&verification.scope==='fox-native-verification-profile-v2'&&verification.policy_id==='jsn-clean-native-v2',
    'Project verification policy scope differs');
  const binding=verification.binding,target=verification.target;
  check(exact(binding,['job_id','source_manifest_sha256','package_sha256','allocation_receipt_sha256'])
    &&/^fox-[a-f0-9]{20}(?![^])/.test(binding.job_id)&&['source_manifest_sha256','package_sha256','allocation_receipt_sha256'].every(k=>isHash(binding[k])),
    'Project verification package binding is invalid');
  check(exact(target,[...FIXED_KEYS,'workspace','parsing_schema','workspace_id','application_id','application_alias'])
    &&FIXED_KEYS.every(k=>target[k]===SCOPE[k]),'Project target is outside the pinned JSN scope');
  check(typeof target.workspace==='string'&&/^FOX_QA_[0-9]{6}_[A-F0-9]{8}(?![^])/.test(target.workspace)
    &&target.parsing_schema===target.workspace&&target.application_alias===`F2A_QA_${target.workspace.slice(7)}`
    &&typeof target.workspace_id==='string'&&/^[1-9][0-9]{0,37}(?![^])/.test(target.workspace_id)
    &&Number.isSafeInteger(target.application_id)&&target.application_id>0,'Project target allocation identity is invalid');
  const date=target.workspace.slice(7,13),year=2000+Number(date.slice(0,2)),month=Number(date.slice(2,4)),day=Number(date.slice(4,6));
  const allocatedDate=new Date(Date.UTC(year,month-1,day));
  check(allocatedDate.getUTCFullYear()===year&&allocatedDate.getUTCMonth()===month-1&&allocatedDate.getUTCDate()===day,
    'Project target allocation date token is invalid');
  check(same(verification.expected_versions,VERSIONS),'Project runtime version tuple is not actively supported');
  check(Number.isSafeInteger(verification.max_evidence_age_seconds)&&verification.max_evidence_age_seconds>=60
    &&verification.max_evidence_age_seconds<=604800,'Project verification freshness bound is invalid');
  check(sha256(allocationRaw)===binding.allocation_receipt_sha256
    &&exact(allocation,['schema_version','scope','passed','plan_sha256','allocated_at_utc','binding','target','observed_versions','fresh_namespace'])
    &&allocation.schema_version===1&&allocation.scope==='fox-clean-allocation-v2'&&allocation.passed===true&&isHash(allocation.plan_sha256)
    &&same(allocation.binding,Object.fromEntries(['job_id','source_manifest_sha256','package_sha256'].map(k=>[k,binding[k]])))
    &&same(allocation.target,{...target,instance_id:INSTANCE})&&same(allocation.observed_versions,VERSIONS),
    'Project allocation is not bound to the approved package, target and versions');
  utc(allocation.allocated_at_utc);
  check(same(allocation.fresh_namespace,{workspace_created_fresh:true,schema_created_fresh:true,application_count:0,user_object_count:0}),
    'Project allocation does not prove a fresh empty namespace');
}

function validateClean(clean,project,plan,binding,verification,historical) {
  check(clean.schema_version===1&&clean.scope==='fox-project-clean-package-install-v1'&&clean.profile_id===PROJECT_PROFILE_ID
    &&Object.entries(binding).every(([k,v])=>clean[k]===v)&&same(clean.target,verification.target)
    &&same(clean.observed_versions,verification.expected_versions),'Project clean import binding differs');
  check(same(clean.before_install?.application_ids,[])&&clean.before_install?.user_object_count===0,
    'Project clean import namespace was not empty');
  const tables=plan.tables.map(t=>t.table_name),target=verification.target;
  check(same(clean.after_install?.application_ids,[target.application_id])&&same(clean.after_install?.physical_tables,tables)
    &&clean.after_install?.unexpected_schema_dependency_count===0,'Project clean import application or tables differ');
  check(Array.isArray(clean.table_metadata)&&same(clean.table_metadata.map(t=>t.table_name),tables),'Project clean import table coverage differs');
  for(const table of clean.table_metadata) {
    const spec=project.forms.find(f=>f.native_form.table_name===table.table_name).native_form;
    const key=spec.columns.find(c=>c.primary_key===true).name;
    const columns=spec.columns.map(c=>({name:c.name,data_type:c.data_type,nullable:c.nullable,char_length:c.data_type==='VARCHAR2'?c.length:0,identity:c.identity??false}));
    check(table.schema===target.parsing_schema&&table.row_count===0&&same(table.primary_keys,[])
      &&table.unexpected_schema_dependency_count===0&&same(table.columns,columns)
      &&same(table.primary_key,{columns:[key],status:'ENABLED',validated:'VALIDATED'}),'Project clean import table metadata differs');
  }
  check(same(clean.module_metadata,plan.forms.map(f=>Object.fromEntries(['module_id','table_name','report_page_id','form_page_id','items'].map(k=>[k,f[k]]))))
    &&same(clean.page_ids,[0,...Array.from({length:plan.form_count*2},(_,i)=>i+1),9999])
    &&same(clean.navigation,plan.forms.map(f=>({module_id:f.module_id,report_page_id:f.report_page_id}))),
    'Project clean import page, item or navigation coverage differs');
  check(clean.original_parsing_schema===historical.database.parsing_schema&&clean.original_parsing_schema!==target.parsing_schema
    &&/^[A-Z][A-Z0-9_]{0,29}(?![^])/.test(clean.original_parsing_schema)&&clean.original_schema_reference_count===0,
    'Project clean import original-schema independence is unproven');
}

/** Pure validation: caller passes mounted exact raw bytes, not pre-parsed claims. */
export function validateProjectRunnerInputs(inputs,{now=Date.now()}={}) {
  try {
    const names=['targetRaw','profileRaw','projectRaw','traceRaw','importRaw','verificationRaw','allocationRaw','packageRaw','credentialRaw'];
    check(exact(inputs,names),'Project runner mounted input coverage differs');
    for(const name of names)bounded(inputs[name],name==='packageRaw'?8_000_000:name==='credentialRaw'||name==='verificationRaw'||name==='allocationRaw'?16_384:2_000_000);
    const parsed=Object.fromEntries(names.filter(n=>n!=='packageRaw').map(n=>[n.replace(/Raw$/,''),parseUniqueJson(inputs[n],{
      // All numbers in these mounted contracts are bounded integer metadata.
      // Do not let JS make JSON 1.0 / 1e0 look like Python's strict integer 1.
      onNumber:lexeme=>check(/^(?:0|[1-9][0-9]*)(?![^])/.test(lexeme)&&Number.isSafeInteger(Number(lexeme)),
        'Project integer metadata must use exact safe integer JSON tokens'),
    })]));
    const {target,profile,verification,allocation,import:clean,credential}=parsed;
    const packageEvidence=inspectProjectPackageBytes(inputs.packageRaw),{project,trace,plan}=packageEvidence;
    check(inputs.projectRaw.equals(packageEvidence.members.get('native-project-spec.json'))
      &&inputs.traceRaw.equals(packageEvidence.members.get('source-to-apex.json')),'Mounted project or trace bytes differ from the package');
    validatePolicy(verification,allocation,inputs.allocationRaw);
    const release=packageEvidence.release;
    check(verification.binding.job_id===release.job_id&&verification.binding.source_manifest_sha256===project.source_manifest_sha256
      &&verification.binding.package_sha256===packageEvidence.package_sha256,'Project policy authorizes different source or package bytes');
    check(![release.application_id,release.package_reimport?.application_id].includes(verification.target.application_id)
      &&![release.application_alias,release.package_reimport?.application_alias].includes(verification.target.application_alias),
      'Project QA requires its own allocated application');
    const binding={job_id:release.job_id,source_manifest_sha256:project.source_manifest_sha256,package_sha256:packageEvidence.package_sha256,
      project_spec_sha256:sha256(inputs.projectRaw),source_to_apex_sha256:sha256(inputs.traceRaw),
      schema_script_sha256:packageEvidence.schema_script_sha256,sql_sha256:packageEvidence.sql_sha256,
      verification_profile_sha256:sha256(inputs.verificationRaw),allocation_receipt_sha256:sha256(inputs.allocationRaw)};
    validateClean(clean,project,plan,binding,verification,packageEvidence.historical);
    check(same(profile,packageEvidence.profile),'Project runtime profile omitted or changed a form');
    const targetUrl=`${SCOPE.origin}/ords/r/${verification.target.workspace.toLowerCase()}/${verification.target.application_alias.toLowerCase()}/`;
    const expectedTarget={schema_version:1,scope:'fox-project-qa-target-v1',...binding,target:verification.target,url:targetUrl,
      profile_sha256:sha256(inputs.profileRaw),import_receipt_sha256:sha256(inputs.importRaw),test_plan_sha256:hash(plan),synthetic_qa_approved:true};
    check(same(target,expectedTarget),'Project target receipt differs from the exact approved clean import');
    check(Number.isFinite(now)&&utc(allocation.allocated_at_utc)<=utc(clean.started_at_utc)&&utc(clean.started_at_utc)<=utc(clean.finished_at_utc)
      &&utc(clean.finished_at_utc)<=now&&now-utc(clean.finished_at_utc)<=verification.max_evidence_age_seconds*1000,
      'Project clean import is stale, future-dated or out of sequence');
    const accounts=validateCredentials(credential);
    // These are the two allocator-owned runtime identities, never a personal,
    // schema-administrator or human-acceptance account selected by a caller.
    check(accounts.twoIndependentAccounts&&accounts.primary.username==='FOX_QA_A'&&accounts.secondary.username==='FOX_QA_B',
      'Project QA requires the two separately supplied allocator runtime identities');
    const targetReceiptSha256=sha256(inputs.targetRaw);
    const inputSha256={...binding,profile_sha256:sha256(inputs.profileRaw),import_receipt_sha256:sha256(inputs.importRaw),target_receipt_sha256:targetReceiptSha256};
    return {project,trace,plan,profile,target,targetUrl,accounts,inputSha256,targetReceiptSha256,verification,allocation,clean,packageEvidence};
  } catch(error) {
    // No parser/native exception, path, source data or credential value reaches
    // a log; named validations above are deliberately value-free diagnostics.
    const safe=error instanceof Error&&/^Project |^Mounted project |^Required project /.test(error.message);
    throw new Error(safe?error.message:'Project runner input is malformed, unsupported or incomplete');
  }
}

const INPUT_ENV={targetRaw:'FOX_QA_TARGET_RECEIPT',profileRaw:'FOX_QA_PROFILE',projectRaw:'FOX_QA_PROJECT_SPEC',traceRaw:'FOX_QA_PROJECT_TRACE',
  importRaw:'FOX_QA_IMPORT_RECEIPT',verificationRaw:'FOX_QA_VERIFICATION_PROFILE',allocationRaw:'FOX_QA_ALLOCATION_RECEIPT',packageRaw:'FOX_QA_PACKAGE',credentialRaw:'FOX_QA_CREDENTIAL_FILE'};
export function loadProjectRunnerInputs(env=process.env,options={}) {
  try {
    const inputs={};
    for(const [name,key] of Object.entries(INPUT_ENV)) {
      const file=env[key],max=name==='packageRaw'?8_000_000:['credentialRaw','verificationRaw','allocationRaw'].includes(name)?16_384:2_000_000;
      check(typeof file==='string'&&path.isAbsolute(file),'Project runner requires absolute mounted input paths');
      const stat=lstatSync(file);
      check(stat.isFile()&&!stat.isSymbolicLink()&&stat.size>0&&stat.size<=max,'Project runner input must be a bounded regular file');
      if(name==='credentialRaw'&&process.platform!=='win32')check((stat.mode&0o077)===0,'Project credentials must be owner-private');
      inputs[name]=readFileSync(file);
    }
    return validateProjectRunnerInputs(inputs,options);
  } catch(error) {
    const safe=error instanceof Error&&/^Project |^Mounted project |^Required project /.test(error.message);
    throw new Error(safe?error.message:'Project runner mounted input is unavailable or unsafe');
  }
}
