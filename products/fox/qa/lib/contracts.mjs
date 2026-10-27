import {createHash} from 'node:crypto';
import {readFileSync, lstatSync} from 'node:fs';
import path from 'node:path';

export const SCOPE = Object.freeze({
  compartment_id: 'ocid1.compartment.oc1..aaaaaaaa2q5aelkapmt5mhumvxadcynq5chez2faeucy5plefhy3ylmahtba',
  database_id: 'ocid1.autonomousdatabase.oc1.iad.anuwcljrc7x6gxiapkxouj7emfbelvnvompwjcpoxx5vg727cegjsqkbp4rq',
  region: 'us-ashburn-1',
  db_name: 'ASZ8EQWFM8UNCA2_JSNF2APEX',
  origin: 'https://asz8eqwfm8unca2-jsnf2apex.adb.us-ashburn-1.oraclecloudapps.com',
});
export const sha256 = value => createHash('sha256').update(value).digest('hex');
// (?![^]) asserts absolute end-of-input; JS $ also matches before a final newline.
export const isHash = value => typeof value === 'string' && /^[a-f0-9]{64}(?![^])/.test(value);
export function check(value, message) { if (!value) throw new Error(message); }

export function validateCredentials(value) {
  check(value && typeof value==='object' && !Array.isArray(value),'Invalid QA credential object');
  check(Object.keys(value).every(key=>['username','password','second_username','second_password'].includes(key)),'Unexpected QA credential properties');
  const validUser=user=>typeof user==='string'&&user.length>0&&user.length<=254;
  const validPassword=password=>typeof password==='string'&&password.length>0&&password.length<=1024;
  check(validUser(value.username)&&validPassword(value.password),'Missing QA primary credentials');
  const secondPresent=Object.hasOwn(value,'second_username')||Object.hasOwn(value,'second_password');
  if(secondPresent) {
    check(validUser(value.second_username)&&validPassword(value.second_password),'Both secondary QA credential fields are required');
    check(value.second_username.toLowerCase()!==value.username.toLowerCase(),'Secondary QA account must differ from the primary account');
  }
  return {primary:{username:value.username,password:value.password},
    secondary:secondPresent?{username:value.second_username,password:value.second_password}:null,
    twoIndependentAccounts:secondPresent};
}

export function readJson(file, maxBytes = 1048576, {nativeSpec=false}={}) {
  check(typeof file === 'string' && path.isAbsolute(file), 'An absolute file path is required');
  const stat = lstatSync(file);
  check(stat.isFile() && !stat.isSymbolicLink() && stat.size <= maxBytes, 'Input must be a bounded regular file, not a symlink');
  const raw = readFileSync(file);
  return {value: nativeSpec?parseNativeQaSpecBytes(raw):parseUniqueJson(raw), sha256: sha256(raw)};
}

export function parseUniqueJson(raw,{onNumber}={}) {
  const text=typeof raw==='string'?raw:new TextDecoder('utf-8',{fatal:true}).decode(raw);
  let at=0;
  const space=()=>{while(/[\t\n\r ]/.test(text[at]??'x'))at++;};
  function string() {const start=at++;while(at<text.length){if(text[at]==='\\'){at+=2;continue;}if(text[at++]==='"')return JSON.parse(text.slice(start,at));}throw new Error('Invalid JSON string');}
  function value(depth=0,keysPath=[]) {
    check(depth<=64,'JSON nesting exceeds the bound');space();const char=text[at];
    if(char==='"')return string();
    if(char==='{'||char==='[') {
      const object=char==='{',end=object?'}':']',result=object?Object.create(null):[],keys=new Set();at++;space();
      if(text[at]===end){at++;return result;}
      while(at<text.length) {
        space();let key;
        if(object){check(text[at]==='"','Invalid JSON object key');key=string();check(!keys.has(key),'Duplicate JSON keys are prohibited');keys.add(key);space();check(text[at++]===':','Invalid JSON separator');}
        const item=value(depth+1,[...keysPath,object?key:result.length]);if(object)result[key]=item;else result.push(item);
        space();if(text[at]===end){at++;return result;}check(text[at++]===',','Invalid JSON collection separator');
      }throw new Error('Unterminated JSON collection');
    }
    const match=/^(?:true|false|null|-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?)/.exec(text.slice(at));
    check(match,'Invalid JSON value');at+=match[0].length;const parsed=JSON.parse(match[0]);check(typeof parsed!=='number'||Number.isFinite(parsed),'Non-finite JSON is prohibited');
    if(typeof parsed==='number') {
      const integerFields=new Set(['schema_version','application_id','max_evidence_age_seconds','application_count','user_object_count','native_table_count',
        'initial_row_count','row_count','reference_count','unexpected_schema_dependency_count','char_length','max_length','member_count']);
      if(integerFields.has(keysPath.at(-1)))check(/^-?(?:0|[1-9][0-9]*)(?![^])/.test(match[0])&&Number.isSafeInteger(parsed),'Protocol integer must use an exact safe integer JSON token');
      onNumber?.(match[0],keysPath);
    }return parsed;
  }
  const parsed=value();space();check(at===text.length,'Unexpected JSON trailing data');return parsed;
}
export function parseNativeQaSpecBytes(raw) {
  const spec=parseUniqueJson(raw,{onNumber:(lexeme,keysPath)=>{
    if(keysPath.length===3&&keysPath[0]==='columns'&&keysPath[2]==='length')check(/^(?:0|[1-9][0-9]*)(?![^])/.test(lexeme),'Native VARCHAR2 length must be an integer JSON token');
  }});
  return validateNativeQaSpec(spec);
}

export const CLEAN_WORKSPACE='FOX_QA_261017A';
export const CLEAN_WORKSPACE_ID='22042420337195497';
const BINDING_HASHES=['package_sha256','sql_sha256','native_spec_sha256','schema_script_sha256','source_manifest_sha256'];

export function validateProfileSpec(profile,spec) {
  check(spec?.profile_id===profile.profile_id&&spec.data_mode==='synthetic_test_only'&&spec.table_name===profile.table_name,'Mounted native spec does not identify the QA profile/table');
  check(Array.isArray(spec.columns),'Mounted native spec columns missing');
  const keys=spec.columns.filter(column=>column.primary_key===true);
  check(keys.length===1&&keys[0].data_type==='NUMBER'&&keys[0].nullable===false&&keys[0].identity===true,'Mounted native spec requires its explicit non-null identity key');
  const editable=spec.columns.filter(column=>column.primary_key!==true);
  check(editable.length===profile.fields.length&&new Set(spec.columns.map(column=>column.name)).size===spec.columns.length,'QA profile must cover every editable native column exactly once');
  for(const field of profile.fields) {
    const column=editable.find(item=>item.name===field.name);
    check(column&&column.label===field.label&&column.data_type===field.data_type&&typeof column.nullable==='boolean'&&field.required===!column.nullable,'QA field metadata differs from mounted native spec');
    if(field.data_type==='VARCHAR2')check(column.length===field.max_length,'QA string limit differs from native spec');
  }
  if(spec.supported_operations!==undefined)check(JSON.stringify(spec.supported_operations)==='["query","insert","update"]','Native spec operations differ from the supported profile');
}

function mounted(receipt,name,artifact) {
  const expected=receipt[`${name}_sha256`];
  if(expected===null){check(!artifact,`Unexpected mounted ${name} without a target binding`);return null;}
  check(isHash(expected),`Invalid mounted ${name} SHA-256 binding`);
  check(artifact&&artifact.sha256===expected,`Mounted ${name} bytes do not match the target receipt`);
  return artifact.value;
}

export function validateTarget(receipt, profile, profileHash, packageHash = null, artifacts = {}) {
  if(receipt?.schema_version===2)return validateTargetV2(receipt,profile,profileHash,packageHash,artifacts);
  check(receipt?.schema_version === 1, 'Unsupported target receipt');
  for (const name of ['compartment_id', 'database_id', 'region']) {
    check(receipt[name] === SCOPE[name], `Target ${name} is outside JSN scope`);
  }
  check(receipt.synthetic_qa_approved === true, 'Synthetic browser writes require an approved receipt');
  check(Number.isSafeInteger(receipt.application_id) && receipt.application_id > 0, 'Explicit positive application ID required');
  check(typeof receipt.alias === 'string' && /^F2A_[A-Z0-9_]{1,80}(?![^])/.test(receipt.alias), 'Explicit FOX alias required');
  const clean=receipt.clean_install===true;
  check(receipt.clean_install===undefined||typeof receipt.clean_install==='boolean','clean_install must be an explicit boolean');
  check(receipt.workspace==='FORMS2APEX_POC'?!clean:receipt.workspace===CLEAN_WORKSPACE&&clean,'Only existing JSN proof workspace or the exact bound clean workspace is approved');
  const parsingSchema=receipt.parsing_schema??receipt.workspace;
  check(parsingSchema===receipt.workspace,'Parsing schema must exactly match the approved workspace');
  const url = new URL(receipt.url);
  check(url.origin === SCOPE.origin && !url.username && !url.password && !url.search && !url.hash, 'Target must use the exact JSN HTTPS origin without credentials/query/fragment');
  const expectedPath = `/ords/r/${receipt.workspace.toLowerCase()}/${receipt.alias.toLowerCase()}/`;
  check(url.pathname.toLowerCase() === expectedPath, 'Application URL does not match the receipt alias/workspace');
  check(isHash(profileHash) && receipt.profile_sha256 === profileHash, 'QA profile hash does not match the target receipt');
  check(profile?.schema_version === 1 && profile.profile_id === 'native-table-form-v1', 'Unsupported QA profile');
  check(profile.data_mode === 'synthetic_test_only' && /^FOX_NATIVE_[A-Z0-9_]{1,19}(?![^])/.test(profile.table_name), 'Only explicit synthetic native tables may be tested');
  check(receipt.table_name === profile.table_name, 'Target receipt table does not match the QA profile');
  check(Array.isArray(profile.fields) && profile.fields.length >= 1 && profile.fields.length <= 19, 'QA fields must describe the editable native items');
  const labels = new Set(); const names = new Set();
  for (const field of profile.fields) {
    check(field && /^[A-Z][A-Z0-9_]{0,29}(?![^])/.test(field.name), 'Invalid QA field name');
    check(typeof field.label === 'string' && field.label.length > 0 && field.label.length <= 80, 'Explicit accessible field label required');
    check(!labels.has(field.label) && !names.has(field.name), 'QA field names and labels must be unique');
    labels.add(field.label); names.add(field.name);
    check(['VARCHAR2','NUMBER','DATE'].includes(field.data_type) && typeof field.required === 'boolean', 'Unsupported QA field metadata');
    check(typeof field.valid_value === 'string' && field.valid_value.length <= 4000, 'Explicit synthetic field value required');
    if (field.data_type === 'VARCHAR2') {
      check(Number.isSafeInteger(field.max_length) && field.max_length >= 1 && field.max_length <= 4000, 'Explicit VARCHAR2 limit required');
      check(field.valid_value.length <= field.max_length, 'Synthetic field value exceeds declared length');
    }
    if (field.data_type === 'NUMBER') decimalCents(field.valid_value);
    if (field.data_type === 'DATE' && field.valid_value) check(/^\d{4}-\d{2}-\d{2}(?![^])/.test(field.valid_value), 'Synthetic date must use YYYY-MM-DD');
  }
  const marker = profile.fields.find(field => field.name === profile.marker_field);
  check(marker?.data_type === 'VARCHAR2' && marker.max_length >= 40, 'Marker field must be a VARCHAR2 with at least 40 characters');
  const edit = profile.fields.find(field => field.name === profile.edit_field);
  check(edit?.data_type === 'NUMBER', 'Explicit editable numeric field required for persisted edit/concurrency tests');
  check(Array.isArray(profile.database_constraints), 'Optional database constraint cases must be explicitly listed');
  for (const item of profile.database_constraints) {
    check(names.has(item.field) && typeof item.invalid_value === 'string' && item.invalid_value.length <= 200, 'Invalid constraint test value');
    check(typeof item.expected_error === 'string' && item.expected_error.length <= 200 && item.expected_error.length > 0, 'Expected database error text is required');
  }
  check(receipt.package_sha256 === null || isHash(receipt.package_sha256), 'Package hash must be explicit SHA-256 or null');
  if (receipt.package_sha256 !== null) check(packageHash === receipt.package_sha256, 'Mounted package bytes do not match the target receipt');
  else check(packageHash === null, 'Mounted package has no receipt binding');
  for (const name of ['source_manifest_sha256','native_spec_sha256','import_receipt_sha256']) {
    check(receipt[name] === null || isHash(receipt[name]), `${name} must be explicit SHA-256 or null`);
  }
  const spec=mounted(receipt,'native_spec',artifacts.nativeSpec);
  if(spec)validateProfileSpec(profile,spec);
  const imported=mounted(receipt,'import_receipt',artifacts.importReceipt);
  if(imported) {
    check(imported.passed===true&&imported.application_id===receipt.application_id&&imported.application_alias===receipt.alias&&imported.workspace===receipt.workspace,'Mounted import receipt identifies a different or unsuccessful app');
    check(new URL(imported.application_url).href===url.href,'Mounted import receipt URL differs from exact target');
    if(imported.compartment_id!==undefined)check(imported.compartment_id===SCOPE.compartment_id,'Import receipt compartment differs');
  }
  if(clean) {
    check(receipt.db_name===SCOPE.db_name&&receipt.parsing_schema===CLEAN_WORKSPACE&&spec&&imported&&artifacts.packageEvidence,'Clean installation requires exact DB_NAME and actual mounted native spec, import receipt and package');
    check(receipt.workspace_id===CLEAN_WORKSPACE_ID&&imported.workspace_id===CLEAN_WORKSPACE_ID,'Clean workspace ID must match the exact bootstrap string without numeric conversion');
    check(imported.schema_version===1&&imported.scope==='fox-clean-package-install-v1','Unsupported clean-install proof scope');
    for(const name of ['compartment_id','database_id','region','db_name'])check(imported[name]===SCOPE[name],`Clean import ${name} differs`);
    check(imported.parsing_schema===CLEAN_WORKSPACE&&imported.table_name===profile.table_name&&imported.profile_id===profile.profile_id,'Clean import parsing schema/profile/table differs');
    check(typeof receipt.job_id==='string'&&/^fox-[a-z0-9]{20}(?![^])/.test(receipt.job_id)&&imported.job_id===receipt.job_id&&artifacts.packageEvidence.releaseEvidence.job_id===receipt.job_id,'Clean source job identity differs');
    for(const name of BINDING_HASHES)check(isHash(receipt[name])&&imported[name]===receipt[name]&&artifacts.packageEvidence[name]===receipt[name],`Clean package ${name} binding differs`);
    const proof=imported.clean_install;
    check(proof?.passed===true&&proof.workspace_created_fresh===true&&proof.schema_created_fresh===true,'Fresh workspace/schema creation is not proven');
    check(proof.before_install?.passed===true&&proof.before_install.application_count===0&&proof.before_install.user_object_count===0,'Pre-install empty workspace/schema evidence is not passed');
    check(proof.after_install?.passed===true&&proof.after_install.application_count===1&&proof.after_install.native_table_count===1,'Post-install exact app/table evidence is not passed');
    const versions=imported.observed_versions;
    const family26=value=>typeof value==='string'&&/^26\.1(?:\.\d+){0,4}(?![^])/.test(value);
    check(versions&&family26(versions.apex)&&family26(versions.sqlcl)&&typeof versions.database==='string'&&/^\d{1,2}(?:\.\d{1,5}){1,5}(?![^])/.test(versions.database),'Compatible numeric observed APEX/SQLcl/database versions are missing');
    const dependencies=imported.no_original_schema_dependencies;
    check(dependencies?.passed===true&&dependencies.original_schema==='FORMS2APEX_POC'&&dependencies.reference_count===0,'No-original-schema-dependency evidence is not passed');
    check(JSON.stringify(spec)===JSON.stringify(artifacts.packageEvidence.nativeSpec),'Mounted native spec differs from exact package member');
    check(profile.database_constraints.length===0,'Clean FOX_NATIVE_BETA profile must not invent database CHECK constraints');
    check(profile.table_name==='FOX_NATIVE_BETA','The fixed clean target requires FOX_NATIVE_BETA');
  }
  return {receipt,profile,targetUrl:url.href,packageBound:receipt.package_sha256!==null,cleanInstallBound:clean,
    nativeSpecBound:spec!==null,importReceiptBound:imported!==null,bindingScope:clean?'exact-package-clean-install':'legacy-runtime-proof-not-clean'};
}

export function allowedRequest(rawUrl, method = 'GET') {
  try {
    const url = new URL(rawUrl);
    if (url.username || url.password) return false;
    if (url.origin === SCOPE.origin) return true;
    return url.origin === 'https://static.oracle.com' && url.pathname.startsWith('/cdn/apex/') && ['GET','HEAD'].includes(method);
  } catch { return false; }
}

export function safeMessage(error, secrets = []) {
  let message = String(error?.message || error || 'Unknown failure');
  for (const secret of secrets.filter(value => typeof value === 'string' && value.length > 0)) message = message.split(secret).join('[REDACTED]');
  message = message.replace(/https?:\/\/\S+/g, '[URL REDACTED]').replace(/(?:password|authorization|cookie)["']?\s*[:=]\s*[^\s,;]+/gi, '[CREDENTIAL REDACTED]');
  return message.slice(0,1200);
}

export function outcome(tests) {
  const required = tests.filter(test => test.required !== false);
  if (tests.some(test => test.status === 'FAILED')) return 'FAILED';
  if (required.some(test => test.status !== 'PASSED')) return 'INCOMPLETE';
  return 'PASSED';
}

export function decimalCents(value) {
  const normalized=String(value).replaceAll(',','');
  check(/^-?\d{1,9}(?:\.\d{1,2})?(?![^])/.test(normalized), 'QA numeric fixtures/readbacks require at most 9 integer digits and 2 decimal places');
  const negative=normalized.startsWith('-'); const [whole,fraction='']=normalized.replace(/^-/,'').split('.');
  return (Number(whole)*100+Number(fraction.padEnd(2,'0')))*(negative?-1:1);
}
export function formatCents(value) {
  check(Number.isSafeInteger(value), 'Unsafe QA numeric arithmetic');
  const absolute=Math.abs(value);
  return `${value<0?'-':''}${Math.floor(absolute/100)}.${String(absolute%100).padStart(2,'0')}`;
}

// V2 derives test applicability and synthetic values from the exact mounted spec.
// V1 fixtures and receipts deliberately retain their historical interpretation.
export const NATIVE_QA_CASES=Object.freeze(['login','create','search_positive','search_negative','reread','edit_save','cancel_edit','cancel_create',
  'required_fields','invalid_number','invalid_date','maximum_length','concurrent_edit','browser_runtime_errors']);
const EXCLUDED_NAMES=new Set(('ACCESS ADD ALL ALTER AND ANY AS ASC AUDIT BETWEEN BY CHAR CHECK CLUSTER COLUMN COMMENT COMPRESS CONNECT CREATE CURRENT DATE DECIMAL DEFAULT DELETE DESC DISTINCT DROP ELSE EXCLUSIVE EXISTS FILE FLOAT FOR FROM GRANT GROUP HAVING IDENTIFIED IMMEDIATE IN INCREMENT INDEX INITIAL INSERT INTEGER INTERSECT INTO IS LEVEL LIKE LOCK LONG MAXEXTENTS MINUS MLSLABEL MODE MODIFY NOAUDIT NOCOMPRESS NOT NOWAIT NULL NUMBER OF OFFLINE ON ONLINE OPTION OR ORDER PCTFREE PRIOR PRIVILEGES PUBLIC RAW RENAME RESOURCE REVOKE ROW ROWID ROWNUM ROWS SELECT SESSION SET SHARE SIZE SMALLINT START SUCCESSFUL SYNONYM SYSDATE TABLE THEN TO TRIGGER UID UNION UNIQUE UPDATE USER VALIDATE VALUES VARCHAR VARCHAR2 VIEW WHENEVER WHERE WITH PRIMARY KEY IDENTITY CONSTRAINT').split(' '));
// QA derives selectors and cases, not permission to generate/import a package.
// Producer label policy is enforced upstream by the canonical Python validators.
// Do not duplicate their runtime Unicode categories or SQL-looking-label policy.
export function validateNativeQaSpec(spec) {
  const object=(value,required,optional=[])=>check(value&&typeof value==='object'&&!Array.isArray(value)&&required.every(key=>Object.hasOwn(value,key))&&Object.keys(value).every(key=>[...required,...optional].includes(key)),'Unexpected or missing native metadata');
  const identifier=value=>check(typeof value==='string'&&/^[A-Z][A-Z0-9_]{0,29}(?![^])/.test(value)&&!EXCLUDED_NAMES.has(value),'Invalid native identifier');
  object(spec,['profile_id','data_mode','table_name','columns'],['supported_operations']);
  check(spec.profile_id==='native-table-form-v1'&&spec.data_mode==='synthetic_test_only','Unsupported native QA scope');
  identifier(spec.table_name);check(spec.table_name.startsWith('FOX_NATIVE_'),'Only synthetic native tables are in scope');
  check(spec.supported_operations===undefined||JSON.stringify(spec.supported_operations)==='["query","insert","update"]','Unsupported native operations');
  check(Array.isArray(spec.columns)&&spec.columns.length>=2&&spec.columns.length<=20,'Native spec requires 2–20 columns');
  const names=new Set();let keyCount=0;
  for(const column of spec.columns) {
    object(column,['name','label','data_type','nullable'],['primary_key','identity','length']);identifier(column.name);
    check(!names.has(column.name),'Duplicate native column');names.add(column.name);
    check(['VARCHAR2','NUMBER','DATE'].includes(column.data_type)&&typeof column.nullable==='boolean','Unsupported native field metadata');
    const primary=Object.hasOwn(column,'primary_key')?column.primary_key:false,identity=Object.hasOwn(column,'identity')?column.identity:false;
    check(typeof primary==='boolean'&&typeof identity==='boolean'&&primary===identity&&(!primary||(column.data_type==='NUMBER'&&!column.nullable)),'Invalid identity primary key');
    if(primary)keyCount++;
    check(typeof column.label==='string'&&[...column.label].length>=1&&[...column.label].length<=80&&!/[\uD800-\uDFFF]/u.test(column.label),'Invalid bounded Unicode-scalar QA label');
    if(column.data_type==='VARCHAR2')check(Number.isSafeInteger(column.length)&&column.length>=1&&column.length<=4000,'Invalid VARCHAR2 length');
    else check(!Object.hasOwn(column,'length'),'Only VARCHAR2 has a length');
  }
  check(keyCount===1,'Exactly one identity primary key is required');return spec;
}
export function canonicalQaPlan(value) {
  const sort=item=>Array.isArray(item)?item.map(sort):item&&typeof item==='object'?Object.fromEntries(Object.keys(item).sort().map(key=>[key,sort(item[key])])):item;
  return JSON.stringify(sort(value));
}
export function deriveNativeQaPlan(spec,nativeSpecSha256) {
  validateNativeQaSpec(spec);check(isHash(nativeSpecSha256),'Actual native spec SHA-256 is required');
  const key=spec.columns.find(column=>column.primary_key===true),fields=spec.columns.filter(column=>column.primary_key!==true),names=fields.map(column=>column.name);
  const typed={required_fields:[fields.filter(column=>!column.nullable),'REQUIRED_EDITABLE_FIELDS','NO_REQUIRED_EDITABLE_FIELDS'],
    invalid_number:[fields.filter(column=>column.data_type==='NUMBER'),'EDITABLE_NUMBER_FIELDS','NO_EDITABLE_NUMBER_FIELDS'],
    invalid_date:[fields.filter(column=>column.data_type==='DATE'),'EDITABLE_DATE_FIELDS','NO_EDITABLE_DATE_FIELDS'],
    maximum_length:[fields.filter(column=>column.data_type==='VARCHAR2'),'BOUNDED_VARCHAR2_FIELDS','NO_EDITABLE_VARCHAR2_FIELDS']};
  return {schema_version:1,scope:'fox-native-qa-plan-v2',profile_id:spec.profile_id,native_spec_sha256:nativeSpecSha256,
    primary_key:{name:key.name,item_name:`P2_${key.name}`,representation:'decimal_string'},
    row_tracking:{mode:'clean_empty_then_observed_pk',initial_row_count:0},edit_field:names[0],
    cases:NATIVE_QA_CASES.map(name=>{
      if(typed[name]){const [columns,yes,no]=typed[name];return{name,applicable:columns.length>0,field_names:columns.map(column=>column.name),reason_code:columns.length?yes:no};}
      return{name,applicable:true,field_names:['create','reread','edit_save','cancel_edit','cancel_create'].includes(name)?names:name==='concurrent_edit'?[names[0]]:[],reason_code:'UNIVERSAL_NATIVE_FLOW'};
    })};
}
export function deriveNativeQaValues(spec,phase) {
  validateNativeQaSpec(spec);const index=['create','edit','cancel_edit','winner','stale','cancel_create'].indexOf(phase);
  check(index>=0,'Unknown native QA value phase');
  return Object.fromEntries(spec.columns.filter(column=>column.primary_key!==true).map(column=>[column.name,
    column.data_type==='VARCHAR2'?String.fromCharCode(65+index):column.data_type==='NUMBER'?String(index+1):`2026-01-0${index+1}`]));
}
export function deriveNativeQaProfile(spec) {
  validateNativeQaSpec(spec);const values=deriveNativeQaValues(spec,'create');
  return {schema_version:2,profile_id:spec.profile_id,data_mode:spec.data_mode,table_name:spec.table_name,
    primary_key:spec.columns.find(column=>column.primary_key===true).name,
    fields:spec.columns.filter(column=>column.primary_key!==true).map(column=>({name:column.name,label:column.label,data_type:column.data_type,
      required:!column.nullable,...(column.data_type==='VARCHAR2'?{max_length:column.length}:{}),valid_value:values[column.name]})),database_constraints:[]};
}
function validateTargetV2(receipt,profile,profileHash,packageHash,artifacts) {
  const verification=mounted(receipt,'verification_profile',artifacts.verificationProfile);
  check(verification?.schema_version===1&&verification.scope==='fox-native-verification-profile-v2'&&verification.policy_id==='jsn-clean-native-v2','V2 requires the exact mounted operator verification profile');
  check(isHash(receipt.allocation_receipt_sha256)&&verification.binding?.allocation_receipt_sha256===receipt.allocation_receipt_sha256,'V2 allocation hash differs');
  if(artifacts.allocationReceipt)check(artifacts.allocationReceipt.sha256===receipt.allocation_receipt_sha256,'Mounted allocation bytes differ');
  const allocated=verification.target;
  for(const key of ['compartment_id','database_id','region','db_name'])check(receipt[key]===SCOPE[key]&&allocated?.[key]===SCOPE[key],`V2 ${key} is outside exact JSN scope`);
  check(receipt.clean_install===true&&receipt.synthetic_qa_approved===true,'V2 requires an approved clean synthetic target');
  check(typeof allocated.workspace==='string'&&/^FOX_QA_[0-9]{6}_[A-F0-9]{8}(?![^])/.test(allocated.workspace)&&allocated.parsing_schema===allocated.workspace,'V2 allocated namespace is invalid');
  check(typeof allocated.workspace_id==='string'&&/^[1-9][0-9]{0,37}(?![^])/.test(allocated.workspace_id),'V2 workspace ID must be an exact decimal string');
  check(Number.isSafeInteger(allocated.application_id)&&allocated.application_id>0&&typeof allocated.application_alias==='string'&&/^F2A_QA_[0-9]{6}_[A-F0-9]{8}(?![^])/.test(allocated.application_alias),'V2 allocated application is invalid');
  for(const key of ['workspace','parsing_schema','workspace_id','application_id'])check(receipt[key]===allocated[key],`V2 target ${key} differs from allocation`);
  check(receipt.alias===allocated.application_alias,'V2 alias differs from allocation');
  const targetUrl=`${SCOPE.origin}/ords/r/${allocated.workspace.toLowerCase()}/${allocated.application_alias.toLowerCase()}/`;
  check(new URL(receipt.url).href===targetUrl,'V2 URL differs from exact allocated target');
  check(isHash(profileHash)&&receipt.profile_sha256===profileHash,'V2 field-profile bytes differ');
  check(isHash(receipt.package_sha256)&&packageHash===receipt.package_sha256&&verification.binding.package_sha256===packageHash,'V2 exact package bytes differ');
  const spec=mounted(receipt,'native_spec',artifacts.nativeSpec),imported=mounted(receipt,'import_receipt',artifacts.importReceipt);
  check(spec&&imported&&artifacts.packageEvidence,'V2 requires mounted native spec, clean receipt and package');
  check(canonicalQaPlan(profile)===canonicalQaPlan(deriveNativeQaProfile(spec)),'V2 field profile must be completely derived from the exact native spec');
  check(receipt.table_name===spec.table_name,'V2 table differs from native spec');
  check(imported.schema_version===2&&imported.scope==='fox-clean-package-install-v2'&&imported.passed===true,'V2 clean installation did not pass');
  for(const key of ['verification_profile_sha256','allocation_receipt_sha256'])check(imported[key]===receipt[key],`V2 clean receipt ${key} differs`);
  for(const key of ['compartment_id','database_id','region','db_name','workspace','parsing_schema','workspace_id','application_id'])check(imported[key]===receipt[key],`V2 clean identity ${key} differs`);
  check(imported.application_alias===receipt.alias&&new URL(imported.application_url).href===targetUrl&&imported.table_name===spec.table_name&&imported.profile_id===spec.profile_id,'V2 clean app/profile/table differs');
  check(typeof receipt.job_id==='string'&&/^fox-[a-z0-9]{20}(?![^])/.test(receipt.job_id)&&verification.binding.job_id===receipt.job_id&&imported.job_id===receipt.job_id&&artifacts.packageEvidence.releaseEvidence.job_id===receipt.job_id,'V2 job identity differs');
  for(const key of BINDING_HASHES)check(isHash(receipt[key])&&imported[key]===receipt[key]&&artifacts.packageEvidence[key]===receipt[key],`V2 package ${key} differs`);
  check(verification.binding.source_manifest_sha256===receipt.source_manifest_sha256,'V2 approved source differs');
  check(canonicalQaPlan(spec)===canonicalQaPlan(artifacts.packageEvidence.nativeSpec),'V2 mounted spec differs from packaged spec');
  const proof=imported.clean_install;
  check(proof?.passed===true&&proof.workspace_created_fresh===true&&proof.schema_created_fresh===true,'V2 fresh allocation is unproven');
  check(proof.before_install?.passed===true&&proof.before_install.application_count===0&&proof.before_install.user_object_count===0,'V2 pre-install emptiness is unproven');
  check(proof.after_install?.passed===true&&proof.after_install.application_count===1&&proof.after_install.native_table_count===1&&proof.after_install.initial_row_count===0,'V2 initial empty table is unproven');
  const metadata=imported.table_metadata,expectedColumns=spec.columns.map(column=>({name:column.name,data_type:column.data_type,nullable:column.nullable,
    char_length:column.data_type==='VARCHAR2'?column.length:0,identity:column.identity===true}));
  check(metadata?.passed===true&&metadata.schema===receipt.parsing_schema&&metadata.table_name===spec.table_name&&metadata.row_count===0&&metadata.unexpected_schema_dependency_count===0,'V2 table metadata did not prove the exact initial target');
  check(canonicalQaPlan(metadata.columns)===canonicalQaPlan(expectedColumns),'V2 table columns differ from exact native spec');
  check(canonicalQaPlan(metadata.primary_key)===canonicalQaPlan({columns:[profile.primary_key],status:'ENABLED',validated:'VALIDATED'}),'V2 primary key metadata differs');
  for(const key of ['apex','sqlcl','database','mmd']) {
    const value=verification.expected_versions?.[key];
    const pattern=key==='mmd'?/^26\.1\.0\+[0-9]+(?![^])/:key==='database'?/^[0-9]{1,2}(?:\.[0-9]{1,5}){1,5}(?![^])/:/^26\.1(?:\.[0-9]+){0,4}(?![^])/;
    check(typeof value==='string'&&pattern.test(value)&&imported.observed_versions?.[key]===value,`V2 observed ${key} differs from approved numeric version`);
  }
  check(imported.no_original_schema_dependencies?.passed===true&&imported.no_original_schema_dependencies.original_schema==='FORMS2APEX_POC'&&imported.no_original_schema_dependencies.reference_count===0,'V2 original-schema independence is unproven');
  const plan=deriveNativeQaPlan(spec,receipt.native_spec_sha256);
  check(receipt.test_plan_sha256===sha256(canonicalQaPlan(plan)),'V2 deterministic test plan differs');
  return {receipt,profile,targetUrl,packageBound:true,cleanInstallBound:true,nativeSpecBound:true,importReceiptBound:true,
    bindingScope:'exact-package-clean-install-v2',nativeSpec:spec,plan,verificationProfile:verification};
}
export function canonicalPrimaryKey(value) {
  check(typeof value==='string'&&/^[1-9][0-9]{0,37}(?![^])/.test(value),'Observed primary key must be an exact positive decimal string');return value;
}
export function samePrimaryKeySet(actual,expected) {
  check(Array.isArray(actual)&&Array.isArray(expected),'Primary key set arrays required');
  actual.forEach(canonicalPrimaryKey);expected.forEach(canonicalPrimaryKey);
  return new Set(actual).size===actual.length&&new Set(expected).size===expected.length&&actual.length===expected.length&&actual.every(value=>expected.includes(value));
}
export function nativeReportPrimaryKeysFromTables(tables,spec) {
  validateNativeQaSpec(spec);
  check(Array.isArray(tables)&&tables.every(table=>table&&typeof table.sticky_header==='boolean'&&Array.isArray(table.rows)),
    'Native report table description is invalid');
  for(const table of tables) {
    check(table.rows.every(row=>Array.isArray(row)&&row.length>0&&row.every(cell=>cell&&['TH','TD'].includes(cell.tag)&&typeof cell.text==='string')),
      'Unexpected native report cell structure');
    if(table.sticky_header)check(table.rows.every(row=>row.every(cell=>cell.tag==='TH')),'Sticky report header unexpectedly contains data cells');
  }
  const actual=tables.filter(table=>!table.sticky_header);
  check(actual.length===1,'Expected exactly one native data table excluding sticky headers');
  const headers=[],rows=[];
  for(const row of actual[0].rows) {
    if(row.every(cell=>cell.tag==='TH'))headers.push(row);
    else {check(row.every(cell=>cell.tag==='TD'),'Native report row mixes header and data cells');rows.push(row);}
  }
  check(headers.length===1&&headers[0].length===spec.columns.length+1,'Report header structure differs from native spec');
  for(let index=0;index<spec.columns.length;index++)check(headers[0][index+1].text.trim()===spec.columns[index].label.trim(),
    'Report column order/heading differs from native spec');
  const keyIndex=spec.columns.findIndex(column=>column.primary_key===true)+1;
  const keys=rows.map(row=>{check(row.length===spec.columns.length+1,'Unexpected report data row shape');return canonicalPrimaryKey(row[keyIndex].text.trim());});
  check(new Set(keys).size===keys.length,'Duplicate report primary keys');return keys;
}
export async function readNativeReportPrimaryKeys(page,spec) {
  // APEX sticky headers clone the table. The original can have its TH header
  // row inside TBODY and no THEAD, so classify direct cells, not sections.
  const tables=await page.locator('table.a-IRR-table').evaluateAll(elements=>elements.map(table=>({
    id:table.id,sticky_header:table.closest('.t-fht-thead')!==null,
    rows:[...table.rows].map(row=>[...row.cells].map(cell=>({tag:cell.tagName,text:cell.tagName==='TH'?cell.textContent:cell.innerText}))),
  })));
  return nativeReportPrimaryKeysFromTables(tables,spec);
}
export async function nativeFilterControl(dialog,name) {
  check(['Column','Operator','Expression'].includes(name),'Unsupported native filter control');
  const control=dialog.getByLabel(name,{exact:true}).and(dialog.locator(name==='Expression'?'input:visible':'select:visible'));
  check(await control.count()===1,`Expected exactly one visible native filter ${name} control`);
  return control;
}
async function clearNativeQaText(input,column) {
  check(column.data_type==='VARCHAR2'&&Number.isSafeInteger(column.max_length)&&column.max_length>=1&&column.max_length<=4000,
    'Native text input requires its declared VARCHAR2 limit');
  check(await input.getAttribute('maxlength')===String(column.max_length)
    &&await input.evaluate(element=>element.maxLength)===column.max_length,`Native ${column.name} maxlength differs from the declared limit`);
  await input.click();
  await input.press('ControlOrMeta+A');
  const selection=await input.evaluate(element=>({activeElementIsInput:document.activeElement===element,
    selectionStart:element.selectionStart,selectionEnd:element.selectionEnd,valueLength:element.value.length,
    activeElementTag:document.activeElement?.tagName||null,activeElementId:document.activeElement?.id||null}));
  check(selection.activeElementIsInput&&selection.selectionStart===0&&selection.selectionEnd===selection.valueLength,
    `Native ${column.name} full active selection is not confirmed; no write attempted`);
  await input.press('Backspace');
  await input.press('Tab');
  check(await input.inputValue()==='',`Native ${column.name} did not clear before input; no write attempted`);
}
export async function fillNativeQaValue(input,column,value) {
  check(typeof value==='string'&&['VARCHAR2','NUMBER','DATE'].includes(column.data_type),'Invalid native QA input intent');
  if(column.data_type==='VARCHAR2') {
    check(value.length<=column.max_length,'Valid native text intent exceeds the declared limit');
    await clearNativeQaText(input,column);
  }
  await input.fill(value);
  check(await input.inputValue()===value,`Native ${column.name} differs from intended input; no write attempted`);
}
export async function probeNativeQaMaximumLength(input,column) {
  check(column.data_type==='VARCHAR2'&&Number.isSafeInteger(column.max_length)&&column.max_length>=1&&column.max_length<=4000,
    'Maximum-length probe requires a bounded VARCHAR2 field');
  const boundary='X'.repeat(column.max_length),overlength=boundary+'X';
  await fillNativeQaValue(input,column,boundary);
  await clearNativeQaText(input,column);
  await input.fill(overlength);
  const actual=await input.inputValue();
  check(actual===boundary||actual===overlength,`Native ${column.name} maximum-length input was unexpectedly transformed; no write attempted`);
  return {actual,evidence:{limit:column.max_length,html_maxlength:column.max_length,
    exact_boundary_input_accepted:true,boundary_readback:'unsaved_input_only',
    attempted_overlength:overlength.length,observed_input_length:actual.length,
    mode:actual===boundary?'browser_maxlength':'apex_validation',server_validation_proven:false}};
}
export function assertNativeQaWriteAllowed({stopped,browserErrors,networkDenials,unexpectedDialog}) {
  check(stopped===false&&Array.isArray(browserErrors)&&browserErrors.length===0&&Array.isArray(networkDenials)&&networkDenials.length===0&&unexpectedDialog===false,
    'Native QA failure or unsafe browser state; no further business write is allowed');
}
export function outcomeV2(tests,plan) {
  if(tests.some(test=>test.status==='FAILED'))return 'FAILED';
  if(tests.length!==plan.cases.length||new Set(tests.map(test=>test.name)).size!==tests.length)return 'INCOMPLETE';
  for(const item of plan.cases) {
    const test=tests.find(test=>test.name===item.name);
    if(!test||test.applicable!==item.applicable||test.required!==item.applicable||test.reason_code!==item.reason_code||canonicalQaPlan(test.field_names)!==canonicalQaPlan(item.field_names))return 'INCOMPLETE';
    const expected=item.field_names.map(field_name=>({field_name,status:'PASSED'}));
    if(test.status!==(item.applicable?'PASSED':'NOT_APPLICABLE')||canonicalQaPlan(test.field_results)!==canonicalQaPlan(expected))return 'INCOMPLETE';
  }
  return 'PASSED';
}
