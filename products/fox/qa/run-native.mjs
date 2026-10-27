import {mkdirSync, writeFileSync, renameSync, readFileSync,openSync,fsyncSync,closeSync} from 'node:fs';
import {randomBytes} from 'node:crypto';
import path from 'node:path';
import {SCOPE, check, readJson, sha256, validateTarget, validateCredentials, allowedRequest, safeMessage, outcome,decimalCents,formatCents,
  canonicalQaPlan,deriveNativeQaValues,canonicalPrimaryKey,samePrimaryKeySet,readNativeReportPrimaryKeys,nativeFilterControl,fillNativeQaValue,probeNativeQaMaximumLength,assertNativeQaWriteAllowed,outcomeV2} from './lib/contracts.mjs';
import {readPackageEvidence} from './lib/package-evidence.mjs';

process.umask(0o077);

// No Playwright traces, videos, HAR, storage-state files, request bodies or console forwarding:
// all can retain authentication material. Screenshots are post-login only, with account masking.
const cases = [
  ['login', true], ['create', true], ['search_positive', true], ['search_negative', true],
  ['reread', true], ['edit_save', true], ['cancel_edit', true], ['cancel_create', true],
  ['required_fields', true], ['invalid_number', true], ['invalid_date', true],
  ['maximum_length', true], ['concurrent_edit', true], ['database_constraints', false], ['browser_runtime_errors', true],
  ['database_sql_readback', false],
];
const runId = `FQ-${new Date().toISOString().replace(/[-:]/g,'').slice(0,15)}-${randomBytes(4).toString('hex')}`;
const result = {
  schema_version: 1, run_id: runId, status: 'RUNNING', started_at: new Date().toISOString(),
  test_scope: 'authenticated_browser_native_table_form_synthetic_only',
  credentials_recorded: false, browser_storage_saved: false, human_acceptance_recorded: false,
  browser_persistence_readback: 'APEX form reread; independent SQL verification is separate',
  retained_records: [], write_attempts: [], network_denials: [], browser_errors: [], browser_dialogs: [],
  tests: cases.map(([name,required]) => ({name,required,status:'NOT_RUN',reason:'Not reached'})),
};
let outputDir; let browser; let secrets = []; let activePages = []; let stopped = false;

function persist(durable=false) {
  if (!outputDir) return;
  const pending = path.join(outputDir,'qa-result.json.tmp');
  writeFileSync(pending, JSON.stringify(result,null,2)+'\n', {mode:0o600});
  if(durable){const fd=openSync(pending,'r');try{fsyncSync(fd);}finally{closeSync(fd);}}
  renameSync(pending,path.join(outputDir,'qa-result.json'));
  if(durable){const fd=openSync(outputDir,'r');try{fsyncSync(fd);}finally{closeSync(fd);}}
}
const sleep = ms => new Promise(resolve => setTimeout(resolve,ms));
async function until(fn, message, timeout=20000) {
  const deadline = Date.now()+timeout;
  while (Date.now()<deadline) { if (await fn()) return; await sleep(250); }
  throw new Error(message);
}
async function screenshot(page,name) {
  try {
    if (!page || page.isClosed() || new URL(page.url()).origin !== SCOPE.origin) return null;
    if (await page.locator('input[type="password"]').count()) return null;
    const relative = `${name}.png`;
    await page.screenshot({path:path.join(outputDir,relative),fullPage:true,
      mask:secrets.map(value => page.getByText(value,{exact:true}))});
    return relative;
  } catch { return null; }
}
async function test(name,fn,{depends=[],page=()=>activePages[0]}={}) {
  const entry = result.tests.find(item=>item.name===name);
  if(entry.status==='NOT_APPLICABLE')return true;
  if (stopped || depends.some(dep=>result.tests.find(item=>item.name===dep)?.status!=='PASSED')) {
    entry.reason='A prerequisite did not pass; no test action was attempted'; persist(); return false;
  }
  entry.started_at=new Date().toISOString();
  if(result.schema_version===2)result.current_test=name;
  try {
    const detail=await fn(); entry.status='PASSED'; delete entry.reason;
    if(result.schema_version===2)entry.field_results=entry.field_names.map(field_name=>({field_name,status:'PASSED'}));
    if (detail) entry.evidence=detail;
  } catch (error) {
    entry.status='FAILED'; entry.reason=safeMessage(error,secrets);
    if(result.schema_version===2)stopped=true;
    try {entry.page_diagnostic={path:new URL(page().url()).pathname,
      headings:(await page().getByRole('heading').allTextContents()).map(value=>safeMessage(value,secrets)),
      title:safeMessage(await page().title(),secrets)};} catch {}
  }
  entry.finished_at=new Date().toISOString();
  if(result.schema_version===2)delete result.current_test;
  const image=await screenshot(page(),name); if(image) entry.screenshot=image;
  persist(); return entry.status==='PASSED';
}

async function main() {
  check(!process.env.DEBUG && !process.env.PWDEBUG, 'Debug logging is prohibited for authenticated QA');
  check(typeof process.env.FOX_QA_OUTPUT_DIR==='string' && path.isAbsolute(process.env.FOX_QA_OUTPUT_DIR), 'Absolute output directory required');
  outputDir=path.join(process.env.FOX_QA_OUTPUT_DIR,runId);
  mkdirSync(outputDir,{recursive:true,mode:0o700}); persist();
  const receiptFile=readJson(process.env.FOX_QA_TARGET_RECEIPT);
  const profileFile=readJson(process.env.FOX_QA_PROFILE);
  const packagePath=process.env.FOX_QA_PACKAGE;
  const packageEvidence=receiptFile.value.clean_install===true?readPackageEvidence(packagePath):null;
  const packageHash=packageEvidence?.package_sha256??(packagePath ? sha256(readFileSync(packagePath)) : null);
  const nativeSpec=process.env.FOX_QA_NATIVE_SPEC?readJson(process.env.FOX_QA_NATIVE_SPEC,1048576,{nativeSpec:receiptFile.value.schema_version===2}):null;
  const importReceipt=process.env.FOX_QA_IMPORT_RECEIPT?readJson(process.env.FOX_QA_IMPORT_RECEIPT):null;
  const verificationProfile=process.env.FOX_QA_VERIFICATION_PROFILE?readJson(process.env.FOX_QA_VERIFICATION_PROFILE):null;
  const binding=validateTarget(receiptFile.value,profileFile.value,profileFile.sha256,packageHash,{nativeSpec,importReceipt,packageEvidence,verificationProfile});
  const {receipt,profile,targetUrl,packageBound}=binding;
  const v2=receipt.schema_version===2;
  check(!v2||process.env.FOX_QA_INSPECT_ONLY!=='1','Inspect-only v2 is not a write authorization; use the separate read-only capture tool');
  if(v2) {
    result.schema_version=2;result.test_plan=binding.plan;result.test_plan_sha256=sha256(canonicalQaPlan(binding.plan));
    result.verification_profile_sha256=verificationProfile.sha256;result.allocation_receipt_sha256=receipt.allocation_receipt_sha256;
    result.tests=binding.plan.cases.map(item=>({...item,required:item.applicable,status:item.applicable?'NOT_RUN':'NOT_APPLICABLE',field_results:[],
      reason:item.applicable?'Not reached':'No matching editable fields in the exact native spec'}));
    result.additional_checks=[{name:'database_constraints',required:false,status:'NOT_RUN',reason:'The native contract defines no CHECK constraints; none are invented.'},
      {name:'database_sql_readback',required:false,status:'NOT_RUN',reason:'Independent operator SQL proof is separate; this runner performs authenticated UI rereads.'}];
    result.dispatch_state='PREFLIGHT';
  }
  let secretFile;
  try { secretFile=readJson(process.env.FOX_QA_CREDENTIAL_FILE,16384); }
  catch { throw new Error('QA credential file is missing, unsafe or invalid JSON; its contents were not logged'); }
  const accounts=validateCredentials(secretFile.value);
  check(!binding.cleanInstallBound||accounts.twoIndependentAccounts,'Clean-package QA requires two independent runtime accounts');
  secrets=[accounts.primary.username,accounts.primary.password,accounts.secondary?.username,accounts.secondary?.password].filter(Boolean);
  result.two_independent_accounts=accounts.twoIndependentAccounts;
  result.target={...receipt}; result.target_receipt_sha256=receiptFile.sha256;
  result.binding={profile_bytes_verified:true,package_bytes_verified:packageBound,
    native_spec_bytes_verified:binding.nativeSpecBound,import_receipt_bytes_verified:binding.importReceiptBound,
    package_manifest_verified:packageEvidence!==null,clean_install_verified:binding.cleanInstallBound,scope:binding.bindingScope,
    package_import_provenance:'Actual mounted operator import receipt and byte bindings; browser also checks rendered application ID. Operator provenance is established separately from these hashes.',
    package_sha256:packageHash};
  if(v2)Object.assign(result.binding,{verification_profile_bytes_verified:true,verification_profile_sha256:verificationProfile.sha256,allocation_receipt_sha256:receipt.allocation_receipt_sha256});
  result.synthetic_table=profile.table_name;
  const {chromium}=await import('playwright');
  async function beginV2Attempt() {
    assertV2WriteAllowed();
    check(typeof process.env.FOX_QA_DISPATCH_DIR==='string'&&path.isAbsolute(process.env.FOX_QA_DISPATCH_DIR),'Private durable v2 dispatch directory required');
    check(typeof process.env.FOX_QA_IMAGE_ID==='string'&&/^(?:sha256:)?[a-f0-9]{64}(?![^])/.test(process.env.FOX_QA_IMAGE_ID),'V2 requires the actual immutable QA image ID');
    // This create-only intent follows all file/credential/runtime prechecks. Once
    // written, even an uncertain attempt cannot be silently replayed on this allocation.
    const intent={schema_version:2,scope:'fox-native-qa-dispatch-v2',run_id:runId,job_id:receipt.job_id,
      allocation_receipt_sha256:receipt.allocation_receipt_sha256,verification_profile_sha256:verificationProfile.sha256,
      target_receipt_sha256:receiptFile.sha256,profile_sha256:profileFile.sha256,package_sha256:packageHash,
      image_id:process.env.FOX_QA_IMAGE_ID,
      test_plan_sha256:result.test_plan_sha256,started_at:new Date().toISOString(),state:'ATTEMPT_STARTED_NO_AUTOMATIC_REPLAY'};
    try{
      const fd=openSync(path.join(process.env.FOX_QA_DISPATCH_DIR,`${receipt.allocation_receipt_sha256}.json`),'wx',0o600);
      try{writeFileSync(fd,JSON.stringify(intent,null,2)+'\n');fsyncSync(fd);}finally{closeSync(fd);}
      const directory=openSync(process.env.FOX_QA_DISPATCH_DIR,'r');try{fsyncSync(directory);}finally{closeSync(directory);}
    }
    catch{throw new Error('V2 dispatch is unavailable or already attempted; no business write was attempted and no automatic replay is allowed');}
    result.dispatch_state='ATTEMPT_STARTED';persist();
  }
  browser=await chromium.launch({headless:true,chromiumSandbox:false});
  result.runtime={playwright:'1.64.0',chromium:browser.version(),chromium_sandbox:false,
    isolation:'Rootless on-demand container; no published ports; only trusted synthetic JSN APEX target'};
  if(v2)result.runtime.image_id=process.env.FOX_QA_IMAGE_ID;
  const sessions=[];
  function assertV2WriteAllowed() {
    assertNativeQaWriteAllowed({stopped,browserErrors:result.browser_errors,networkDenials:result.network_denials,
      unexpectedDialog:sessions.some(state=>state.unexpectedDialog)});
  }
  async function session() {
    const context=await browser.newContext({locale:'en-US',viewport:{width:1440,height:1000},
      ignoreHTTPSErrors:false,acceptDownloads:false,serviceWorkers:'block'});
    context.setDefaultTimeout(15000); context.setDefaultNavigationTimeout(45000);
    await context.route('**/*',async route=>{
      const request=route.request();
      if (allowedRequest(request.url(),request.method())) return route.continue();
      let origin='invalid'; try{origin=new URL(request.url()).origin;}catch{}
      if(!result.network_denials.includes(origin)) result.network_denials.push(origin);
      await route.abort('blockedbyclient');
    });
    await context.routeWebSocket('**/*',websocket=>websocket.close());
    const pendingRequests=new Set();
    const state={context,page:null,reportUrl:null,allowCancelDialog:false,unexpectedDialog:false,pendingRequests,lastNetworkChange:Date.now()};
    context.on('request',request=>{pendingRequests.add(request);state.lastNetworkChange=Date.now();});
    const finished=request=>{pendingRequests.delete(request);state.lastNetworkChange=Date.now();};
    context.on('requestfinished',finished);context.on('requestfailed',finished);
    const page=await context.newPage();state.page=page;
    page.on('pageerror',error=>{result.browser_errors.push(safeMessage(error,secrets));persist();});
    page.on('dialog',async dialog=>{
      result.browser_dialogs.push({type:dialog.type(),message:safeMessage(dialog.message(),secrets),cancel_scoped:state.allowCancelDialog});persist();
      if(state.allowCancelDialog && ['beforeunload','confirm'].includes(dialog.type())) await dialog.accept();
      else {state.unexpectedDialog=true; await dialog.dismiss();}
    });
    activePages.push(page); sessions.push(state); return state;
  }
  const a=await session();
  const markerField=profile.fields.find(field=>field.name===profile.marker_field);
  const editField=profile.fields.find(field=>field.name===(v2?binding.plan.edit_field:profile.edit_field));
  const rowMarker=runId;
  let expectedEdit=v2?null:formatCents(decimalCents(editField.valid_value)+100);
  async function assertApp(page) {
    check(new URL(page.url()).origin===SCOPE.origin,'Unexpected browser origin');
    check(await page.locator('input[name="p_flow_id"]').inputValue()===String(receipt.application_id), 'Rendered APEX application ID differs from target receipt');
  }
  async function ready(page) {
    await page.waitForLoadState('load');
    const state=sessions.find(item=>item.page===page);
    check(state,'Missing browser context readiness state');
    await until(()=>state.pendingRequests.size===0&&Date.now()-state.lastNetworkChange>=750,'Browser requests did not settle',30000);
  }
  async function ajax(state,action) {
    // Capture the exact UI-triggered XHR/fetch response, not a document-lifecycle
    // networkidle event that may already have fired before this later Ajax request.
    const responsePromise=state.page.waitForResponse(response=>{
      const request=response.request();
      return new URL(response.url()).origin===SCOPE.origin&&request.method()==='POST'&&['xhr','fetch'].includes(request.resourceType());
    });
    const [response]=await Promise.all([responsePromise,action()]);
    check(response.ok(),'Native report Ajax returned a non-success HTTP status');
    await response.finished(); await ready(state.page);
  }
  async function login(state,{secondary=false}={}) {
    const account=secondary&&accounts.secondary?accounts.secondary:accounts.primary;
    await state.page.goto(targetUrl,{waitUntil:'domcontentloaded'});
    const usernameField=state.page.getByLabel(/^Username$/i);
    await usernameField.fill(account.username);
    await state.page.getByLabel(/^Password$/i).fill(account.password);
    await state.page.getByRole('button',{name:/^Sign In$/i}).click();
    await state.page.getByRole('button',{name:'Create Record',exact:true}).waitFor({state:'visible'});
    await ready(state.page);
    await assertApp(state.page); state.reportUrl=state.page.url();
  }
  async function report(state) {
    check(state.reportUrl,'Report URL was not established by a successful login');
    // Follow only the actual report URL obtained after login. Never append clear-cache
    // arguments to an APEX URL: checksum protection may correctly reject changed URLs.
    await state.page.goto(state.reportUrl,{waitUntil:'domcontentloaded'});
    await ready(state.page);
    await state.page.getByRole('button',{name:'Create Record',exact:true}).waitFor({state:'visible'});
    await assertApp(state.page);
  }
  async function search(state,text,{absent=false}={}) {
    await report(state);
    await state.page.getByRole('button',{name:'Actions',exact:true}).click();
    await state.page.getByRole('menuitem',{name:'Report',exact:true}).hover();
    await state.page.getByRole('menuitem',{name:'Reset',exact:true}).click();
    await ajax(state,()=>state.page.getByRole('button',{name:'Apply',exact:true}).click());
    await state.page.getByRole('button',{name:'Apply',exact:true}).waitFor({state:'hidden'});
    const input=state.page.getByRole('searchbox',{name:'Row Search',exact:true});
    await input.fill(text); await ajax(state,()=>input.press('Enter'));
    if (absent) {
      await ready(state.page);
      await state.page.locator('.a-IRR-noDataMsg').waitFor({state:'visible'});
      check(await state.page.getByRole('cell',{name:text,exact:true}).count()===0,'Negative search returned the test marker');
      check(await state.page.getByRole('link',{name:'Edit',exact:true}).count()===0,'Negative search still exposes editable result rows');
    } else await state.page.getByRole('cell',{name:text,exact:true}).waitFor({state:'visible'});
  }
  async function openRow(state) {
    await search(state,rowMarker);
    const row=state.page.getByRole('row').filter({has:state.page.getByRole('cell',{name:rowMarker,exact:true})});
    check(await row.count()===1,'Expected exactly one retained synthetic test row');
    await row.getByRole('link',{name:'Edit',exact:true}).click();
    await state.page.getByRole('button',{name:'Save Changes',exact:true}).waitFor({state:'visible'}); await ready(state.page); await assertApp(state.page);
  }
  // Exact accessible labels and Playwright strictness: never silently address another field.
  function field(page,column) { return v2?page.locator(`input[name="P2_${column.name}"]`):page.getByLabel(column.label,{exact:true}).and(page.locator('input')); }
  async function fillValid(page,marker=rowMarker) {
    for(const column of profile.fields) await field(page,column).fill(column===markerField?marker:column.valid_value);
  }
  async function createPage(state) {
    await report(state); await state.page.getByRole('button',{name:'Create Record',exact:true}).click();
    await state.page.getByRole('button',{name:'Create',exact:true}).waitFor({state:'visible'}); await ready(state.page); await assertApp(state.page);
  }
  async function submit(state,button,expectedValues={}) {
    if(v2)assertV2WriteAllowed();
    await assertApp(state.page);
    check(!state.unexpectedDialog,'An unexpected browser dialog occurred; refusing a write');
    const values={}; for(const column of profile.fields) values[column.name]=await field(state.page,column).inputValue();
    for(const [name,value] of Object.entries(expectedValues)) check(values[name]===value,`Test field ${name} changed before submission; no write attempted`);
    const identity=v2?{primary_key:{name:profile.primary_key,value:button==='Create'?null:canonicalPrimaryKey(await state.page.locator(`input[name="P2_${profile.primary_key}"]`).inputValue())}}
      :{marker:await field(state.page,markerField).inputValue()};
    if(v2&&button!=='Create')check(identity.primary_key.value===result.retained_records[0]?.primary_key.value,'Refusing a write to a different retained primary key');
    result.write_attempts.push({sequence:result.write_attempts.length+1,button,...identity,submitted_at:new Date().toISOString(),
      intended_values:values,
      outcome:'Inspect per-test result and fresh readback; failed submissions are never retried automatically'});
    persist(v2);
    if(v2)assertV2WriteAllowed();
    await state.page.getByRole('button',{name:button,exact:true}).click();
  }
  async function saved(state) {
    await state.page.getByRole('button',{name:'Create Record',exact:true}).waitFor({state:'visible'});
    await ready(state.page); await state.page.getByText('Record saved.',{exact:true}).waitFor({state:'visible'}); await assertApp(state.page);
  }
  async function cancel(state) {
    state.allowCancelDialog=true;
    try {
      await state.page.getByRole('button',{name:'Cancel',exact:true}).click();
      await state.page.getByRole('button',{name:'Create Record',exact:true}).waitFor({state:'visible'});
      await ready(state.page);
    } finally {state.allowCancelDialog=false;}
  }
  const errorSelector='.t-Alert--danger, .t-Alert--warning, #APEX_ERROR_MESSAGE, .t-Form-error, .a-Form-error';
  async function hasError(page) {
    const errors=page.locator(`${errorSelector}, [aria-invalid="true"]`);
    for(let i=0;i<await errors.count();i++) if(await errors.nth(i).isVisible()) return true;
    return await page.getByRole('heading',{name:'Error Message',exact:true}).count()>0;
  }
  async function visibleErrorText(page) {
    const parts=[];const errors=page.locator(errorSelector);
    for(let i=0;i<await errors.count();i++) if(await errors.nth(i).isVisible()) parts.push(await errors.nth(i).innerText());
    return parts.join(' ');
  }
  async function rejected(state) {
    await until(()=>hasError(state.page),'No visible native APEX validation/error feedback appeared');
    check(await state.page.getByRole('button',{name:'Cancel',exact:true}).isVisible(),'Rejected input left the form unexpectedly');
    check(!await state.page.getByText('Record saved.',{exact:true}).isVisible().catch(()=>false),'Invalid submission reported a save');
  }
  async function runV2Cases() {
    const spec=binding.nativeSpec,key=profile.primary_key;
    let retainedPk=null,expectedValues=deriveNativeQaValues(spec,'create');
    result.pk_set_checks=[];
    const valid=(phase)=>deriveNativeQaValues(spec,phase);
    async function assertFields(page) {
      for(const column of profile.fields) {
        const input=field(page,column);check(await input.count()===1,`Native item ${column.name} is not unique`);
        // DATE uses an inner *_input control and aria-labelledby, not a native
        // label association. Intersect its exact item name with the accessible label.
        check(await page.getByLabel(column.label,{exact:true}).and(input).count()===1,`Native item label differs for ${column.name}`);
      }
    }
    async function fillValues(page,values) {
      await assertFields(page);
      for(const column of profile.fields)await fillNativeQaValue(field(page,column),column,values[column.name]);
    }
    async function assertValues(page,values) {
      await assertFields(page);
      for(const column of profile.fields) {
        const actual=await field(page,column).inputValue(),expected=values[column.name];
        check(column.data_type==='NUMBER'?decimalCents(actual)===decimalCents(expected):actual===expected,`Fresh query differs for ${column.name}`);
      }
    }
    async function resetReport(state) {
      await report(state);await state.page.getByRole('button',{name:'Actions',exact:true}).click();
      await state.page.getByRole('menuitem',{name:'Report',exact:true}).hover();await state.page.getByRole('menuitem',{name:'Reset',exact:true}).click();
      await ajax(state,()=>state.page.getByRole('button',{name:'Apply',exact:true}).click());
      await state.page.getByRole('button',{name:'Apply',exact:true}).waitFor({state:'hidden'});
    }
    async function reportKeys(state) {
      if(await state.page.locator('.a-IRR-noDataMsg').isVisible().catch(()=>false))return [];
      return readNativeReportPrimaryKeys(state.page,spec);
    }
    async function assertRetainedSet(state,fieldName=null,testName=result.current_test??'preflight') {
      await resetReport(state);const actual=await reportKeys(state);
      const expected=retainedPk?[retainedPk]:[],passed=samePrimaryKeySet(actual,expected);
      result.pk_set_checks.push({test_name:testName,...(fieldName?{field_name:fieldName}:{}),expected_primary_keys:expected,observed_primary_keys:actual,passed});persist();
      check(passed,'Unexpected insert/deletion or different primary key set');return actual;
    }
    async function openRetained(state) {
      await assertRetainedSet(state);check(retainedPk,'No confirmed retained primary key');
      const link=state.page.getByRole('link',{name:'Edit',exact:true});check(await link.count()===1,'Expected one observed Edit link');
      await link.click();await state.page.getByRole('button',{name:'Save Changes',exact:true}).waitFor({state:'visible'});await ready(state.page);await assertApp(state.page);
      check(canonicalPrimaryKey(await state.page.locator(`input[name="P2_${key}"]`).inputValue())===retainedPk,'Edit link opened a different primary key');
    }
    async function searchPk(state,pk,{absent=false}={}) {
      await resetReport(state);await state.page.getByRole('button',{name:'Actions',exact:true}).click();
      await state.page.getByRole('menuitem',{name:'Filter',exact:true}).click();
      const dialog=state.page.getByRole('dialog');await dialog.waitFor({state:'visible'});
      const type=dialog.getByRole('radio',{name:'Column',exact:true});if(await type.count())await type.check();
      const column=await nativeFilterControl(dialog,'Column');
      check(await column.locator('option').evaluateAll((options,name)=>options.some(option=>option.value===name),key),'PK column filter is not available');
      await column.selectOption(key);
      const operator=await nativeFilterControl(dialog,'Operator');await operator.selectOption({label:'='});
      const expression=await nativeFilterControl(dialog,'Expression');await expression.fill(pk);
      await ajax(state,()=>dialog.getByRole('button',{name:'Apply',exact:true}).click());await dialog.waitFor({state:'hidden'});
      const actual=await reportKeys(state);check(samePrimaryKeySet(actual,absent?[]:[retainedPk]),'Native PK filter returned unexpected rows');
      return{column:key,operator:'=',expression:pk,observed_primary_keys:actual};
    }
    // Login and the actual empty report are read-only preflight. The durable
    // dispatch is consumed immediately before the first possible business write.
    if(result.tests.find(item=>item.name==='login').status==='PASSED') {
      await assertRetainedSet(a);result.initial_primary_keys=[];persist();
    }
    await test('create',async()=>{
      await createPage(a);await fillValues(a.page,expectedValues);
      await beginV2Attempt();
      result.retained_records.push({table:profile.table_name,primary_key:{name:key,value:null},write_state:'CREATE_SUBMITTED_OUTCOME_NOT_YET_CONFIRMED'});persist();
      await submit(a,'Create',expectedValues);await saved(a);await resetReport(a);
      const keys=await reportKeys(a);check(keys.length===1,'Create did not yield exactly one new report row');retainedPk=keys[0];
      result.retained_records[0].primary_key.value=retainedPk;result.retained_records[0].write_state='REPORTED_PRIMARY_KEY_PENDING_FORM_CONFIRMATION';persist();
      await openRetained(a);await assertValues(a.page,expectedValues);
      result.retained_records[0].write_state='CREATED_AND_REREAD';await cancel(a);return{primary_key:{name:key,value:retainedPk},all_declared_fields_matched:true,no_delete:true};
    },{depends:['login']});
    await test('search_positive',()=>searchPk(a,retainedPk),{depends:['create']});
    await test('search_negative',()=>searchPk(a,'0',{absent:true}),{depends:['create']});
    await test('reread',async()=>{await openRetained(a);await assertValues(a.page,expectedValues);await cancel(a);return{all_declared_fields_matched:true};},{depends:['create']});
    await test('edit_save',async()=>{
      const values=valid('edit');await openRetained(a);await fillValues(a.page,values);await submit(a,'Save Changes',values);await saved(a);
      await openRetained(a);await assertValues(a.page,values);expectedValues=values;await cancel(a);return{all_declared_fields_matched:true,expected_values:values};
    },{depends:['create']});
    await test('cancel_edit',async()=>{
      await openRetained(a);await fillValues(a.page,valid('cancel_edit'));await cancel(a);await openRetained(a);await assertValues(a.page,expectedValues);await cancel(a);
      return{all_declared_fields_unchanged:true};
    },{depends:['edit_save']});
    await test('cancel_create',async()=>{
      await createPage(a);await fillValues(a.page,valid('cancel_create'));await cancel(a);return{primary_key_set_after:await assertRetainedSet(a)};
    },{depends:['create']});
    await test('required_fields',async()=>{
      const checked=[];
      for(const name of binding.plan.cases.find(item=>item.name==='required_fields').field_names) {
        const column=profile.fields.find(item=>item.name===name);await createPage(a);await fillValues(a.page,valid('create'));
        const input=field(a.page,column);await input.click();await input.press('ControlOrMeta+A');await input.press('Backspace');await input.press('Tab');
        check(await input.inputValue()==='',`Required ${name} did not remain empty; no write attempted`);
        await submit(a,'Create',{...valid('create'),[name]:''});await rejected(a);await cancel(a);await assertRetainedSet(a,name);checked.push(name);
      }return{fields:checked,primary_key_set_unchanged:true};
    },{depends:['create']});
    for(const [name,invalid] of [['invalid_number','NOT_A_NUMBER'],['invalid_date','NOT_A_DATE']])await test(name,async()=>{
      const checked=[];
      for(const fieldName of binding.plan.cases.find(item=>item.name===name).field_names) {
        const column=profile.fields.find(item=>item.name===fieldName);await createPage(a);await fillValues(a.page,valid('create'));
        const input=field(a.page,column);let mode='apex_validation';
        try{await input.fill(invalid);}catch{await input.fill('');await input.pressSequentially(invalid);check(await input.inputValue()==='','Unexpected invalid input transformation; inspect instead of claiming rejection');mode='browser_input_type_rejected_text';}
        if(mode==='apex_validation'){check(await input.inputValue()===invalid,'Input was transformed; validation needs inspection');await submit(a,'Create',{...valid('create'),[fieldName]:invalid});await rejected(a);}
        await cancel(a);await assertRetainedSet(a,fieldName);checked.push({field:fieldName,rejection_mode:mode,server_validation_proven:false});
      }return{fields:checked,primary_key_set_unchanged:true};
    },{depends:['create']});
    await test('maximum_length',async()=>{
      const checked=[];
      for(const fieldName of binding.plan.cases.find(item=>item.name==='maximum_length').field_names) {
        const column=profile.fields.find(item=>item.name===fieldName);await createPage(a);await fillValues(a.page,valid('create'));
        const input=field(a.page,column),probe=await probeNativeQaMaximumLength(input,column);
        if(probe.evidence.mode==='apex_validation'){await submit(a,'Create',{...valid('create'),[fieldName]:probe.actual});await rejected(a);}
        checked.push({field:fieldName,...probe.evidence});
        await cancel(a);await assertRetainedSet(a,fieldName);
      }return{fields:checked,primary_key_set_unchanged:true};
    },{depends:['create']});
    await test('concurrent_edit',async()=>{
      const b=await session();await login(b,{secondary:true});await openRetained(a);await openRetained(b);await assertValues(a.page,expectedValues);await assertValues(b.page,expectedValues);
      const winning={...expectedValues,[editField.name]:valid('winner')[editField.name]},stale={...expectedValues,[editField.name]:valid('stale')[editField.name]};
      await fillNativeQaValue(field(a.page,editField),editField,winning[editField.name]);await submit(a,'Save Changes',winning);await saved(a);expectedValues=winning;
      await fillNativeQaValue(field(b.page,editField),editField,stale[editField.name]);await submit(b,'Save Changes',stale);
      await until(async()=>await b.page.getByRole('button',{name:'Create Record',exact:true}).isVisible().catch(()=>false)||await hasError(b.page),'Stale writer returned no identified outcome');
      if(await b.page.getByRole('button',{name:'Create Record',exact:true}).isVisible().catch(()=>false)) {
        await openRetained(a);const actual={};for(const column of profile.fields)actual[column.name]=await field(a.page,column).inputValue();
        result.last_confirmed_record={primary_key:{name:key,value:retainedPk},observed_values:actual};persist();throw new Error('Stale save was accepted without a conflict; retained observed values recorded');
      }
      await rejected(b);check(/(?:changed|modified).*(?:another|since|user)|lost.update|checksum/i.test(await visibleErrorText(b.page)),'Rejection does not identify stale/lost update');
      await cancel(b);await openRetained(a);await assertValues(a.page,winning);await cancel(a);await b.context.close();
      return{independent_browser_contexts:2,two_independent_accounts:true,first_writer_retained:true,stale_writer_rejected:true,field:editField.name,final_value:winning[editField.name]};
    },{depends:['edit_save'],page:()=>activePages.at(-1)});
    if(!stopped&&retainedPk) {
      const finalKeys=await assertRetainedSet(a,null,'final');
      result.row_tracking={mode:'clean_empty_then_observed_pk',initial_primary_keys:result.initial_primary_keys,
        retained_primary_key:{name:key,value:retainedPk},final_observed_primary_keys:finalKeys,single_row_preserved:true};
    }
    const errors=result.tests.find(item=>item.name==='browser_runtime_errors');errors.status=result.browser_errors.length?'FAILED':'PASSED';
    errors.field_results=[];errors.evidence={unhandled_error_count:result.browser_errors.length};delete errors.reason;
    result.final_expected_record={primary_key:{name:key,value:retainedPk},expected_values:expectedValues};
    result.status=outcomeV2(result.tests,binding.plan);
    if(sessions.some(state=>state.unexpectedDialog)||result.network_denials.length){result.status='FAILED';result.failure='Unexpected dialog or network denial requires operator inspection';}
    result.dispatch_state=result.dispatch_state==='PREFLIGHT'?'PREFLIGHT_BLOCKED':result.status==='PASSED'?'ATTEMPT_COMPLETED':'ATTEMPT_INCOMPLETE';
    result.finished_at=new Date().toISOString();persist();
  }
  const prerequisites=['login'];
  await test('login',async()=>{await login(a);return {authenticated:true,rendered_application_id:receipt.application_id};});
  if(v2) {
    await runV2Cases();return;
  }
  if(process.env.FOX_QA_INSPECT_ONLY==='1') {
    const controls=async()=>({
      path:new URL(a.page.url()).pathname,query_keys:[...new URL(a.page.url()).searchParams.keys()],
      buttons:(await a.page.getByRole('button').allTextContents()).map(value=>safeMessage(value,secrets)),
      inputs:await a.page.locator('input').evaluateAll(elements=>elements.map(input=>({id:input.id,name:input.name,type:input.type,
        placeholder:input.getAttribute('placeholder'),ariaLabel:input.getAttribute('aria-label'),ariaLabelledby:input.getAttribute('aria-labelledby'),
        labels:[...input.labels||[]].map(label=>label.textContent),readonly:input.readOnly}))),
      menuitems:(await a.page.getByRole('menuitem').allTextContents()).map(value=>safeMessage(value,secrets)),
    });
    result.diagnostic={report:await controls()};
    await a.page.getByRole('button',{name:'Create Record',exact:true}).click();
    await a.page.getByRole('button',{name:'Cancel',exact:true}).waitFor({state:'visible'});
    await a.page.waitForLoadState('load'); await a.page.waitForLoadState('networkidle');
    result.diagnostic.form=await controls();
    await cancel(a); await a.page.getByRole('button',{name:'Actions',exact:true}).click();
    await a.page.getByRole('menuitem',{name:'Report',exact:true}).hover();
    await a.page.getByRole('menuitem',{name:'Reset',exact:true}).waitFor({state:'visible'});
    result.diagnostic.actions=await controls();
    await a.page.getByRole('menuitem',{name:'Reset',exact:true}).click();
    await a.page.getByRole('dialog').waitFor({state:'visible'});
    result.diagnostic.reset_dialog=await controls();
    result.status='INCOMPLETE';result.finished_at=new Date().toISOString();result.diagnostic_only=true;persist();return;
  }
  await test('create',async()=>{
    await createPage(a); await fillValid(a.page);
    result.retained_records.push({marker:rowMarker,table:profile.table_name,write_state:'CREATE_SUBMITTED_OUTCOME_NOT_YET_CONFIRMED'}); persist();
    await submit(a,'Create'); await saved(a); await openRow(a);
    check(await field(a.page,markerField).inputValue()===rowMarker,'Created marker could not be reread');
    result.retained_records[0].write_state='CREATED_AND_REREAD'; await cancel(a);
    return {marker:rowMarker,readback:'fresh authenticated APEX form query',no_delete:true};
  },{depends:prerequisites});
  await test('search_positive',async()=>{await search(a,rowMarker);return{matched_marker:rowMarker};},{depends:['create']});
  await test('search_negative',async()=>{await search(a,`${runId}-NONE`,{absent:true});return{no_results:true};},{depends:prerequisites});
  await test('reread',async()=>{
    await openRow(a);
    for(const column of profile.fields) {
      const actual=await field(a.page,column).inputValue(); const expected=column===markerField?rowMarker:column.valid_value;
      check(column.data_type==='NUMBER'?decimalCents(actual)===decimalCents(expected):actual===expected,`Fresh query value differs for ${column.name}`);
    }
    await cancel(a); return{all_declared_fields_matched:true};
  },{depends:['create']});
  await test('edit_save',async()=>{
    await openRow(a); await field(a.page,editField).fill(expectedEdit); await submit(a,'Save Changes'); await saved(a);
    await openRow(a); check(decimalCents(await field(a.page,editField).inputValue())===decimalCents(expectedEdit),'Saved update did not survive a fresh form query');
    await cancel(a); return{field:editField.name,value:expectedEdit,reread:true};
  },{depends:['create']});
  await test('cancel_edit',async()=>{
    await openRow(a); await field(a.page,editField).fill(formatCents(decimalCents(expectedEdit)+10000)); await cancel(a);
    await openRow(a); check(decimalCents(await field(a.page,editField).inputValue())===decimalCents(expectedEdit),'Cancelled edit persisted unexpectedly');
    await cancel(a); return{unchanged_after_reread:true};
  },{depends:['edit_save']});
  await test('cancel_create',async()=>{
    const marker=`${runId}-CANCEL`; await createPage(a); await fillValid(a.page,marker); await cancel(a); await search(a,marker,{absent:true});
    return{cancelled_marker_absent:true};
  },{depends:prerequisites});
  await test('required_fields',async()=>{
    const fields=profile.fields.filter(item=>item.required); check(fields.length>0,'No required editable field configured');
    const verified=[];
    for(const column of fields) {
      await createPage(a); await fillValid(a.page,`${runId}-REQ`);
      const requiredInput=field(a.page,column);
      await requiredInput.click(); await requiredInput.press('ControlOrMeta+A'); await requiredInput.press('Backspace'); await requiredInput.press('Tab');
      check(await requiredInput.inputValue()==='',`Required test field ${column.name} did not remain empty; no write attempted`);
      await submit(a,'Create',{[column.name]:''}); await rejected(a); await cancel(a); verified.push(column.name);
    }
    await search(a,`${runId}-REQ`,{absent:true}); return{fields:verified,invalid_marker_absent:true};
  },{depends:prerequisites});
  for(const [name,type,invalid] of [['invalid_number','NUMBER','NOT_A_NUMBER'],['invalid_date','DATE','NOT_A_DATE']]) {
    const column=profile.fields.find(item=>item.data_type===type);
    if(!column){const item=result.tests.find(item=>item.name===name);item.reason=`No ${type} field in this profile`;persist();continue;}
    await test(name,async()=>{
      const marker=`${runId}-${type}`; await createPage(a); await fillValid(a.page,marker);
      const input=field(a.page,column); let mode='server_or_apex_validation';
      try {await input.fill(invalid);} catch {
        await input.fill(''); await input.pressSequentially(invalid);
        check((await input.inputValue())!==invalid,'Invalid input was accepted unexpectedly after fill failure'); mode='browser_input_type_rejected_text';
      }
      if(mode==='server_or_apex_validation') {check(await input.inputValue()===invalid,'Test input was transformed; validation semantics need inspection');await submit(a,'Create');await rejected(a);}
      await cancel(a); await search(a,marker,{absent:true}); return{field:column.name,rejection_mode:mode,invalid_marker_absent:true,
        apex_or_server_rejection:mode==='server_or_apex_validation',server_validation_proven:false,
        validation_layer_qualification:'UI feedback and non-persistence verified; this test does not separately identify client APEX validation versus server validation'};
    },{depends:prerequisites});
  }
  await test('maximum_length',async()=>{
    const verified=[];
    for(const column of profile.fields.filter(item=>item.data_type==='VARCHAR2')) {
      await createPage(a); await fillValid(a.page,`${runId}-MAX`); const input=field(a.page,column);
      await input.fill('X'.repeat(column.max_length+1)); const actual=await input.inputValue();
      if(actual.length<=column.max_length) verified.push({field:column.name,mode:'browser_maxlength',limit:column.max_length,server_validation_proven:false});
      else {await submit(a,'Create');await rejected(a);verified.push({field:column.name,mode:'apex_validation',limit:column.max_length});}
      await cancel(a);
    }
    check(verified.length>0,'No VARCHAR2 limits were tested'); return{fields:verified};
  },{depends:prerequisites});
  await test('concurrent_edit',async()=>{
    const b=await session(); await login(b,{secondary:true}); await openRow(a); await openRow(b);
    const winning=formatCents(decimalCents(expectedEdit)+1000); const stale=formatCents(decimalCents(expectedEdit)+2000);
    const entry=result.tests.find(item=>item.name==='concurrent_edit');
    entry.evidence={independent_browser_contexts:2,two_independent_accounts:accounts.twoIndependentAccounts,initial_a:await field(a.page,editField).inputValue(),
      initial_b:await field(b.page,editField).inputValue(),first_writer_value:winning,stale_writer_value:stale};persist();
    check(decimalCents(entry.evidence.initial_a)===decimalCents(entry.evidence.initial_b),'Independent sessions did not load the same initial version');
    await field(a.page,editField).fill(winning); await submit(a,'Save Changes'); await saved(a);
    expectedEdit=winning;
    await field(b.page,editField).fill(stale); await submit(b,'Save Changes');
    await until(async()=>await b.page.getByRole('button',{name:'Create Record',exact:true}).isVisible().catch(()=>false)
      || await hasError(b.page),'Stale writer returned neither a report nor native error feedback');
    if(await b.page.getByRole('button',{name:'Create Record',exact:true}).isVisible().catch(()=>false)) {
      await openRow(a); const actual=await field(a.page,editField).inputValue();
      entry.evidence.stale_writer_returned_to_report=true;entry.evidence.fresh_reread_after_stale_save=actual;
      result.last_confirmed_record={marker:rowMarker,field:editField.name,value:actual};persist();
      throw new Error(decimalCents(actual)===decimalCents(stale)?'LOST UPDATE: stale independent session overwrote the first writer':'Stale save was accepted without an identified conflict; inspect fresh readback');
    }
    await rejected(b);
    const error=await visibleErrorText(b.page);
    check(/(?:changed|modified).*(?:another|since|user)|lost.update|checksum/i.test(error),'Submission was rejected but evidence does not identify a stale/lost update');
    await cancel(b); await openRow(a); check(decimalCents(await field(a.page,editField).inputValue())===decimalCents(winning),'Stale update overwrote the first writer');
    expectedEdit=winning; await cancel(a); await b.context.close();
    return{independent_browser_contexts:2,two_independent_accounts:accounts.twoIndependentAccounts,first_writer_retained:true,stale_writer_rejected:true,field:editField.name,final_value:winning};
  },{depends:['edit_save'],page:()=>activePages.at(-1)});
  if(profile.database_constraints.length) {
    result.tests.find(item=>item.name==='database_constraints').required=true;
    await test('database_constraints',async()=>{
      const checked=[];
      for(const item of profile.database_constraints) {
        const column=profile.fields.find(field=>field.name===item.field);
        await createPage(a); await fillValid(a.page,`${runId}-CHK`); await field(a.page,column).fill(item.invalid_value); await submit(a,'Create'); await rejected(a);
        const messages=await visibleErrorText(a.page);
        check(messages.toLowerCase().includes(item.expected_error.toLowerCase()),`Expected constraint error was not shown for ${item.field}`);
        await cancel(a); checked.push(item.field);
      }
      await search(a,`${runId}-CHK`,{absent:true}); return{fields:checked,scope:'Explicit fixture database constraints only; not inferred from native contract'};
    },{depends:prerequisites});
  } else result.tests.find(item=>item.name==='database_constraints').reason='No authoritative database constraint cases supplied; not inferred';
  result.tests.find(item=>item.name==='database_sql_readback').reason='This runner uses browser APEX rereads. Parent/operator must append independent SQL proof separately; no arbitrary SQL adapter is executed.';
  const browserErrorCase=result.tests.find(item=>item.name==='browser_runtime_errors');
  browserErrorCase.status=result.browser_errors.length?'FAILED':'PASSED';
  browserErrorCase.evidence={unhandled_error_count:result.browser_errors.length};
  if(result.browser_errors.length) browserErrorCase.reason='Unhandled browser errors occurred; inspect browser_errors before acceptance';
  else delete browserErrorCase.reason;
  result.final_expected_record={marker:rowMarker,edit_field:editField.name,value:expectedEdit};
  result.status=outcome(result.tests);
  if(sessions.some(state=>state.unexpectedDialog)){result.status='FAILED';result.failure='An unexpected browser confirmation was dismissed; operator inspection required';}
  result.finished_at=new Date().toISOString(); persist();
}

process.on('SIGTERM',async()=>{
  stopped=true; result.status='INCOMPLETE'; result.failure='QA runner terminated; inspect retained write intents before any rerun';
  if(result.schema_version===2)result.dispatch_state=result.dispatch_state==='PREFLIGHT'?'PREFLIGHT_BLOCKED':'ATTEMPT_INCOMPLETE';
  result.finished_at=new Date().toISOString(); persist(); await browser?.close().catch(()=>{}); process.exit(2);
});
try { await main(); }
catch(error) { result.status='FAILED'; result.failure=safeMessage(error,secrets); result.finished_at=new Date().toISOString();
  if(result.schema_version===2)result.dispatch_state=result.dispatch_state==='PREFLIGHT'?'PREFLIGHT_BLOCKED':'ATTEMPT_INCOMPLETE';
  result.failure_screenshot=await screenshot(activePages.at(-1),'fatal'); persist(); }
finally { await browser?.close().catch(()=>{}); }
// Never print stack traces, credentials, complete browser URLs or page bodies.
console.log(JSON.stringify({run_id:runId,status:result.status,result_file:outputDir?path.join(outputDir,'qa-result.json'):null}));
process.exitCode=result.status==='PASSED'?0:2;
