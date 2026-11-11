/** Actual new-profile Playwright entrypoint. No SQL, delete, source execution,
 * traces, HAR, videos, storage state, credentials, console or network bodies
 * are retained. Synthetic rows remain labelled and recorded for reconciliation.
 * Unknown UI/input shapes fail closed; submissions are never retried. */
import {readFileSync,writeFileSync,openSync,closeSync,fsyncSync,lstatSync} from 'node:fs';
import {createRequire} from 'node:module';
import {pathToFileURL} from 'node:url';
import path from 'node:path';
import {randomBytes} from 'node:crypto';
import {check,sha256,canonicalQaPlan,parseUniqueJson,nativeFilterControl,fillNativeQaValue} from './lib/contracts.mjs';

export const ORIGIN='https://asz8eqwfm8unca2-jsnf2apex.adb.us-ashburn-1.oraclecloudapps.com';
const REQUIRED_PROFILE='native-blueprint-prototype-required-v1';
const same=(a,b)=>canonicalQaPlan(a)===canonicalQaPlan(b);
const now=()=>new Date().toISOString();
export function assertUnexpired(packet,nowMs=Date.now()) {
  const values=[packet?.deadline_at_utc,packet?.request_deadline_at_utc];
  check(values.every(value=>typeof value==='string'&&value.length<=40
    &&/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?(?:Z|\+00:00)$/.test(value)),
    'Absolute runtime expiry required');
  const [deadline,requestDeadline]=values.map(value=>Date.parse(value));
  check(Number.isFinite(nowMs)&&Number.isFinite(deadline)&&Number.isFinite(requestDeadline)
    &&deadline<=requestDeadline&&nowMs<deadline&&nowMs<requestDeadline
    &&requestDeadline-nowMs<=540_000,'Runtime expiry reached; outcome unknown without replay');
}
export function validatePacket(packet,nowMs=Date.now()) {
  assertUnexpired(packet,nowMs);
  const b=packet?.binding;
  check(b?.schema_version===1&&b.scope==='fox-native-blueprint-runtime-v1'
    &&['native-blueprint-prototype-v1',REQUIRED_PROFILE].includes(b.profile_id)&&b.workspace==='FORMS2APEX_POC'
    &&Number.isSafeInteger(b.application_id)&&b.application_id>0
    &&/^F2A_[A-Z0-9_]{3,48}$/.test(b.application_alias),'Unbound runtime target');
  check(packet.url===`${ORIGIN}/ords/r/forms2apex_poc/${b.application_alias.toLowerCase()}/`
    &&packet.spec?.profile_id===b.profile_id&&packet.spec.project_id===b.project_id
    &&packet.spec.source_binding===b.source_binding&&Array.isArray(packet.spec.blocks)
    &&packet.spec.blocks.length>0&&packet.spec.blocks.length<=50,'Runtime specification differs');
  if(b.profile_id===REQUIRED_PROFILE){
    check(packet.spec.schema_version===2&&packet.spec.input_validation_policy==='forms-required-inputs-v1',
      'Required-input profile policy differs');
    for(const block of packet.spec.blocks){
      check(Array.isArray(block.fields)&&block.fields.every(field=>typeof field?.value_required==='boolean'
        &&(!field.value_required||(block.classification==='database'&&block.native_component==='form'
          &&field.in_edit_form===true&&field.widget!=='display'))),'Required-input item policy differs');
    }
  }
  check(packet.data_retention==='synthetic_test_rows_retained'
    &&packet.credential_authority?.scope==='fox-prototype-runtime-credentials-target-v1'
    &&packet.credential_authority.workspace===b.workspace&&packet.credential_authority.ords_origin===ORIGIN
    &&packet.credential_authority.db_name==='ASZ8EQWFM8UNCA2_JSNF2APEX','Original-workspace credential authority required');
  const pages=[];
  for(const block of packet.spec.blocks){
    const page=2*block.sequence-1,checks=block.classification==='database'
      ?['render','report_columns','search',...(block.native_component==='form'?['detail_navigation']:[])]
      :['render','native_items'];
    pages.push({page_id:page,source_block_id:block.source_block_id,checks});
    if(block.native_component==='form')pages.push({page_id:page+1,source_block_id:block.source_block_id,
      checks:['render','native_items','create','update','synthetic_records_accounted',
        ...(b.profile_id===REQUIRED_PROFILE?['additional_required_input_validation']:[])]});
  }
  check(same(packet.pages,pages),'Runtime page checks differ from the independent specification');
  check(/^sha256:[a-f0-9]{64}$/.test(packet.image_id)
    &&sha256(canonicalQaPlan(packet.runner_files))===packet.code_sha256,'Runner identity differs');
  return packet;
}

export function allowedRequest(request,packet,nowMs=Date.now()) {
  try {
    // Every network continuation, including login/AJAX/accept POSTs, crosses
    // this absolute fence even if an earlier DOM action is still awaiting UI.
    assertUnexpired(packet,nowMs);
    const url=new URL(request.url()),method=request.method();
    if(url.username||url.password)return false;
    if(url.origin==='https://static.oracle.com')return ['GET','HEAD'].includes(method)&&url.pathname.startsWith('/cdn/apex/');
    if(url.origin!==ORIGIN)return false;
    if(['GET','HEAD'].includes(method)){
      // APEX serves these application-bound scripts outside the friendly URL.
      // Keep account/password-change documents and other apps forbidden.
      if(['/ords/wwv_flow.js_messages','/ords/wwv_flow.js_dialogs'].includes(url.pathname)){
        const keys=[...url.searchParams.keys()];
        decodeURIComponent(url.search);
        return request.resourceType()==='script'&&url.search.length<=4096
          &&new Set(keys).size===keys.length
          &&keys.every(key=>['p_app_id','p_lang','p_version','p_nls_settings'].includes(key))
          &&url.searchParams.getAll('p_app_id').length===1
          &&url.searchParams.get('p_app_id')===String(packet.binding.application_id);
      }
      if(request.resourceType()!=='document'&&url.pathname.startsWith('/i/'))return true;
      return url.pathname.toLowerCase().startsWith(new URL(packet.url).pathname.toLowerCase())
        ||url.pathname==='/ords/f'&&url.searchParams.get('p')?.split(':')[0]===String(packet.binding.application_id);
    }
    if(method!=='POST'||!['/ords/wwv_flow.accept','/ords/wwv_flow.ajax','/ords/wwv_flow.show'].includes(url.pathname))return false;
    const raw=request.postData();if(typeof raw!=='string'||raw.length>2_000_000)return false;
    if(!/^application\/x-www-form-urlencoded(?:\s*;|$)/i.test(request.headers()['content-type']??''))return false;
    decodeURIComponent(raw);const body=new URLSearchParams(raw);
    return body.getAll('p_flow_id').length===1&&body.get('p_flow_id')===String(packet.binding.application_id)
      &&body.getAll('p_flow_step_id').length===1&&['9999',...packet.pages.map(row=>String(row.page_id))].includes(body.get('p_flow_step_id'))
      &&!url.searchParams.has('p_flow_id')&&!url.searchParams.has('p_flow_step_id');
  }catch{return false;}
}

function read(file,limit=20_000_000){
  const value=lstatSync(file);check(value.isFile()&&!value.isSymbolicLink()&&value.size<=limit,'Unsafe bounded input');
  return readFileSync(file);
}
function durable(file,value){
  const fd=openSync(file,'wx',0o600);
  try{writeFileSync(fd,canonicalQaPlan(value));fsyncSync(fd);}finally{closeSync(fd);}
}

export async function assertAdditionalRequiredInputRejected(page,itemId,submit,guard) {
  // The caller blocks and fails any POST during this probe. A matching field
  // error (or browser-native valueMissing) is required, not just staying put.
  const input=page.locator(`[name="${itemId}"]`);
  check(await input.inputValue()==='','Negative required-input probe must be empty');
  await submit();await page.waitForLoadState('networkidle');guard();
  check(await input.inputValue()==='','Required-input probe value unexpectedly changed');
  const errors=page.locator(`[id="${itemId}"][aria-invalid="true"],[id="${itemId}_error"]:visible`);
  check(await errors.count()>0||await input.evaluate(element=>element.validity?.valueMissing===true),
    'Additional required input was not rejected');
}

export async function sourceNavigationUrl(page,block,packet) {
  // Standard APEX tree navigation uses anchors with role=treeitem, and its
  // collapsed accessibility state can hide them from a default role query.
  // Read the exact source-labelled anchor's URL; never click hidden controls.
  const options={name:block.name,exact:true,includeHidden:true};
  const anchors=page.getByRole('link',options).or(page.getByRole('treeitem',options))
    .and(page.locator('a[href]'));
  const links=await anchors.evaluateAll(items=>items.map(item=>item.href));
  const candidates=[...new Set(links)].filter(href=>{try{const url=new URL(href);
    return allowedRequest({url:()=>href,method:()=> 'GET',resourceType:()=> 'document'},packet)
      &&(url.pathname.toLowerCase().replace(/\/$/,'').endsWith(`/block_${block.sequence}`)
        ||url.searchParams.get('p')?.split(':')[1]===String(2*block.sequence-1));}catch{return false;}});
  check(candidates.length===1,'Source-bound navigation link missing or ambiguous');
  return candidates[0];
}

export async function run(packet,accounts,chromium,{output='/results',dispatch='/dispatch'}={}) {
  validatePacket(packet);
  const report={...packet.binding,passed:false,authenticated:false,business_pages_tested:false,business_behavior_accepted:false,
    started_at_utc:now(),completed_at_utc:now(),data_retention:'synthetic_test_rows_retained',retained_rows:[],
    runner:{kind:'authenticated_browser',tool:'playwright',code_sha256:packet.code_sha256,image_id:packet.image_id},pages:[]};
  const progress=()=>writeFileSync(path.join(dispatch,'progress.json'),canonicalQaPlan(report),{mode:0o600});
  let browser,unsafe=false,sequence=0,invalidRequiredProbe=false;
  const guard=()=>{assertUnexpired(packet);check(!unsafe,'Unsafe browser state; no further write allowed');};
  const act=async action=>{guard();return action();};
  try {
    guard();
    browser=await chromium.launch({headless:true,chromiumSandbox:false});
    guard();
    const context=await browser.newContext({locale:'en-US',viewport:{width:1440,height:1000},
      ignoreHTTPSErrors:false,acceptDownloads:false,serviceWorkers:'block'});
    context.setDefaultTimeout(15000);context.setDefaultNavigationTimeout(45000);
    await context.route('**/*',async route=>{
      // No server write is allowed by a negative required-input probe. Any
      // unexpected POST fails closed and is never continued or retried.
      if(invalidRequiredProbe&&route.request().method()==='POST'){
        unsafe=true;await route.abort('blockedbyclient');return;
      }
      if(allowedRequest(route.request(),packet))return route.continue();
      unsafe=true;await route.abort('blockedbyclient');
    });
    await context.routeWebSocket('**/*',socket=>{unsafe=true;socket.close();});
    const page=await context.newPage();
    page.on('pageerror',()=>{unsafe=true;});
    page.on('dialog',async dialog=>{unsafe=true;await dialog.dismiss();});
    page.on('download',download=>{unsafe=true;void download.cancel();});
    context.on('page',other=>{if(other!==page){unsafe=true;void other.close();}});
    async function settled(){await page.waitForLoadState('networkidle');guard();
      check(await page.locator('.t-Alert--danger:visible,#APEX_ERROR_MESSAGE:visible,.t-Form-error:visible,[aria-invalid="true"]:visible').count()===0,
        'Visible APEX error blocks continuation');}
    async function identity(pageId){
      guard();check(allowedRequest({url:()=>page.url(),method:()=> 'GET',resourceType:()=> 'document'},packet),'Foreign app navigation');
      check(await page.locator('input[name="p_flow_id"]').inputValue()===String(packet.binding.application_id)
        &&await page.locator('input[name="p_flow_step_id"]').inputValue()===String(pageId),'Rendered app/page identity differs');
    }
    async function account(){const label=page.locator('.t-NavigationBar-item.has-username .t-Button-label');
      check(await label.count()===1&&sha256((await label.innerText()).trim().toLowerCase())===packet.credential_authority.username_sha256,
        'Authenticated account identity differs');}
    await act(()=>page.goto(packet.url,{waitUntil:'domcontentloaded'}));await identity(9999);
    await act(()=>page.getByLabel(/^Username$/i).fill(accounts.username));
    await act(()=>page.getByLabel(/^Password$/i).fill(accounts.password));
    await act(()=>page.getByRole('button',{name:/^Sign In$/i}).click());await settled();await account();report.authenticated=true;
    const urls=new Map();
    async function navigate(block){
      if(!urls.has(block.source_block_id)){
        urls.set(block.source_block_id,await sourceNavigationUrl(page,block,packet));
      }
      await act(()=>page.goto(urls.get(block.source_block_id),{waitUntil:'domcontentloaded'}));await settled();
      await identity(2*block.sequence-1);await account();
    }
    async function filter(block,column,value,{checkColumns=false}={}){
      await act(()=>page.getByRole('button',{name:'Actions',exact:true}).click());
      await act(()=>page.getByRole('menuitem',{name:'Filter',exact:true}).click());
      const dialog=page.getByRole('dialog');await dialog.waitFor({state:'visible'});
      const radio=dialog.getByRole('radio',{name:'Column',exact:true});if(await radio.count())await act(()=>radio.check());
      const selector=await nativeFilterControl(dialog,'Column');
      if(checkColumns){const options=await selector.locator('option').evaluateAll(items=>items.map(item=>item.value));
        check(['FOX_ROW_ID',...block.fields.map(field=>field.name)].every(name=>options.includes(name)),'Declared report column is not available');}
      await act(()=>selector.selectOption(column));
      const operator=await nativeFilterControl(dialog,'Operator');await act(()=>operator.selectOption({label:'='}));
      const expression=await nativeFilterControl(dialog,'Expression');await act(()=>expression.fill(value));
      await act(()=>dialog.getByRole('button',{name:'Apply',exact:true}).click());await dialog.waitFor({state:'hidden'});await settled();
      await identity(2*block.sequence-1);
    }
    async function reset(){
      await act(()=>page.getByRole('button',{name:'Actions',exact:true}).click());
      await act(()=>page.getByRole('menuitem',{name:'Report',exact:true}).hover());
      await act(()=>page.getByRole('menuitem',{name:'Reset',exact:true}).click());
      const apply=page.getByRole('button',{name:'Apply',exact:true});await act(()=>apply.click());await apply.waitFor({state:'hidden'});await settled();
    }
    async function items(block,formPage){
      const expected=block.fields.filter(field=>formPage?field.in_edit_form:true).map(field=>`P${formPage??2*block.sequence-1}_${field.name}`);
      for(const item of expected)check(await page.locator(`[id="${item}"]`).count()===1,'Mapped native item missing or duplicated');
      if(formPage){const names=await page.locator('input[name],select[name],textarea[name]').evaluateAll(elements=>elements.map(item=>item.name).filter(name=>/^P[0-9]+_/.test(name)));
        check(new Set(names).size===names.length&&same([...names].sort(),[...expected,`P${formPage}_FOX_ROW_ID`].sort()),'Full editable item set differs');}
    }
    async function submit(block,button,key,values){
      guard();const formPage=2*block.sequence;await identity(formPage);await account();
      check(await page.locator(`input[name="P${formPage}_FOX_ROW_ID"]`).inputValue()===key,'Wrong row before submit');
      for(const field of block.fields.filter(field=>field.in_edit_form))
        check(await page.locator(`[name="P${formPage}_${field.name}"]`).inputValue()===values[field.name],'Input intent changed');
      durable(path.join(dispatch,`write-${String(++sequence).padStart(3,'0')}.json`),
        {binding:packet.binding,source_block_id:block.source_block_id,table_name:block.table_name,button,primary_key:key||null,
          intended_values_sha256:sha256(canonicalQaPlan(values)),state:'ATTEMPT_STARTED_NO_AUTOMATIC_REPLAY'});
      await act(()=>page.getByRole('button',{name:button,exact:true}).click());await settled();await identity(formPage-1);
      await page.getByText('Record saved.',{exact:true}).waitFor({state:'visible'});
    }
    for(const block of packet.spec.blocks){
      await navigate(block);
      const pageRow={page_id:2*block.sequence-1,source_block_id:block.source_block_id,passed:false,authenticated:true,checks:{}};
      report.pages.push(pageRow);pageRow.checks.render=true;
      if(block.classification==='control'){
        await items(block,null);pageRow.checks.native_items=true;pageRow.passed=true;progress();continue;
      }
      await filter(block,'FOX_ROW_ID','999999999999999999999999',{checkColumns:true});
      check(await page.locator('.a-IRR-noDataMsg').isVisible(),'Negative report search did not produce no data');
      pageRow.checks.report_columns=true;pageRow.checks.search=true;await reset();
      if(block.native_component==='report'){pageRow.passed=true;progress();continue;}
      const formPage=2*block.sequence,editable=block.fields.filter(field=>field.in_edit_form);
      const markerField=editable.find(field=>field.data_type==='VARCHAR2'&&field.length>=16);
      check(markerField&&block.fields.every(field=>field.nullable||field.in_edit_form),'Labelled synthetic input policy unavailable');
      const marker='FPQ-'+randomBytes(6).toString('hex'),updatedMarker='FPQ-'+randomBytes(6).toString('hex');
      check(marker!==updatedMarker,'Independent synthetic update marker collision');
      const values=Object.fromEntries(editable.map(field=>[field.name,field===markerField?marker:
        field.data_type==='VARCHAR2'?'A':field.data_type==='NUMBER'?'1':'2026-01-01']));
      const ledger={source_block_id:block.source_block_id,table_name:block.table_name,primary_key:null,marker,created:false,updated:false,deleted:false};
      report.retained_rows.push(ledger);progress();
      await act(()=>page.getByRole('button',{name:'Create Record',exact:true}).click());await settled();await identity(formPage);await items(block,formPage);
      const detail={page_id:formPage,source_block_id:block.source_block_id,passed:false,authenticated:true,checks:{render:true,native_items:true}};
      report.pages.push(detail);pageRow.checks.detail_navigation=true;
      if(packet.spec.profile_id===REQUIRED_PROFILE){
        const required=editable.find(field=>field.value_required);
        detail.checks.additional_required_input_validation=required?'NOT_COMPLETED':'NOT_EXERCISED_NO_ADDITIONAL_REQUIRED_FIELDS';
        if(required){
          for(const field of editable)await act(()=>fillNativeQaValue(page.locator(`[name="P${formPage}_${field.name}"]`),
            {name:field.name,data_type:field.data_type,max_length:field.length},field===required?'':values[field.name]));
          check(await page.locator(`input[name="P${formPage}_FOX_ROW_ID"]`).inputValue()==='',
            'Required-input negative probe must target a new row');
          durable(path.join(dispatch,`required-input-${String(++sequence).padStart(3,'0')}.json`),
            {binding:packet.binding,source_block_id:block.source_block_id,source_item_id:required.source_item_id,
              state:'INVALID_SUBMIT_ATTEMPT_STARTED_NO_AUTOMATIC_REPLAY'});
          invalidRequiredProbe=true;
          try{
            await assertAdditionalRequiredInputRejected(page,`P${formPage}_${required.name}`,
              ()=>act(()=>page.getByRole('button',{name:'Create',exact:true}).click()),guard);
          }finally{invalidRequiredProbe=false;}
          await identity(formPage);await account();
          check(await page.locator(`input[name="P${formPage}_FOX_ROW_ID"]`).inputValue()==='',
            'Rejected required input acquired a row identity');
          await act(()=>page.getByRole('button',{name:'Cancel',exact:true}).click());await settled();await identity(formPage-1);
          await reset();
          check(await page.locator('.a-IRR-noDataMsg').isVisible(),
            'Rejected required input unexpectedly created a synthetic row');
          detail.checks.additional_required_input_validation='PASSED';progress();
          await act(()=>page.getByRole('button',{name:'Create Record',exact:true}).click());
          await settled();await identity(formPage);await items(block,formPage);
        }
      }
      for(const field of editable)await act(()=>fillNativeQaValue(page.locator(`[name="P${formPage}_${field.name}"]`),
        {name:field.name,data_type:field.data_type,max_length:field.length},values[field.name]));
      await submit(block,'Create','',values);ledger.created=true;progress();
      async function open(markerValue){
        await filter(block,markerField.name,markerValue);const links=page.getByRole('link',{name:'Edit',exact:true});
        check(await links.count()===1,'Synthetic marker does not identify exactly one row');
        await act(()=>links.click());await settled();await identity(formPage);await items(block,formPage);
        const key=await page.locator(`input[name="P${formPage}_FOX_ROW_ID"]`).inputValue();
        check(/^[1-9][0-9]{0,37}$/.test(key),'Generated primary key missing');return key;
      }
      const key=await open(marker);ledger.primary_key=key;
      for(const field of editable)check(await page.locator(`[name="P${formPage}_${field.name}"]`).inputValue()===values[field.name],'Fresh create reread differs');
      detail.checks.create=true;
      values[markerField.name]=updatedMarker;
      await act(()=>fillNativeQaValue(page.locator(`[name="P${formPage}_${markerField.name}"]`),
        {name:markerField.name,data_type:'VARCHAR2',max_length:markerField.length},updatedMarker));
      await submit(block,'Save Changes',key,values);ledger.updated=true;ledger.marker=updatedMarker;progress();
      await reset();check(await open(updatedMarker)===key,'Update changed row identity');
      for(const field of editable)check(await page.locator(`[name="P${formPage}_${field.name}"]`).inputValue()===values[field.name],'Fresh update reread differs');
      detail.checks.update=true;detail.checks.synthetic_records_accounted=true;detail.passed=true;pageRow.passed=true;progress();
      await act(()=>page.getByRole('button',{name:'Cancel',exact:true}).click());await settled();await identity(formPage-1);await reset();
    }
    guard();check(report.pages.every(row=>row.passed),'Runtime page checks incomplete');
    report.passed=report.business_pages_tested=true;
  }finally{
    report.completed_at_utc=now();progress();if(browser)await browser.close();
    durable(path.join(output,'browser-report.json'),report);
  }
  return report;
}

export async function main(){
  process.umask(0o077);
  try{
    check(!process.env.DEBUG&&!process.env.PWDEBUG,'Debug output prohibited');
    const packet=validatePacket(parseUniqueJson(read('/inputs/target.json')));
    const files={'run-prototype.mjs':sha256(read('/opt/fox-qa/run-prototype.mjs')),'lib/contracts.mjs':sha256(read('/opt/fox-qa/lib/contracts.mjs'))};
    check(same(files,packet.runner_files),'Mounted runner source differs');
    const credentialRaw=read('/inputs/credentials.json',8192);
    check(sha256(credentialRaw)===packet.credential_authority.credentials_sha256,'Protected credential bytes differ');
    const accounts=parseUniqueJson(credentialRaw);
    check(accounts&&Object.keys(accounts).every(name=>['username','password','second_username','second_password'].includes(name))
      &&typeof accounts.username==='string'&&accounts.username.length>0&&accounts.username.length<=254
      &&typeof accounts.password==='string'&&accounts.password.length>0&&accounts.password.length<=1024
      &&sha256(accounts.username.trim().toLowerCase())===packet.credential_authority.username_sha256,'Credential identity differs');
    const require=createRequire(import.meta.url);check(require('playwright/package.json').version==='1.64.0','Pinned Playwright unavailable');
    const {chromium}=await import('playwright');await run(packet,accounts,chromium);
    process.stdout.write('{"status":"PASSED","business_behavior_accepted":false}\n');return 0;
  }catch{process.stderr.write('Prototype browser QA failed; inspect private retained evidence without replay.\n');return 1;}
}
if(process.argv[1]&&import.meta.url===pathToFileURL(path.resolve(process.argv[1])).href)process.exitCode=await main();
