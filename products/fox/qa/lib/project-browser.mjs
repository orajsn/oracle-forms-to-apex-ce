/** Real Playwright adapter for the bounded generated project UI.
 * No SQL, arbitrary endpoints, DOM mutation, traces, HAR, videos or storage-state.
 * Unknown DOM/pagination shapes fail closed; supported selectors need real APEX
 * verification on the allocated target before a project can be VERIFIED. */
import {SCOPE,check,canonicalPrimaryKey,samePrimaryKeySet,readNativeReportPrimaryKeys,
  nativeFilterControl,fillNativeQaValue,probeNativeQaMaximumLength,safeMessage} from './contracts.mjs';
import {PROJECT_OBSERVATION_SCOPE} from './project-profile.mjs';

const delay=ms=>new Promise(resolve=>setTimeout(resolve,ms));
async function until(fn,message,timeout=30000) {
  const end=Date.now()+timeout;
  while(Date.now()<end){if(await fn())return;await delay(100);}
  throw new Error(message);
}
const ERROR_SELECTOR='.t-Alert--danger, .t-Alert--warning, #APEX_ERROR_MESSAGE, .t-Form-error, .a-Form-error, [aria-invalid="true"]';

/** Deliberately accept only bounded, independently rendered IR row totals. */
export function parseProjectPagination({labels,nextControls,noData},keys) {
  check(Array.isArray(labels)&&Array.isArray(nextControls)&&typeof noData==='boolean','Report pagination DOM is incomplete');
  const totals=new Set();
  for(const label of labels) {
    const normalized=label.replace(/\s+/g,' ').trim();
    const match=/^(\d[\d,]*)\s*[-–]\s*(\d[\d,]*)\s+of\s+(\d[\d,]*)$/i.exec(normalized);
    if(match){const numbers=match.slice(1).map(value=>Number(value.replaceAll(',','')));
      check(numbers.every(Number.isSafeInteger)&&numbers[0]>=1&&numbers[1]>=numbers[0]&&numbers[2]>=numbers[1],
        'Report pagination range is invalid');totals.add(numbers[2]);}
    else if(!noData&&normalized)throw new Error('Report does not expose an exact total; refusing a visible-page-only observation');
  }
  check(nextControls.length<=1&&nextControls.every(value=>typeof value==='boolean'),'Report has ambiguous Next controls');
  if(noData){check(keys.length===0&&totals.size===0&&nextControls.every(value=>!value),'Empty-report observations conflict');return{total:0,nextEnabled:false};}
  check(totals.size===1&&keys.length>0,'Nonempty report is missing its independently rendered total');
  return {total:[...totals][0],nextEnabled:nextControls[0]??false};
}

export class ProjectBrowserDriver {
  constructor({chromium,playwrightVersion=null,binding,result,persist=async()=>{}}) {
    this.chromium=chromium;this.binding=binding;this.result=result;this.persist=persist;this.sessions=new Map();this.browser=null;
    this.playwrightVersion=playwrightVersion;
    this.secrets=[binding.accounts.primary,binding.accounts.secondary].flatMap(account=>[account.username,account.password]);
  }
  redact(error){return safeMessage(error,this.secrets);}
  hasUnexpectedDialog(){return [...this.sessions.values()].some(state=>state.unexpectedDialog);}
  state(name){const state=this.sessions.get(name);check(state,'Independent browser session is unavailable');return state;}
  async close(){if(this.browser)await this.browser.close();}
  async start() {
    this.browser=await this.chromium.launch({headless:true,chromiumSandbox:false});
    this.result.runtime={playwright:this.playwrightVersion,chromium:this.browser.version(),chromium_sandbox:false,
      isolation:'Rootless on-demand container; no published ports; exact allocated JSN synthetic project only'};
    for(const name of ['primary','secondary']) {
      const context=await this.browser.newContext({locale:'en-US',viewport:{width:1440,height:1000},
        ignoreHTTPSErrors:false,acceptDownloads:false,serviceWorkers:'block'});
      context.setDefaultTimeout(15000);context.setDefaultNavigationTimeout(45000);
      const state={context,page:null,pending:new Set(),lastChange:Date.now(),reportUrls:new Map(),allowCancelDialog:false,unexpectedDialog:false};
      this.sessions.set(name,state);
      await context.route('**/*',async route=>{
        const request=route.request();
        if(this.allowedRequest(request))return route.continue();
        let origin='invalid';try{origin=new URL(request.url()).origin;}catch{}
        if(!this.result.network_denials.includes(origin))this.result.network_denials.push(origin);
        await this.persist();await route.abort('blockedbyclient');
      });
      await context.routeWebSocket('**/*',socket=>socket.close());
      context.on('request',request=>{state.pending.add(request);state.lastChange=Date.now();});
      const finished=request=>{state.pending.delete(request);state.lastChange=Date.now();};
      context.on('requestfinished',finished);context.on('requestfailed',finished);
      const page=await context.newPage();state.page=page;
      page.on('pageerror',error=>{this.result.browser_errors.push(this.redact(error));void this.persist();});
      page.on('dialog',async dialog=>{
        this.result.browser_dialogs.push({type:dialog.type(),message:this.redact(dialog.message()),cancel_scoped:state.allowCancelDialog});
        if(state.allowCancelDialog&&['beforeunload','confirm'].includes(dialog.type()))await dialog.accept();
        else{state.unexpectedDialog=true;await dialog.dismiss();}await this.persist();
      });
      page.on('download',download=>{state.unexpectedDialog=true;void download.cancel();});
      context.on('page',newPage=>{if(state.page&&newPage!==state.page){state.unexpectedDialog=true;void newPage.close();}});
      await page.goto(this.binding.targetUrl,{waitUntil:'domcontentloaded'});
      await this.assertLoginTarget(page);
      const account=this.binding.accounts[name];
      await page.getByLabel(/^Username$/i).fill(account.username);
      await page.getByLabel(/^Password$/i).fill(account.password);
      await page.getByRole('button',{name:/^Sign In$/i}).click();
      await page.getByRole('button',{name:'Create Record',exact:true}).waitFor({state:'visible'});await this.ready(state);
      await this.context(name,this.binding.plan.forms[0],'report');
      // Prove which supplied QA identity is actually shown after login. No
      // account text is serialized, captured or forwarded to the console.
      const accountLabel=page.locator('.t-Button--account .t-Button-label');
      check(await accountLabel.count()===1&&(await accountLabel.innerText()).trim().toLowerCase()===account.username.toLowerCase(),
        'Authenticated runtime account differs or cannot be observed');
    }
  }
  async ready(state) {
    await state.page.waitForLoadState('load');
    await until(()=>state.pending.size===0&&Date.now()-state.lastChange>=500,'Browser requests did not settle');
  }
  async ajax(state,action) {
    const pending=state.page.waitForResponse(response=>new URL(response.url()).origin===SCOPE.origin
      &&response.request().method()==='POST'&&['xhr','fetch'].includes(response.request().resourceType()));
    const [response]=await Promise.all([pending,action()]);check(response.ok(),'Native report Ajax failed');
    await response.finished();await this.ready(state);
  }
  assertUrl(url) {
    const actual=new URL(url),base=new URL(this.binding.targetUrl);
    check(actual.origin===base.origin&&!actual.username&&!actual.password,'Unexpected browser target');
    // Friendly URLs must remain in the allocated app. Legacy f?p links are
    // accepted only with the exact application ID; rendered context rechecks it.
    check(actual.pathname.toLowerCase().startsWith(base.pathname.toLowerCase())
      ||actual.pathname==='/ords/f'&&actual.searchParams.get('p')?.split(':')[0]===String(this.binding.target.target.application_id),
    'Link is outside the allocated application');return actual;
  }
  allowedRequest(request) {
    // Shared APEX accept/Ajax endpoints are not app-specific URLs. Inspect
    // their bounded form payload in memory for the exact allocated app/page;
    // NEVER retain or log that body (login passwords can be present).
    try {
      const url=new URL(request.url()),method=request.method();
      if(url.username||url.password)return false;
      if(url.origin==='https://static.oracle.com')return ['GET','HEAD'].includes(method)&&url.pathname.startsWith('/cdn/apex/');
      if(url.origin!==SCOPE.origin)return false;
      if(['GET','HEAD'].includes(method)) {
        if(request.resourceType()!=='document'&&url.pathname.startsWith('/i/'))return true;
        this.assertUrl(url.href);return true;
      }
      if(method!=='POST'||!['/ords/wwv_flow.accept','/ords/wwv_flow.ajax','/ords/wwv_flow.show'].includes(url.pathname))return false;
      const contentType=request.headers()['content-type']??'';
      if(!/^application\/x-www-form-urlencoded(?:\s*;|$)/i.test(contentType))return false;
      const raw=request.postData();if(typeof raw!=='string'||raw.length>2_000_000)return false;
      // URLSearchParams alone silently replaces malformed percent/UTF-8
      // encoding. Reject such input rather than interpreting a different body.
      decodeURIComponent(raw);
      const body=new URLSearchParams(raw),apps=body.getAll('p_flow_id'),pages=body.getAll('p_flow_step_id');
      const pageIds=new Set(['9999',...this.binding.plan.forms.flatMap(form=>[String(form.report_page_id),String(form.form_page_id)])]);
      return apps.length===1&&apps[0]===String(this.binding.target.target.application_id)
        &&pages.length===1&&pageIds.has(pages[0])&&!url.searchParams.has('p_flow_id')&&!url.searchParams.has('p_flow_step_id');
    }catch{return false;}
  }
  async assertLoginTarget(page) {
    // Authentication is itself sensitive: never fill credentials following a
    // redirect until BOTH the destination and rendered login app are checked.
    this.assertUrl(page.url());
    check(await page.locator('input[name="p_flow_id"]').inputValue()===String(this.binding.target.target.application_id)
      &&await page.locator('input[name="p_flow_step_id"]').inputValue()==='9999',
    'Rendered login is outside the exact allocated application');
  }
  async context(name,form,kind) {
    const {page}=this.state(name);this.assertUrl(page.url());
    const app=await page.locator('input[name="p_flow_id"]').inputValue();
    const pageId=await page.locator('input[name="p_flow_step_id"]').inputValue();
    check(/^[1-9][0-9]*$/.test(app)&&/^(?:0|[1-9][0-9]*)$/.test(pageId),'Rendered app/page identity is missing');
    const names=await page.locator('input[name],select[name],textarea[name]').evaluateAll(elements=>
      elements.map(element=>element.name).filter(name=>/^P[0-9]+_/.test(name)));
    const expected=kind==='report'?[]:form.items.map(item=>item.item);
    check(new Set(names).size===names.length&&names.length===expected.length&&expected.every(item=>names.includes(item)),
      'Rendered full page-item set differs from the mapped module');
    check(Number(app)===this.binding.target.target.application_id&&Number(pageId)===form[kind==='report'?'report_page_id':'form_page_id'],
      'Rendered application or page differs from the selected module');
    return {application_id:Number(app),page_id:Number(pageId),page_item_names:expected.map(item=>names.find(name=>name===item))};
  }
  async navigate(name,form) {
    const state=this.state(name),{page}=state;
    if(state.reportUrls.has(form.module_id))await page.goto(state.reportUrls.get(form.module_id),{waitUntil:'domcontentloaded'});
    else {
      const links=await page.getByRole('link',{name:form.form_name,exact:true}).evaluateAll(elements=>elements.map(element=>element.href));
      const candidates=[...new Set(links)].filter(href=>{
        try {const url=this.assertUrl(href),p=url.searchParams.get('p')?.split(':');
          return url.pathname.toLowerCase().replace(/\/$/,'').endsWith('/'+form.report_alias.toLowerCase())
            ||p?.[1]===String(form.report_page_id);}catch{return false;}
      });
      check(candidates.length===1,'Mapped module navigation link is missing or ambiguous');
      await page.goto(candidates[0],{waitUntil:'domcontentloaded'});
    }
    await page.getByRole('button',{name:'Create Record',exact:true}).waitFor({state:'visible'});await this.ready(state);
    await this.context(name,form,'report');state.reportUrls.set(form.module_id,page.url());
  }
  async createPage(name,form) {
    await this.navigate(name,form);const state=this.state(name);
    await state.page.getByRole('button',{name:'Create Record',exact:true}).click();
    await state.page.getByRole('button',{name:'Create',exact:true}).waitFor({state:'visible'});await this.ready(state);
    await this.context(name,form,'form');
  }
  field(name,form,column) {return this.state(name).page.locator(`input[name="${form.item_prefix}${column.name}"]`);}
  profile(form){return this.binding.profile.forms.find(item=>item.module_id===form.module_id).native_profile;}
  async assertFields(name,form) {
    await this.context(name,form,'form');const page=this.state(name).page;
    for(const column of this.profile(form).fields) {
      const input=this.field(name,form,column);check(await input.count()===1,'Mapped input is missing or duplicated');
      check(await page.getByLabel(column.label,{exact:true}).and(input).count()===1,'Mapped input accessible label differs');
    }
  }
  async readInputs(name,form) {
    await this.assertFields(name,form);const values={};
    for(const column of this.profile(form).fields)values[column.name]=await this.field(name,form,column).inputValue();return values;
  }
  async fill(name,form,values) {
    await this.assertFields(name,form);
    for(const column of this.profile(form).fields)await fillNativeQaValue(this.field(name,form,column),column,values[column.name]);
    return this.readInputs(name,form);
  }
  async probe(name,form,column,attempted,kind) {
    await this.assertFields(name,form);const input=this.field(name,form,column);
    if(kind==='maximum_length')return (await probeNativeQaMaximumLength(input,this.profile(form).fields.find(field=>field.name===column.name))).actual;
    await input.fill(attempted);await input.press('Tab');return input.inputValue();
  }
  async submit(name,form,button,expected,key,beforeClick) {
    await this.assertFields(name,form);check(!this.hasUnexpectedDialog(),'Unexpected dialog blocks writes');
    const state=this.state(name),actual=await this.readInputs(name,form);
    check(Object.keys(expected).length===Object.keys(actual).length&&Object.entries(expected).every(([name,value])=>actual[name]===value),
      'Input differs immediately before submission; no write attempted');
    const observed=await state.page.locator(`input[name="${form.primary_key.item_name}"]`).inputValue();
    check(button==='Create'?observed==='':canonicalPrimaryKey(observed)===key,'Wrong retained identity; no write attempted');
    await beforeClick(actual);await state.page.getByRole('button',{name:button,exact:true}).click();
  }
  async saved(name,form) {
    const state=this.state(name);await state.page.getByRole('button',{name:'Create Record',exact:true}).waitFor({state:'visible'});
    await this.ready(state);await state.page.getByText('Record saved.',{exact:true}).waitFor({state:'visible'});
    return this.context(name,form,'report');
  }
  async cancel(name,form) {
    const state=this.state(name);state.allowCancelDialog=true;
    try {await state.page.getByRole('button',{name:'Cancel',exact:true}).click();
      await state.page.getByRole('button',{name:'Create Record',exact:true}).waitFor({state:'visible'});await this.ready(state);
      return await this.context(name,form,'report');
    }finally{state.allowCancelDialog=false;}
  }
  async rejected(name,form,{stale=false}={}) {
    const state=this.state(name),{page}=state;let text='';
    await until(async()=>{
      const messages=page.locator(ERROR_SELECTOR),parts=[];
      for(let index=0;index<await messages.count();index++)if(await messages.nth(index).isVisible())parts.push(await messages.nth(index).innerText());
      text=parts.join(' ');return parts.length>0;
    },'No visible APEX validation or stale-update feedback appeared');
    await this.context(name,form,'form');
    check(await page.getByRole('button',{name:'Cancel',exact:true}).isVisible(),'Rejected submission left the form');
    check(!await page.getByText('Record saved.',{exact:true}).isVisible().catch(()=>false),'Rejected input reported a save');
    if(stale)check(/(?:changed|modified).*(?:another|since|user)|lost.update|checksum/i.test(text),'Rejection does not identify a stale update');
    return true;
  }
  async resetReport(name,form) {
    // This resets only APEX interactive-report filters, never table data.
    await this.navigate(name,form);const state=this.state(name),{page}=state;
    await page.getByRole('button',{name:'Actions',exact:true}).click();
    await page.getByRole('menuitem',{name:'Report',exact:true}).hover();
    await page.getByRole('menuitem',{name:'Reset',exact:true}).click();
    await this.ajax(state,()=>page.getByRole('button',{name:'Apply',exact:true}).click());
    await page.getByRole('button',{name:'Apply',exact:true}).waitFor({state:'hidden'});await this.context(name,form,'report');
  }
  nextControl(page){return page.locator('.a-IRR-paginationWrap [title="Next"]:visible, .a-IRR-paginationWrap [aria-label="Next"]:visible');}
  async collectReport(name,form,native) {
    const state=this.state(name),{page}=state,pages=[],links=new Map();let total=null;
    for(let index=0;index<1000;index++) {
      await this.context(name,form,'report');
      const noData=await page.locator('.a-IRR-noDataMsg').isVisible().catch(()=>false);
      const keys=noData?[]:await readNativeReportPrimaryKeys(page,native);
      const next=this.nextControl(page),nextControls=[];
      for(let cursor=0;cursor<await next.count();cursor++)nextControls.push(await next.nth(cursor).evaluate(element=>
        !element.disabled&&element.getAttribute('aria-disabled')!=='true'&&!element.classList.contains('is-disabled')));
      const observed=parseProjectPagination({labels:await page.locator('.a-IRR-pagination-label:visible').allTextContents(),nextControls,noData},keys);
      check(total===null||total===observed.total,'Report total changed during pagination');total=observed.total;
      check(keys.every(key=>!links.has(key)),'Report pagination repeated a row or cycled');
      const hrefs=await page.getByRole('link',{name:'Edit',exact:true}).evaluateAll(elements=>elements.map(element=>element.href));
      check(hrefs.length===keys.length,'Report Edit links do not cover every observed row');
      keys.forEach((key,i)=>{this.assertUrl(hrefs[i]);links.set(key,hrefs[i]);});pages.push(keys);
      if(!observed.nextEnabled){check(links.size===total,'Terminal report page does not cover the rendered total');
        return {links,pagination:{page_primary_keys:pages,reported_total_rows:total,terminal_next_page_enabled:false}};}
      check(links.size<total&&await next.count()===1,'Next control conflicts with the rendered row total');
      await this.ajax(state,()=>next.click());
    }
    throw new Error('Bounded pagination limit exceeded');
  }
  async openHref(name,form,href,key) {
    this.assertUrl(href);const state=this.state(name);
    await state.page.goto(href,{waitUntil:'domcontentloaded'});
    await state.page.getByRole('button',{name:'Save Changes',exact:true}).waitFor({state:'visible'});await this.ready(state);
    await this.context(name,form,'form');
    check(canonicalPrimaryKey(await state.page.locator(`input[name="${form.primary_key.item_name}"]`).inputValue())===key,
      'Observed Edit link opened another primary key');
  }
  async readRecord(name,form,native) {
    const state=this.state(name),values=await this.readInputs(name,form);
    for(const column of native.columns.filter(column=>!column.primary_key))if(values[column.name]===''&&column.nullable)values[column.name]=null;
    return {primary_key:canonicalPrimaryKey(await state.page.locator(`input[name="${form.primary_key.item_name}"]`).inputValue()),values};
  }
  async observeTable(name,form,native) {
    await this.resetReport(name,form);const {links,pagination}=await this.collectReport(name,form,native),records=[];
    for(const [key,href] of links){await this.openHref(name,form,href,key);records.push(await this.readRecord(name,form,native));await this.cancel(name,form);}
    return {observation_scope:PROJECT_OBSERVATION_SCOPE,records,pagination};
  }
  async search(name,form,native,key) {
    await this.resetReport(name,form);const state=this.state(name),{page}=state;
    await page.getByRole('button',{name:'Actions',exact:true}).click();await page.getByRole('menuitem',{name:'Filter',exact:true}).click();
    const dialog=page.getByRole('dialog');await dialog.waitFor({state:'visible'});
    const type=dialog.getByRole('radio',{name:'Column',exact:true});if(await type.count())await type.check();
    const column=await nativeFilterControl(dialog,'Column');
    check(await column.locator('option').evaluateAll((items,name)=>items.some(item=>item.value===name),form.primary_key.name),'Mapped PK filter is absent');
    await column.selectOption(form.primary_key.name);await(await nativeFilterControl(dialog,'Operator')).selectOption({label:'='});
    await(await nativeFilterControl(dialog,'Expression')).fill(key);
    await this.ajax(state,()=>dialog.getByRole('button',{name:'Apply',exact:true}).click());await dialog.waitFor({state:'hidden'});
    const {links}=await this.collectReport(name,form,native);
    return {primary_keys:[...links.keys()],links,context:await this.context(name,form,'report')};
  }
  async openRecord(name,form,native,key) {
    const result=await this.search(name,form,native,key);
    check(samePrimaryKeySet(result.primary_keys,[key]),'Mapped identity search did not yield exactly one row');
    await this.openHref(name,form,result.links.get(key),key);
  }
}
