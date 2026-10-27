// LOCAL SYNTHETIC BROWSER API ONLY. The production adapter below executes
// against a deterministic page/locator model. No browser, Oracle, SQLcl,
// network or live target is started; these are NOT Oracle verification.
import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {deriveProjectQaArtifacts} from '../lib/project-profile.mjs';
import {deriveNativeQaValues} from '../lib/contracts.mjs';
import {ProjectBrowserDriver} from '../lib/project-browser.mjs';

const fixture=new URL('../../converter/tests/fixtures/project_v1/two-forms-aligned/',import.meta.url);
const keyA='90071992547409931234567890123456789010';
const keyB='90071992547409931234567890123456789011';
const keyC='90071992547409931234567890123456789012';
function inputs() {
  const binding=deriveProjectQaArtifacts(readFileSync(new URL('native-project-spec.json',fixture)),readFileSync(new URL('source-to-apex.json',fixture)));
  return {...binding,target:{target:{application_id:99001}},
    targetUrl:'https://asz8eqwfm8unca2-jsnf2apex.adb.us-ashburn-1.oraclecloudapps.com/ords/r/fox_qa_261025_1234abcd/f2a_qa_261025_1234abcd/',
    accounts:{primary:{username:'FOX_QA_A',password:'synthetic-never-used-a'},secondary:{username:'FOX_QA_B',password:'synthetic-never-used-b'}}};
}

class LocatorModel {
  constructor(elements=()=>[],click=undefined){this.elements=elements;this.onClick=click;}
  async count(){return this.elements().length;}
  nth(index){return new LocatorModel(()=>this.elements().slice(index,index+1),this.onClick);}
  async evaluateAll(fn,arg){return fn(this.elements(),arg);}
  async evaluate(fn,arg){assert.equal(this.elements().length,1);return fn(this.elements()[0],arg);}
  async inputValue(){assert.equal(this.elements().length,1);return this.elements()[0].value;}
  async fill(value){assert.equal(this.elements().length,1);this.elements()[0].value=value;}
  async press(key){assert.equal(this.elements().length,1);this.elements()[0].presses.push(key);}
  async isVisible(){return this.elements().length>0&&this.elements().every(element=>element.visible!==false);}
  async allTextContents(){return this.elements().map(element=>element.textContent);}
  async waitFor(){assert.equal(await this.isVisible(),true);}
  async click(){assert.equal(this.elements().length,1);if(this.onClick)await this.onClick();}
  and(other){return new LocatorModel(()=>this.elements().filter(element=>other.elements().includes(element)));}
}

class PageModel {
  constructor(binding,form,native,{kind='form',pages=[],key=keyA}={}) {
    this.binding=binding;this.form=form;this.native=native;this.kind=kind;this.pages=pages;this.index=0;
    this.appId=String(binding.target.target.application_id);this.formId=String(form.form_page_id);this.reportId=String(form.report_page_id);
    this.pageUrl=binding.targetUrl+(kind==='form'?form.form_alias:form.report_alias).toLowerCase();this.events=[];
    const values=deriveNativeQaValues(native,'edit');
    this.inputs=native.columns.map(column=>({name:form.item_prefix+column.name,label:column.label,
      value:column.primary_key?key:values[column.name],presses:[]}));
  }
  url(){return this.pageUrl;}
  current(){return this.pages[this.index];}
  async waitForLoadState(){}
  async waitForResponse(predicate) {
    const response={url:()=>this.binding.targetUrl+'wwv_flow.ajax',request:()=>({method:()=> 'POST',resourceType:()=> 'xhr'}),
      ok:()=>true,finished:async()=>{}};
    assert.equal(predicate(response),true);return response;
  }
  async goto(url) {
    this.events.push(['goto',url]);this.pageUrl=url;this.kind='form';
    const key=new URL(url).searchParams.get('pk');
    if(key!==null)this.inputs.find(input=>input.name===this.form.primary_key.item_name).value=this.loadedKeyOverride??key;
  }
  table() {
    const headers=['Edit',...this.native.columns.map(column=>column.label)];
    const cells=(values,tag)=>values.map(text=>({tagName:tag,textContent:text,innerText:text}));
    return {id:'synthetic-report',closest:()=>null,rows:[{cells:cells(headers,'TH')},...this.current().keys.map(key=>({cells:cells([
      'Edit',...this.native.columns.map(column=>column.primary_key?key:deriveNativeQaValues(this.native,'edit')[column.name]),
    ],'TD')}))]};
  }
  locator(selector) {
    if(selector==='input[name="p_flow_id"]')return new LocatorModel(()=>[{value:this.appId}]);
    if(selector==='input[name="p_flow_step_id"]')return new LocatorModel(()=>[{value:this.kind==='form'?this.formId:this.reportId}]);
    if(selector==='input[name],select[name],textarea[name]')return new LocatorModel(()=>this.kind==='form'?this.inputs:[]);
    const input=/^input\[name="([^"]+)"\]$/.exec(selector);
    if(input)return new LocatorModel(()=>this.inputs.filter(element=>element.name===input[1]));
    if(selector==='.a-IRR-noDataMsg')return new LocatorModel(()=>this.current().noData?[{visible:true}]:[]);
    if(selector==='table.a-IRR-table')return new LocatorModel(()=>[this.table()]);
    if(selector==='.a-IRR-pagination-label:visible')return new LocatorModel(()=>this.current().labels.map(textContent=>({textContent})));
    if(selector==='.a-IRR-paginationWrap [title="Next"]:visible, .a-IRR-paginationWrap [aria-label="Next"]:visible') {
      return new LocatorModel(()=>this.current().next.map(enabled=>({disabled:!enabled,getAttribute:()=>null,classList:{contains:()=>false}})),async()=>{
        this.events.push(['next',this.index]);this.index=this.current().nextIndex??this.index+1;
      });
    }
    throw new Error(`Synthetic page does not implement selector ${selector}`);
  }
  getByLabel(label){return new LocatorModel(()=>this.inputs.filter(input=>input.label===label));}
  getByRole(role,{name}={}) {
    if(role==='link'&&name==='Edit')return new LocatorModel(()=>
      (this.current().hrefs??this.current().keys.map(key=>this.binding.targetUrl+this.form.form_alias.toLowerCase()+'?pk='+key))
        .map(href=>({href})));
    if(role==='button'&&['Save Changes','Create'].includes(name))return new LocatorModel(()=>[{visible:true}],async()=>this.events.push(['click',name]));
    throw new Error(`Synthetic page does not implement role ${role}/${name}`);
  }
}

function adapter(options={}) {
  const binding=inputs(),form=binding.plan.forms[1],native=binding.project.forms[1].native_form;
  const page=new PageModel(binding,form,native,options);
  const driver=new ProjectBrowserDriver({binding,result:{browser_errors:[],network_denials:[],browser_dialogs:[]},
    chromium:{launch:()=>{throw new Error('A real browser must never launch in these synthetic tests');}}});
  driver.sessions.set('primary',{page,pending:new Set(),lastChange:Date.now()-1000,reportUrls:new Map(),unexpectedDialog:false});
  return {binding,form,native,page,driver};
}

test('synthetic API: real adapter observes P4 full surface in mapped order, never historical P2',async()=>{
  const {driver,page,form}=adapter();page.inputs.reverse();
  assert.deepEqual(await driver.context('primary',form,'form'),{application_id:99001,page_id:4,page_item_names:form.items.map(item=>item.item)});
  assert.equal(driver.field('primary',form,{name:'TITLE'}).elements()[0].name,'P4_TITLE');
});

for(const [name,change] of [
  ['missing mapped item',page=>page.inputs.pop()],['extra orphaned item',page=>page.inputs.push({name:'P4_ORPHAN',value:''})],
  ['duplicate mapped item',page=>page.inputs.push(page.inputs[0])],['stale P2 items',page=>page.inputs.forEach(item=>item.name=item.name.replace('P4_','P2_'))],
  ['wrong page',page=>page.formId='2'],['wrong application',page=>page.appId='99002'],
  ['credential-bearing origin',page=>page.pageUrl=page.pageUrl.replace('https://','https://secret@')],
])test(`synthetic API: real context rejects ${name}`,async()=>{
  const {driver,page,form}=adapter();change(page);await assert.rejects(driver.context('primary',form,'form'));
});

test('synthetic API: real report traversal measures every page and keeps 38-digit keys exact',async()=>{
  const {driver,page,form,native}=adapter({kind:'report',pages:[
    {keys:[keyA,keyB],labels:['1 - 2 of 3'],next:[true]},
    {keys:[keyC],labels:['3 - 3 of 3'],next:[false]},
  ]});
  const observation=await driver.collectReport('primary',form,native);
  assert.deepEqual([...observation.links.keys()],[keyA,keyB,keyC]);
  assert.deepEqual(observation.pagination,{page_primary_keys:[[keyA,keyB],[keyC]],reported_total_rows:3,terminal_next_page_enabled:false});
  assert.deepEqual(page.events,[['next',0]]);
});

for(const [name,pages] of [
  ['duplicate key on next page',[{keys:[keyA],labels:['1 - 1 of 2'],next:[true]},{keys:[keyA],labels:['2 - 2 of 2'],next:[]}]],
  ['pagination cycle',[{keys:[keyA],labels:['1 - 1 of 2'],next:[true],nextIndex:0}]],
  ['missing total',[{keys:[keyA],labels:[],next:[]}]],
  ['missing next before measured terminal',[{keys:[keyA],labels:['1 - 1 of 2'],next:[]}]],
  ['enabled next after measured terminal',[{keys:[keyA],labels:['1 - 1 of 1'],next:[true]}]],
  ['total changes mid traversal',[{keys:[keyA],labels:['1 - 1 of 2'],next:[true]},{keys:[keyB],labels:['2 - 2 of 3'],next:[]}]],
  ['missing edit link',[{keys:[keyA],labels:['1 - 1 of 1'],next:[],hrefs:[]}]],
  ['wrong-target edit link',[{keys:[keyA],labels:['1 - 1 of 1'],next:[],hrefs:['https://example.invalid/edit']}]],
])test(`synthetic API: real traversal rejects ${name}`,async()=>{
  const {driver,form,native}=adapter({kind:'report',pages});await assert.rejects(driver.collectReport('primary',form,native));
});

test('synthetic API: visible empty report needs no-data observation and no enabled next',async()=>{
  const {driver,form,native}=adapter({kind:'report',pages:[{keys:[],labels:[],next:[],noData:true}]});
  const observation=await driver.collectReport('primary',form,native);
  assert.deepEqual(observation.pagination,{page_primary_keys:[[]],reported_total_rows:0,terminal_next_page_enabled:false});
  const invalid=adapter({kind:'report',pages:[{keys:[],labels:[],next:[true],noData:true}]});
  await assert.rejects(invalid.driver.collectReport('primary',invalid.form,invalid.native));
});

test('synthetic API: actual submit verifies every input and exact mapped key before one click',async()=>{
  const {driver,page,form,native}=adapter();let intents=0;
  const expected=deriveNativeQaValues(native,'edit');
  await driver.submit('primary',form,'Save Changes',expected,keyA,async measured=>{intents++;assert.deepEqual(measured,expected);});
  assert.equal(intents,1);assert.deepEqual(page.events,[['click','Save Changes']]);
});

for(const [name,change] of [
  ['changed value',page=>page.inputs.find(input=>input.name==='P4_TITLE').value='unexpected'],
  ['wrong retained key',page=>page.inputs.find(input=>input.name==='P4_ORDER_ID').value=keyB],
  ['inexact decimal key',page=>page.inputs.find(input=>input.name==='P4_ORDER_ID').value='9.007199254740993e37'],
  ['wrong label',page=>page.inputs.find(input=>input.name==='P4_TITLE').label='Not the mapped label'],
])test(`synthetic API: actual submit blocks ${name} without intent or click`,async()=>{
  const {driver,page,form,native}=adapter();change(page);let intents=0;
  await assert.rejects(driver.submit('primary',form,'Save Changes',deriveNativeQaValues(native,'edit'),keyA,async()=>{intents++;}));
  assert.equal(intents,0);assert.deepEqual(page.events,[]);
});

test('synthetic API: Create refuses a nonempty key; observed blank key permits one create click',async()=>{
  const blocked=adapter();let intents=0;
  await assert.rejects(blocked.driver.submit('primary',blocked.form,'Create',deriveNativeQaValues(blocked.native,'edit'),null,async()=>{intents++;}));
  assert.equal(intents,0);assert.deepEqual(blocked.page.events,[]);
  const allowed=adapter({key:''});
  await allowed.driver.submit('primary',allowed.form,'Create',deriveNativeQaValues(allowed.native,'edit'),null,async()=>{intents++;});
  assert.equal(intents,1);assert.deepEqual(allowed.page.events,[['click','Create']]);
});

test('synthetic API: input probe uses mapped P4 item and reports actual typed invalid value',async()=>{
  const {driver,page,form,native}=adapter(),column=native.columns.find(column=>column.name==='AMOUNT');
  assert.equal(await driver.probe('primary',form,column,'not-a-number','invalid_number'),'not-a-number');
  assert.equal(page.inputs.find(input=>input.name==='P4_AMOUNT').value,'not-a-number');
  assert.deepEqual(page.inputs.find(input=>input.name==='P4_AMOUNT').presses,['Tab']);
});

test('synthetic API: fresh mapped link verifies loaded primary key and rejects wrong app before navigation',async()=>{
  const {driver,page,form,binding}=adapter();
  await driver.openHref('primary',form,binding.targetUrl+'edit_2?pk='+keyB,keyB);
  assert.equal(page.events.length,1);
  page.loadedKeyOverride=keyA;
  await assert.rejects(driver.openHref('primary',form,binding.targetUrl+'edit_2?pk='+keyB,keyB),/another primary key/);
  const count=page.events.length;
  await assert.rejects(driver.openHref('primary',form,binding.targetUrl.replace('f2a_qa_261025_1234abcd','another_app')+'edit_2?pk='+keyB,keyB));
  assert.equal(page.events.length,count);
});

test('synthetic API: login target requires the exact app and rendered 9999 login page',async()=>{
  const {driver,page}=adapter();page.formId='9999';
  await driver.assertLoginTarget(page);
  page.formId='4';await assert.rejects(driver.assertLoginTarget(page),/Rendered login/);
});

for(const [name,change] of [
  ['another same-origin application',page=>page.pageUrl=page.pageUrl.replace('f2a_qa_261025_1234abcd','another_app')],
  ['wrong rendered application ID',page=>page.appId='99002'],
  ['wrong rendered login page',page=>page.formId='1'],
])test(`synthetic API: actual start never fills credentials after ${name}`,async()=>{
  const binding=inputs(),form=binding.plan.forms[0],native=binding.project.forms[0].native_form;
  const page=new PageModel(binding,form,native);page.formId='9999';
  page.on=()=>{};
  page.goto=async url=>{page.events.push(['goto']);page.pageUrl=url+'login';change(page);};
  page.getByLabel=()=>({fill:async()=>{page.events.push(['credential-fill']);}});
  page.getByRole=()=>({click:async()=>{page.events.push(['login-click']);}});
  let contexts=0;
  const browser={version:()=> 'synthetic-not-chromium',close:async()=>{},newContext:async()=>{
    contexts++;
    return {setDefaultTimeout:()=>{},setDefaultNavigationTimeout:()=>{},route:async()=>{},routeWebSocket:async()=>{},on:()=>{},newPage:async()=>page};
  }};
  const driver=new ProjectBrowserDriver({binding,result:{browser_errors:[],network_denials:[],browser_dialogs:[]},
    chromium:{launch:async()=>browser}});
  await assert.rejects(driver.start());assert.equal(contexts,1);
  assert.deepEqual(page.events,[['goto']]);await driver.close();
});

function requestModel(binding,{url='/ords/wwv_flow.accept',method='POST',type='document',
  contentType='application/x-www-form-urlencoded; charset=UTF-8',body='p_flow_id=99001&p_flow_step_id=4'}={}) {
  return {url:()=>new URL(url,binding.targetUrl).href,method:()=>method,resourceType:()=>type,
    headers:()=>contentType===null?{}:{'content-type':contentType},postData:()=>body};
}

test('synthetic API: exact allocated app/page form POSTs are allowed only at shared APEX endpoints',()=>{
  const {driver,binding}=adapter();
  for(const endpoint of ['/ords/wwv_flow.accept','/ords/wwv_flow.ajax','/ords/wwv_flow.show'])
    for(const page of ['1','2','3','4','9999']) {
      const request=requestModel(binding,{url:endpoint,type:endpoint.endsWith('.ajax')?'xhr':'document',body:`p_flow_id=99001&p_flow_step_id=${page}`});
      assert.equal(driver.allowedRequest(request),true);
    }
});

for(const [name,options] of [
  ['wrong application',{body:'p_flow_id=99002&p_flow_step_id=4'}],
  ['unmapped page',{body:'p_flow_id=99001&p_flow_step_id=5'}],
  ['noncanonical page',{body:'p_flow_id=99001&p_flow_step_id=04'}],
  ['duplicate application parameter',{body:'p_flow_id=99001&p_flow_id=99001&p_flow_step_id=4'}],
  ['duplicate page parameter',{body:'p_flow_id=99001&p_flow_step_id=4&p_flow_step_id=4'}],
  ['query application override',{url:'/ords/wwv_flow.accept?p_flow_id=99002'}],
  ['query page override',{url:'/ords/wwv_flow.ajax?p_flow_step_id=2'}],
  ['arbitrary same-origin POST',{url:'/ords/admin/remove'}],
  ['missing body',{body:null}],
  ['unstructured JSON body',{body:'{"p_flow_id":99001,"p_flow_step_id":4}'}],
  ['body without page',{body:'p_flow_id=99001'}],
  ['empty body',{body:''}],
  ['malformed percent encoding',{body:'p_flow_id=99001&p_flow_step_id=4&other=%GG'}],
  ['oversize body',{body:'x'.repeat(2_000_001)}],
  ['JSON content type',{contentType:'application/json'}],
  ['missing content type',{contentType:null}],
  ['multipart content type',{contentType:'multipart/form-data; boundary=synthetic'}],
  ['unsupported method',{method:'PUT'}],
])test(`synthetic API: request guard rejects ${name} without forwarding request contents`,()=>{
  const {driver,binding}=adapter();assert.equal(driver.allowedRequest(requestModel(binding,options)),false);
});

test('synthetic API: request guard rejects credential URLs, other app documents and foreign origins',()=>{
  const {driver,binding}=adapter();
  const credentialUrl=binding.targetUrl.replace('https://','https://synthetic-secret@');
  const otherApp=binding.targetUrl.replace('f2a_qa_261025_1234abcd','another_app');
  for(const url of [credentialUrl,otherApp,'https://example.invalid/ords/wwv_flow.accept'])
    assert.equal(driver.allowedRequest(requestModel(binding,{url,method:'GET'})),false);
  assert.equal(driver.allowedRequest(requestModel(binding,{url:credentialUrl,method:'POST'})),false);
});

test('synthetic API: read-only APEX CDN and local static assets allow no document or POST escape',()=>{
  const {driver,binding}=adapter();
  for(const method of ['GET','HEAD']) {
    assert.equal(driver.allowedRequest(requestModel(binding,{url:'https://static.oracle.com/cdn/apex/26.1/libraries/apex.js',method,type:'script'})),true);
    assert.equal(driver.allowedRequest(requestModel(binding,{url:'/i/themes/theme_42/1.0/css/Core.min.css',method,type:'stylesheet'})),true);
    assert.equal(driver.allowedRequest(requestModel(binding,{url:binding.targetUrl+'form_2',method,type:'document'})),true);
  }
  assert.equal(driver.allowedRequest(requestModel(binding,{url:'/i/anything',method:'GET',type:'document'})),false);
  assert.equal(driver.allowedRequest(requestModel(binding,{url:'/i/anything',method:'POST',type:'xhr'})),false);
  assert.equal(driver.allowedRequest(requestModel(binding,{url:'https://static.oracle.com/cdn/apex/anything',method:'POST',type:'xhr'})),false);
  assert.equal(driver.allowedRequest(requestModel(binding,{url:'https://static.oracle.com/cdn/not-apex/anything',method:'GET',type:'script'})),false);
});
