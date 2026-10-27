// Offline only: parent runs in the already-cached QA image with --network=none.
// No credentials, target URL, APEX navigation, ports, or business submissions.
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {createRequire} from 'node:module';
import {pathToFileURL} from 'node:url';
const require=createRequire(process.env.FOX_QA_PACKAGE_JSON||'/opt/fox-qa/package.json');
assert.equal(require('playwright/package.json').version,'1.64.0');
const {chromium}=require('playwright');
const {readNativeReportPrimaryKeys,nativeFilterControl,fillNativeQaValue,probeNativeQaMaximumLength}=await import(process.env.FOX_QA_CONTRACTS_MODULE?pathToFileURL(process.env.FOX_QA_CONTRACTS_MODULE):new URL('../lib/contracts.mjs',import.meta.url));
const fixture=JSON.parse(readFileSync(process.env.FOX_QA_REPORT_FIXTURE||new URL('./fixtures/native-report-sticky-header.json',import.meta.url)));
const escape=value=>String(value).replaceAll('&','&amp;').replaceAll('<','&lt;').replaceAll('>','&gt;').replaceAll('"','&quot;');
const rowMarkup=row=>'<tr>'+row.map(cell=>`<${cell.tag.toLowerCase()}>${escape(cell.text)}</${cell.tag.toLowerCase()}>`).join('')+'</tr>';
const html=(tables,semantic=false)=>'<!doctype html><html><body><div class="a-IRR-container">'+tables.map(table=>{
  const rows=table.rows.map(rowMarkup);const contents=semantic?'<thead>'+rows[0]+'</thead><tbody>'+rows.slice(1).join('')+'</tbody>':'<tbody>'+rows.join('')+'</tbody>';
  return `<div class="${table.sticky_header?'t-fht-thead js-stickyTableHeader':'t-fht-tbody'}"><table class="a-IRR-table" id="${escape(table.id)}">${contents}</table></div>`;
}).join('')+'</div></body></html>';
const cases=[
  {name:'observed-sticky-header-and-tbody-header-row',tables:structuredClone(fixture.tables),keys:['1']},
  {name:'nonsticky-tbody-header-row',tables:[structuredClone(fixture.tables[1])],keys:['1']},
  {name:'semantic-thead',tables:[structuredClone(fixture.tables[1])],semantic:true,keys:['1']},
  {name:'duplicate-actual-table',tables:[structuredClone(fixture.tables[1]),structuredClone(fixture.tables[1])],reject:true},
  {name:'missing-header',tables:[{...structuredClone(fixture.tables[1]),rows:[structuredClone(fixture.tables[1].rows[1])]}],reject:true},
  {name:'duplicate-primary-key',tables:[{...structuredClone(fixture.tables[1]),rows:[...structuredClone(fixture.tables[1].rows),structuredClone(fixture.tables[1].rows[1])]}],reject:true},
  {name:'large-exact-primary-key',tables:[structuredClone(fixture.tables[1])],keys:['9007199254740993']},
];
cases.at(-1).tables[0].rows[1][1].text='9007199254740993';
const browser=await chromium.launch({headless:true,chromiumSandbox:false});let requests=0;const results=[];
try{
  const context=await browser.newContext({serviceWorkers:'block',acceptDownloads:false});
  await context.route('**/*',route=>{requests++;return route.abort();});
  await context.routeWebSocket('**/*',socket=>socket.close());
  const page=await context.newPage();page.setDefaultTimeout(5000);
  for(const item of cases){
    await page.setContent(html(item.tables,item.semantic));
    // Reproduce the observed clone's direct TR, with no THEAD or TBODY.
    await page.locator('.t-fht-thead table').evaluateAll(tables=>tables.forEach(table=>table.replaceChildren(...[...table.rows])));
    if(item.name==='observed-sticky-header-and-tbody-header-row')await page.locator('.t-fht-tbody th').evaluateAll(cells=>cells.forEach(cell=>{cell.style.visibility='hidden';}));
    if(item.reject)await assert.rejects(()=>readNativeReportPrimaryKeys(page,fixture.spec));
    else assert.deepEqual(await readNativeReportPrimaryKeys(page,fixture.spec),item.keys);
    results.push({name:item.name,status:'PASSED'});
  }
  // APEX retains hidden STRING/CLOB/BOOLEAN/DATE operators and BETWEEN date
  // inputs with the same accessible labels as the visible NUMBER/= controls.
  await page.setContent('<div role="dialog" aria-label="Filter">'+
    '<input type="radio" aria-label="Column" checked><label for="column">Column</label><select id="column"><option value="ID">ID</option></select>'+
    ['STRING','CLOB','NUMBER','BOOLEAN','DATE'].map(type=>`<div ${type==='NUMBER'?'':'style="display:none"'}><label for="${type}_OPT">Operator</label><select id="${type}_OPT"><option value="=">=</option></select></div>`).join('')+
    '<label id="expression_label" for="expression">Expression</label><input id="expression">'+
    '<div style="display:none"><input id="between_from_input" aria-labelledby="expression_label"><input id="between_to_input" aria-labelledby="expression_label"></div></div>');
  const dialog=page.getByRole('dialog');
  assert.equal(await dialog.getByLabel('Operator',{exact:true}).count(),5);
  assert.equal(await dialog.getByLabel('Expression',{exact:true}).count(),3);
  await (await nativeFilterControl(dialog,'Column')).selectOption('ID');
  const operator=await nativeFilterControl(dialog,'Operator');assert.equal(await operator.getAttribute('id'),'NUMBER_OPT');await operator.selectOption({label:'='});
  const expression=await nativeFilterControl(dialog,'Expression');assert.equal(await expression.getAttribute('id'),'expression');await expression.fill('9007199254740993');
  assert.equal(await expression.inputValue(),'9007199254740993');results.push({name:'hidden-type-specific-filter-controls',status:'PASSED'});
  await page.locator('#STRING_OPT').evaluate(element=>{element.parentElement.style.display='block';});
  await assert.rejects(()=>nativeFilterControl(dialog,'Operator'));results.push({name:'duplicate-visible-filter-operator-rejected',status:'PASSED'});
  await expression.evaluate(element=>{element.style.display='none';});
  await assert.rejects(()=>nativeFilterControl(dialog,'Expression'));results.push({name:'missing-visible-filter-expression-rejected',status:'PASSED'});
  for(const limit of [1,20,100,4000]){
    await page.setContent(`<input id="text-value" maxlength="${limit}" value="A">`);const input=page.locator('#text-value'),column={name:'TEXT_VALUE',data_type:'VARCHAR2',max_length:limit};
    for(const value of ['A','B','C','D','E','F']){await fillNativeQaValue(input,column,value);assert.equal(await input.inputValue(),value);}
    const probe=await probeNativeQaMaximumLength(input,column);assert.equal(probe.actual,'X'.repeat(limit));
    assert.equal(probe.evidence.mode,'browser_maxlength');assert.equal(probe.evidence.exact_boundary_input_accepted,true);assert.equal(probe.evidence.server_validation_proven,false);
    results.push({name:`clear-then-fill-varchar2-${limit}`,status:'PASSED'});
  }
  await page.setContent('<input id="text-value" maxlength="99" value="A">');
  await assert.rejects(()=>fillNativeQaValue(page.locator('#text-value'),{name:'TEXT_VALUE',data_type:'VARCHAR2',max_length:100},'B'));
  results.push({name:'wrong-declared-maxlength-rejected',status:'PASSED'});
  await page.setContent('<input id="text-value" maxlength="100" value="A" onbeforeinput="if(event.inputType===\'insertText\' &amp;&amp; event.data &amp;&amp; event.data.length>1)event.preventDefault()">');
  await assert.rejects(()=>probeNativeQaMaximumLength(page.locator('#text-value'),{name:'TEXT_VALUE',data_type:'VARCHAR2',max_length:100}));
  results.push({name:'unexpected-input-transformation-rejected',status:'PASSED'});
  const focusFixture=async()=>{
    await page.setContent('<input id="P2_TITLE" maxlength="100"><input id="P2_STATUS" maxlength="20"><input id="P2_AMOUNT"><input id="P2_DUE_DATE"><button id="date-popup-focus">Calendar</button>');
    await page.evaluate(()=>{
      const title=document.querySelector('#P2_TITLE'),status=document.querySelector('#P2_STATUS'),date=document.querySelector('#P2_DUE_DATE'),popup=document.querySelector('#date-popup-focus');
      let restorePending=false;window.__qaFocusFixture={steals:0,backspaces:0,events:[]};
      const mark=(kind,element,key=null)=>{const active=document.activeElement;window.__qaFocusFixture.events.push({
        sequence:window.__qaFocusFixture.events.length,timeMs:performance.now(),kind,field:element?.id||null,key,
        activeElementTag:active?.tagName||null,activeElementId:active?.id||null,
        valueLength:element?.tagName==='INPUT'?element.value.length:null,
        selectionStart:element?.selectionStart??null,selectionEnd:element?.selectionEnd??null});};
      date.addEventListener('blur',()=>{restorePending=true;mark('date-blur',date);});
      for(const input of [title,status]){
        input.addEventListener('focus',()=>{
          mark('text-focus',input);
          if(restorePending){
            restorePending=false;mark('restore-scheduled',input);
            // Model the observed event order, not Oracle's internal code:
            // restore only after the fill action's synchronous focus/select.
            queueMicrotask(()=>{mark('restore-started',input);window.__qaFocusFixture.steals++;popup.focus();mark('restore-completed',input);});
          }
        });
        input.addEventListener('blur',()=>mark('text-blur',input));
      }
      document.addEventListener('keydown',event=>{if(event.key==='Backspace')window.__qaFocusFixture.backspaces++;
        if(['Delete','Backspace'].includes(event.key))mark('keydown',event.target,event.key);});
    });
  };
  const fillFour=async()=>{for(const column of fixture.spec.columns.filter(column=>!column.primary_key)){
    const field={...column,max_length:column.length};const value=column.data_type==='VARCHAR2'?'A':column.data_type==='NUMBER'?'1':'2026-01-01';
    await fillNativeQaValue(page.locator(`#P2_${column.name}`),field,value);
  }};
  await focusFixture();await fillFour();await page.locator('#P2_TITLE').fill('');
  const oldFixture=await page.evaluate(()=>window.__qaFocusFixture),oldTimeline=JSON.stringify(oldFixture.events);
  assert.equal(await page.locator('#P2_TITLE').inputValue(),'A',oldTimeline);
  assert.equal(await page.evaluate(()=>document.activeElement.id),'date-popup-focus',oldTimeline);
  assert.equal(oldFixture.steals,1,oldTimeline);
  const dateBlur=oldFixture.events.findIndex(event=>event.kind==='date-blur');
  const textFocus=oldFixture.events.findIndex((event,index)=>index>dateBlur&&event.kind==='text-focus'&&event.field==='P2_TITLE');
  const scheduled=oldFixture.events.findIndex((event,index)=>index>textFocus&&event.kind==='restore-scheduled');
  const restored=oldFixture.events.findIndex((event,index)=>index>scheduled&&event.kind==='restore-completed');
  const missedDelete=oldFixture.events.findIndex((event,index)=>index>restored&&event.kind==='keydown'&&event.key==='Delete');
  assert.ok(dateBlur>=0&&textFocus>dateBlur&&scheduled>textFocus&&restored>scheduled&&missedDelete>restored,oldTimeline);
  assert.equal(oldFixture.events[missedDelete].activeElementId,'date-popup-focus',oldTimeline);
  results.push({name:'date-blur-focus-loss-reproduces-unguarded-clear',status:'PASSED',evidence:{restoration:'microtask-after-text-focus',title_retained:true,event_timeline:oldFixture.events}});
  await focusFixture();
  for(const name of ['TITLE','STATUS']){
    await fillFour();const column=fixture.spec.columns.find(column=>column.name===name);
    const probe=await probeNativeQaMaximumLength(page.locator(`#P2_${name}`),{...column,max_length:column.length});
    assert.equal(probe.actual,'X'.repeat(column.length));assert.equal(probe.evidence.exact_boundary_input_accepted,true);
  }
  const guardedFixture=await page.evaluate(()=>window.__qaFocusFixture),guardedTimeline=JSON.stringify(guardedFixture.events);
  assert.equal(guardedFixture.steals,2,guardedTimeline);
  for(const restore of guardedFixture.events.filter(event=>event.kind==='restore-completed')){
    const deletion=guardedFixture.events.find(event=>event.sequence>restore.sequence&&event.kind==='keydown'&&event.key==='Backspace');
    assert.ok(deletion,guardedTimeline);assert.equal(deletion.activeElementId,restore.field,guardedTimeline);
    assert.equal(deletion.selectionStart,0,guardedTimeline);assert.equal(deletion.selectionEnd,deletion.valueLength,guardedTimeline);
  }
  results.push({name:'verified-keyboard-clear-survives-date-blur-focus-loss',status:'PASSED',evidence:{both_boundaries_proven:true,event_timeline:guardedFixture.events}});
  // Initial value is fixture markup, not a DOM value/selection setter.
  await page.setContent('<input id="P2_TITLE" maxlength="100" value="A"><button id="other-focus">Other</button>');
  await page.evaluate(()=>{window.__qaBackspaces=0;document.querySelector('#P2_TITLE').addEventListener('focus',()=>document.querySelector('#other-focus').focus());document.addEventListener('keydown',event=>{if(event.key==='Backspace')window.__qaBackspaces++;});});
  await assert.rejects(()=>fillNativeQaValue(page.locator('#P2_TITLE'),{name:'TITLE',data_type:'VARCHAR2',max_length:100},'B'),/full active selection/);
  assert.equal(await page.locator('#P2_TITLE').inputValue(),'A');assert.equal(await page.evaluate(()=>window.__qaBackspaces),0);
  results.push({name:'wrong-focus-prevents-backspace',status:'PASSED'});
  await page.setContent('<input id="P2_TITLE" maxlength="100" value="A">');
  await page.evaluate(()=>{window.__qaBackspaces=0;document.querySelector('#P2_TITLE').addEventListener('keydown',event=>{if((event.ctrlKey||event.metaKey)&&event.key.toLowerCase()==='a')event.preventDefault();});document.addEventListener('keydown',event=>{if(event.key==='Backspace')window.__qaBackspaces++;});});
  await assert.rejects(()=>fillNativeQaValue(page.locator('#P2_TITLE'),{name:'TITLE',data_type:'VARCHAR2',max_length:100},'B'),/full active selection/);
  assert.equal(await page.locator('#P2_TITLE').inputValue(),'A');assert.equal(await page.evaluate(()=>window.__qaBackspaces),0);
  results.push({name:'partial-selection-prevents-backspace',status:'PASSED'});
  assert.equal(requests,0);
  console.log(JSON.stringify({status:'PASSED',scope:'offline-chromium-native-report-dom-regression',tests:results,network_requests:requests,apex_connections:0,business_write_actions:0}));
}finally{await browser.close();}
