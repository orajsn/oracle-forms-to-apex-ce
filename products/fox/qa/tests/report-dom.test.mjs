import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {nativeReportPrimaryKeysFromTables,nativeFilterControl} from '../lib/contracts.mjs';
const fixture=JSON.parse(readFileSync(new URL('./fixtures/native-report-sticky-header.json',import.meta.url)));
const actual=()=>structuredClone(fixture.tables[1]);
test('observed APEX sticky clone and original TBODY header/data rows yield only the actual PK',()=>{
  assert.deepEqual(nativeReportPrimaryKeysFromTables(fixture.tables,fixture.spec),['1']);
});
test('nonsticky data table and a large exact decimal PK remain supported',()=>{
  const table=actual();table.rows[1][1].text='9007199254740993';
  assert.deepEqual(nativeReportPrimaryKeysFromTables([table],fixture.spec),['9007199254740993']);
});
for(const [name,mutate] of [
  ['duplicate actual tables',tables=>tables.push(actual())],
  ['missing actual table',tables=>tables.pop()],
  ['missing header',tables=>tables[1].rows.shift()],
  ['duplicate header',tables=>tables[1].rows.push(structuredClone(tables[1].rows[0]))],
  ['duplicate primary key',tables=>tables[1].rows.push(structuredClone(tables[1].rows[1]))],
  ['wrong header order',tables=>tables[1].rows[0][2].text='Other'],
  ['wrong data width',tables=>tables[1].rows[1].pop()],
  ['mixed header/data row',tables=>tables[1].rows[1][0].tag='TH'],
  ['data hidden in sticky clone',tables=>tables[0].rows.push(structuredClone(tables[1].rows[1]))],
  ['unsafe numeric key coercion',tables=>tables[1].rows[1][1].text='1.0'],
])test(`report reader rejects ${name}`,()=>{const tables=structuredClone(fixture.tables);mutate(tables);assert.throws(()=>nativeReportPrimaryKeysFromTables(tables,fixture.spec));});
test('runner keeps existing stable reset/readiness barriers and does not use first-table selection',()=>{
  const source=readFileSync(new URL('../run-native.mjs',import.meta.url),'utf8');
  assert.match(source,/return readNativeReportPrimaryKeys\(state.page,spec\)/);
  assert.match(source,/await resetReport\(state\);const actual=await reportKeys\(state\)/);
  assert.doesNotMatch(source,/table\.locator\('thead th'\)|table\.locator\('tbody tr'\)/);
});
for(const name of ['Column','Operator','Expression'])test(`native filter ${name} intersects the exact label with one visible control`,async()=>{
  const selections=[];const locator={count:async()=>1};
  const dialog={getByLabel:(label,options)=>{assert.equal(label,name);assert.equal(options.exact,true);return{and:other=>{assert.equal(other,'visible-selection');return locator;}};},
    locator:selector=>{selections.push(selector);return'visible-selection';}};
  assert.equal(await nativeFilterControl(dialog,name),locator);
  assert.deepEqual(selections,[name==='Expression'?'input:visible':'select:visible']);
});
for(const count of [0,2,5])test(`native filter refuses ${count} visible candidates instead of choosing first`,async()=>{
  const dialog={getByLabel:()=>({and:()=>({count:async()=>count})}),locator:()=>({})};
  await assert.rejects(()=>nativeFilterControl(dialog,'Operator'));
});
test('runner resolves expression only after selecting the exact operator',()=>{
  const source=readFileSync(new URL('../run-native.mjs',import.meta.url),'utf8');
  assert.match(source,/operator=await nativeFilterControl\(dialog,'Operator'\);await operator\.selectOption\(\{label:'='\}\);\s*const expression=await nativeFilterControl\(dialog,'Expression'\)/);
});
