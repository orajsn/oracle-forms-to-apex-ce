import test from 'node:test';
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {deriveNativeQaPlan, canonicalQaPlan, deriveNativeQaValues} from '../lib/contracts.mjs';

const RAW_SHA = 'a'.repeat(64);
const CASE_ORDER = [
  'login', 'create', 'search_positive', 'search_negative', 'reread', 'edit_save',
  'cancel_edit', 'cancel_create', 'required_fields', 'invalid_number',
  'invalid_date', 'maximum_length', 'concurrent_edit', 'browser_runtime_errors',
];
const ALL_EDITABLE_CASES = new Set(['create', 'reread', 'edit_save', 'cancel_edit', 'cancel_create']);
const UNIVERSAL = CASE_ORDER.filter(name => !['required_fields', 'invalid_number', 'invalid_date', 'maximum_length'].includes(name));
const PHASES = ['create', 'edit', 'cancel_edit', 'winner', 'stale', 'cancel_create'];
const digest = value => createHash('sha256').update(value).digest('hex');
const key = (name = 'ID') => ({name, label: 'ID', data_type: 'NUMBER', nullable: false, primary_key: true, identity: true});
const field = (name, data_type, nullable = false, length = 1, label = name) => ({
  name, label, data_type, nullable, primary_key: false, identity: false,
  ...(data_type === 'VARCHAR2' ? {length} : {}),
});
const spec = columns => ({profile_id: 'native-table-form-v1', data_mode: 'synthetic_test_only',
  table_name: 'FOX_NATIVE_QA_V2', columns, supported_operations: ['query', 'insert', 'update']});
const minimal = (type, nullable = false) => spec([key(), field('VALUE_COL', type, nullable)]);
const fiveColumns = () => spec([
  key(), field('TITLE', 'VARCHAR2', false, 100, 'Work title'),
  field('STATUS', 'VARCHAR2', false, 20, 'Status'),
  field('AMOUNT', 'NUMBER', false, undefined, 'Amount'),
  field('DUE_DATE', 'DATE', true, undefined, 'Due Date'),
]);
const byName = (plan, name) => plan.cases.find(item => item.name === name);

function expectedPlan(source, rawHash = RAW_SHA) {
  const pk = source.columns.find(column => column.primary_key);
  const editable = source.columns.filter(column => !column.primary_key);
  const names = editable.map(column => column.name);
  const rules = {
    required_fields: [editable.filter(column => !column.nullable).map(column => column.name), 'REQUIRED_EDITABLE_FIELDS', 'NO_REQUIRED_EDITABLE_FIELDS'],
    invalid_number: [editable.filter(column => column.data_type === 'NUMBER').map(column => column.name), 'EDITABLE_NUMBER_FIELDS', 'NO_EDITABLE_NUMBER_FIELDS'],
    invalid_date: [editable.filter(column => column.data_type === 'DATE').map(column => column.name), 'EDITABLE_DATE_FIELDS', 'NO_EDITABLE_DATE_FIELDS'],
    maximum_length: [editable.filter(column => column.data_type === 'VARCHAR2').map(column => column.name), 'BOUNDED_VARCHAR2_FIELDS', 'NO_EDITABLE_VARCHAR2_FIELDS'],
  };
  return {
    schema_version: 1, scope: 'fox-native-qa-plan-v2', profile_id: 'native-table-form-v1', native_spec_sha256: rawHash,
    primary_key: {name: pk.name, item_name: `P2_${pk.name}`, representation: 'decimal_string'},
    row_tracking: {mode: 'clean_empty_then_observed_pk', initial_row_count: 0}, edit_field: names[0],
    cases: CASE_ORDER.map(name => {
      if (rules[name]) {
        const [field_names, positive, negative] = rules[name];
        return {name, applicable: field_names.length > 0, field_names, reason_code: field_names.length ? positive : negative};
      }
      return {name, applicable: true, field_names: ALL_EDITABLE_CASES.has(name) ? [...names] : name === 'concurrent_edit' ? [names[0]] : [], reason_code: 'UNIVERSAL_NATIVE_FLOW'};
    }),
  };
}

test('five-column v2 plan has exact fourteen ordered cases, binding and PK tracking', () => {
  const source = fiveColumns();
  const plan = deriveNativeQaPlan(source, RAW_SHA);
  assert.deepEqual(plan, expectedPlan(source));
  assert.deepEqual(plan.cases.map(item => item.name), CASE_ORDER);
  assert.equal(plan.cases.filter(item => item.applicable).length, 14);
  assert.equal(new Set(plan.cases.map(item => item.name)).size, 14);
});

for (const [type, nullable, applicableCount] of [
  ['VARCHAR2', false, 12], ['VARCHAR2', true, 11],
  ['NUMBER', false, 12], ['NUMBER', true, 11],
  ['DATE', false, 12], ['DATE', true, 11],
]) {
  test(`minimal PK plus ${nullable ? 'nullable' : 'required'} ${type} is covered without a marker column`, () => {
    const source = minimal(type, nullable);
    const plan = deriveNativeQaPlan(source, RAW_SHA);
    assert.deepEqual(plan, expectedPlan(source));
    assert.equal(plan.cases.filter(item => item.applicable).length, applicableCount);
    for (const name of UNIVERSAL) assert.equal(byName(plan, name).applicable, true, name);
    for (const item of plan.cases.filter(item => !item.applicable)) {
      assert.deepEqual(item.field_names, []);
      assert.match(item.reason_code, /^NO_/);
    }
    if (type !== 'NUMBER') assert.equal(byName(plan, 'invalid_number').applicable, false, 'Identity NUMBER is not an editable number');
  });
}

test('all-nullable mixed editable columns do not make identity PK a required-field test', () => {
  const source = spec([key(), field('TXT', 'VARCHAR2', true), field('NUM', 'NUMBER', true), field('DAY', 'DATE', true)]);
  const plan = deriveNativeQaPlan(source, RAW_SHA);
  assert.deepEqual(plan, expectedPlan(source));
  assert.equal(plan.cases.filter(item => item.applicable).length, 13);
  assert.deepEqual(byName(plan, 'required_fields'), {name: 'required_fields', applicable: false, field_names: [], reason_code: 'NO_REQUIRED_EDITABLE_FIELDS'});
});

test('twenty columns, non-first custom PK and duplicate labels preserve all field coverage', () => {
  const columns = Array.from({length: 19}, (_, index) => field(`C${index + 1}`, ['VARCHAR2', 'NUMBER', 'DATE'][index % 3], index % 2 === 0, index % 2 ? 4000 : 1, 'Repeated label'));
  columns.splice(9, 0, {...key('ROW_KEY'), label: 'Repeated label'});
  const source = spec(columns);
  const plan = deriveNativeQaPlan(source, RAW_SHA);
  assert.deepEqual(plan, expectedPlan(source));
  assert.deepEqual(plan.primary_key, {name: 'ROW_KEY', item_name: 'P2_ROW_KEY', representation: 'decimal_string'});
  assert.equal(plan.edit_field, 'C1');
  for (const name of ALL_EDITABLE_CASES) assert.equal(byName(plan, name).field_names.length, 19);
  assert.equal(plan.cases.filter(item => item.applicable).length, 14);
});

test('applicability uses column names and exact metadata rather than label text', () => {
  const source = spec([key(), field('TEXT_COL', 'VARCHAR2', true, 1, 'Amount'), field('DAY_COL', 'DATE', false, undefined, 'Amount')]);
  assert.deepEqual(deriveNativeQaPlan(source, RAW_SHA), expectedPlan(source));
});

test('plan and values derivation leave caller-owned native metadata untouched', () => {
  const source = fiveColumns(); const before = structuredClone(source);
  const plan = deriveNativeQaPlan(source, RAW_SHA);
  for (const phase of PHASES) deriveNativeQaValues(source, phase);
  plan.cases[1].field_names.push('NOT_A_SOURCE_COLUMN');
  assert.deepEqual(source, before);
  assert.deepEqual(deriveNativeQaPlan(source, RAW_SHA), expectedPlan(source));
});

for (const [index, phase] of PHASES.entries()) {
  test(`${phase} fixtures use exact type-specific values and never supply identity PK`, () => {
    const source = fiveColumns();
    const text = String.fromCharCode(65 + index);
    const values = deriveNativeQaValues(source, phase);
    assert.deepEqual(values, {TITLE: text, STATUS: text, AMOUNT: String(index + 1), DUE_DATE: `2026-01-0${index + 1}`});
    assert.equal(Object.hasOwn(values, 'ID'), false);
    assert.ok(Object.values(values).every(value => typeof value === 'string'));
    for (const type of ['VARCHAR2', 'NUMBER', 'DATE']) {
      const value = deriveNativeQaValues(minimal(type), phase).VALUE_COL;
      assert.equal(value, type === 'VARCHAR2' ? text : type === 'NUMBER' ? String(index + 1) : `2026-01-0${index + 1}`);
    }
  });
}

for (const type of ['VARCHAR2', 'NUMBER', 'DATE']) {
  test(`${type} create/edit/cancel/winner/stale/cancel-create values are pairwise distinct`, () => {
    const values = PHASES.map(phase => deriveNativeQaValues(minimal(type), phase).VALUE_COL);
    assert.equal(new Set(values).size, 6);
    if (type === 'VARCHAR2') assert.ok(values.every(value => value.length === 1));
  });
}

test('canonical v2 plan has recursively sorted keys, no whitespace and a stable SHA fixture', () => {
  const source = minimal('VARCHAR2', true);
  const expected = expectedPlan(source);
  const actual = canonicalQaPlan(deriveNativeQaPlan(source, RAW_SHA));
  const canonicalObject = value => Array.isArray(value) ? value.map(canonicalObject) : value && typeof value === 'object'
    ? Object.fromEntries(Object.keys(value).sort().map(name => [name, canonicalObject(value[name])])) : value;
  assert.equal(actual, JSON.stringify(canonicalObject(expected)));
  assert.equal(digest(actual), '7918b4e960771d7c303c8567614658c42ea9dbc5864e1a1bbaf64386375b77f9');
  assert.equal(actual.includes('\n'), false);
  assert.equal(actual.includes('  '), false);
});

test('canonical plan is invariant to recursive object-key order, but preserves arrays', () => {
  const plan = expectedPlan(fiveColumns());
  const reverseKeys = value => Array.isArray(value) ? value.map(reverseKeys) : value && typeof value === 'object'
    ? Object.fromEntries(Object.keys(value).reverse().map(name => [name, reverseKeys(value[name])])) : value;
  const original = canonicalQaPlan(plan);
  assert.equal(canonicalQaPlan(reverseKeys(plan)), original);
  const reordered = structuredClone(plan); reordered.cases.reverse();
  assert.notEqual(canonicalQaPlan(reordered), original);
  const fields = structuredClone(plan); fields.cases.find(item => item.name === 'create').field_names.reverse();
  assert.notEqual(canonicalQaPlan(fields), original);
});

test('source-byte binding changes canonical plan digest even for identical parsed metadata', () => {
  const source = fiveColumns();
  const compact = digest(JSON.stringify(source)); const formatted = digest(JSON.stringify(source, null, 2));
  assert.notEqual(compact, formatted);
  const a = deriveNativeQaPlan(source, compact); const b = deriveNativeQaPlan(source, formatted);
  assert.equal(a.native_spec_sha256, compact); assert.equal(b.native_spec_sha256, formatted);
  assert.notEqual(digest(canonicalQaPlan(a)), digest(canonicalQaPlan(b)));
});

test('changing applicability or reason changes the canonical proof binding', () => {
  const plan = expectedPlan(minimal('DATE', true)); const original = digest(canonicalQaPlan(plan));
  const changed = structuredClone(plan); byName(changed, 'invalid_number').applicable = true;
  assert.notEqual(digest(canonicalQaPlan(changed)), original);
  const reason = structuredClone(plan); byName(reason, 'invalid_number').reason_code = 'OPERATOR_OVERRIDE';
  assert.notEqual(digest(canonicalQaPlan(reason)), original);
});

const corruptions = [
  ['wrong profile', value => {value.profile_id = 'legacy-html-prototype-v1';}],
  ['production mode', value => {value.data_mode = 'production';}],
  ['foreign table prefix', value => {value.table_name = 'CUSTOMER_TABLE';}],
  ['unsafe table identifier', value => {value.table_name = 'FOX_NATIVE_X;DROP';}],
  ['unsupported operation', value => {value.supported_operations = ['query', 'insert', 'update', 'delete'];}],
  ['arbitrary root code', value => {value.sql = 'select 1 from dual';}],
  ['missing columns', value => {delete value.columns;}],
  ['non-array columns', value => {value.columns = {};}],
  ['only primary key', value => {value.columns = [key()];}],
  ['twenty-one columns', value => {value.columns = [key(), ...Array.from({length: 20}, (_, i) => field(`C${i}`, 'NUMBER'))];}],
  ['duplicate column name', value => {value.columns[1].name = value.columns[0].name;}],
  ['unsafe column name', value => {value.columns[1].name = 'VALUE.COL';}],
  ['unsupported type', value => {value.columns[1].data_type = 'CLOB';}],
  ['string nullable', value => {value.columns[1].nullable = 'false';}],
  ['missing nullable', value => {delete value.columns[1].nullable;}],
  ['string primary-key flag', value => {value.columns[0].primary_key = 'true';}],
  ['string identity flag', value => {value.columns[0].identity = 'true';}],
  ['no primary key', value => {value.columns[0].primary_key = false; value.columns[0].identity = false;}],
  ['two identity keys', value => {value.columns.push(key('SECOND_ID'));}],
  ['nullable primary key', value => {value.columns[0].nullable = true;}],
  ['DATE primary key', value => {value.columns[0].data_type = 'DATE';}],
  ['nonidentity primary key', value => {value.columns[0].identity = false;}],
  ['nonkey identity', value => {value.columns.push({...field('EXTRA_NUM', 'NUMBER'), identity: true});}],
  ['missing label', value => {delete value.columns[1].label;}],
  ['empty label', value => {value.columns[1].label = '';}],
  ['arbitrary column code', value => {value.columns[1].default = 'sysdate';}],
  ['missing VARCHAR2 length', value => {delete value.columns[1].length;}],
  ['zero VARCHAR2 length', value => {value.columns[1].length = 0;}],
  ['oversize VARCHAR2 length', value => {value.columns[1].length = 4001;}],
  ['fractional VARCHAR2 length', value => {value.columns[1].length = 1.5;}],
  ['string VARCHAR2 length', value => {value.columns[1].length = '1';}],
  ['NUMBER with length', value => {value.columns[1].data_type = 'NUMBER';}],
];
for (const [name, mutate] of corruptions) {
  test(`rejects corrupted native metadata: ${name}`, () => {
    const source = minimal('VARCHAR2'); mutate(source);
    assert.throws(() => deriveNativeQaPlan(source, RAW_SHA));
    assert.throws(() => deriveNativeQaValues(source, 'create'));
  });
}

for (const badHash of [undefined, null, '', 'a'.repeat(63), 'a'.repeat(65), 'A'.repeat(64), 'z'.repeat(64), 12]) {
  test(`rejects invalid raw spec hash ${JSON.stringify(badHash)}`, () => {
    assert.throws(() => deriveNativeQaPlan(minimal('NUMBER'), badHash));
  });
}
for (const phase of [undefined, null, '', 'CREATE', 'delete', 1]) {
  test(`rejects unsupported fixture phase ${JSON.stringify(phase)}`, () => {
    assert.throws(() => deriveNativeQaValues(minimal('DATE'), phase));
  });
}
