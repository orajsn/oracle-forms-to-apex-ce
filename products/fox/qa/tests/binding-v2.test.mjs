import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {
  SCOPE, sha256, parseUniqueJson, parseNativeQaSpecBytes, validateTarget, deriveNativeQaProfile,
  deriveNativeQaPlan, deriveNativeQaValues, canonicalQaPlan, outcomeV2,
  canonicalPrimaryKey, samePrimaryKeySet,
} from '../lib/contracts.mjs';

// All evidence below is deliberately mocked in memory. It neither allocates a
// workspace nor asserts that these fixture receipts describe any live target.
const OPERATOR_FIXTURE = JSON.parse(readFileSync(new URL('../../fox/tests/fixtures/native-verification-profile-v2.json', import.meta.url), 'utf8'));
const HASH_KEYS = ['package_sha256', 'sql_sha256', 'native_spec_sha256', 'schema_script_sha256', 'source_manifest_sha256'];
const bytesHash = value => sha256(JSON.stringify(value) + '\n');
const baseSpec = () => ({
  profile_id: 'native-table-form-v1', data_mode: 'synthetic_test_only', table_name: 'FOX_NATIVE_BIND_V2',
  supported_operations: ['query', 'insert', 'update'],
  columns: [
    {name: 'ROW_KEY', label: 'Row key', data_type: 'NUMBER', nullable: false, primary_key: true, identity: true},
    {name: 'TINY', label: 'Tiny', data_type: 'VARCHAR2', length: 1, nullable: true, primary_key: false, identity: false},
  ],
});

function fixture(spec = baseSpec()) {
  const verification = structuredClone(OPERATOR_FIXTURE);
  const target = verification.target;
  const nativeHash = bytesHash(spec);
  const packageEvidence = {
    package_sha256: verification.binding.package_sha256,
    sql_sha256: '4'.repeat(64), native_spec_sha256: nativeHash,
    schema_script_sha256: '5'.repeat(64), source_manifest_sha256: verification.binding.source_manifest_sha256,
    nativeSpec: structuredClone(spec), releaseEvidence: {job_id: verification.binding.job_id},
  };
  const profile = deriveNativeQaProfile(spec);
  const profileHash = bytesHash(profile);
  const plan = deriveNativeQaPlan(spec, nativeHash);
  const receipt = {
    schema_version: 2, ...SCOPE, synthetic_qa_approved: true, clean_install: true,
    job_id: verification.binding.job_id, application_id: target.application_id, alias: target.application_alias,
    workspace: target.workspace, workspace_id: target.workspace_id, parsing_schema: target.parsing_schema,
    url: `${SCOPE.origin}/ords/r/${target.workspace.toLowerCase()}/${target.application_alias.toLowerCase()}/`,
    table_name: spec.table_name, profile_sha256: profileHash,
    verification_profile_sha256: bytesHash(verification), allocation_receipt_sha256: verification.binding.allocation_receipt_sha256,
    ...Object.fromEntries(HASH_KEYS.map(name => [name, packageEvidence[name]])),
    test_plan_sha256: sha256(canonicalQaPlan(plan)),
  };
  const imported = {
    schema_version: 2, scope: 'fox-clean-package-install-v2', passed: true,
    ...Object.fromEntries(['compartment_id', 'database_id', 'region', 'db_name', 'workspace', 'parsing_schema', 'workspace_id', 'application_id', 'job_id', 'verification_profile_sha256', 'allocation_receipt_sha256', ...HASH_KEYS].map(name => [name, receipt[name]])),
    application_alias: receipt.alias, application_url: receipt.url,
    table_name: spec.table_name, profile_id: spec.profile_id,
    clean_install: {
      passed: true, workspace_created_fresh: true, schema_created_fresh: true,
      before_install: {passed: true, application_count: 0, user_object_count: 0},
      after_install: {passed: true, application_count: 1, native_table_count: 1, initial_row_count: 0},
    },
    table_metadata: {
      passed: true, schema: receipt.parsing_schema, table_name: spec.table_name, row_count: 0, unexpected_schema_dependency_count: 0,
      columns: spec.columns.map(column => ({name: column.name, data_type: column.data_type, nullable: column.nullable,
        char_length: column.data_type === 'VARCHAR2' ? column.length : 0, identity: column.identity === true})),
      primary_key: {columns: [profile.primary_key], status: 'ENABLED', validated: 'VALIDATED'},
    },
    observed_versions: structuredClone(verification.expected_versions),
    no_original_schema_dependencies: {passed: true, original_schema: 'FORMS2APEX_POC', reference_count: 0},
  };
  const artifacts = {
    nativeSpec: {value: structuredClone(spec), sha256: nativeHash},
    verificationProfile: {value: verification, sha256: receipt.verification_profile_sha256},
    importReceipt: {value: imported, sha256: bytesHash(imported)}, packageEvidence,
  };
  receipt.import_receipt_sha256 = artifacts.importReceipt.sha256;
  return {receipt, profile, profileHash, artifacts, plan};
}
const validate = value => validateTarget(value.receipt, value.profile, value.profileHash, value.artifacts.packageEvidence.package_sha256, value.artifacts);
function rehashImport(value) {
  value.artifacts.importReceipt.sha256 = bytesHash(value.artifacts.importReceipt.value);
  value.receipt.import_receipt_sha256 = value.artifacts.importReceipt.sha256;
}
function rehashVerification(value) {
  value.artifacts.verificationProfile.sha256 = bytesHash(value.artifacts.verificationProfile.value);
  value.receipt.verification_profile_sha256 = value.artifacts.verificationProfile.sha256;
  value.artifacts.importReceipt.value.verification_profile_sha256 = value.receipt.verification_profile_sha256;
  rehashImport(value);
}

test('v2 binds exact mounted bytes, derived profile, metadata and applicability plan', () => {
  const value = fixture(); const bound = validate(value);
  assert.equal(bound.bindingScope, 'exact-package-clean-install-v2');
  assert.equal(bound.targetUrl, value.receipt.url);
  assert.equal(bound.packageBound, true); assert.equal(bound.cleanInstallBound, true);
  assert.deepEqual(bound.plan, value.plan);
  assert.equal(bound.plan.cases.filter(item => item.applicable).length, 11);
  assert.equal(bound.plan.primary_key.representation, 'decimal_string');
});

for (const [name, artifact] of [['native_spec', 'nativeSpec'], ['verification_profile', 'verificationProfile'], ['import_receipt', 'importReceipt']]) {
  test(`v2 rejects missing ${artifact} bytes`, () => {
    const value = fixture(); delete value.artifacts[artifact]; assert.throws(() => validate(value));
  });
  test(`v2 rejects altered mounted ${artifact} byte digest`, () => {
    const value = fixture(); value.artifacts[artifact].sha256 = 'f'.repeat(64); assert.throws(() => validate(value));
  });
  for (const invalid of [null, undefined, '', 'not-a-sha256']) {
    test(`v2 rejects ${name} expected/mounted hash ${JSON.stringify(invalid)}`, () => {
      const value = fixture(); value.receipt[`${name}_sha256`] = invalid; value.artifacts[artifact].sha256 = invalid;
      if (name === 'verification_profile') value.artifacts.importReceipt.value.verification_profile_sha256 = invalid;
      assert.throws(() => validate(value));
    });
  }
}

for (const name of HASH_KEYS) {
  test(`v2 rejects mismatched package binding ${name}`, () => {
    const value = fixture(); value.artifacts.packageEvidence[name] = 'f'.repeat(64); assert.throws(() => validate(value));
  });
  test(`v2 rejects clean receipt binding ${name} even after its raw hash is refreshed`, () => {
    const value = fixture(); value.artifacts.importReceipt.value[name] = 'e'.repeat(64); rehashImport(value); assert.throws(() => validate(value));
  });
}

for (const [name, invalid] of [
  ['compartment_id', 'other'], ['database_id', 'other'], ['region', 'ap-singapore-1'], ['db_name', 'CUSTOMER'],
  ['workspace', 'FORMS2APEX_POC'], ['parsing_schema', 'OTHER'], ['workspace_id', 22042420337195501],
  ['application_id', 0], ['alias', 'F2A_DIFFERENT'], ['table_name', 'FOX_NATIVE_DIFFERENT'],
  ['clean_install', 'true'], ['synthetic_qa_approved', 1], ['job_id', 'fox-bbbbbbbbbbbbbbbbbbbb'],
]) {
  test(`v2 rejects target identity or approval tamper ${name}`, () => {
    const value = fixture(); value.receipt[name] = invalid; assert.throws(() => validate(value));
  });
}
for (const name of ['compartment_id', 'database_id', 'region', 'db_name']) {
  test(`v2 rejects foreign operator allocation ${name} even when the mounted profile hash matches`, () => {
    const value = fixture(); value.artifacts.verificationProfile.value.target[name] = 'other'; rehashVerification(value); assert.throws(() => validate(value));
  });
}

test('v2 rejects malformed namespace even when target and clean receipt agree', () => {
  const value = fixture();
  for (const object of [value.receipt, value.artifacts.importReceipt.value, value.artifacts.verificationProfile.value.target]) {
    object.workspace = 'CUSTOMER'; object.parsing_schema = 'CUSTOMER';
  }
  rehashVerification(value); assert.throws(() => validate(value));
});
test('v2 checks allocated receipt bytes when explicitly mounted', () => {
  const value = fixture();
  value.artifacts.allocationReceipt = {value: {}, sha256: value.receipt.allocation_receipt_sha256};
  assert.equal(validate(value).cleanInstallBound, true);
  value.artifacts.allocationReceipt.sha256 = 'f'.repeat(64); assert.throws(() => validate(value));
});
test('v2 rejects foreign URLs and identity-bearing query strings', () => {
  for (const url of ['https://example.test/', 'http://asz8eqwfm8unca2-jsnf2apex.adb.us-ashburn-1.oraclecloudapps.com/',
    `${fixture().receipt.url}?session=123`, `${fixture().receipt.url}#fragment`]) {
    const value = fixture(); value.receipt.url = url; assert.throws(() => validate(value));
  }
});

test('v2 field profile is derived, not an operator escape hatch', () => {
  const mutations = [
    profile => {profile.fields[0].required = true;}, profile => {profile.fields[0].max_length = 40;},
    profile => {profile.fields[0].valid_value = 'OPERATOR';}, profile => {profile.marker_field = 'TINY';},
    profile => {profile.database_constraints.push({field: 'TINY', invalid_value: 'Q', expected_error: 'check constraint'});},
    profile => {profile.primary_key = 'TINY';},
  ];
  for (const mutate of mutations) {
    const value = fixture(); mutate(value.profile); value.profileHash = bytesHash(value.profile); value.receipt.profile_sha256 = value.profileHash;
    assert.throws(() => validate(value));
  }
});
test('v2 rejects plan digest tampering and mismatched packaged native spec', () => {
  const value = fixture(); value.receipt.test_plan_sha256 = 'f'.repeat(64); assert.throws(() => validate(value));
  const other = fixture(); other.artifacts.packageEvidence.nativeSpec.columns[1].nullable = false; assert.throws(() => validate(other));
});

for (const [name, mutate] of [
  ['install failure', imported => {imported.passed = false;}],
  ['nonboolean install', imported => {imported.passed = 1;}],
  ['unproven fresh workspace', imported => {imported.clean_install.workspace_created_fresh = null;}],
  ['existing initial app', imported => {imported.clean_install.before_install.application_count = 1;}],
  ['preexisting user object', imported => {imported.clean_install.before_install.user_object_count = 1;}],
  ['two installed apps', imported => {imported.clean_install.after_install.application_count = 2;}],
  ['two native tables', imported => {imported.clean_install.after_install.native_table_count = 2;}],
  ['initial rows', imported => {imported.clean_install.after_install.initial_row_count = 1;}],
  ['string zero rows', imported => {imported.clean_install.after_install.initial_row_count = '0';}],
  ['metadata nonempty table', imported => {imported.table_metadata.row_count = 1;}],
  ['metadata dependency', imported => {imported.table_metadata.unexpected_schema_dependency_count = 1;}],
  ['wrong table schema', imported => {imported.table_metadata.schema = 'FORMS2APEX_POC';}],
  ['wrong column nullable', imported => {imported.table_metadata.columns[1].nullable = false;}],
  ['wrong column width', imported => {imported.table_metadata.columns[1].char_length = 2;}],
  ['wrong key identity', imported => {imported.table_metadata.columns[0].identity = false;}],
  ['disabled primary key', imported => {imported.table_metadata.primary_key.status = 'DISABLED';}],
  ['wrong primary key', imported => {imported.table_metadata.primary_key.columns = ['TINY'];}],
  ['original schema reference', imported => {imported.no_original_schema_dependencies.reference_count = 1;}],
]) {
  test(`v2 rejects clean metadata tamper: ${name}`, () => {
    const value = fixture(); mutate(value.artifacts.importReceipt.value); rehashImport(value); assert.throws(() => validate(value));
  });
}

for (const name of ['apex', 'sqlcl', 'database', 'mmd']) {
  test(`v2 ${name} must match the operator version`, () => {
    const value = fixture(); value.artifacts.importReceipt.value.observed_versions[name] = 'other'; rehashImport(value); assert.throws(() => validate(value));
  });
  for (const invalid of ['unknown', null, ['26.1.5']]) {
    test(`v2 rejects malformed approved and observed ${name} ${JSON.stringify(invalid)}`, () => {
      const value = fixture(); value.artifacts.verificationProfile.value.expected_versions[name] = invalid;
      value.artifacts.importReceipt.value.observed_versions[name] = invalid;
      rehashVerification(value); assert.throws(() => validate(value));
    });
  }
}

test('v2 permits non-BMP labels up to 80 codepoints, not UTF-16 units', () => {
  const source = baseSpec(); source.columns[1].label = '\u{1F680}'.repeat(80);
  assert.equal(source.columns[1].label.length, 160);
  assert.equal(validate(fixture(source)).cleanInstallBound, true);
  source.columns[1].label += '\u{1F680}';
  assert.throws(() => deriveNativeQaPlan(source, 'a'.repeat(64)));
});
test('optional nonkey flags omitted mean false; explicit null never means omitted', () => {
  const source = baseSpec(); delete source.columns[1].primary_key; delete source.columns[1].identity;
  assert.equal(validate(fixture(source)).cleanInstallBound, true);
  for (const name of ['primary_key', 'identity']) {
    const corrupted = structuredClone(source); corrupted.columns[1][name] = null;
    assert.throws(() => deriveNativeQaPlan(corrupted, 'a'.repeat(64)));
    assert.throws(() => deriveNativeQaValues(corrupted, 'create'));
  }
});
test('derived labels preserve exact source strings and source byte binding', () => {
  const source = baseSpec(); source.columns[1].label = '  Tiny  ';
  const value = fixture(source); assert.equal(value.profile.fields[0].label, '  Tiny  ');
  assert.equal(validate(value).nativeSpec.columns[1].label, '  Tiny  ');
});

test('v2 runner addresses actual named DATE/text/number inputs and intersects accessible labels', () => {
  const source = readFileSync(new URL('../run-native.mjs', import.meta.url), 'utf8');
  assert.match(source, /return v2\?page\.locator\(`input\[name="P2_\$\{column\.name\}"\]`\)/);
  assert.match(source, /page\.getByLabel\(column\.label,\{exact:true\}\)\.and\(input\)\.count\(\)===1/);
  assert.doesNotMatch(source, /return v2\?page\.locator\(`#P2_/);
  assert.doesNotMatch(source, /input\.evaluate\([^\n]*\.labels/);
  assert.match(source, /input\[name="P2_\$\{profile\.primary_key\}"\]/);
});

function passingCases(plan) {
  return plan.cases.map(item => ({...structuredClone(item), required: item.applicable,
    status: item.applicable ? 'PASSED' : 'NOT_APPLICABLE',
    field_results: item.field_names.map(field_name => ({field_name, status: 'PASSED'}))}));
}
test('v2 coverage explicitly distinguishes eleven passes and three not-applicable cases', () => {
  const value = fixture(); const cases = passingCases(value.plan);
  assert.equal(cases.filter(item => item.status === 'PASSED').length, 11);
  assert.equal(cases.filter(item => item.status === 'NOT_APPLICABLE').length, 3);
  assert.equal(outcomeV2(cases, value.plan), 'PASSED');
});
for (const [name, mutate] of [
  ['missing case', cases => {cases.pop();}],
  ['duplicate case', cases => {cases[1] = {...cases[0]};}],
  ['applicable marked N/A', cases => {cases.find(item => item.name === 'create').status = 'NOT_APPLICABLE';}],
  ['missing field result', cases => {cases.find(item => item.name === 'create').field_results = [];}],
  ['wrong field result', cases => {cases.find(item => item.name === 'create').field_results[0].field_name = 'ROW_KEY';}],
  ['N/A marked passed', cases => {cases.find(item => item.name === 'invalid_number').status = 'PASSED';}],
  ['N/A left unrun', cases => {cases.find(item => item.name === 'invalid_number').status = 'NOT_RUN';}],
  ['reason override', cases => {cases.find(item => item.name === 'invalid_number').reason_code = 'OPERATOR';}],
  ['applicability override', cases => {cases.find(item => item.name === 'create').applicable = false;}],
  ['required override', cases => {cases.find(item => item.name === 'create').required = false;}],
  ['extra unplanned check', cases => {cases.push({name: 'other', status: 'PASSED'});}],
]) {
  test(`v2 coverage refuses ${name}`, () => {
    const value = fixture(); const cases = passingCases(value.plan); mutate(cases);
    assert.equal(outcomeV2(cases, value.plan), 'INCOMPLETE');
  });
}
test('any attempted failure prevents a v2 pass, including a claimed nonapplicable case', () => {
  const value = fixture(); const cases = passingCases(value.plan);
  cases.find(item => item.name === 'invalid_number').status = 'FAILED';
  assert.equal(outcomeV2(cases, value.plan), 'FAILED');
});

test('primary keys remain exact decimal strings above Number.MAX_SAFE_INTEGER', () => {
  const large = '9007199254740993'; const adjacent = '9007199254740992'; const max = '9'.repeat(38);
  assert.equal(canonicalPrimaryKey(large), large); assert.equal(canonicalPrimaryKey(max), max);
  assert.equal(samePrimaryKeySet([large], [large]), true);
  assert.equal(samePrimaryKeySet([large], [adjacent]), false);
  assert.equal(samePrimaryKeySet([large, adjacent], [adjacent, large]), true);
  assert.equal(samePrimaryKeySet([large, large], [large, adjacent]), false);
});
for (const invalid of [9007199254740993, 1, 1n, '0', '-1', '01', '1.0', '1e3', '1,000', ' 1', '1 ', '9'.repeat(39), null, undefined]) {
  test(`primary key rejects noncanonical ${String(invalid)} (${typeof invalid})`, () => {
    assert.throws(() => canonicalPrimaryKey(invalid));
  });
}
test('PK sets reject duplicates, missing rows and extra rows without unsafe numeric conversion', () => {
  assert.equal(samePrimaryKeySet([], []), true);
  assert.equal(samePrimaryKeySet(['1'], []), false);
  assert.equal(samePrimaryKeySet([], ['1']), false);
  assert.equal(samePrimaryKeySet(['1', '2'], ['1']), false);
  assert.equal(samePrimaryKeySet(['1'], ['1', '1']), false);
  assert.throws(() => samePrimaryKeySet([1], ['1']));
});

test('unique JSON preserves exact string IDs and permits nested primitive values', () => {
  const value = parseUniqueJson(Buffer.from('{"workspace_id":"22042420337195501","items":[true,false,null,-1.25e2,"a\\\"b"]}'));
  assert.equal(value.workspace_id, '22042420337195501');
  assert.deepEqual(value.items, [true, false, null, -125, 'a"b']);
});
test('unique JSON treats prototype-looking keys as inert own data', () => {
  const value = parseUniqueJson('{"__proto__":{"polluted":true},"constructor":1}');
  assert.equal(Object.getPrototypeOf(value), null);
  assert.equal(Object.hasOwn(value, '__proto__'), true);
  assert.equal(value.__proto__.polluted, true);
  assert.equal({}.polluted, undefined);
});
for (const raw of [
  '{"a":1,"a":2}', '{"a":1,"\\u0061":2}', '{"outer":{"a":1,"a":2}}',
  '{"a":1,}', '[1,]', '{a:1}', '[01]', '[1.]', '[+1]', '[NaN]', '[Infinity]', '[1e999]',
  '{"a":true} trailing', 'true false', '{"a":}', '{"a" 1}', '{"a":"unterminated}',
  '"bad\\q"', '"literal\nnewline"', '[', '{', '', '\uFEFF{}',
]) {
  test(`unique JSON rejects malformed or duplicate input ${JSON.stringify(raw)}`, () => {
    assert.throws(() => parseUniqueJson(raw));
  });
}
test('unique JSON rejects invalid UTF-8 and excessive nesting', () => {
  assert.throws(() => parseUniqueJson(Buffer.from([0x7b, 0x22, 0xff, 0x22, 0x3a, 0x31, 0x7d])));
  assert.throws(() => parseUniqueJson('['.repeat(66) + '0' + ']'.repeat(66)));
  assert.deepEqual(parseUniqueJson('[[0]]'), [[0]]);
});

// Shared immutable data is also consumed by the independent Python release-gate
// suite. Hash exact UTF-8 source strings before either implementation parses them.
const PARITY = parseUniqueJson(readFileSync(new URL('../../fox/tests/fixtures/native-qa-plan-v2-vectors.json', import.meta.url)));
test('shared Python/JavaScript native QA parity corpus is versioned and nonempty', () => {
  assert.equal(PARITY.schema_version, 1);
  assert.equal(PARITY.scope, 'fox-native-qa-plan-v2-parity-vectors');
  assert.ok(Array.isArray(PARITY.vectors) && PARITY.vectors.length >= 32);
  assert.equal(new Set(PARITY.vectors.map(item => item.name)).size, PARITY.vectors.length);
});
for (const vector of PARITY.vectors) {
  test(`shared native QA parity vector: ${vector.name}`, () => {
    assert.equal(typeof vector.derivable, 'boolean');
    const raw = Buffer.from(vector.spec_json, 'utf8');
    assert.equal(sha256(raw), vector.native_spec_sha256, 'Exact source-byte identity differs');
    if (!vector.derivable) {
      assert.throws(() => parseNativeQaSpecBytes(raw));
      return;
    }
    const source = parseNativeQaSpecBytes(raw);
    const plan = deriveNativeQaPlan(source, vector.native_spec_sha256);
    const profile = deriveNativeQaProfile(source);
    assert.equal(sha256(canonicalQaPlan(plan)), vector.plan_sha256, 'Canonical JavaScript/Python plan digest differs');
    assert.equal(sha256(canonicalQaPlan(profile)), vector.profile_sha256, 'Canonical JavaScript/Python profile digest differs');
  });
}
