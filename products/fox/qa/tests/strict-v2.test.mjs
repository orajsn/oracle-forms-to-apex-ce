import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {isHash,canonicalPrimaryKey,parseUniqueJson,parseNativeQaSpecBytes,deriveNativeQaProfile,assertNativeQaWriteAllowed} from '../lib/contracts.mjs';

const integerFields=['schema_version','application_id','max_evidence_age_seconds','application_count','user_object_count','native_table_count',
  'initial_row_count','row_count','reference_count','unexpected_schema_dependency_count','char_length','max_length','member_count'];
for(const field of integerFields) {
  test(`protocol integer ${field} rejects decimal/exponent/unsafe raw tokens at any depth`,()=>{
    for(const token of ['1.0','1e0','1E+0','9007199254740993'])assert.throws(()=>parseUniqueJson(`{"nested":[{"${field}":${token}}]}`));
    assert.equal(parseUniqueJson(`{"${field}":1}`)[field],1);
    assert.equal(parseUniqueJson(`{"${field}":0}`)[field],0);
  });
}
test('ordinary receipt float metrics remain valid without byte rewriting',()=>{
  const raw='{"elapsed_seconds":1.0,"cpu_seconds":1e0,"peak_memory_mib":1.25,"nested":{"duration_seconds":2.5e-1}}';
  const parsed=parseUniqueJson(Buffer.from(raw));
  assert.equal(parsed.elapsed_seconds,1);assert.equal(parsed.cpu_seconds,1);assert.equal(parsed.peak_memory_mib,1.25);
  assert.equal(parsed.nested.duration_seconds,0.25);
  assert.equal(raw,'{"elapsed_seconds":1.0,"cpu_seconds":1e0,"peak_memory_mib":1.25,"nested":{"duration_seconds":2.5e-1}}');
});
test('native VARCHAR2 length requires an integer token, not an integer-valued float',()=>{
  const source={profile_id:'native-table-form-v1',data_mode:'synthetic_test_only',table_name:'FOX_NATIVE_STRICT',columns:[
    {name:'ID',label:'ID',data_type:'NUMBER',nullable:false,primary_key:true,identity:true},
    {name:'TXT',label:'Text',data_type:'VARCHAR2',nullable:true,length:1}]};
  const raw=JSON.stringify(source);
  assert.equal(parseNativeQaSpecBytes(raw).columns[1].length,1);
  for(const token of ['1.0','1e0','1E+0','1.5','true'])assert.throws(()=>parseNativeQaSpecBytes(raw.replace('"length":1',`"length":${token}`)));
});
test('native write guard refuses all failure signals and unknown state',()=>{
  const state={stopped:false,browserErrors:[],networkDenials:[],unexpectedDialog:false};
  assert.doesNotThrow(()=>assertNativeQaWriteAllowed(state));
  for(const patch of [{stopped:true},{browserErrors:['unhandled']},{networkDenials:['denied']},{unexpectedDialog:true},
    {stopped:undefined},{browserErrors:null},{networkDenials:null},{unexpectedDialog:undefined}]) {
    assert.throws(()=>assertNativeQaWriteAllowed({...state,...patch}));
  }
});
test('QA derivability preserves bounded labels without granting producer approval',()=>{
  for(const label of ['  Exact  ','SELECT x FROM y','<b>','\u200b','\u2028','\u0000','   ',String.fromCodePoint(0x1fae9),String.fromCodePoint(0x1faea)]) {
    const source={profile_id:'native-table-form-v1',data_mode:'synthetic_test_only',table_name:'FOX_NATIVE_STRUCTURAL',columns:[
      {name:'ID',label:'ID',data_type:'NUMBER',nullable:false,primary_key:true,identity:true},
      {name:'TXT',label,data_type:'VARCHAR2',nullable:true,length:1}]};
    assert.equal(deriveNativeQaProfile(parseNativeQaSpecBytes(Buffer.from(JSON.stringify(source)))).fields[0].label,label);
  }
});
test('QA label UTF-8 canonicalization rejects lone surrogates but preserves astral scalars',()=>{
  for(const label of ['\ud800','\udfff']) {
    const source={profile_id:'native-table-form-v1',data_mode:'synthetic_test_only',table_name:'FOX_NATIVE_STRUCTURAL',columns:[
      {name:'ID',label:'ID',data_type:'NUMBER',nullable:false,primary_key:true,identity:true},
      {name:'TXT',label,data_type:'VARCHAR2',nullable:true,length:1}]};
    assert.throws(()=>parseNativeQaSpecBytes(Buffer.from(JSON.stringify(source))));
  }
});
test('exact protocol strings reject terminal line breaks accepted by a bare JS dollar anchor',()=>{
  for(const suffix of ['\n','\r','\r\n','\u2028','\u2029']) {
    assert.equal(isHash('a'.repeat(64)+suffix),false);
    assert.throws(()=>canonicalPrimaryKey('123'+suffix));
    for(const target of ['table_name','column_name']) {
      const source={profile_id:'native-table-form-v1',data_mode:'synthetic_test_only',table_name:'FOX_NATIVE_STRUCTURAL',columns:[
        {name:'ID',label:'ID',data_type:'NUMBER',nullable:false,primary_key:true,identity:true},
        {name:'TXT',label:'Text',data_type:'VARCHAR2',nullable:true,length:1}]};
      if(target==='table_name')source.table_name+=suffix;else source.columns[1].name+=suffix;
      assert.throws(()=>parseNativeQaSpecBytes(Buffer.from(JSON.stringify(source))));
    }
  }
});
test('v2 runner checks failure state before dispatch and again before every submit click',()=>{
  const source=readFileSync(new URL('../run-native.mjs',import.meta.url),'utf8');
  assert.match(source,/async function beginV2Attempt\(\) \{\s*assertV2WriteAllowed\(\);/);
  assert.match(source,/async function submit\(state,button,expectedValues=\{\}\) \{\s*if\(v2\)assertV2WriteAllowed\(\);/);
  assert.match(source,/persist\(v2\);\s*if\(v2\)assertV2WriteAllowed\(\);\s*await state\.page\.getByRole\('button',\{name:button,exact:true\}\)\.click\(\);/);
  assert.match(source,/check\(!v2\|\|process\.env\.FOX_QA_INSPECT_ONLY!=='1'/);
});
