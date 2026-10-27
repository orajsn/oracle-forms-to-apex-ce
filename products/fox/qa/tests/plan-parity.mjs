// Optional local cross-language audit, separate from dependency-free Node tests.
// Runs only deterministic Python/JavaScript validators; no targets or SQL.
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {fileURLToPath} from 'node:url';
import {spawnSync} from 'node:child_process';
import {sha256,parseNativeQaSpecBytes,deriveNativeQaPlan,deriveNativeQaProfile,canonicalQaPlan} from '../lib/contracts.mjs';

const root=fileURLToPath(new URL('../../',import.meta.url));
const corpus=JSON.parse(readFileSync(new URL('../../fox/tests/fixtures/native-qa-plan-v2-vectors.json',import.meta.url),'utf8'));
const makeSpec=(count,type,nullable,keyAtEnd=false,label='Value')=>{
  const key={name:'ROW_KEY',label:'Row key',data_type:'NUMBER',nullable:false,primary_key:true,identity:true};
  const fields=Array.from({length:count},(_,index)=>({name:`VALUE_${index+1}`,label,data_type:type,nullable,
    ...(type==='VARCHAR2'?{length:index%2?4000:1}:{})}));
  return{profile_id:'native-table-form-v1',data_mode:'synthetic_test_only',table_name:'FOX_NATIVE_PARITY',
    columns:keyAtEnd?[...fields,key]:[key,...fields]};
};
const vectors=[];
for(let count=1;count<=19;count++)for(const type of ['NUMBER','VARCHAR2','DATE'])for(const nullable of [true,false])for(const keyAtEnd of [true,false]) {
  vectors.push({name:`width-${count+1}-${type}-${nullable}-${keyAtEnd}`,spec_json:JSON.stringify(makeSpec(count,type,nullable,keyAtEnd))});
}
const labels=[
  'Value',' Same ','明細','🚀'.repeat(80),'🚀'.repeat(81),'e\u0301','\u0301SELECT x FROM y','éSELECT x FROM y',
  'SELECT x FROM yé','_SELECT x FROM y','SELECT x FROM y_','ⅧSELECT x FROM y','²SELECT x FROM y','SELECT x FROM y²',
  'SELECT x FROM y','select x from y','ſelect x from y','ſelect x froM y','INSERT INTO x','İNSERT INTO x','ınsert into x',
  'UPDATE x SET y','DELETE FROM x','CREATE TABLE x','ALTER VIEW x','DROP INDEX x','EXECUTE IMMEDIATE x','BEGIN x END',
  String.fromCodePoint(0x1faea),'SELECTx FROM y',String.fromCodePoint(0x1fae0),String.fromCodePoint(0x1fae8),String.fromCodePoint(0x1fae9),' Value ','\u3000Value\u3000','\u2007Value\u2007',
  '','   ','line\nbreak','hidden\u200bcontrol','line\u2028break','line\u2029break','<b>','semi;colon','comment--x','open/*x','brace{x}','ticks`x',
];
assert.equal(labels.length,48);
for(const [index,label] of labels.entries())for(const type of ['NUMBER','VARCHAR2','DATE'])for(const nullable of [true,false]) {
  vectors.push({name:`label-${index}-${type}-${nullable}`,spec_json:JSON.stringify(makeSpec(1,type,nullable,false,label))});
}
assert.equal(vectors.length,516);
const all=[...corpus.vectors,...vectors];
const program=String.raw`
import hashlib,json,sys,unicodedata
sys.stdin.reconfigure(encoding='utf-8')
sys.stdout.reconfigure(encoding='utf-8')
sys.path.insert(0,sys.argv[1]+'/fox')
from fox.native_qa_plan import derive_native_qa_plan,derive_native_qa_profile,qa_plan_sha256
def unique(pairs):
    value={}
    for key,item in pairs:
        if key in value: raise ValueError('duplicate')
        value[key]=item
    return value
def reject_constant(value): raise ValueError('nonfinite')
results=[]
for item in json.load(sys.stdin):
    try:
        raw=item['spec_json'].encode('utf-8')
        spec=json.loads(raw,object_pairs_hook=unique,parse_constant=reject_constant)
        plan=derive_native_qa_plan(spec,hashlib.sha256(raw).hexdigest())
        profile=derive_native_qa_profile(spec)
        results.append({'accepted':True,'plan_sha256':qa_plan_sha256(plan),'profile_sha256':qa_plan_sha256(profile)})
    except (ValueError,TypeError,UnicodeError): results.append({'accepted':False})
print(json.dumps({'python_version':sys.version.split()[0],'python_unicode_version':unicodedata.unidata_version,'results':results},separators=(',',':')))
`;
const python=process.env.FOX_QA_TEST_PYTHON||'python';
const result=spawnSync(python,['-c',program,root],{input:JSON.stringify(all),encoding:'utf8',timeout:120000,maxBuffer:8*1024*1024,
  env:{...process.env,PYTHONDONTWRITEBYTECODE:'1'}});
assert.equal(result.error,undefined,result.error?.message);
assert.equal(result.status,0,result.stderr);
const pythonResult=JSON.parse(result.stdout),expected=pythonResult.results;assert.equal(expected.length,all.length);
let accepted=0;
for(const [index,vector] of all.entries()) {
  let actual;
  try {
    const raw=Buffer.from(vector.spec_json,'utf8'),spec=parseNativeQaSpecBytes(raw);
    actual={accepted:true,plan_sha256:sha256(canonicalQaPlan(deriveNativeQaPlan(spec,sha256(raw)))),profile_sha256:sha256(canonicalQaPlan(deriveNativeQaProfile(spec)))};
  }catch{actual={accepted:false};}
  assert.deepEqual(actual,expected[index],`JavaScript/Python mismatch: ${vector.name}`);
  if(Object.hasOwn(vector,'derivable'))assert.equal(actual.accepted,vector.derivable,`Shared structural derivability drift: ${vector.name}`);
  if(actual.accepted)accepted++;
}
console.log(JSON.stringify({status:'PASSED',scope:'structural-qa-derivation-not-package-authorization',node_unicode_version:process.versions.unicode,
  python_version:pythonResult.python_version,python_unicode_version:pythonResult.python_unicode_version,
  shared_raw_vectors:corpus.vectors.length,derived_vectors:vectors.length,total:all.length,derivable:accepted,rejected:all.length-accepted}));
