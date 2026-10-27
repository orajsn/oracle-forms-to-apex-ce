// Labelled synthetic input only. No browser, provider or database operation.
import {readFileSync} from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {ORIGIN,INSTANCE,FIXTURE_FILES,SOURCE_SHA,sha,receiptHash} from '../live.mjs';
export const ROOT=fileURLToPath(new URL('../../../',import.meta.url));
export const NOW=Date.parse('2026-10-27T00:00:00.000Z');
export function reseal(input){const p=input.preflight;delete p.receipt_sha256;p.receipt_sha256=receiptHash(p);return input;}
export function fixture(){
 const source=JSON.parse(readFileSync(new URL('../fixtures/ordinary-two-form.json',import.meta.url),'utf8'));
 if(source.schema_version!==1||source.scope!=='fox-synthetic-project-sources-v1'||!source.files||Object.keys(source.files).length!==4)
  throw new Error('BUNDLED_SYNTHETIC_SOURCE_REQUIRED');
 const files=Object.entries(FIXTURE_FILES).map(([name,sha256])=>{
  if(typeof source.files[name]!=='string')throw new Error('BUNDLED_SYNTHETIC_SOURCE_REQUIRED');
  const raw=Buffer.from(source.files[name],'utf8');if(sha(raw)!==sha256)throw new Error('SYNTHETIC_FIXTURE_BYTES_CHANGED');
  return {name,sha256,base64:raw.toString('base64')};});
 return reseal({schema_version:1,scope:'fox-live-project-journey-input-v1',mode:'live',apply:true,origin:ORIGIN,
  attempt_id:'live-'+'f'.repeat(24),output_dir:path.resolve(os.tmpdir(),'synthetic-fox-node-output'),
  credentials:{username:'synthetic-observer',password:'SyntheticOnlyPassword-'+ 'q'.repeat(30)},
  project:{customer:'Synthetic UI engineering',name:'Synthetic Two Form Test',description:'Synthetic sources only. No customer or production records.'},
  files,source_manifest_sha256:SOURCE_SHA,expected_forms:['ALPHA','BETA'],
  preflight:{schema_version:1,scope:'fox-live-project-preflight-v1',observed_at_utc:new Date(NOW).toISOString(),
   source_bundle_sha256:'1'.repeat(64),release_sha256:'2'.repeat(64),provider_sha256:'3'.repeat(64),admission_sha256:'4'.repeat(64),
   images:{fox:'sha256:'+'5'.repeat(64),converter:'sha256:'+'6'.repeat(64)},
   containers:{fox:{id:'7'.repeat(64),image:'sha256:'+'5'.repeat(64)},'forms2apex-mcp':{id:'8'.repeat(64),image:'sha256:'+'6'.repeat(64)},
    'oracle-applied-ai-label':{id:'9'.repeat(64),image:'sha256:'+'a'.repeat(64)}},
   instance:{...INSTANCE},database:{id:'ocid1.autonomousdatabase.oc1.iad.anuwcljrc7x6gxiapkxouj7emfbelvnvompwjcpoxx5vg727cegjsqkbp4rq',
    compartment_id:INSTANCE.compartment_id,lifecycle_state:'AVAILABLE',db_name:'JSNF2APEX'},
   operator_service:{unit:'fox-product-verifier.service',pid:123,start_ticks:'123456',state:'running'},active_conversion_count:0,application_profile:'native-project-v1'},
  ui_assets:{'index.html':sha('html'),'assets/app-test.js':sha('js'),'assets/app-test.css':sha('css')},max_wait_seconds:30,poll_seconds:2,
  browser:{playwright_module:path.resolve(os.tmpdir(),'playwright/index.mjs'),index_sha256:'e'.repeat(64),version:'1.62.1',channel:'msedge'}});
}
