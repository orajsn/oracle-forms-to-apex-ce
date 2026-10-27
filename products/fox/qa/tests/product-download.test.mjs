import test from 'node:test';
import assert from 'node:assert/strict';
import {ORIGIN,BACKEND_IMAGE,QA_IMAGE,UI,NOTES,validateManifest,permittedGet,permittedPost,acceptanceBody} from '../run-product-download.mjs';

const fixture=()=>({schema_version:1,scope:'fox-isolated-product-download-v1',simulated_fixtures:true,live_acceptance_recorded:false,
 origin:ORIGIN,backend_image:BACKEND_IMAGE,qa_image:QA_IMAGE,ui:{...UI},owner:'synthetic-product-0123456789ab',
 project_id:'a'.repeat(24),run_id:'fox-'+'b'.repeat(20),project_name:'Synthetic isolated acceptance browser check',
 notes:NOTES,source_hash:'c'.repeat(64),package_sha256:'d'.repeat(64),package_bytes:1000,files:{'credentials.json':'e'.repeat(64)}});
test('only explicit synthetic candidate fixture is accepted',()=>assert.equal(validateManifest(fixture()).origin,ORIGIN));
for(const [name,mutate] of Object.entries({
 realOwner:v=>v.owner='jason',liveFlag:v=>v.live_acceptance_recorded=true,nonsynthetic:v=>v.simulated_fixtures=false,
 externalOrigin:v=>v.origin='https://fox.example.test',wrongImage:v=>v.backend_image='f'.repeat(64),
 staleUI:v=>v.ui['index.html']='f'.repeat(64),trailingIdentifier:v=>v.run_id+='\n',badSize:v=>v.package_bytes=1.5,
}))test(`manifest rejects ${name}`,()=>{const value=fixture();mutate(value);assert.throws(()=>validateManifest(value));});
test('read allowlist remains one loopback origin and one synthetic run',()=>{
 const f=fixture(),run=`/api/projects/${f.project_id}/runs/${f.run_id}`;
 for(const suffix of ['/', '/api/health','/api/session','/api/projects',`/api/projects/${f.project_id}`,`${run}/evidence`,`${run}/download`,'/assets/index-DcyynC8H.js'])assert.equal(permittedGet(ORIGIN+suffix,f),true);
 for(const url of ['https://fox.example.test/',ORIGIN+'/api/projects/other',ORIGIN+'/api/projects?all=true',ORIGIN+'/api/logout',ORIGIN+'/api/projects/'+f.project_id+'/assessment','http://127.0.0.1:8100@evil.test/'])assert.equal(permittedGet(url,f),false);
});
test('only the armed exact login or synthetic acceptance may mutate',()=>{
 const f=fixture(),creds={username:f.owner,password:'synthetic-only-password'},login=ORIGIN+'/api/login',accept=`${ORIGIN}/api/projects/${f.project_id}/runs/${f.run_id}/accept`;
 assert.equal(permittedPost(login,creds,f,creds,'login'),true);
 assert.equal(permittedPost(login,creds,f,creds,null),false);
 assert.equal(permittedPost(accept,acceptanceBody(f),f,creds,'accept'),true);
 for(const body of [{...acceptanceBody(f),notes:'Real acceptance'}, {...acceptanceBody(f),business_flow_tested:false},{...acceptanceBody(f),source_hash:'0'.repeat(64)}])assert.equal(permittedPost(accept,body,f,creds,'accept'),false);
 assert.equal(permittedPost(ORIGIN+'/api/projects',{},f,creds,'accept'),false);
});
