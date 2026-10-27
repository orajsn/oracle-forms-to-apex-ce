// Run with: node --test tests/test_prepared_upload_ui.mjs
// Uses installed TypeScript only to load the same browser helper; no build/install.
import {test} from 'node:test';
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import {createHash} from 'node:crypto';
import ts from 'typescript';
const source=await readFile(new URL('../web/preparedUpload.ts',import.meta.url),'utf8');
const compiled=ts.transpileModule(source,{compilerOptions:{module:ts.ModuleKind.ESNext,target:ts.ScriptTarget.ES2022}}).outputText;
const {checkSelectedSources,uploadManifestName}=await import(`data:text/javascript;base64,${Buffer.from(compiled).toString('base64')}`);
const digest=bytes=>createHash('sha256').update(bytes).digest('hex');
const xml=Buffer.from('<FormModule Name="SYNTHETIC"/>');
const sql=Buffer.from('CREATE TABLE SYNTHETIC (ID NUMBER);');
const defaults=()=>[new File([xml],'source.xml'),new File([sql],'schema.sql')];
async function manifest(files=defaults()){
 const entries=await Promise.all(files.map(async f=>({name:f.name,bytes:f.size,sha256:digest(Buffer.from(await f.arrayBuffer()))})));
 return {format:'FOX-READABLE-UPLOAD',schema_version:1,extraction_job_id:'extract-ui-test',
  readable_source_hash:digest(entries.slice().sort((a,b)=>a.name<b.name?-1:1).map(f=>`${f.name}:${f.sha256}`).join('\n')),files:entries};
}
const sidecar=value=>new File([JSON.stringify(value)],uploadManifestName);
async function selected(files=defaults()){return [...files,sidecar(await manifest(files))];}

test('prepared set preserves exact selected File objects and never calls fetch',async()=>{
 const files=defaults(),metadata=sidecar(await manifest(files));
 const prior=globalThis.fetch;globalThis.fetch=()=>{throw Error('must not send');};
 try{const result=await checkSelectedSources([metadata,...files],'prepared');assert.deepEqual(result.files,files);assert.equal(result.manifest,metadata);}
 finally{globalThis.fetch=prior;}
});
test('direct readable mode remains supported with no manifest',async()=>{
 const files=defaults();assert.deepEqual(await checkSelectedSources(files,'direct'),{files});
});
test('prepared exact byte hashes preserve BOM and CRLF',async()=>{
 const files=[new File([Buffer.from('\ufeff<FormModule Name="SYNTHETIC">\r\n</FormModule>')],'source.xml')];
 assert.equal((await checkSelectedSources(await selected(files),'prepared')).files[0],files[0]);
});
for(const mode of ['prepared','direct'])for(const raw of [Buffer.from([0xff,0,1]),Buffer.from('binary\0text')]){
 test(`${mode} rejects binary bytes hidden behind a readable extension`,async()=>{
  const files=[new File([raw],'source.txt')];
  await assert.rejects(checkSelectedSources(mode==='prepared'?await selected(files):files,mode),/UTF-8 readable source only/);
 });
}
test('file and JSON key ordering does not change a valid selection',async()=>{
 const files=defaults(),m=await manifest(files);m.files.reverse();
 const shuffled={files:m.files,readable_source_hash:m.readable_source_hash,extraction_job_id:m.extraction_job_id,schema_version:1,format:m.format};
 assert.equal((await checkSelectedSources([files[1],sidecar(shuffled),files[0]],'prepared')).files.length,2);
});
for(const name of ['raw.fmb','raw.mmb','raw.olb','raw.pll','raw.zip','manifest.json','status.json','inventory.json']){
 test(`rejects ${name} before reading or sending it`,async()=>{
  const file=new File(['private'],name);file.arrayBuffer=()=>{throw Error('must not read raw/private file');};
  await assert.rejects(checkSelectedSources([file],'prepared'),/Keep raw Forms/);
 });
}
for(const mode of ['prepared','direct'])test(`${mode} rejects empty and oversized selections`,async()=>{
 await assert.rejects(checkSelectedSources([],mode),/Choose/);
 const zero=[new File([],'empty.xml')];if(mode==='prepared')zero.push(sidecar(await manifest(zero)));
 await assert.rejects(checkSelectedSources(zero,mode),/non-empty/);
 const oversized=new File(['x'],'large.txt');Object.defineProperty(oversized,'size',{value:5*1024*1024+1});
 await assert.rejects(checkSelectedSources(mode==='prepared'?[oversized,sidecar({})]:[oversized],mode),/5 MB/);
});
test('prepared requires exactly one sidecar; direct never silently consumes it',async()=>{
 const files=defaults(),m=sidecar(await manifest(files));
 await assert.rejects(checkSelectedSources(files,'prepared'),/Select fox-readable/);
 await assert.rejects(checkSelectedSources([...files,m,m],'prepared'),/Select fox-readable/);
 await assert.rejects(checkSelectedSources([...files,m],'direct'),/Use Prepared/);
});
test('prepared rejects missing, extra, renamed and byte-mutated readable files',async()=>{
 const files=defaults(),m=sidecar(await manifest(files));
 for(const altered of [files.slice(0,1),[...files,new File(['notes'],'notes.txt')],
  [new File([xml],'renamed.xml'),files[1]],[new File([Buffer.from('<FormModule Name="DIFFERENT"/>')],'source.xml'),files[1]],
  [new File([xml.toString().replace('SYNTHETIC','SYNTHETIX')],'source.xml'),files[1]]])
  await assert.rejects(checkSelectedSources([...altered,m],'prepared'),/complete file set|missing, renamed or changed/);
});
test('prepared rejects case-insensitive filename collisions',async()=>{
 const files=[new File([xml],'Source.xml'),new File([xml],'source.xml')];
 await assert.rejects(checkSelectedSources([...files,sidecar(await manifest(files))],'prepared'),/unique/);
});
for(const patch of [{approved:true},{raw_inputs:[]},{schema_version:2},{format:'PRIVATE-MANIFEST'},
 {extraction_job_id:'C:/private/raw'},{readable_source_hash:'f'.repeat(64)},{files:[]}]){
 test(`rejects invalid top metadata ${Object.keys(patch).join()}`,async()=>{
  const files=defaults(),m={...await manifest(files),...patch};
  await assert.rejects(checkSelectedSources([...files,sidecar(m)],'prepared'),/manifest|complete file set/);
 });
}
for(const patch of [{source:'C:/private/raw.fmb'},{name:'../secret.xml'},{name:'NUL.xml'},
 {name:'readme.json'},{bytes:true},{bytes:1.5},{bytes:-1},{sha256:'F'.repeat(64)},{sha256:'notsha'}]){
 test(`rejects invalid file metadata ${JSON.stringify(patch)}`,async()=>{
  const files=defaults(),m=await manifest(files);Object.assign(m.files[0],patch);
  await assert.rejects(checkSelectedSources([...files,sidecar(m)],'prepared'),/invalid file metadata/);
 });
}
for(const raw of [Buffer.from('{bad'),Buffer.from('\ufeff{}'),Buffer.from([0xff,0xfe])]){
 test(`rejects malformed sidecar bytes ${raw.toString('hex')}`,async()=>{
  await assert.rejects(checkSelectedSources([...defaults(),new File([raw],uploadManifestName)],'prepared'),/valid UTF-8 JSON/);
 });
}
test('oversized sidecar is bounded before decoding',async()=>{
 const m=new File(['x'.repeat(32769)],uploadManifestName);m.arrayBuffer=()=>{throw Error('must not read');};
 await assert.rejects(checkSelectedSources([...defaults(),m],'prepared'),/32 KB/);
});
test('duplicate JSON keys cannot hide private metadata before upload',async()=>{
 const files=defaults(),raw=JSON.stringify(await manifest(files));
 for(const modified of [
  raw.replace('{','{"files":[{"path":"C:/private/raw.fmb","approval":true}],'),
  raw.replace('{','{"schema\\u005fversion":1,'),
  raw.replace('"bytes":','"name":"C:/private/raw.fmb","bytes":'),
  raw.replace('"sha256":','"sha256":"not-a-digest","sha256":'),
 ])await assert.rejects(checkSelectedSources([...files,new File([modified],uploadManifestName)],'prepared'),/valid UTF-8 JSON/);
});
test('deeply nested sidecar is rejected before parsing',async()=>{
 const raw='['.repeat(10000)+'0'+']'.repeat(10000);
 await assert.rejects(checkSelectedSources([...defaults(),new File([raw],uploadManifestName)],'prepared'),/valid UTF-8 JSON/);
});
test('UI keeps explicit upload, isolated project state and independent approval controls',async()=>{
 const ui=await readFile(new URL('../web/main.tsx',import.meta.url),'utf8');
 // Source history now isolates selection state by the complete selected
 // version, not just project ID. Mounted browser tests exercise the reset.
 assert.match(ui,/<SourceUpload key=\{'upload-'\+sourceUiKey\}/);
 assert.match(ui,/sourceKey=sourceIdentity\(detail\),sourceUiKey=sourceKey\+'-'\+sourceUiEpoch/);
 assert.match(ui,/Upload and assess/);
 assert.match(ui,/checkSelectedSources\(files,mode\)/);
 assert.match(ui,/d.append\('prepared_manifest',selected.manifest\)/);
 assert.match(ui,/setMode\('direct'\);setSelected\(\[\]\)/);
 assert.match(ui,/approved_redacted_source:consent\[0\]/);
 assert.match(ui,/approved_external_ai:consent\[1\]/);
 assert.match(ui,/approved_prototype_scope:consent\[2\]/);
 const syntax=ts.createSourceFile('main.tsx',ui,ts.ScriptTarget.Latest,true,ts.ScriptKind.TSX);
 for(const name of ['Acceptance','ProjectAcceptance']){
  const component=syntax.statements.find(node=>ts.isFunctionDeclaration(node)&&node.name?.text===name);
  assert.ok(component,`${name} review component is present`);
  assert.equal((component.getText(syntax).match(/className="acceptance-check"/g)||[]).length,2,
   `${name} keeps separate business-test and remediation confirmations`);
 }
 const css=await readFile(new URL('../web/sourcePreparation.css',import.meta.url),'utf8');
 assert.match(css,/\.acceptance-check\{display:flex/);
 assert.match(css,/\.acceptance-check input\{flex:0 0 16px;width:16px;height:16px/);
});
