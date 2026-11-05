import {test} from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {createRequire} from 'node:module';
import React from 'react';
import {renderToStaticMarkup} from 'react-dom/server';
import ts from 'typescript';
const require=createRequire(import.meta.url);
const metadata=JSON.parse(readFileSync(new URL('../fox/release.json',import.meta.url),'utf8'));
function load(file,imports={}){
 const code=ts.transpileModule(readFileSync(new URL('../web/'+file,import.meta.url),'utf8'),
  {fileName:file,compilerOptions:{target:ts.ScriptTarget.ES2022,module:ts.ModuleKind.CommonJS,jsx:ts.JsxEmit.ReactJSX,esModuleInterop:true}}).outputText;
 const m={exports:{}};new Function('require','module','exports',code)(name=>Object.hasOwn(imports,name)?imports[name]:name.endsWith('.css')?{}:require(name),m,m.exports);return m.exports;
}
const p=load('releasePresentation.ts');
const {ReleaseDetails}=load('ReleaseInfo.tsx',{'./releasePresentation':p,'../fox/release.json':metadata});
test('matching version is identity, never conversion acceptance',()=>{
 const html=renderToStaticMarkup(React.createElement(ReleaseDetails,{serverVersion:metadata.version}));
 assert.ok(html.includes('FOX v'+metadata.version));assert.match(html,/What changed/);assert.match(html,/not a conversion verification result/);
 assert.match(html,/business acceptance remain separate/);assert.match(html,/<summary>/);
});
test('mismatch and unavailable notes never claim the UI is the installed server',()=>{
 assert.equal(p.presentRelease('0.2.0','0.1.0').kind,'mismatch');
 assert.match(p.presentRelease('0.2.0','0.1.0').message,/Refresh/);
 const html=renderToStaticMarkup(React.createElement(ReleaseDetails,{serverVersion:null,onRetry:()=>{}}));
 assert.match(html,/Server version unconfirmed/);assert.match(html,/Retry version check/);
 assert.match(html,/notes describe the UI files/);assert.doesNotMatch(html,/versions match/);
});
test('bad metadata is rejected instead of echoed as a version',()=>{
 for(const patch of [{version:'private-value'},{released_on:'2026-02-30'},{changes:[]},{title:'bad\nlabel'}])
  assert.throws(()=>p.readRelease({...metadata,...patch}));
 assert.equal(p.presentRelease('0.2.0','<script>').kind,'unavailable');
});
test('checking status is bounded to a read-only metadata request, with cleanup',()=>{
 assert.equal(p.presentRelease('0.2.0',null,true).kind,'checking');
 const source=readFileSync(new URL('../web/ReleaseInfo.tsx',import.meta.url),'utf8');
 assert.match(source,/fetch\('\/api\/release'/);assert.match(source,/controller\.abort\(\)/);
 assert.doesNotMatch(source,/method:\s*['"]POST/);
});
