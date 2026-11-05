// Capability policy against the actual bundled main module. No service or upload.
import {test,after} from 'node:test';
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import {fileURLToPath} from 'node:url';
import {build} from 'esbuild';

const source=await readFile(new URL('../web/main.tsx',import.meta.url),'utf8');
const built=await build({entryPoints:[fileURLToPath(new URL('../web/main.tsx',import.meta.url))],
 bundle:true,write:false,format:'esm',platform:'browser',loader:{'.css':'empty'},
 plugins:[{name:'no-mount',setup(b){b.onResolve({filter:/^react-dom\/client$/},()=>({path:'no-mount',namespace:'test'}));b.onLoad({filter:/.*/,namespace:'test'},()=>({contents:'export const createRoot=()=>({render(){}});',loader:'js'}));}}]});
const oldDocument=globalThis.document,oldLocation=Object.getOwnPropertyDescriptor(globalThis,'location');
globalThis.document={getElementById:()=>({})};
const {localPreparationCapability}=await import('data:text/javascript;base64,'+Buffer.from(built.outputFiles[0].contents).toString('base64'));
after(()=>{globalThis.document=oldDocument;if(oldLocation)Object.defineProperty(globalThis,'location',oldLocation);else delete globalThis.location;});
const origin=url=>Object.defineProperty(globalThis,'location',{configurable:true,value:new URL(url)});

test('hosted origin is unavailable even when server advertises preparation',()=>{
 origin('https://fox.example.test/');
 const result=localPreparationCapability({enabled:true});
 assert.equal(result.enabled,false);assert.match(result.reason,/local FOX preparation tool/);
});
test('approved loopback and explicit server capability enable preparation',()=>{
 origin('http://127.0.0.1:8100/');
 assert.equal(localPreparationCapability({enabled:true}).enabled,true);
});
test('missing or disabled server capability fails closed on loopback',()=>{
 origin('http://127.0.0.1:8100/');
 for(const capability of [undefined,{enabled:false},{}])assert.equal(localPreparationCapability(capability).enabled,false);
});
test('workbench capability, handler and mounted panel use the same gate',()=>{
 assert.match(source,/local_preparation:localPreparation/);
 assert.match(source,/onOpenPreparation=\{localPreparation\.enabled\?/);
 assert.match(source,/preparationOpen&&localPreparation\.enabled&&/);
});
