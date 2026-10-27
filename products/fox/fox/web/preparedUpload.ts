// UX precheck only. The authenticated server always repeats authoritative intake.
export const uploadManifestName='fox-readable-upload.json';
export type UploadMode='prepared'|'direct';
const readable=/\.(xml|pld|sql|pks|pkb|txt)$/i;
const shaPattern=/^[a-f0-9]{64}$/;
const maxFileBytes=5*1024*1024;
const exactFields=(value:unknown,fields:string[]):value is Record<string,unknown>=>
 typeof value==='object'&&value!==null&&!Array.isArray(value)
 &&Object.keys(value).sort().join('|')===[...fields].sort().join('|');
const safeName=(name:unknown):name is string=>typeof name==='string'
 &&/^[A-Za-z0-9][A-Za-z0-9_. -]{0,119}$/.test(name)&&!name.includes('..')&&!/[ .]$/.test(name)
 &&!/^(CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])(?:\.|$)/i.test(name)&&readable.test(name);
async function sha256(raw:BufferSource){
 return Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256',raw)),b=>b.toString(16).padStart(2,'0')).join('');
}
async function readableBytes(file:File):Promise<ArrayBuffer>{
 const raw=await file.arrayBuffer();
 try{
  if(new TextDecoder('utf-8',{fatal:true}).decode(raw).includes('\0'))throw new Error('NUL');
 }catch{throw new Error('Select UTF-8 readable source only. Raw binary content must stay local.');}
 return raw;
}
function parseManifest(text:string):unknown{
 // JSON.parse silently keeps the last duplicate key. Reject duplicates before
 // uploading the original File, including escaped keys concealing private data.
 // The public shape is only object -> files array -> file object.
 const containers:(Set<string>|null)[]=[];
 for(const token of text.matchAll(/"(?:\\[\s\S]|[^"\\])*"|[{}\[\]]/g)){
  const value=token[0];
  if(value==='{'||value==='['){
   containers.push(value==='{'?new Set<string>():null);
   if(containers.length>3)throw new Error('Manifest is nested too deeply.');
  }else if(value==='}'||value===']'){
   if(!containers.length)throw new Error('Invalid manifest structure.');
   containers.pop();
  }else if(/^\s*:/.test(text.slice(token.index!+value.length))){
   const keys=containers[containers.length-1],key=JSON.parse(value) as string;
   if(!keys||keys.has(key))throw new Error('Duplicate manifest key.');
   keys.add(key);
  }
 }
 return JSON.parse(text);
}
export async function checkSelectedSources(selected:File[],mode:UploadMode):Promise<{files:File[];manifest?:File}>{
 if(!selected.length)throw new Error('Choose the readable source files first.');
 const manifestFiles=selected.filter(file=>file.name===uploadManifestName);
 const files=selected.filter(file=>file.name!==uploadManifestName);
 if(selected.some(file=>!readable.test(file.name)&&file.name!==uploadManifestName))
  throw new Error('Keep raw Forms, archives and private extraction files local. Select readable XML/PLD/SQL/PKS/PKB/TXT only, plus fox-readable-upload.json for a prepared set.');
 if(mode==='direct'&&manifestFiles.length)throw new Error('Use Prepared source set to upload fox-readable-upload.json.');
 if(mode==='prepared'&&manifestFiles.length!==1)throw new Error('Select fox-readable-upload.json and every readable file listed in it, together.');
 if(!files.length||files.length>50||files.some(file=>file.size<1||file.size>maxFileBytes)
  ||files.reduce((sum,file)=>sum+file.size,0)>25*1024*1024)
  throw new Error('Select 1–50 non-empty readable files, at most 5 MB each and 25 MB together.');
 if(new Set(files.map(file=>mode==='prepared'?file.name.toLowerCase():file.name)).size!==files.length)
  throw new Error('The selected filenames must be unique.');
 if(mode==='direct'){
  for(const file of files)await readableBytes(file);
  return {files};
 }
 const manifest=manifestFiles[0];
 if(manifest.size>32768)throw new Error('The prepared-source manifest exceeds 32 KB.');
 let value:unknown;
 try{value=parseManifest(new TextDecoder('utf-8',{fatal:true,ignoreBOM:true}).decode(await manifest.arrayBuffer()));}
 catch{throw new Error('The prepared-source manifest is not valid UTF-8 JSON.');}
 if(!exactFields(value,['format','schema_version','extraction_job_id','readable_source_hash','files'])
  ||value.format!=='FOX-READABLE-UPLOAD'||value.schema_version!==1
  ||typeof value.extraction_job_id!=='string'||!/^[A-Za-z0-9][A-Za-z0-9_-]{0,79}$/.test(value.extraction_job_id)
  ||typeof value.readable_source_hash!=='string'||!shaPattern.test(value.readable_source_hash)
  ||!Array.isArray(value.files)||value.files.length!==files.length)
  throw new Error('Select the public FOX readable-upload manifest and its complete file set.');
 const declared=value.files;
 const names=new Set<string>();
 for(const entry of declared){
  if(!exactFields(entry,['name','sha256','bytes'])||!safeName(entry.name)
   ||typeof entry.sha256!=='string'||!shaPattern.test(entry.sha256)
   ||!Number.isInteger(entry.bytes)||typeof entry.bytes!=='number'||entry.bytes<1||entry.bytes>maxFileBytes
   ||names.has(entry.name.toLowerCase()))throw new Error('The prepared-source manifest has invalid file metadata.');
  names.add(entry.name.toLowerCase());
  const file=files.find(file=>file.name===entry.name);
  if(!file||file.size!==entry.bytes||await sha256(await readableBytes(file))!==entry.sha256)
   throw new Error('A readable file is missing, renamed or changed. Select the unchanged complete ready folder, or prepare a new set.');
 }
 const ordered=[...declared].sort((a,b)=>a.name<b.name?-1:a.name>b.name?1:0);
 const combined=await sha256(new TextEncoder().encode(ordered.map(file=>`${file.name}:${file.sha256}`).join('\n')));
 if(combined!==value.readable_source_hash)throw new Error('The prepared-source manifest hash does not match its file list.');
 return {files,manifest};
}
