import {createHash} from 'node:crypto';
import {inflateRawSync} from 'node:zlib';
import {readFileSync,lstatSync} from 'node:fs';
import path from 'node:path';
import {parseUniqueJson,parseNativeQaSpecBytes,isHash} from './contracts.mjs';

const requireThat=(value,message)=>{if(!value)throw new Error(message);};
const hash=bytes=>createHash('sha256').update(bytes).digest('hex');
export function crc32(bytes) {
  let value=0xffffffff;
  for(const byte of bytes){value^=byte;for(let bit=0;bit<8;bit++)value=(value>>>1)^((value&1)?0xedb88320:0);}
  return (value^0xffffffff)>>>0;
}

// Deliberately narrow, read-only ZIP32 reader for FOX-produced release packages.
// No files are extracted. Encryption, descriptors, symlinks and ZIP64 fail closed.
export function inspectPackageBytes(bytes) {
  requireThat(Buffer.isBuffer(bytes)&&bytes.length>=22&&bytes.length<=32*1024*1024,'Release package size is invalid');
  const end=bytes.length-22;
  requireThat(bytes.readUInt32LE(end)===0x06054b50&&bytes.readUInt16LE(end+20)===0,'Package requires a standard ZIP32 end record without a comment');
  const count=bytes.readUInt16LE(end+10),directorySize=bytes.readUInt32LE(end+12),directoryOffset=bytes.readUInt32LE(end+16);
  requireThat(bytes.readUInt16LE(end+4)===0&&bytes.readUInt16LE(end+6)===0&&bytes.readUInt16LE(end+8)===count,'Multi-disk ZIP is prohibited');
  requireThat(count>0&&count<=200&&directoryOffset+directorySize===end,'Invalid ZIP member count or directory bounds');
  const members=new Map(),names=new Set(),intervals=[],entries=[];let cursor=directoryOffset,total=0;
  for(let index=0;index<count;index++) {
    requireThat(cursor+46<=end&&bytes.readUInt32LE(cursor)===0x02014b50,'Invalid ZIP central record');
    const flags=bytes.readUInt16LE(cursor+8),method=bytes.readUInt16LE(cursor+10),crc=bytes.readUInt32LE(cursor+16);
    const compressed=bytes.readUInt32LE(cursor+20),size=bytes.readUInt32LE(cursor+24),nameLength=bytes.readUInt16LE(cursor+28);
    const extra=bytes.readUInt16LE(cursor+30),comment=bytes.readUInt16LE(cursor+32),disk=bytes.readUInt16LE(cursor+34);
    const mode=bytes.readUInt32LE(cursor+38)>>>16,offset=bytes.readUInt32LE(cursor+42);
    requireThat((flags&~0x800)===0&&[0,8].includes(method)&&disk===0,'Encrypted, descriptor-based or unsupported ZIP member');
    requireThat(size<=8*1024*1024&&compressed<=32*1024*1024&&(total+=size)<=32*1024*1024,'ZIP expansion limit exceeded');
    requireThat(cursor+46+nameLength+extra+comment<=end,'ZIP member metadata exceeds directory');
    const nameBytes=bytes.subarray(cursor+46,cursor+46+nameLength),name=new TextDecoder('utf-8',{fatal:true}).decode(nameBytes);
    requireThat(/^[A-Za-z0-9_.\/-]+(?![^])/.test(name)&&!name.startsWith('/')&&!name.endsWith('/')&&!name.split('/').some(part=>!part||part==='.'||part==='..'),'Unsafe ZIP path');
    requireThat(!names.has(name.toLowerCase())&&[0,0x8000].includes(mode&0xf000),'Duplicate/case-colliding or nonregular ZIP member');
    names.add(name.toLowerCase());
    requireThat(offset+30<=directoryOffset&&bytes.readUInt32LE(offset)===0x04034b50,'Invalid local ZIP header');
    const localName=bytes.readUInt16LE(offset+26),localExtra=bytes.readUInt16LE(offset+28),dataStart=offset+30+localName+localExtra;
    requireThat(bytes.readUInt16LE(offset+6)===flags&&bytes.readUInt16LE(offset+8)===method&&bytes.readUInt32LE(offset+14)===crc&&bytes.readUInt32LE(offset+18)===compressed&&bytes.readUInt32LE(offset+22)===size,'Central/local ZIP headers differ');
    requireThat(dataStart+compressed<=directoryOffset&&nameBytes.equals(bytes.subarray(offset+30,offset+30+localName)),'ZIP local path or payload bounds differ');
    intervals.push([offset,dataStart+compressed]);entries.push({name,dataStart,compressed,size,method,crc});cursor+=46+nameLength+extra+comment;
  }
  requireThat(cursor===end,'Unexpected central-directory data');
  intervals.sort((a,b)=>a[0]-b[0]);let previous=0;
  for(const [start,finish] of intervals){requireThat(start===previous,'Overlapping, hidden or unaccounted ZIP data');previous=finish;}
  requireThat(previous===directoryOffset,'Unexpected data before ZIP directory');
  // Only decompress after every structural interval has passed the whole-archive audit.
  for(const entry of entries){
    const packed=bytes.subarray(entry.dataStart,entry.dataStart+entry.compressed);
    const content=entry.method===0?packed:inflateRawSync(packed,{maxOutputLength:Math.max(1,entry.size)});
    requireThat(content.length===entry.size&&crc32(content)===entry.crc,'ZIP member length/CRC mismatch');members.set(entry.name,content);
  }
  const json=name=>{requireThat(members.has(name),`Required package evidence missing: ${name}`);return parseUniqueJson(members.get(name));};
  const manifest=json('manifest.json');
  requireThat(manifest&&typeof manifest==='object'&&!Array.isArray(manifest)&&Object.keys(manifest).length===members.size-1,'Package manifest coverage differs');
  for(const [name,content] of members)if(name!=='manifest.json')requireThat(manifest[name]===hash(content),'Package member hash mismatch');
  const sqlNames=[...members.keys()].filter(name=>name.startsWith('sql/'));
  requireThat(sqlNames.length===1&&/^sql\/f[0-9]+\.sql(?![^])/.test(sqlNames[0]),'Package requires exactly one conventional SQL export');
  requireThat(members.has('native-form-spec.json'),'Required native spec is missing');
  const nativeSpec=parseNativeQaSpecBytes(members.get('native-form-spec.json')),release=json('evidence/release-evidence.json');
  requireThat(release.reviewer_approved===true&&release.sqlcl_valid===true&&release.import_passed===true,'Package lacks successful review/validation/import evidence');
  requireThat(isHash(release.source_manifest_sha256),'Package source hash is missing');
  requireThat(members.has('schema/01_synthetic_schema.sql'),'Package schema script is missing');
  requireThat(Number.isSafeInteger(release.application_id)&&release.application_id>0,'Package application ID must be a positive safe integer');
  requireThat(sqlNames[0]===`sql/f${release.application_id}.sql`,'Package SQL export identity differs from release evidence');
  return {package_sha256:hash(bytes),sql_sha256:hash(members.get(sqlNames[0])),native_spec_sha256:hash(members.get('native-form-spec.json')),
    schema_script_sha256:hash(members.get('schema/01_synthetic_schema.sql')),source_manifest_sha256:release.source_manifest_sha256,
    nativeSpec,releaseEvidence:release,member_count:members.size,sql_member:sqlNames[0]};
}

export function readPackageEvidence(file) {
  requireThat(typeof file==='string'&&path.isAbsolute(file),'Absolute package path required');
  const stat=lstatSync(file);
  requireThat(stat.isFile()&&!stat.isSymbolicLink()&&stat.size<=32*1024*1024,'Package must be a bounded regular file');
  return inspectPackageBytes(readFileSync(file));
}
