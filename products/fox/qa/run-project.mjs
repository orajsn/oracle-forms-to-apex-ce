import {mkdirSync,writeFileSync,renameSync,openSync,fsyncSync,closeSync,lstatSync} from 'node:fs';
import {randomBytes} from 'node:crypto';
import path from 'node:path';
import {pathToFileURL} from 'node:url';
import {createRequire} from 'node:module';
import {check,isHash,safeMessage} from './lib/contracts.mjs';
import {loadProjectRunnerInputs} from './lib/project-runner-inputs.mjs';
import {createProjectRuntimeResult,executeProjectCases} from './lib/project-runtime.mjs';
import {ProjectBrowserDriver} from './lib/project-browser.mjs';

// Entrypoint only. No historical native v1/v2 dispatch or acceptance behavior.
// All exact bytes and the two dedicated QA credentials are validated BEFORE
// loading Playwright or opening a network connection. No traces/screenshots,
// console logs, storage state, request bodies or credential copies are saved.
// Operator input contract (all filenames absolute, mounted read-only):
//   FOX_QA_PACKAGE              exact independently Python-verified ZIP
//   FOX_QA_PROJECT_SPEC         packaged native-project-spec.json bytes
//   FOX_QA_PROJECT_TRACE        packaged source-to-apex.json bytes
//   FOX_QA_PROFILE              derive_project_qa_profile result JSON
//   FOX_QA_TARGET_RECEIPT       fox-project-qa-target-v1 receipt JSON
//   FOX_QA_IMPORT_RECEIPT       fox-project-clean-package-install-v1 JSON
//   FOX_QA_VERIFICATION_PROFILE exact bound active operator policy JSON
//   FOX_QA_ALLOCATION_RECEIPT   exact private fresh-allocation JSON
//   FOX_QA_CREDENTIAL_FILE      owner-private FOX_QA_A / FOX_QA_B credentials
// Writable preexisting private dirs: FOX_QA_OUTPUT_DIR, FOX_QA_DISPATCH_DIR.
// FOX_QA_IMAGE_ID is the actual immutable container hash, not a mutable tag.
// Output: <OUTPUT_DIR>/<run_id>/qa-result.json (project runtime contract),
// one JSON stdout summary {run_id,status,result_file,human_acceptance_recorded},
// exit 0 only on PASSED. A browser PASSED is not a technical promotion nor
// acceptance: the operator must independently verify all private receipts.
function directory(value,label) {
  check(typeof value==='string'&&path.isAbsolute(value),`${label} must be an absolute private directory`);
  const stat=lstatSync(value);check(stat.isDirectory()&&!stat.isSymbolicLink(),`${label} must be a regular private directory`);return value;
}
function syncDirectory(value) {
  const descriptor=openSync(value,'r');try{fsyncSync(descriptor);}finally{closeSync(descriptor);}
}

export async function main(env=process.env) {
  process.umask(0o077);
  let result,outputDir,binding;
  const runId=`FPQ-${new Date().toISOString().replace(/[-:]/g,'').slice(0,15)}-${randomBytes(4).toString('hex')}`;
  const persist=()=>{
    if(!result||!outputDir)return;
    const temporary=path.join(outputDir,'qa-result.json.tmp');
    const descriptor=openSync(temporary,'w',0o600);
    try{writeFileSync(descriptor,JSON.stringify(result,null,2)+'\n');fsyncSync(descriptor);}finally{closeSync(descriptor);}
    renameSync(temporary,path.join(outputDir,'qa-result.json'));syncDirectory(outputDir);
  };
  try {
    check(!env.DEBUG&&!env.PWDEBUG,'Debug logging is prohibited for authenticated project QA');
    check(env.FOX_QA_INSPECT_ONLY!=='1','Project write runner has no inspect-only promotion path');
    const outputRoot=directory(env.FOX_QA_OUTPUT_DIR,'Output root');
    const dispatchRoot=directory(env.FOX_QA_DISPATCH_DIR,'Durable dispatch directory');
    check(typeof env.FOX_QA_IMAGE_ID==='string'&&/^(?:sha256:)?[a-f0-9]{64}$/.test(env.FOX_QA_IMAGE_ID),
      'An actual immutable project QA image ID is required');
    binding=loadProjectRunnerInputs(env);
    check(isHash(binding.target.allocation_receipt_sha256),'Exact allocation identity is required');
    outputDir=path.join(outputRoot,runId);mkdirSync(outputDir,{mode:0o700});
    result=createProjectRuntimeResult(binding,runId);result.runtime_image_id=env.FOX_QA_IMAGE_ID;persist();
    const {chromium}=await import('playwright');
    const playwrightVersion=createRequire(import.meta.url)('playwright/package.json').version;
    check(playwrightVersion==='1.64.0','Installed Playwright version differs from the pinned QA image contract');
    const driver=new ProjectBrowserDriver({chromium,playwrightVersion,binding,result,persist});
    await executeProjectCases(binding,driver,result,{persist,beginAttempt:async()=>{
      // Create-only intent is durable before the first possible business
      // write. A later uncertain/failed attempt can NEVER silently replay.
      const intent={schema_version:1,scope:'fox-project-qa-dispatch-v1',run_id:runId,
        job_id:binding.target.job_id,allocation_receipt_sha256:binding.target.allocation_receipt_sha256,
        verification_profile_sha256:binding.target.verification_profile_sha256,
        target_receipt_sha256:binding.targetReceiptSha256,test_plan_sha256:result.test_plan_sha256,
        package_sha256:binding.target.package_sha256,image_id:env.FOX_QA_IMAGE_ID,
        started_at:new Date().toISOString(),state:'ATTEMPT_STARTED_NO_AUTOMATIC_REPLAY'};
      try {
        const descriptor=openSync(path.join(dispatchRoot,`${binding.target.allocation_receipt_sha256}.json`),'wx',0o600);
        try{writeFileSync(descriptor,JSON.stringify(intent,null,2)+'\n');fsyncSync(descriptor);}finally{closeSync(descriptor);}
        syncDirectory(dispatchRoot);
      }catch{throw new Error('Project allocation dispatch is unavailable or already attempted; no automatic replay is allowed');}
    }});
  }catch(error) {
    const secrets=binding?[binding.accounts.primary,binding.accounts.secondary].flatMap(account=>[account.username,account.password]):[];
    if(result){result.status='FAILED';result.failure=safeMessage(error,secrets);result.finished_at=new Date().toISOString();persist();}
    // Preflight errors intentionally omit arbitrary file contents, paths and
    // exception text. Detailed credential/parser errors never reach stdout.
    else process.stderr.write('Project QA preflight failed; no browser or business write was started.\n');
  }
  process.stdout.write(JSON.stringify({run_id:runId,status:result?.status??'PREFLIGHT_BLOCKED',
    ...(outputDir?{result_file:path.join(outputDir,'qa-result.json')}:{}),human_acceptance_recorded:false})+'\n');
  return result?.status==='PASSED'?0:1;
}

if(process.argv[1]&&import.meta.url===pathToFileURL(path.resolve(process.argv[1])).href)process.exitCode=await main();
