// Isolated delivery UI proof only. No conversion, model, database or live acceptance.
import {createHash} from 'node:crypto';
import {createRequire} from 'node:module';
import {closeSync, constants, fsyncSync, lstatSync, openSync, readdirSync,
  realpathSync, writeFileSync} from 'node:fs';
import path from 'node:path';
import {pathToFileURL} from 'node:url';

export const ORIGIN = 'http://127.0.0.1:8123';
export const NOTES = 'Automated isolated delivery QA only. Not Jason approval, customer review, business equivalence, or live acceptance.';
export const PLAYWRIGHT = '/opt/fox-qa/node_modules/playwright/index.mjs';
const SHA = /^[a-f0-9]{64}$/;
const MAX_INPUT = 262144;
const MAX_RESPONSE = 8_000_000;

export function need(value, code) {
  if (!value) throw new Error(code);
}

function record(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value)
    && Object.getPrototypeOf(value) === Object.prototype;
}

export function canonical(value) {
  if (value === null || typeof value === 'boolean' || typeof value === 'string') return JSON.stringify(value);
  if (typeof value === 'number') {
    need(Number.isFinite(value), 'CANONICAL_VALUE_INVALID');
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) return '[' + value.map(canonical).join(',') + ']';
  need(record(value), 'CANONICAL_VALUE_INVALID');
  return '{' + Object.keys(value).sort().map(key => JSON.stringify(key) + ':' + canonical(value[key])).join(',') + '}';
}

export const sha = raw => createHash('sha256').update(raw).digest('hex');

export function validateInput(value) {
  need(record(value) && Object.keys(value).every(key => [
    'origin', 'username', 'password', 'fixture', 'output_directory', 'playwright_module',
  ].includes(key)), 'INPUT_FIELDS_INVALID');
  need(value.origin === ORIGIN && /^synthetic-[a-z0-9-]{1,64}$/.test(value.username ?? '')
    && typeof value.password === 'string' && /^[A-Za-z0-9_-]{32,128}$/.test(value.password),
  'ISOLATED_NORMAL_LOGIN_REQUIRED');
  need(typeof value.output_directory === 'string' && path.isAbsolute(value.output_directory),
    'ABSOLUTE_OUTPUT_REQUIRED');
  const input = value.fixture;
  need(record(input) && Object.keys(input).length <= 32, 'FIXTURE_REQUIRED');
  need(/^[a-f0-9]{32}$/.test(input.project_id ?? '')
    && /^fox-[a-f0-9]{20}$/.test(input.run_id ?? '')
    && typeof input.project_name === 'string' && /^[A-Za-z0-9][A-Za-z0-9 ._-]{0,79}$/.test(input.project_name)
    && [input.source_hash, input.package_sha256, input.proof_sha256].every(item => typeof item === 'string' && SHA.test(item))
    && Number.isSafeInteger(input.package_bytes) && input.package_bytes > 0 && input.package_bytes <= MAX_RESPONSE
    && Number.isSafeInteger(input.form_count) && input.form_count >= 2 && input.form_count <= 50
    && input.notes === NOTES, 'EXACT_SYNTHETIC_PROJECT_BINDING_REQUIRED');
  need(record(input.ui) && Object.keys(input.ui).length >= 3 && Object.keys(input.ui).length <= 100
    && Object.hasOwn(input.ui, 'index.html'), 'EXACT_UI_INVENTORY_REQUIRED');
  for (const [name, digest] of Object.entries(input.ui)) {
    need((name === 'index.html' || /^assets\/[A-Za-z0-9_.-]+\.(js|css|svg|png|jpg|webp)$/.test(name))
      && typeof digest === 'string' && SHA.test(digest), 'UI_MEMBER_INVALID');
  }
  const modulePath = value.playwright_module ?? PLAYWRIGHT;
  need(typeof modulePath === 'string' && path.isAbsolute(modulePath)
    && /(?:^|[\\/])node_modules[\\/]playwright[\\/]index\.mjs$/.test(modulePath)
    && path.resolve(modulePath) === path.normalize(modulePath), 'LOCAL_PLAYWRIGHT_MODULE_REQUIRED');
  // Retain only the fields used by this browser contract, never arbitrary export data.
  const fixture = Object.fromEntries(['project_id', 'project_name', 'run_id', 'source_hash',
    'package_sha256', 'package_bytes', 'proof_sha256', 'form_count', 'notes'].map(key => [key, input[key]]));
  fixture.ui = {...input.ui};
  return {origin: ORIGIN, username: value.username, password: value.password,
    fixture, output_directory: path.resolve(value.output_directory), playwright_module: modulePath};
}

export function createRequestPolicy(input) {
  const value = validateInput(input), fixture = value.fixture;
  const project = '/api/projects/' + fixture.project_id;
  const run = project + '/runs/' + fixture.run_id;
  const acceptance = {source_hash: fixture.source_hash, business_flow_tested: true,
    remediation_reviewed: true, notes: NOTES};
  const actions = [
    {name: 'login', pathname: '/api/login', body: {username: value.username, password: value.password}, status: 200},
    {name: 'incomplete_review', pathname: run + '/accept', body: {...acceptance, business_flow_tested: false}, status: 422},
    {name: 'acceptance', pathname: run + '/accept', body: acceptance, status: 200},
    {name: 'duplicate_acceptance', pathname: run + '/accept', body: acceptance, status: 409},
  ];
  const getters = new Set(['/', '/favicon.ico', '/api/health', '/api/session', '/api/projects',
    '/api/local-preparation/capabilities', project, project + '/conversion-plan', project + '/source-sets',
    run + '/evidence', run + '/download', ...Object.keys(fixture.ui).filter(key => key !== 'index.html').map(key => '/' + key)]);
  let next = 0, armed = null;
  const counters = {login: 0, acceptance_attempts: 0, allowed_gets: 0};
  return {
    project, run, counters,
    arm(name) {
      need(armed === null && actions[next]?.name === name, 'ACTION_SEQUENCE_INVALID');
      armed = actions[next];
      return {pathname: armed.pathname, body: {...armed.body}, status: armed.status};
    },
    request(method, rawUrl, body) {
      const url = new URL(rawUrl);
      need(url.origin === ORIGIN && !url.username && !url.password && !url.search && !url.hash,
        'REQUEST_ORIGIN_OR_URL_BLOCKED');
      if (method === 'GET') {
        const sourceMetadata = new RegExp('^' + project + '/source-sets/ss-[a-f0-9]{32}$').test(url.pathname);
        need(getters.has(url.pathname) || sourceMetadata, 'GET_NOT_ALLOWED');
        counters.allowed_gets++;
        return {kind: 'read', pathname: url.pathname, expectedStatus: null};
      }
      need(method === 'POST' && armed !== null && url.pathname === armed.pathname,
        'UNARMED_MUTATION_BLOCKED');
      need(canonical(body) === canonical(armed.body), 'MUTATION_BODY_DIFFERS');
      const action = armed;
      armed = null; next++;
      if (action.name === 'login') counters.login++; else counters.acceptance_attempts++;
      return {kind: action.name, pathname: url.pathname, expectedStatus: action.status};
    },
    complete() {
      need(next === actions.length && armed === null && counters.login === 1 && counters.acceptance_attempts === 3,
        'ACTION_SEQUENCE_INCOMPLETE');
    },
  };
}

export function assertRun(project, fixture, accepted) {
  need(record(project) && project.id === fixture.project_id && project.name === fixture.project_name
    && project.inventory?.source_hash === fixture.source_hash && project.inventory?.conversion_profile === 'native-project-v1'
    && project.project_plan?.forms?.length === fixture.form_count
    && project.project_plan?.summary?.form_count === fixture.form_count
    && Array.isArray(project.runs) && project.runs.length === 1, 'PROJECT_RESPONSE_BINDING_DIFFERS');
  const run = project.runs[0];
  need(run.id === fixture.run_id && run.project_id === fixture.project_id && run.source_hash === fixture.source_hash
    && run.state === (accepted ? 'ACCEPTED' : 'VERIFIED') && run.artifact_generated === true
    && run.technical_verified === true && run.human_accepted === accepted && run.downloadable === accepted
    && run.review_available === !accepted, 'RUN_RESPONSE_BINDING_DIFFERS');
  return run;
}

export function assertEvidence(value, fixture) {
  const proof = value?.technical_verification;
  need(record(proof) && proof.scope === 'fox-project-technical-verification-v1'
    && proof.job_id === fixture.run_id && proof.source_manifest_sha256 === fixture.source_hash
    && proof.package_sha256 === fixture.package_sha256 && proof.human_acceptance_recorded === false
    && proof.clean_schema_install_passed === true && proof.authenticated_runtime_passed === true
    && Array.isArray(proof.form_results) && proof.form_results.length === fixture.form_count
    && new Set(proof.form_results.map(row => row.module_id)).size === fixture.form_count,
  'TECHNICAL_EVIDENCE_BINDING_DIFFERS');
  return sha(canonical(proof)); // Semantic API JSON identity, not the raw retained proof-file SHA.
}

export function finalizeReport(report, failure, closed) {
  report.browser_closed = closed;
  if (failure !== null || report.blocked_requests !== 0) {
    report.passed = false;
    report.failure_code = failure ?? 'UNEXPECTED_BROWSER_ACTION';
  }
  if (!closed) {
    report.passed = false;
    report.failure_code = 'BROWSER_CLOSE_UNCONFIRMED';
  }
  return report;
}

export function decodedResponseHeaders(headers, bytes) {
  need(record(headers) && Number.isSafeInteger(bytes) && bytes >= 0 && bytes <= MAX_RESPONSE,
    'RESPONSE_HEADERS_INVALID');
  // APIResponse.body() is decoded by Playwright's fetch client. Do not send
  // gzip/transfer framing or the compressed length alongside those bytes.
  const result = {};
  for (const [key, value] of Object.entries(headers)) {
    const name = key.toLowerCase();
    need(typeof value === 'string', 'RESPONSE_HEADERS_INVALID');
    if (!['content-encoding', 'transfer-encoding', 'content-length'].includes(name)) result[name] = value;
  }
  result['content-length'] = String(bytes);
  return result;
}

function checkedDirectory(directory) {
  need(process.platform === 'linux' && process.getuid() > 0, 'UNPRIVILEGED_LINUX_RUNNER_REQUIRED');
  for (let current = directory;; current = path.dirname(current)) {
    const stat = lstatSync(current);
    need(!stat.isSymbolicLink() && realpathSync(current) === current, 'OUTPUT_PATH_LINK_FORBIDDEN');
    if (path.dirname(current) === current) break;
  }
  const stat = lstatSync(directory);
  need(stat.isDirectory() && stat.uid === process.getuid() && (stat.mode & 0o777) === 0o700
    && readdirSync(directory).length === 0, 'FRESH_PRIVATE_OUTPUT_REQUIRED');
  return {dev: stat.dev, ino: stat.ino};
}

function outputWriter(directory, identity) {
  return (name, raw) => {
    need(/^(browser-intent\.json|browser-result\.json|accepted-apex\.zip)$/.test(name), 'OUTPUT_NAME_INVALID');
    const stat = lstatSync(directory);
    need(stat.isDirectory() && !stat.isSymbolicLink() && stat.dev === identity.dev && stat.ino === identity.ino
      && stat.uid === process.getuid() && (stat.mode & 0o777) === 0o700, 'OUTPUT_DIRECTORY_CHANGED');
    const descriptor = openSync(path.join(directory, name), constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, 0o600);
    try { writeFileSync(descriptor, raw); fsyncSync(descriptor); } finally { closeSync(descriptor); }
    const parent = openSync(directory, constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW);
    try { fsyncSync(parent); } finally { closeSync(parent); }
  };
}

export async function run(rawInput) {
  const input = validateInput(rawInput), fixture = input.fixture, policy = createRequestPolicy(input);
  need(!process.env.DEBUG && !process.env.PWDEBUG && !process.env.NODE_OPTIONS, 'DEBUG_ENVIRONMENT_FORBIDDEN');
  const identity = checkedDirectory(input.output_directory), save = outputWriter(input.output_directory, identity);
  const report = {schema_version: 1, scope: 'fox-isolated-project-delivery-browser-v1', passed: false,
    origin: ORIGIN, synthetic_owner: input.username, fixture_sha256: sha(canonical(fixture)),
    job_id: fixture.run_id, package_sha256: fixture.package_sha256, retained_proof_sha256: fixture.proof_sha256,
    raw_retained_proof_verified_by_browser: false, live_acceptance_recorded: false,
    conversion_invoked: false, model_invoked: false, database_connection_opened: false,
    personal_profile_used: false, screenshots_or_traces_saved: false, tests: [], served_ui: {},
    browser_closed: false, blocked_requests: 0, requests: policy.counters};
  save('browser-intent.json', JSON.stringify({schema_version: 1, scope: report.scope,
    fixture_sha256: report.fixture_sha256, job_id: fixture.run_id, origin: ORIGIN,
    pid: process.pid, started_at_utc: new Date().toISOString(), automatic_replay_permitted: false}) + '\n');
  let browser, context, page, failure = null, phase = 'launch';
  const inFlightRoutes = new Set();
  const mark = name => report.tests.push({name, status: 'PASSED'});
  try {
    const modulePath = path.resolve(input.playwright_module), moduleStat = lstatSync(modulePath);
    need(moduleStat.isFile() && !moduleStat.isSymbolicLink() && realpathSync(modulePath) === modulePath,
      'PLAYWRIGHT_MODULE_UNSAFE');
    const require = createRequire(modulePath), version = require('./package.json').version;
    need(version === '1.64.0', 'PLAYWRIGHT_VERSION_DIFFERS');
    const {chromium} = await import(pathToFileURL(modulePath).href);
    browser = await chromium.launch({headless: true, args: ['--disable-background-networking', '--disable-component-update', '--disable-sync', '--no-first-run']});
    report.browser = {playwright: version, version: browser.version()};
    context = await browser.newContext({viewport: {width: 1440, height: 1000}, acceptDownloads: true, serviceWorkers: 'block'});
    context.setDefaultTimeout(15000);
    const handleRoute = async route => {
      try {
        const request = route.request();
        const action = policy.request(request.method(), request.url(), request.method() === 'POST' ? request.postDataJSON() : undefined);
        const response = await route.fetch({maxRedirects: 0, maxRetries: 0, timeout: 15000});
        need(response.status() < 300 || response.status() >= 400, 'REDIRECT_FORBIDDEN');
        if (action.expectedStatus !== null) need(response.status() === action.expectedStatus, 'POST_STATUS_DIFFERS');
        const declared = response.headers()['content-length'];
        if (declared !== undefined) need(/^\d+$/.test(declared) && Number(declared) <= MAX_RESPONSE, 'RESPONSE_TOO_LARGE');
        const bytes = await response.body();
        need(bytes.length <= MAX_RESPONSE, 'RESPONSE_TOO_LARGE');
        const asset = action.pathname === '/' ? 'index.html' : action.pathname.slice(1);
        if (Object.hasOwn(fixture.ui, asset)) {
          need(sha(bytes) === fixture.ui[asset], 'SERVED_UI_BYTES_CHANGED');
          report.served_ui[asset] = sha(bytes);
        }
        await route.fulfill({status: response.status(), headers: decodedResponseHeaders(response.headers(), bytes.length), body: bytes});
      } catch (error) {
        failure = /^[A-Z0-9_]+$/.test(error.message ?? '') ? error.message : 'REQUEST_GUARD_FAILED';
        report.blocked_requests++;
        await route.abort('blockedbyclient').catch(() => {});
      }
    };
    await context.route('**/*', route => {
      const operation = handleRoute(route);
      inFlightRoutes.add(operation);
      void operation.finally(() => inFlightRoutes.delete(operation)).catch(() => { failure = 'REQUEST_HANDLER_FAILED'; });
      return operation;
    });
    await context.routeWebSocket('**/*', socket => { failure = 'WEBSOCKET_FORBIDDEN'; socket.close(); });
    page = await context.newPage();
    page.on('popup', popup => { failure = 'POPUP_FORBIDDEN'; void popup.close(); });
    page.on('pageerror', () => { failure = 'PAGE_SCRIPT_ERROR'; });
    const get = async relative => page.evaluate(async url => {
      const response = await fetch(url, {credentials: 'same-origin', redirect: 'error'});
      return {status: response.status, body: await response.json()};
    }, relative);
    const post = async (name, action) => {
      const armed = policy.arm(name);
      const pending = page.waitForResponse(response => new URL(response.url()).pathname === armed.pathname && response.request().method() === 'POST');
      // Attach an observer immediately so a failed click cannot produce an unhandled promise rejection.
      void pending.catch(() => {});
      if (action) await action();
      else await page.evaluate(async ({pathname, body}) => {
        const response = await fetch(pathname, {method: 'POST', credentials: 'same-origin', redirect: 'error',
          headers: {'Content-Type': 'application/json'}, body: JSON.stringify(body)});
        await response.arrayBuffer();
      }, armed);
      const response = await pending;
      need(response.status() === armed.status, 'POST_STATUS_DIFFERS');
      return response.json();
    };
    phase = 'login';
    await page.goto(ORIGIN, {waitUntil: 'domcontentloaded'});
    await page.getByLabel('Username', {exact: true}).fill(input.username);
    await page.getByLabel('Password', {exact: true}).fill(input.password);
    await post('login', () => page.getByRole('button', {name: 'Sign in', exact: true}).click());
    const session = await get('/api/session');
    need(session.status === 200 && session.body.username === input.username
      && session.body.conversion_profile === 'native-project-v1' && session.body.conversion_configured === false,
    'ISOLATED_SESSION_DIFFERS');
    const health = await get('/api/health');
    need(health.status === 200 && health.body.worker?.enabled === false, 'WORKER_MUST_BE_DISABLED');
    const projects = await get('/api/projects');
    need(projects.status === 200 && Array.isArray(projects.body) && projects.body.length === 1
      && projects.body[0].id === fixture.project_id, 'ONE_SYNTHETIC_PROJECT_REQUIRED');
    const card = page.locator('button.fw-project-card').filter({has: page.getByRole('heading', {name: fixture.project_name, exact: true, level: 3})});
    await card.waitFor({state: 'visible'});
    need(await card.count() === 1, 'PROJECT_CARD_DIFFERS');
    await card.click();
    await page.getByRole('navigation', {name: 'Conversion steps', exact: true}).getByRole('button', {name: /^5\s*Output$/}).click();
    const row = page.getByRole('article', {name: 'Output for run ' + fixture.run_id, exact: true});
    await row.waitFor({state: 'visible'});
    const firstProject = await get(policy.project);
    need(firstProject.status === 200, 'PROJECT_UNAVAILABLE');
    assertRun(firstProject.body, fixture, false);
    const firstEvidence = await get(policy.run + '/evidence');
    need(firstEvidence.status === 200, 'TECHNICAL_EVIDENCE_UNAVAILABLE');
    report.technical_evidence_before_sha256 = assertEvidence(firstEvidence.body, fixture);
    need(Object.keys(report.served_ui).length >= 3 && Object.hasOwn(report.served_ui, 'index.html'), 'BUILT_UI_NOT_OBSERVED');
    mark('exact_built_ui_and_normal_synthetic_login');

    phase = 'review_gates';
    const review = row.getByRole('region', {name: 'Human acceptance', exact: true});
    const accept = review.getByRole('button', {name: 'Accept tested package', exact: true});
    const download = row.getByRole('button', {name: 'Download APEX package', exact: true});
    need(await accept.isDisabled() && await download.isDisabled(), 'UNACCEPTED_UI_MUST_STAY_LOCKED');
    need((await get(policy.run + '/download')).status === 409, 'UNACCEPTED_DOWNLOAD_MUST_BE_BLOCKED');
    await post('incomplete_review');
    assertRun((await get(policy.project)).body, fixture, false);
    mark('incomplete_review_does_not_unlock_package');

    phase = 'explicit_synthetic_review';
    const tested = review.getByLabel('I tested the business flow.', {exact: true});
    const remediation = review.getByLabel('I reviewed the unresolved remediation.', {exact: true});
    const notes = review.getByLabel('Test notes', {exact: true});
    need(!await tested.isChecked() && !await remediation.isChecked() && await notes.inputValue() === '', 'REVIEW_MUST_START_EMPTY');
    await tested.check(); need(await accept.isDisabled(), 'BOTH_REVIEW_CHECKS_REQUIRED');
    await remediation.check(); need(await accept.isDisabled(), 'REVIEW_NOTES_REQUIRED');
    await notes.fill('   '); need(await accept.isDisabled(), 'NONBLANK_REVIEW_NOTES_REQUIRED');
    await notes.fill(NOTES);
    const accepted = await post('acceptance', () => accept.click());
    need(accepted.id === fixture.run_id && accepted.state === 'ACCEPTED'
      && accepted.artifact_sha256 === fixture.package_sha256, 'ACCEPTANCE_PACKAGE_BINDING_DIFFERS');
    assertRun((await get(policy.project)).body, fixture, true);
    mark('normal_ui_records_only_synthetic_review');

    phase = 'exact_download';
    const pendingDownload = page.waitForEvent('download');
    void pendingDownload.catch(() => {});
    await download.click();
    const delivery = await pendingDownload;
    need(delivery.suggestedFilename() === fixture.run_id + '-apex.zip', 'DOWNLOAD_FILENAME_DIFFERS');
    const stream = await delivery.createReadStream();
    need(stream !== null, 'DOWNLOAD_STREAM_UNAVAILABLE');
    const chunks = []; let count = 0;
    for await (const chunk of stream) {
      count += chunk.length; need(count <= fixture.package_bytes, 'DOWNLOAD_TOO_LARGE'); chunks.push(chunk);
    }
    const zip = Buffer.concat(chunks);
    need(zip.length === fixture.package_bytes && sha(zip) === fixture.package_sha256, 'EXACT_ZIP_BYTES_DIFFER');
    save('accepted-apex.zip', zip);
    report.download = {name: 'accepted-apex.zip', bytes: zip.length, sha256: sha(zip)};
    mark('normal_ui_download_returns_exact_genuine_zip');

    phase = 'unchanged_proof_and_duplicate_guard';
    await post('duplicate_acceptance');
    assertRun((await get(policy.project)).body, fixture, true);
    const finalEvidence = await get(policy.run + '/evidence');
    need(finalEvidence.status === 200, 'TECHNICAL_EVIDENCE_UNAVAILABLE');
    report.technical_evidence_after_sha256 = assertEvidence(finalEvidence.body, fixture);
    need(report.technical_evidence_after_sha256 === report.technical_evidence_before_sha256, 'TECHNICAL_EVIDENCE_CHANGED');
    policy.complete(); need(failure === null && report.blocked_requests === 0, 'UNEXPECTED_BROWSER_ACTION');
    mark('duplicate_review_blocked_and_technical_proof_unchanged');
    report.passed = true;
  } catch (error) {
    report.failure_phase = phase;
    report.failure_code = failure ?? (/^[A-Z0-9_]+$/.test(error.message ?? '') ? error.message : 'BROWSER_STEP_FAILED');
  } finally {
    let closed = true;
    try { if (context) await context.close(); } catch { closed = false; }
    try { if (browser) await browser.close(); } catch { closed = false; }
    // Closing a page can settle an already-started handler with an error.
    // Preserve that error before deciding whether the complete run passed.
    await Promise.allSettled([...inFlightRoutes]);
    if (browser?.isConnected()) closed = false;
    finalizeReport(report, failure, closed);
    report.finished_at_utc = new Date().toISOString();
    save('browser-result.json', JSON.stringify(report, null, 2) + '\n');
  }
  return report;
}

async function main() {
  need(process.argv.slice(2).length === 1 && process.argv[2] === '--apply', 'EXPLICIT_ISOLATED_BROWSER_APPLY_REQUIRED');
  let length = 0; const chunks = [];
  for await (const chunk of process.stdin) { length += chunk.length; need(length <= MAX_INPUT, 'STDIN_BOUND_EXCEEDED'); chunks.push(chunk); }
  const report = await run(JSON.parse(Buffer.concat(chunks).toString('utf8')));
  process.stdout.write(JSON.stringify({status: report.passed ? 'PASSED' : 'FAILED',
    scope: report.scope, job_id: report.job_id, package_sha256: report.package_sha256,
    live_acceptance_recorded: false, browser_closed: report.browser_closed,
    automatic_replay_permitted: false}) + '\n');
  return report.passed ? 0 : 1;
}

if (process.argv[1] && import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href) {
  try { process.exitCode = await main(); }
  catch (error) {
    // A persistence failure can occur after the normal acceptance POST.
    // Do not label an unconfirmed outcome as a preflight-only/no-write result.
    process.stderr.write(JSON.stringify({status: 'NOT_CONFIRMED',
      code: /^[A-Z0-9_]+$/.test(error.message ?? '') ? error.message : 'DELIVERY_BROWSER_PREFLIGHT_FAILED',
      live_acceptance_recorded: false, automatic_replay_permitted: false}) + '\n');
    process.exitCode = 1;
  }
}
