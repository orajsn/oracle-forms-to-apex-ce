// Pure policy/contract tests. No browser, server, model, DB or live acceptance.
import test from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import {canonical, validateInput, createRequestPolicy, assertRun, assertEvidence, finalizeReport, decodedResponseHeaders, ORIGIN, NOTES} from './browser.mjs';

const clone = value => JSON.parse(JSON.stringify(value));
function input() {
  return {origin: ORIGIN, username: 'synthetic-project-delivery', password: 'A'.repeat(48),
    output_directory: path.resolve('work/synthetic-delivery-browser-only'),
    playwright_module: path.resolve('qa/node_modules/playwright/index.mjs'),
    fixture: {project_id: 'a'.repeat(32), project_name: 'Synthetic two form delivery',
      run_id: 'fox-' + 'b'.repeat(20), source_hash: 'c'.repeat(64), package_sha256: 'd'.repeat(64),
      proof_sha256: 'e'.repeat(64), package_bytes: 1234, form_count: 2, notes: NOTES,
      ui: {'index.html': 'f'.repeat(64), 'assets/index-a.js': '1'.repeat(64), 'assets/index-b.css': '2'.repeat(64)}}};
}
const failure = (fn, code) => assert.throws(fn, error => error.message === code);
function project(fixture, accepted = false) {
  return {id: fixture.project_id, name: fixture.project_name,
    inventory: {source_hash: fixture.source_hash, conversion_profile: 'native-project-v1'},
    project_plan: {forms: [{}, {}], summary: {form_count: 2}},
    runs: [{id: fixture.run_id, project_id: fixture.project_id, source_hash: fixture.source_hash,
      state: accepted ? 'ACCEPTED' : 'VERIFIED', artifact_generated: true, technical_verified: true,
      human_accepted: accepted, downloadable: accepted, review_available: !accepted}]};
}
function evidence(fixture) {
  return {technical_verification: {scope: 'fox-project-technical-verification-v1',
    job_id: fixture.run_id, source_manifest_sha256: fixture.source_hash,
    package_sha256: fixture.package_sha256, human_acceptance_recorded: false,
    clean_schema_install_passed: true, authenticated_runtime_passed: true,
    form_results: [{module_id: 'form-a'}, {module_id: 'form-b'}]}};
}

test('input keeps only explicit non-secret fixture fields', () => {
  const value = input(); value.fixture.unused_private_metadata = 'not copied';
  const actual = validateInput(value);
  assert.equal(actual.username, 'synthetic-project-delivery');
  assert.equal(actual.fixture.form_count, 2);
  assert.equal(Object.hasOwn(actual.fixture, 'unused_private_metadata'), false);
  assert.notEqual(actual.fixture.ui, value.fixture.ui);
});

for (const [label, mutation, code] of [
  ['public host', x => { x.origin = 'https://fox.129.213.189.48.sslip.io'; }, 'ISOLATED_NORMAL_LOGIN_REQUIRED'],
  ['different port', x => { x.origin = 'http://127.0.0.1:8100'; }, 'ISOLATED_NORMAL_LOGIN_REQUIRED'],
  ['localhost alias', x => { x.origin = 'http://localhost:8123'; }, 'ISOLATED_NORMAL_LOGIN_REQUIRED'],
  ['real owner', x => { x.username = 'jason'; }, 'ISOLATED_NORMAL_LOGIN_REQUIRED'],
  ['weak password', x => { x.password = 'demo'; }, 'ISOLATED_NORMAL_LOGIN_REQUIRED'],
  ['extra top-level action', x => { x.approve_real_user = true; }, 'INPUT_FIELDS_INVALID'],
  ['relative output', x => { x.output_directory = 'out'; }, 'ABSOLUTE_OUTPUT_REQUIRED'],
  ['one form', x => { x.fixture.form_count = 1; }, 'EXACT_SYNTHETIC_PROJECT_BINDING_REQUIRED'],
  ['unbound raw proof', x => { delete x.fixture.proof_sha256; }, 'EXACT_SYNTHETIC_PROJECT_BINDING_REQUIRED'],
  ['non-synthetic notes', x => { x.fixture.notes = 'Jason accepts this application'; }, 'EXACT_SYNTHETIC_PROJECT_BINDING_REQUIRED'],
  ['oversized package', x => { x.fixture.package_bytes = 8_000_001; }, 'EXACT_SYNTHETIC_PROJECT_BINDING_REQUIRED'],
  ['remote module', x => { x.playwright_module = 'https://example.com/playwright/index.mjs'; }, 'LOCAL_PLAYWRIGHT_MODULE_REQUIRED'],
  ['unbounded asset path', x => { x.fixture.ui['../secret'] = 'a'.repeat(64); }, 'UI_MEMBER_INVALID'],
]) test('rejects ' + label, () => {
  const value = input(); mutation(value); failure(() => validateInput(value), code);
});

test('canonical equality ignores object order but not types or fields', () => {
  assert.equal(canonical({b: [1, true], a: 'x'}), canonical({a: 'x', b: [1, true]}));
  assert.notEqual(canonical({a: false}), canonical({a: 0}));
  failure(() => canonical({a: Infinity}), 'CANONICAL_VALUE_INVALID');
  failure(() => canonical({a: undefined}), 'CANONICAL_VALUE_INVALID');
});

test('read allowlist is limited to one project and pinned UI assets', () => {
  const policy = createRequestPolicy(input());
  for (const uri of ['/', '/api/health', '/api/session', '/api/projects', policy.project,
    policy.project + '/conversion-plan', policy.project + '/source-sets',
    policy.project + '/source-sets/ss-' + 'a'.repeat(32), policy.run + '/evidence',
    policy.run + '/download', '/assets/index-a.js']) {
    assert.equal(policy.request('GET', ORIGIN + uri).kind, 'read');
  }
  failure(() => policy.request('GET', ORIGIN + '/api/projects/' + 'b'.repeat(32)), 'GET_NOT_ALLOWED');
  failure(() => policy.request('GET', ORIGIN + '/assets/unknown.js'), 'GET_NOT_ALLOWED');
  failure(() => policy.request('GET', ORIGIN + policy.project + '?secret=yes'), 'REQUEST_ORIGIN_OR_URL_BLOCKED');
  failure(() => policy.request('GET', 'https://example.com/'), 'REQUEST_ORIGIN_OR_URL_BLOCKED');
  failure(() => policy.request('GET', 'http://username:password@127.0.0.1:8123/'), 'REQUEST_ORIGIN_OR_URL_BLOCKED');
  failure(() => policy.request('GET', ORIGIN + '/#fragment'), 'REQUEST_ORIGIN_OR_URL_BLOCKED');
});

test('all mutations are blocked until the exact next action is armed', () => {
  const policy = createRequestPolicy(input());
  failure(() => policy.request('POST', ORIGIN + policy.run + '/accept', {}), 'UNARMED_MUTATION_BLOCKED');
  failure(() => policy.arm('acceptance'), 'ACTION_SEQUENCE_INVALID');
  const login = policy.arm('login');
  failure(() => policy.arm('login'), 'ACTION_SEQUENCE_INVALID');
  failure(() => policy.request('POST', ORIGIN + '/api/login', {...login.body, role: 'admin'}), 'MUTATION_BODY_DIFFERS');
  failure(() => policy.request('DELETE', ORIGIN + '/api/login', login.body), 'UNARMED_MUTATION_BLOCKED');
  assert.equal(policy.request('POST', ORIGIN + '/api/login', login.body).expectedStatus, 200);
  failure(() => policy.request('POST', ORIGIN + '/api/login', login.body), 'UNARMED_MUTATION_BLOCKED');
  failure(() => policy.request('POST', ORIGIN + policy.project + '/runs', {}), 'UNARMED_MUTATION_BLOCKED');
});

test('ordered four-action sequence permits only one successful synthetic acceptance', () => {
  const policy = createRequestPolicy(input());
  for (const [name, status] of [['login', 200], ['incomplete_review', 422], ['acceptance', 200], ['duplicate_acceptance', 409]]) {
    const action = policy.arm(name);
    assert.equal(action.status, status);
    const result = policy.request('POST', ORIGIN + action.pathname, clone(action.body));
    assert.equal(result.kind, name); assert.equal(result.expectedStatus, status);
  }
  policy.complete();
  assert.deepEqual(policy.counters, {login: 1, acceptance_attempts: 3, allowed_gets: 0});
  failure(() => policy.arm('acceptance'), 'ACTION_SEQUENCE_INVALID');
});

test('incomplete or changed request sequence cannot be reported complete', () => {
  const policy = createRequestPolicy(input());
  failure(() => policy.complete(), 'ACTION_SEQUENCE_INCOMPLETE');
  const login = policy.arm('login'); policy.request('POST', ORIGIN + login.pathname, login.body);
  const review = policy.arm('incomplete_review');
  failure(() => policy.request('POST', ORIGIN + review.pathname, {...review.body, business_flow_tested: true}), 'MUTATION_BODY_DIFFERS');
  failure(() => policy.complete(), 'ACTION_SEQUENCE_INCOMPLETE');
});

test('project/run projection requires actual declared generated and technical states', () => {
  const fixture = input().fixture;
  assert.equal(assertRun(project(fixture), fixture, false).state, 'VERIFIED');
  assert.equal(assertRun(project(fixture, true), fixture, true).state, 'ACCEPTED');
  for (const key of ['artifact_generated', 'technical_verified']) {
    const value = project(fixture); value.runs[0][key] = false;
    failure(() => assertRun(value, fixture, false), 'RUN_RESPONSE_BINDING_DIFFERS');
  }
  const wrong = project(fixture); wrong.runs[0].source_hash = '0'.repeat(64);
  failure(() => assertRun(wrong, fixture, false), 'RUN_RESPONSE_BINDING_DIFFERS');
  const partial = project(fixture); partial.project_plan.forms.pop();
  failure(() => assertRun(partial, fixture, false), 'PROJECT_RESPONSE_BINDING_DIFFERS');
  const accepted = project(fixture, true);
  failure(() => assertRun(accepted, fixture, false), 'RUN_RESPONSE_BINDING_DIFFERS');
});

test('evidence binds whole project and keeps human acceptance out of technical proof', () => {
  const fixture = input().fixture, value = evidence(fixture);
  const before = assertEvidence(value, fixture);
  assert.match(before, /^[a-f0-9]{64}$/);
  assert.equal(assertEvidence(clone(value), fixture), before);
  for (const mutation of [
    x => { x.technical_verification.human_acceptance_recorded = true; },
    x => { x.technical_verification.scope = 'fox-native-technical-verification-v2'; },
    x => { x.technical_verification.package_sha256 = '0'.repeat(64); },
    x => { x.technical_verification.form_results.pop(); },
    x => { x.technical_verification.form_results[1].module_id = 'form-a'; },
    x => { x.technical_verification.clean_schema_install_passed = false; },
  ]) {
    const changed = clone(value); mutation(changed);
    failure(() => assertEvidence(changed, fixture), 'TECHNICAL_EVIDENCE_BINDING_DIFFERS');
  }
});

test('late request failures or uncertain browser closure cannot leave a passing report', () => {
  assert.equal(finalizeReport({passed: true, blocked_requests: 0}, null, true).passed, true);
  const late = finalizeReport({passed: true, blocked_requests: 1}, 'GET_NOT_ALLOWED', true);
  assert.equal(late.passed, false); assert.equal(late.failure_code, 'GET_NOT_ALLOWED');
  const callback = finalizeReport({passed: true, blocked_requests: 0}, 'PAGE_SCRIPT_ERROR', true);
  assert.equal(callback.passed, false);
  const close = finalizeReport({passed: true, blocked_requests: 0}, null, false);
  assert.equal(close.passed, false); assert.equal(close.failure_code, 'BROWSER_CLOSE_UNCONFIRMED');
});

test('decoded fulfillment removes compressed framing while retaining normal cookies and disposition', () => {
  assert.deepEqual(decodedResponseHeaders({'Content-Encoding': 'gzip', 'Content-Length': '10',
    'Transfer-Encoding': 'chunked', 'Content-Type': 'application/zip', 'Set-Cookie': 'synthetic-cookie',
    'Content-Disposition': 'attachment; filename="synthetic.zip"'}, 100), {
    'content-type': 'application/zip', 'set-cookie': 'synthetic-cookie',
    'content-disposition': 'attachment; filename="synthetic.zip"', 'content-length': '100',
  });
  failure(() => decodedResponseHeaders({}, 8_000_001), 'RESPONSE_HEADERS_INVALID');
});

