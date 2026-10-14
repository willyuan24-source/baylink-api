// API-OPS-KEY: ANTHROPIC_USE_UNTIL reading, the startup warning, the admin metrics field and
// scripts/check-ai-readiness.mjs. $0: no provider call, no network beyond 127.0.0.1 stubs.
const test = require('node:test');
const assert = require('node:assert/strict');
const http = require('node:http');
const path = require('node:path');
const { execFile } = require('node:child_process');
const { pathToFileURL } = require('node:url');
const jwt = require('jsonwebtoken');
const { readUseUntil, useUntilStatus, useUntilWarning, USE_UNTIL_PROBLEMS } = require('../lib/anthropicUseUntil');
const { anthropicAvailable } = require('../lib/anthropicBaybay');
const { createMemoryModels } = require('./support/memory-models');
const { createApplication } = require('../server');

const SECRET = 'isolated-ai-readiness-test-secret';
const NOW = Date.parse('2026-10-13T20:00:00Z');
const SCRIPT = path.join(__dirname, '..', 'scripts', 'check-ai-readiness.mjs');
const loadScript = () => import(pathToFileURL(SCRIPT).href);

// anthropicAvailable as it was before API-OPS-KEY (d9bae34), verbatim: the oracle that pins
// "do not change what valid values do" (and what invalid values do).
function legacyAnthropicAvailable(config, now = Date.now()) {
  if (typeof config.ANTHROPIC_API_KEY !== 'string' || !config.ANTHROPIC_API_KEY.trim()) return false;
  const until = config.ANTHROPIC_USE_UNTIL;
  if (until == null || until === '') return true;
  if (typeof until !== 'string' || !/^\d{4}-\d{2}-\d{2}(?:T\d{2}:\d{2}:\d{2}(?:\.\d{1,3})?(?:Z|[+-]\d{2}:\d{2}))?$/.test(until)) return false;
  const expiry = Date.parse(until), day = until.slice(0, 10);
  const [year, month, date] = day.split('-').map(Number);
  const validDay = new Date(Date.UTC(year, month - 1, date)).toISOString().slice(0, 10) === day;
  return validDay && Number.isFinite(expiry) && Number.isFinite(now) && now < expiry;
}

const VALID = [
  ['2027-04-19', Date.UTC(2027, 3, 19)],
  ['2027-04-19T00:00:00Z', Date.UTC(2027, 3, 19)],
  ['2027-04-18T17:00:00-07:00', Date.UTC(2027, 3, 19)],
  ['2026-10-30T00:00:00Z', Date.UTC(2026, 9, 30)],
  ['2027-04-19T00:00:00.5Z', Date.UTC(2027, 3, 19) + 500],
  ['2027-04-19T05:30:00+05:30', Date.UTC(2027, 3, 19)],
  ['2028-02-29', Date.UTC(2028, 1, 29)],
  ['2027-04-19T24:00:00Z', Date.UTC(2027, 3, 20)],
];
const INVALID = [
  [' ', 'spaces'], ['2027-04-19 ', 'spaces'], [' 2027-04-19', 'spaces'], ['2027-04-19 00:00:00Z', 'spaces'], ['2027-04-19\t', 'spaces'],
  ['2027-04-19T00:00:00', 'missing_zone'], ['2027-04-19T00:00', 'missing_zone'], ['2027-04-18T17:00:00.000', 'missing_zone'],
  ['2027-02-30', 'invalid_date'], ['2027-02-29', 'invalid_date'], ['2027-02-30T00:00:00Z', 'invalid_date'], ['2027-04-19T25:00:00Z', 'invalid_date'], ['0050-01-01', 'invalid_date'],
  ['2027/04/19', 'format'], ['not-a-date', 'format'], ['1', 'format'], ['2027-04-19T00:00:00z', 'format'], ['2027-04-19T00:00Z', 'format'],
  ['2027-04-19T00:00:00+0700', 'format'], ['2027-04-19T00:00:00.1234Z', 'format'], ['April 19, 2027', 'spaces'], ['20270419', 'format'],
  [1808092800000, 'format'], [true, 'format'], [{}, 'format'],
];

test('readUseUntil: unset means no cutoff; the accepted forms give the cutoff instant; everything else names its problem', () => {
  for (const value of [undefined, null, '']) assert.deepEqual(readUseUntil(value), { set: false, valid: true, problem: null, at: null }, String(value));
  for (const [value, at] of VALID) assert.deepEqual(readUseUntil(value), { set: true, valid: true, problem: null, at }, value);
  for (const [value, problem] of INVALID) {
    assert.deepEqual(readUseUntil(value), { set: true, valid: false, problem, at: null }, JSON.stringify(value));
    assert.ok(USE_UNTIL_PROBLEMS[problem], problem);
  }
});

test('anthropicAvailable is unchanged: identical to the d9bae34 implementation for every value, key and clock', () => {
  const values = [undefined, null, '', ...VALID.map(([value]) => value), ...INVALID.map(([value]) => value), '2000-01-01T00:00:00Z', '9999-12-31', '2026-10-13T20:00:00.000Z'];
  const nows = [NaN, -Infinity, Infinity, 0, NOW - 1, NOW, NOW + 1, Date.UTC(2026, 9, 30) - 1, Date.UTC(2026, 9, 30), Date.UTC(2027, 3, 19) - 1, Date.UTC(2027, 3, 19), 8.64e15];
  let compared = 0;
  for (const key of ['fixture', ' ', '', undefined, 42]) for (const value of values) for (const now of nows) {
    const config = { ...(key === undefined ? {} : { ANTHROPIC_API_KEY: key }), ...(value === undefined ? {} : { ANTHROPIC_USE_UNTIL: value }) };
    assert.equal(anthropicAvailable(config, now), legacyAnthropicAvailable(config, now), `${JSON.stringify(config)} @ ${now}`);
    compared++;
  }
  assert.ok(compared > 2000);
  // The default clock too.
  assert.equal(anthropicAvailable({ ANTHROPIC_API_KEY: 'fixture', ANTHROPIC_USE_UNTIL: '9999-12-31' }), true);
  assert.equal(anthropicAvailable({ ANTHROPIC_API_KEY: 'fixture', ANTHROPIC_USE_UNTIL: '2027-04-19 00:00:00Z' }), false, 'a malformed value still fails closed');
});

test('useUntilWarning: none for unset or valid values; one line naming the problem, never the value', () => {
  for (const value of [undefined, '', ...VALID.map(([item]) => item)]) assert.equal(useUntilWarning({ ANTHROPIC_USE_UNTIL: value }), null, String(value));
  assert.equal(useUntilWarning({}), null);
  assert.equal(useUntilWarning(), null);
  for (const [value, problem] of INVALID) {
    const warning = useUntilWarning({ ANTHROPIC_USE_UNTIL: value });
    assert.match(warning, /^\[ai-config\] ANTHROPIC_USE_UNTIL is set but invalid \(/);
    assert.ok(warning.includes(`(${problem}: `), `${JSON.stringify(value)} -> ${problem}`);
    assert.match(warning, /no advance banner/);
    assert.doesNotMatch(warning, /\n/);
  }
  for (const value of ['sk-ant-api03-pasted-in-the-wrong-variable', '2031-01-02 03:04:05Z', '2031-01-02T03:04:05']) {
    assert.ok(!useUntilWarning({ ANTHROPIC_USE_UNTIL: value }).includes(value), 'the raw value is never logged');
  }
});

test('useUntilStatus: the admin view of the cutoff, without the raw value', () => {
  assert.deepEqual(useUntilStatus({}, NOW), { set: false, valid: true, problem: null, at: null, passed: null });
  assert.deepEqual(useUntilStatus({ ANTHROPIC_USE_UNTIL: '2026-10-30T00:00:00Z' }, NOW), { set: true, valid: true, problem: null, at: '2026-10-30T00:00:00.000Z', passed: false });
  assert.deepEqual(useUntilStatus({ ANTHROPIC_USE_UNTIL: '2026-10-30T00:00:00Z' }, Date.UTC(2026, 9, 30)), { set: true, valid: true, problem: null, at: '2026-10-30T00:00:00.000Z', passed: true });
  assert.deepEqual(useUntilStatus({ ANTHROPIC_USE_UNTIL: '2027-04-18T17:00:00-07:00' }, NOW), { set: true, valid: true, problem: null, at: '2027-04-19T00:00:00.000Z', passed: false });
  assert.deepEqual(useUntilStatus({ ANTHROPIC_USE_UNTIL: 'sk-ant-api03-secret' }, NOW), { set: true, valid: false, problem: 'format', at: null, passed: null });
});

async function startApp(t, config, options = {}) {
  const models = createMemoryModels({ User: [{ id: 'admin', role: 'admin', accountStatus: 'active' }, { id: 'member', role: 'user', accountStatus: 'active' }] });
  const application = createApplication({ models, config: { NODE_ENV: 'test', JWT_SECRET: SECRET, ...config }, plannerNow: () => NOW, ...options });
  await new Promise(resolve => application.server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise(resolve => application.io.close(resolve)));
  const get = async (route, id) => {
    const res = await fetch(`http://127.0.0.1:${application.server.address().port}/api${route}`, { headers: id ? { Authorization: `Bearer ${jwt.sign({ id }, SECRET, { expiresIn: '1h' })}` } : {} });
    return { status: res.status, data: await res.json() };
  };
  return { get };
}

test('server: a malformed ANTHROPIC_USE_UNTIL logs one startup warning and shows in admin metrics; Claude stays off as before', async t => {
  const logged = [];
  const { get } = await startApp(t, { BAYBAY_AI_PROVIDER: 'anthropic', ANTHROPIC_API_KEY: 'fixture-not-a-key', ANTHROPIC_USE_UNTIL: '2027-04-19 00:00:00Z' }, { configWarningLog: line => logged.push(line) });
  assert.equal(logged.length, 1);
  assert.match(logged[0], /^\[ai-config\] ANTHROPIC_USE_UNTIL is set but invalid \(spaces: /);
  assert.ok(!logged[0].includes('2027-04-19 00:00:00Z'));

  assert.equal((await get('/admin/ai-metrics')).status, 401);
  assert.equal((await get('/admin/ai-metrics', 'member')).status, 403);
  const metrics = await get('/admin/ai-metrics', 'admin');
  assert.equal(metrics.status, 200);
  assert.deepEqual(metrics.data.useUntil, { set: true, valid: false, problem: 'spaces', at: null, passed: null });
  assert.ok(!JSON.stringify(metrics.data).includes('2027-04-19 00:00:00Z'));

  // Unchanged behaviour (the reason for the warning): Claude is unavailable at once, no advance banner.
  const capabilities = await get('/ai/baybay-capabilities');
  assert.equal(capabilities.data.enabled, false);
  assert.equal(capabilities.data.pause.reason, 'provider_unavailable');
  assert.equal(capabilities.data.aiUntil, undefined);
  assert.equal(capabilities.data.pauseScheduled, undefined);
  // The public endpoints never carry the admin field.
  assert.equal(capabilities.data.useUntil, undefined);
  assert.equal((await get('/ai/usage')).data.useUntil, undefined);
});

test('server: valid or unset values log nothing; admin metrics show the cutoff and whether it has passed', async t => {
  for (const [config, useUntil] of [
    [{ ANTHROPIC_USE_UNTIL: '2026-10-30T00:00:00Z' }, { set: true, valid: true, problem: null, at: '2026-10-30T00:00:00.000Z', passed: false }],
    [{ ANTHROPIC_USE_UNTIL: '2026-10-01' }, { set: true, valid: true, problem: null, at: '2026-10-01T00:00:00.000Z', passed: true }],
    [{}, { set: false, valid: true, problem: null, at: null, passed: null }],
  ]) {
    const logged = [];
    const { get } = await startApp(t, { BAYBAY_AI_PROVIDER: 'anthropic', ANTHROPIC_API_KEY: 'fixture-not-a-key', ...config }, { configWarningLog: line => logged.push(line) });
    assert.deepEqual(logged, [], JSON.stringify(config));
    assert.deepEqual((await get('/admin/ai-metrics', 'admin')).data.useUntil, useUntil);
  }
});

test('server: tests stay quiet unless a warning log is injected', async t => {
  const warn = t.mock.method(console, 'warn', () => {});
  await startApp(t, { ANTHROPIC_USE_UNTIL: 'not-a-date' });
  assert.equal(warn.mock.calls.filter(call => String(call.arguments[0]).startsWith('[ai-config]')).length, 0);
});

// ---- scripts/check-ai-readiness.mjs ------------------------------------------------------
const LIVE_TODAY = { // GET /api/ai/baybay-capabilities as a guest on 2026-10-13 (d9bae34)
  version: 2, enabled: true, tools: ['site', 'plans'], taskMemory: true, routeEstimates: false, configuredProvider: 'anthropic', configuredModel: 'claude-sonnet-5-5',
  modelAccessVerified: false, engine: 'v2', aiUntil: '2026-10-30T00:00:00.000Z', pause: null, reduced: null, webRequiresAuth: true, webAccess: { authenticated: false, allowed: false, reason: 'auth_required' },
};
const HEALTH = { status: 'ok', service: 'baylink-api', commit: 'd9bae34b65ff2da88cc6564d86c6c1bab0aec6e0' };
const byName = (report, name) => report.checks.find(item => item.name === name);

test('readiness: today\'s live shape is READY; a week before the cutoff it warns about the banner', async () => {
  const { assessReadiness } = await loadScript();
  const today = assessReadiness({ health: HEALTH, capabilities: LIVE_TODAY, now: NOW });
  assert.equal(today.result, 'READY');
  assert.equal(byName(today, 'aiUntil').level, 'ok');
  assert.match(byName(today, 'aiUntil').detail, /Thu, Oct 29, 2026, 5:00 PM PT \(16\.2 days left\)/);
  assert.match(byName(today, 'health').detail, /commit d9bae34$/);
  assert.equal(byName(today, 'key').level, 'info');

  const banner = { kind: 'ai_pause_scheduled', at: LIVE_TODAY.aiUntil, banner: { en: 'The AI assistant is scheduled to pause from Thu, Oct 29, 5:00 PM PT.' } };
  const lastWeek = assessReadiness({ health: HEALTH, capabilities: { ...LIVE_TODAY, pauseScheduled: banner }, now: Date.parse('2026-10-23T17:00:00Z') });
  assert.equal(lastWeek.result, 'READY');
  assert.equal(byName(lastWeek, 'aiUntil').level, 'warn');
  assert.equal(byName(lastWeek, 'scheduled').level, 'warn');
  assert.match(byName(lastWeek, 'scheduled').detail, /scheduled to pause/);
});

test('readiness: after the switch, --expect-until and --expect-commit must match what the API reports', async () => {
  const { assessReadiness } = await loadScript();
  const switched = { ...LIVE_TODAY, aiUntil: '2027-04-19T00:00:00.000Z' };
  for (const expectUntil of ['2027-04-19T00:00:00Z', '2027-04-19', '2027-04-18T17:00:00-07:00']) {
    const report = assessReadiness({ health: HEALTH, capabilities: switched, now: Date.parse('2026-10-23T18:00:00Z'), expectUntil, expectCommit: 'd9bae34' });
    assert.equal(report.result, 'READY', expectUntil);
    assert.equal(byName(report, 'commit').level, 'ok');
  }
  const stale = assessReadiness({ health: HEALTH, capabilities: LIVE_TODAY, now: Date.parse('2026-10-23T18:00:00Z'), expectUntil: '2027-04-19T00:00:00Z' });
  assert.equal(stale.result, 'NOT_READY');
  assert.match(byName(stale, 'aiUntil').detail, /expected 2027-04-19T00:00:00.000Z = Sun, Apr 18, 2027, 5:00 PM PT/);
  assert.equal(assessReadiness({ health: HEALTH, capabilities: switched, now: NOW, expectCommit: 'abcdef1' }).result, 'NOT_READY');
  const missing = assessReadiness({ health: HEALTH, capabilities: { ...LIVE_TODAY, aiUntil: undefined }, now: NOW, expectUntil: '2027-04-19' });
  assert.equal(missing.result, 'NOT_READY'); assert.match(byName(missing, 'aiUntil').detail, /none reported/);
  assert.equal(assessReadiness({ health: HEALTH, capabilities: { ...LIVE_TODAY, aiUntil: undefined }, now: NOW, expectUntil: 'none' }).result, 'READY');
  assert.equal(assessReadiness({ health: HEALTH, capabilities: LIVE_TODAY, now: NOW, expectUntil: 'none' }).result, 'NOT_READY');
  assert.equal(byName(assessReadiness({ health: HEALTH, capabilities: { ...LIVE_TODAY, aiUntil: undefined }, now: NOW }), 'aiUntil').level, 'info');
});

test('readiness: a pause, a passed cutoff, another provider or a bad health read is NOT_READY with the reason', async () => {
  const { assessReadiness } = await loadScript();
  const paused = assessReadiness({ health: HEALTH, now: NOW, capabilities: { ...LIVE_TODAY, enabled: false, aiUntil: undefined, pause: { reason: 'provider_unavailable', kind: 'ai_paused' } } });
  assert.equal(paused.result, 'NOT_READY');
  assert.match(byName(paused, 'pause').detail, /ANTHROPIC_USE_UNTIL is not a valid value/);
  const budget = assessReadiness({ health: HEALTH, now: NOW, capabilities: { ...LIVE_TODAY, enabled: false, pause: { reason: 'daily_budget', resumesAt: '2026-10-14T07:00:00.000Z' } } });
  assert.match(byName(budget, 'pause').detail, /hard \$ cap.*resumes Wed, Oct 14, 2026, 12:00 AM PT/);
  const reduced = assessReadiness({ health: HEALTH, now: NOW, capabilities: { ...LIVE_TODAY, reduced: { reason: 'daily_budget_soft' } } });
  assert.equal(reduced.result, 'READY'); assert.equal(byName(reduced, 'reduced').level, 'warn');
  assert.equal(assessReadiness({ health: HEALTH, now: Date.UTC(2026, 9, 30), capabilities: LIVE_TODAY }).result, 'NOT_READY');
  const openai = assessReadiness({ health: HEALTH, now: NOW, capabilities: { ...LIVE_TODAY, configuredProvider: 'openai', aiUntil: undefined } });
  assert.equal(openai.result, 'NOT_READY'); assert.match(byName(openai, 'provider').detail, /not on Claude/);
  assert.equal(assessReadiness({ health: { status: 'down' }, now: NOW, capabilities: LIVE_TODAY }).result, 'NOT_READY');
  assert.equal(assessReadiness({ now: NOW }).result, 'NOT_READY');
});

test('readiness: arguments are validated with the API\'s own reading of the value', async () => {
  const { parseArgs, DEFAULT_BASE } = await loadScript();
  assert.deepEqual(parseArgs([]), { base: DEFAULT_BASE, json: false });
  assert.equal(parseArgs(['--base', 'http://127.0.0.1:9/api/']).base, 'http://127.0.0.1:9/api');
  assert.equal(parseArgs(['--expect-commit', 'D9BAE34']).expectCommit, 'd9bae34');
  for (const argv of [['--base', 'https://baylink-api.onrender.com'], ['--expect-commit', 'xyz'], ['--expect-until'], ['--nope'], ['--expect-until', '2027-04-19 00:00:00Z'], ['--expect-until', '']]) {
    assert.throws(() => parseArgs(argv), error => error.usage === true, JSON.stringify(argv));
  }
  assert.throws(() => parseArgs(['--expect-until', '2027-04-19T00:00:00']), /missing_zone/);
});

test('readiness --check-value: offline, same verdict as the API', async () => {
  const { main, EXIT } = await loadScript();
  const run = async value => {
    const lines = [];
    const code = await main(['--check-value', value], { fetchImpl: () => { throw new Error('no network in --check-value'); }, now: () => NOW, out: line => lines.push(line) });
    return { code, text: lines.join('\n') };
  };
  const valid = await run('2027-04-19T00:00:00Z');
  assert.equal(valid.code, EXIT.READY); assert.match(valid.text, /RESULT: VALID/); assert.match(valid.text, /Sun, Apr 18, 2027, 5:00 PM PT/);
  assert.match(valid.text, /banner shows from Sun, Apr 11, 2027, 5:00 PM PT/);
  const spaced = await run('2027-04-19 00:00:00Z');
  assert.equal(spaced.code, EXIT.NOT_READY); assert.match(spaced.text, /invalid \(spaces/); assert.match(spaced.text, /RESULT: INVALID/);
  const passed = await run('2026-10-01');
  assert.equal(passed.code, EXIT.NOT_READY); assert.match(passed.text, /RESULT: PASSED/);
  const empty = await run('');
  assert.equal(empty.code, EXIT.READY); assert.match(empty.text, /no cutoff/);
  for (const [value, problem] of INVALID.filter(([item]) => typeof item === 'string')) {
    const result = await run(value);
    assert.equal(result.code, EXIT.NOT_READY, JSON.stringify(value));
    assert.equal(anthropicAvailable({ ANTHROPIC_API_KEY: 'fixture', ANTHROPIC_USE_UNTIL: value }, NOW), false);
    assert.ok(result.text.includes(`(${problem}: `), value);
  }
});

async function stubApi(t, routes) {
  const seen = [];
  const server = http.createServer((req, res) => {
    seen.push({ method: req.method, url: req.url, authorization: req.headers.authorization, cookie: req.headers.cookie });
    const route = routes[req.url];
    res.writeHead(route ? route.status || 200 : 404, { 'content-type': 'application/json' });
    res.end(JSON.stringify(route ? route.body : { code: 'NOT_FOUND' }));
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise(resolve => server.close(resolve)));
  return { base: `http://127.0.0.1:${server.address().port}/api`, seen };
}

test('readiness main: two credential-free GETs; READY, NOT READY and ERROR exit codes', async t => {
  const { main, EXIT } = await loadScript();
  const lines = [], out = line => lines.push(line);
  const ready = await stubApi(t, { '/api/health': { body: HEALTH }, '/api/ai/baybay-capabilities': { body: { ...LIVE_TODAY, aiUntil: '2027-04-19T00:00:00.000Z' } } });
  assert.equal(await main(['--base', ready.base, '--expect-until', '2027-04-19', '--expect-commit', 'd9bae34'], { now: () => NOW, out }), EXIT.READY);
  assert.match(lines.at(-1), /RESULT: READY$/);
  assert.deepEqual(ready.seen.map(item => `${item.method} ${item.url}`).sort(), ['GET /api/ai/baybay-capabilities', 'GET /api/health']);
  assert.ok(ready.seen.every(item => item.authorization === undefined && item.cookie === undefined));

  lines.length = 0;
  assert.equal(await main(['--base', ready.base, '--json'], { now: () => NOW, out }), EXIT.READY);
  const json = JSON.parse(lines[0]);
  assert.equal(json.result, 'READY'); assert.equal(json.aiUntil, '2027-04-19T00:00:00.000Z'); assert.equal(json.commit, HEALTH.commit);

  const paused = await stubApi(t, { '/api/health': { body: HEALTH }, '/api/ai/baybay-capabilities': { body: { ...LIVE_TODAY, enabled: false, pause: { reason: 'paused' } } } });
  lines.length = 0;
  assert.equal(await main(['--base', paused.base], { now: () => NOW, out }), EXIT.NOT_READY);
  assert.match(lines[0], /BAYBAY_PAUSED=true/);

  const down = await stubApi(t, { '/api/health': { status: 503, body: { status: 'starting' } } });
  lines.length = 0;
  assert.equal(await main(['--base', down.base], { now: () => NOW, out }), EXIT.ERROR);
  assert.match(lines[0], /^ERROR: GET \/(health|ai\/baybay-capabilities) answered HTTP (503|404)/);

  lines.length = 0;
  assert.equal(await main(['--base', 'nope'], { out }), EXIT.USAGE);
});

test('readiness: runs as a command (exit code and output) against a local stub', async t => {
  const stub = await stubApi(t, { '/api/health': { body: HEALTH }, '/api/ai/baybay-capabilities': { body: { ...LIVE_TODAY, aiUntil: '2099-04-19T00:00:00.000Z' } } });
  const run = args => new Promise(resolve => execFile(process.execPath, [SCRIPT, ...args], { timeout: 30000, windowsHide: true }, (error, stdout) => resolve({ code: error ? error.code : 0, stdout })));
  const ready = await run(['--base', stub.base, '--expect-until', '2099-04-19T00:00:00Z']);
  assert.equal(ready.code, 0, ready.stdout); assert.match(ready.stdout, /RESULT: READY/);
  const invalid = await run(['--check-value', '2027-04-19T00:00:00']);
  assert.equal(invalid.code, 1); assert.match(invalid.stdout, /missing_zone/);
});
