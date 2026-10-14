// API-OPS: the AI credit burn-down (lib/aiCredit.js), its ledger read and retention
// (lib/aiGovernance.js) and the admin AI metrics `credit` field. Offline: memory models only.
const test = require('node:test');
const assert = require('node:assert/strict');
const jwt = require('jsonwebtoken');
const { readCreditTotal, readCreditStart, creditConfig, creditLedgerFrom, creditBurnDown, CREDIT_ALERT_LEAD_DAYS } = require('../lib/aiCredit');
const { createAiGovernance, extendLedgerRetentionAtStartup } = require('../lib/aiGovernance');
const { createMemoryModels } = require('./support/memory-models');
const { createApplication } = require('../server');

const SECRET = 'isolated-ai-credit-test-secret';
const DAY = 86400000;
const NOW = Date.parse('2026-11-20T20:00:00Z'); // Fri 2026-11-20 12:00 PST
const CONFIG = { AI_CREDIT_TOTAL_USD: '1000', AI_CREDIT_START: '2026-10-23', ANTHROPIC_USE_UNTIL: '2027-04-19T00:00:00Z' };
const addDays = (day, count) => new Date(Date.parse(`${day}T12:00:00Z`) + count * DAY).toISOString().slice(0, 10);
// $2/day before the start (the old key), `rate` $/day from the start to yesterday, $1 so far today.
function ledgerFor(rate = 5, { from = '2026-10-01', today = '2026-11-20' } = {}) {
  const days = {}, months = {};
  for (let day = from; day <= today; day = addDays(day, 1)) {
    const micro = Math.round((day < '2026-10-23' ? 2 : day < today ? rate : 1) * 1e6);
    days[day] = micro; months[day.slice(0, 7)] = (months[day.slice(0, 7)] || 0) + micro;
  }
  return { days, months };
}

test('AI_CREDIT_TOTAL_USD and AI_CREDIT_START: what is accepted and the problem names', () => {
  assert.deepEqual(readCreditTotal(undefined), { set: false, valid: true, problem: null, microUsd: null });
  assert.deepEqual(readCreditTotal(' 1000 '), { set: true, valid: true, problem: null, microUsd: 1000e6 });
  assert.equal(readCreditTotal('999.5').microUsd, 999.5e6);
  for (const value of ['$1000', '1,000', '1e3', '-5', 'abc', '10.123']) assert.equal(readCreditTotal(value).problem, 'format', value);
  for (const value of ['0', '0.00', '1000001']) assert.equal(readCreditTotal(value).problem, 'range', value);
  assert.deepEqual(readCreditStart(''), { set: false, valid: true, problem: null, day: null });
  assert.deepEqual(readCreditStart('2026-10-23'), { set: true, valid: true, problem: null, day: '2026-10-23' });
  // A full ISO time counts as its Pacific day (05:00Z on the 24th is the evening of the 23rd).
  assert.equal(readCreditStart('2026-10-24T05:00:00Z').day, '2026-10-23');
  assert.equal(readCreditStart('2026-10-23T09:00:00-07:00').day, '2026-10-23');
  assert.equal(readCreditStart('2026-02-30').problem, 'invalid_date');
  assert.equal(readCreditStart('Oct 23').problem, 'format');
  assert.equal(readCreditStart('2026-10-23T09:00:00').problem, 'missing_zone');
  // Both are needed; one alone names the other as missing.
  assert.equal(creditConfig({}).configured, false);
  assert.deepEqual(creditConfig({}).problems, { total: null, start: null });
  assert.deepEqual(creditConfig({ AI_CREDIT_TOTAL_USD: '1000' }).problems, { total: null, start: 'missing' });
  assert.deepEqual(creditConfig({ AI_CREDIT_START: '2026-10-23' }).problems, { total: 'missing', start: null });
  assert.equal(creditConfig(CONFIG).configured, true);
});

test('the burn-down: spend since the start, 7 / 30-day averages, run-out dates and the cutoff comparison', () => {
  const credit = creditBurnDown({ config: CONFIG, ledger: ledgerFor(5), now: NOW });
  assert.equal(credit.configured, true); assert.equal(credit.totalUsd, 1000); assert.equal(credit.start, '2026-10-23');
  // October from its day rows (10/23-10/31: 9 x $5), November from its month row (19 x $5 + $1 today).
  assert.equal(credit.spentUsd, 141); assert.equal(credit.remainingUsd, 859);
  assert.equal(credit.started, true); assert.equal(credit.daysSinceStart, 29); assert.equal(credit.exhausted, false);
  // Full days before today: the last 7 are all $5; the last 30 reach back to 10/21 (two $2 days).
  assert.deepEqual(credit.perDay, { last7: { days: 7, usd: 5 }, last30: { days: 30, usd: 4.8 } });
  assert.deepEqual(credit.runOut.last7, { day: '2027-05-11', at: '2027-05-11T15:12:00.000Z', daysLeft: 171.8 });
  assert.equal(credit.runOut.last30.day, '2027-05-18');
  // The projection is the faster rate, so the earlier (cautious) date.
  assert.equal(credit.projected.basis, 'last7'); assert.equal(credit.projected.day, '2027-05-11');
  assert.deepEqual(credit.useUntil, { at: '2027-04-19T00:00:00.000Z', daysEarly: -22.6 });
  assert.equal(credit.alert, false);
  assert.match(credit.estimate, /Console/);
});

test('alert: only when the projected run-out comes more than 14 days before a cutoff still ahead', () => {
  assert.equal(CREDIT_ALERT_LEAD_DAYS, 14);
  const fast = creditBurnDown({ config: CONFIG, ledger: ledgerFor(8), now: NOW });
  // 9 x $8 + 19 x $8 + $1 = $225 spent; $775 left at $8/day is 96.9 days: 2027-02-25, 52 days early.
  assert.equal(fast.spentUsd, 225); assert.equal(fast.projected.day, '2027-02-25');
  assert.equal(fast.useUntil.daysEarly, 52.3); assert.equal(fast.alert, true);
  // About 14 days early is not enough.
  const edge = creditBurnDown({ config: { ...CONFIG, ANTHROPIC_USE_UNTIL: '2027-03-11T00:00:00Z' }, ledger: ledgerFor(8), now: NOW });
  assert.ok(edge.useUntil.daysEarly <= 14 && edge.useUntil.daysEarly > 13, String(edge.useUntil.daysEarly)); assert.equal(edge.alert, false);
  // No cutoff, an invalid cutoff or one already passed: nothing to compare, no alert.
  for (const until of ['', '2027-04-19 00:00:00Z', '2026-11-01']) {
    const credit = creditBurnDown({ config: { ...CONFIG, ANTHROPIC_USE_UNTIL: until }, ledger: ledgerFor(8), now: NOW });
    assert.equal(credit.alert, false, until);
  }
  assert.equal(creditBurnDown({ config: { ...CONFIG, ANTHROPIC_USE_UNTIL: '' }, ledger: ledgerFor(8), now: NOW }).useUntil.at, null);
});

test('edge cases: not configured, no spend, exhausted, not started, a start on the 1st, a young ledger, a lost day row', () => {
  // Not configured: averages only (useful on their own), no projection.
  const plain = creditBurnDown({ config: {}, ledger: ledgerFor(5), now: NOW });
  assert.deepEqual(Object.keys(plain), ['configured', 'totalUsd', 'start', 'problems', 'perDay']);
  assert.equal(plain.perDay.last7.usd, 5);
  // No spend at all: no run-out date.
  const quiet = creditBurnDown({ config: CONFIG, ledger: { days: {}, months: {} }, now: NOW });
  assert.equal(quiet.spentUsd, 0); assert.deepEqual(quiet.perDay, { last7: { days: 0, usd: null }, last30: { days: 0, usd: null } });
  assert.equal(quiet.projected, null); assert.equal(quiet.useUntil.daysEarly, null); assert.equal(quiet.alert, false);
  // Exhausted: run-out is now, and with the cutoff months away that is an alert.
  const gone = creditBurnDown({ config: { ...CONFIG, AI_CREDIT_TOTAL_USD: '100' }, ledger: ledgerFor(5), now: NOW });
  assert.equal(gone.exhausted, true); assert.equal(gone.remainingUsd, 0);
  assert.deepEqual(gone.projected, { basis: 'spent', day: '2026-11-20', at: new Date(NOW).toISOString(), daysLeft: 0 });
  assert.equal(gone.alert, true);
  // Set before the switch day: nothing spent yet, and the projection counts from the start.
  const early = creditBurnDown({ config: { ...CONFIG, AI_CREDIT_START: '2026-11-23' }, ledger: ledgerFor(5), now: NOW });
  assert.equal(early.started, false); assert.equal(early.daysSinceStart, 0); assert.equal(early.spentUsd, 0);
  assert.equal(early.runOut.last7.at, new Date(Date.parse('2026-11-23T08:00:00Z') + 200 * DAY).toISOString(), '$1000 at $5/day from Pacific midnight on the start day');
  // A start on the 1st of a month uses that month's row as a whole.
  const first = creditBurnDown({ config: { ...CONFIG, AI_CREDIT_START: '2026-11-01' }, ledger: ledgerFor(5), now: NOW });
  assert.equal(first.spentUsd, 96);
  // A ledger younger than the window averages over the days it has.
  const young = creditBurnDown({ config: CONFIG, ledger: ledgerFor(5, { from: '2026-11-17' }), now: NOW });
  assert.deepEqual(young.perDay, { last7: { days: 3, usd: 5 }, last30: { days: 3, usd: 5 } });
  // A whole month whose day rows are incomplete still counts its month row (a lost write never hides spend).
  const ledger = ledgerFor(5);
  delete ledger.days['2026-11-02'];
  assert.equal(creditBurnDown({ config: CONFIG, ledger, now: NOW }).spentUsd, 141);
  ledger.months['2026-11'] = 50e6;
  assert.equal(creditBurnDown({ config: CONFIG, ledger, now: NOW }).spentUsd, 45 + 91, 'and the day rows when the month row is short');
});

test('creditLedgerFrom: the start or 30 days back, whichever is earlier, never past the 400-day retention', () => {
  assert.equal(creditLedgerFrom(CONFIG, '2026-11-20'), '2026-10-21');
  assert.equal(creditLedgerFrom(CONFIG, '2027-01-20'), '2026-10-23');
  assert.equal(creditLedgerFrom({}, '2027-01-20'), '2026-12-21');
  assert.equal(creditLedgerFrom({ ...CONFIG, AI_CREDIT_START: '2020-01-01' }, '2026-11-20'), '2025-10-16');
});

test('governance: getCreditState reads only the spend ledger rows it needs', async () => {
  const models = createMemoryModels();
  let now = Date.parse('2026-10-23T17:00:00Z');
  const governance = createAiGovernance({ Model: models.AiGovernance, config: { JWT_SECRET: SECRET, ...CONFIG }, now: () => now });
  for (let index = 0; index < 28; index++) {
    now = Date.parse('2026-10-23T17:00:00Z') + index * DAY;
    await governance.recordSpend({ priced: true, microUsd: 6e6 });
    await governance.recordSpend({ priced: false });
  }
  // Rows the burn-down must ignore: quota rows, alert claims, a month before the read range, junk.
  models.AiGovernance.rows.push({ id: 'ai:2026-11-19', count: 5, expiresAt: new Date(now).toISOString() },
    { id: 'ai-alert:mtd:2026-11:100', expiresAt: new Date(now).toISOString() },
    { id: 'ai-usd:2026-08', microUsd: 999e6, expiresAt: new Date(now).toISOString() },
    { id: 'ai-usd:2026-11-xx', microUsd: 999e6, expiresAt: new Date(now).toISOString() },
    { id: 'ai-usd:2026-11-10x', microUsd: 999e6 });
  const credit = await governance.getCreditState();
  assert.equal(credit.spentUsd, 168); assert.equal(credit.remainingUsd, 832);
  assert.deepEqual(credit.perDay.last7, { days: 7, usd: 6 });
  assert.equal(credit.daysSinceStart, 28);
});

test('governance: day rows are kept 400 days; rows from the 62-day era are extended once', async () => {
  const at = Date.parse('2026-10-14T19:00:00Z');
  const old = day => ({ id: `ai-usd:${day}`, microUsd: 1, expiresAt: new Date(Date.parse(`${day}T19:00:00Z`) + 62 * DAY).toISOString() });
  const models = createMemoryModels({ AiGovernance: [old('2026-10-09'), old('2026-10-13'), { id: 'ai-usd:2026-10', microUsd: 2, expiresAt: 'month-row' }, { id: 'ai:2026-10-13', count: 1, expiresAt: 'quota-row' }] });
  const governance = createAiGovernance({ Model: models.AiGovernance, config: { JWT_SECRET: SECRET }, now: () => at });
  assert.deepEqual(await governance.extendLedgerRetention(), { rows: 2, extended: 2 });
  const row = id => models.AiGovernance.rows.find(item => item.id === id);
  assert.equal(new Date(row('ai-usd:2026-10-09').expiresAt).toISOString(), new Date(Date.parse('2026-10-09T12:00:00Z') + 400 * DAY).toISOString());
  assert.equal(row('ai-usd:2026-10').expiresAt, 'month-row'); assert.equal(row('ai:2026-10-13').expiresAt, 'quota-row');
  assert.deepEqual(await governance.extendLedgerRetention(), { rows: 2, extended: 0 }, 'idempotent');
  // A row written now already has the new retention.
  await governance.recordSpend({ priced: true, microUsd: 5 });
  assert.equal(row('ai-usd:2026-10-14').expiresAt, new Date(at + 400 * DAY).toISOString());
  assert.deepEqual(await governance.extendLedgerRetention(), { rows: 3, extended: 0 });
});

test('the startup extension logs one neutral line and never throws', async () => {
  const lines = [], errors = [];
  const logger = { log: line => lines.push(line), error: (...parts) => errors.push(parts.join(' ')) };
  const models = createMemoryModels({ AiGovernance: [{ id: 'ai-usd:2026-10-09', microUsd: 1, expiresAt: new Date(Date.parse('2026-10-09T19:00:00Z') + 62 * DAY).toISOString() }] });
  const governance = createAiGovernance({ Model: models.AiGovernance, config: { JWT_SECRET: SECRET }, now: () => Date.parse('2026-10-14T19:00:00Z') });
  assert.deepEqual(await extendLedgerRetentionAtStartup(governance, logger), { rows: 1, extended: 1 });
  assert.deepEqual(lines, ['[ai-ledger] retention checked: 1 day rows, 1 extended to 400 days']); assert.deepEqual(errors, []);
  // A failed read (e.g. a buffering timeout) is logged by its code only, and resolves.
  const failing = { extendLedgerRetention: async () => { throw Object.assign(new Error('ai-usd:2026-10-09 secret-detail'), { code: 'ETIMEOUT' }); } };
  assert.equal(await extendLedgerRetentionAtStartup(failing, logger), null);
  assert.deepEqual(errors, ['[ai-ledger] retention extension failed: ETIMEOUT']);
  assert.equal(await extendLedgerRetentionAtStartup({ extendLedgerRetention: () => { throw new TypeError('sync'); } }, logger), null);
  assert.equal(errors.at(-1), '[ai-ledger] retention extension failed: TypeError');
});

async function startApp(t, config) {
  const models = createMemoryModels({ User: [{ id: 'admin', role: 'admin', accountStatus: 'active' }, { id: 'member', role: 'user', accountStatus: 'active' }] });
  for (let day = '2026-10-23'; day < '2026-11-20'; day = addDays(day, 1)) models.AiGovernance.rows.push({ id: `ai-usd:${day}`, microUsd: 5e6, pricedCalls: 10 });
  models.AiGovernance.rows.push({ id: 'ai-usd:2026-10', microUsd: 45e6 }, { id: 'ai-usd:2026-11', microUsd: 95e6 });
  const application = createApplication({ models, config: { NODE_ENV: 'test', JWT_SECRET: SECRET, ...config }, plannerNow: () => NOW });
  await new Promise(resolve => application.server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise(resolve => application.io.close(resolve)));
  return async (route, id) => {
    const res = await fetch(`http://127.0.0.1:${application.server.address().port}/api${route}`, { headers: id ? { Authorization: `Bearer ${jwt.sign({ id }, SECRET, { expiresIn: '1h' })}` } : {} });
    return { status: res.status, data: await res.json() };
  };
}

test('admin AI metrics: `credit` for admins only, next to the unchanged `useUntil`', async t => {
  const get = await startApp(t, { ...CONFIG, ANTHROPIC_API_KEY: 'fixture-not-a-key' });
  assert.equal((await get('/admin/ai-metrics')).status, 401);
  assert.equal((await get('/admin/ai-metrics', 'member')).status, 403);
  const { status, data } = await get('/admin/ai-metrics', 'admin');
  assert.equal(status, 200);
  assert.deepEqual(data.useUntil, { set: true, valid: true, problem: null, at: '2027-04-19T00:00:00.000Z', passed: false });
  assert.equal(data.credit.configured, true); assert.equal(data.credit.spentUsd, 140); assert.equal(data.credit.remainingUsd, 860);
  assert.deepEqual(data.credit.perDay.last7, { days: 7, usd: 5 });
  assert.equal(data.credit.projected.basis, 'last7'); assert.equal(data.credit.alert, false);
  for (const route of ['/ai/usage', '/ai/baybay-capabilities', '/health']) {
    for (const id of [undefined, 'member']) assert.ok(!JSON.stringify((await get(route, id)).data).includes('"credit"'), route);
  }
});

test('admin AI metrics without the credit env: averages only, never an error', async t => {
  const get = await startApp(t, {});
  const { data } = await get('/admin/ai-metrics', 'admin');
  assert.deepEqual(data.credit, { configured: false, totalUsd: null, start: null, problems: { total: null, start: null }, perDay: { last7: { days: 7, usd: 5 }, last30: { days: 28, usd: 5 } } });
  assert.deepEqual(data.useUntil, { set: false, valid: true, problem: null, at: null, passed: null });
  const broken = await startApp(t, { AI_CREDIT_TOTAL_USD: '1,000', AI_CREDIT_START: '2026-10-23' });
  assert.deepEqual((await broken('/admin/ai-metrics', 'admin')).data.credit.problems, { total: 'format', start: null });
});
