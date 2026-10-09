// API-BB-CUTOVER: owner e-mails at $100/$150/$180 month-to-date, at the daily hard cap and
// 7/3/1 days before ANTHROPIC_USE_UNTIL. Offline: the sender and the claim store are fakes.
const test = require('node:test');
const assert = require('node:assert/strict');
const { createAiSpendAlerts, governanceAlertStore, dueAlerts, alertState, mtdThresholds, TICK_MS } = require('../lib/aiSpendAlerts');
const { createAiGovernance } = require('../lib/aiGovernance');
const { createMemoryModels } = require('./support/memory-models');

const NOW = Date.parse('2026-10-20T17:00:00Z'); // Tue 2026-10-20 10:00 PDT
const UNTIL = '2026-10-30T00:00:00Z';
const LIVE = { NODE_ENV: 'production', NOTIFICATION_DELIVERY_ENABLED: 'true', OWNER_DIGEST_EMAIL: 'owner@example.test', ANTHROPIC_API_KEY: 'fixture', ANTHROPIC_USE_UNTIL: UNTIL };
const spend = (monthUsd, dayUsd = 1, level = 'ok', enforced = true) => ({ day: '2026-10-20', month: '2026-10', monthMicroUsd: Math.round(monthUsd * 1e6), dayMicroUsd: Math.round(dayUsd * 1e6),
  level, caps: { softDailyUsd: 6, hardDailyUsd: 10, enforced } });
const ids = alerts => alerts.map(alert => alert.id);
function memoryStore() {
  const claimed = new Map();
  return { claimed, claim: async (id, { now }) => claimed.has(id) ? false : (claimed.set(id, now), true), release: async id => { claimed.delete(id); } };
}

test('thresholds: default $100/$150/$180; AI_ALERT_MTD_USD overrides with positive values only', () => {
  assert.deepEqual(mtdThresholds({}), [100, 150, 180]);
  assert.deepEqual(mtdThresholds({ AI_ALERT_MTD_USD: '50, 25 ,50,abc,-3,0' }), [25, 50]);
  assert.deepEqual(mtdThresholds({ AI_ALERT_MTD_USD: 'none' }), [100, 150, 180]);
});

test('month-to-date: only the highest crossed threshold is due, once per month id', () => {
  assert.deepEqual(ids(dueAlerts({ spend: spend(99.99), config: {}, now: NOW })), []);
  assert.deepEqual(ids(dueAlerts({ spend: spend(100), config: {}, now: NOW })), ['ai-alert:mtd:2026-10:100']);
  assert.deepEqual(ids(dueAlerts({ spend: spend(160), config: {}, now: NOW })), ['ai-alert:mtd:2026-10:150']);
  const [alert] = dueAlerts({ spend: spend(181.5, 4.2), config: {}, now: NOW });
  assert.equal(alert.id, 'ai-alert:mtd:2026-10:180');
  assert.match(alert.subject, /本月 Claude 花费已过 \$180/);
  assert.match(alert.text, /\$181\.50/); assert.match(alert.text, /今天：\$4\.20，状态：正常/); assert.match(alert.text, /BAYBAY_PAUSED=true/);
});

test('daily hard cap: one alert per Pacific day; with AI_SPEND_CAPS=off the text says nothing was blocked', () => {
  const hard = dueAlerts({ spend: spend(40, 10.01, 'hard'), config: {}, now: NOW });
  assert.deepEqual(ids(hard), ['ai-alert:hard:2026-10-20']);
  assert.match(hard[0].text, /今日 AI 名额已满/); assert.match(hard[0].text, /已到硬上限 \$10/);
  const reportOnly = dueAlerts({ spend: spend(40, 10.01, 'hard', false), config: {}, now: NOW });
  assert.match(reportOnly[0].text, /只记录，没有拦截/); assert.doesNotMatch(reportOnly[0].text, /今日 AI 名额已满/);
});

test('credit window: 7 / 3 / 1 days before ANTHROPIC_USE_UNTIL, the most urgent stage only; none when unset, invalid, past or keyless', () => {
  const at = days => Date.parse(UNTIL) - days * 86400000;
  const stage = days => ids(dueAlerts({ spend: null, config: LIVE, now: at(days) }));
  assert.deepEqual(stage(8), []);
  assert.deepEqual(stage(6.5), [`ai-alert:until:2026-10-30T00:00:00.000Z:7`]);
  assert.deepEqual(stage(2.9), [`ai-alert:until:2026-10-30T00:00:00.000Z:3`]);
  assert.deepEqual(stage(0.4), [`ai-alert:until:2026-10-30T00:00:00.000Z:1`]);
  assert.deepEqual(stage(-0.1), []);
  for (const config of [{ ...LIVE, ANTHROPIC_USE_UNTIL: '' }, { ...LIVE, ANTHROPIC_USE_UNTIL: 'soon' }, { ...LIVE, ANTHROPIC_API_KEY: '' }]) assert.deepEqual(ids(dueAlerts({ spend: null, config, now: at(2) })), []);
  const [alert] = dueAlerts({ spend: spend(12), config: LIVE, now: at(2.9) });
  assert.match(alert.subject, /3 天内到期/); assert.match(alert.text, /绑卡或购买额度/); assert.match(alert.text, /BAYBAY_AI_PROVIDER=openai/); assert.match(alert.text, /\$12\.00/);
});

test('delivery gates: tests never send; NOTIFICATION_DELIVERY_ENABLED and an owner address are required; AI_ALERT_EMAIL wins', () => {
  assert.equal(alertState({ ...LIVE, NODE_ENV: 'test' }).reason, 'test');
  assert.equal(alertState({ ...LIVE, NOTIFICATION_DELIVERY_ENABLED: 'false' }).reason, 'delivery-disabled');
  assert.equal(alertState({ ...LIVE, OWNER_DIGEST_EMAIL: 'not-an-address' }).reason, 'no-owner-email');
  assert.deepEqual(alertState(LIVE), { enabled: true, reason: 'on', to: 'owner@example.test' });
  assert.equal(alertState({ ...LIVE, AI_ALERT_EMAIL: ' alerts@example.test ' }).to, 'alerts@example.test');
});

test('the scheduler sends each due alert once across instances, retries a failed send, and stops after three failures', async () => {
  const store = memoryStore(), mails = [];
  let month = 101, failing = 0;
  const governance = { getSpendState: async () => spend(month) };
  const sendEmail = async mail => { if (failing) { failing--; throw Object.assign(new Error('private provider detail'), { status: 500 }); } mails.push(mail); };
  const logger = { info: () => {}, error: () => {} };
  const a = createAiSpendAlerts({ governance, store, config: LIVE, now: () => Date.parse(UNTIL) - 10 * 86400000, sendEmail, logger });
  const b = createAiSpendAlerts({ governance, store, config: LIVE, now: () => Date.parse(UNTIL) - 10 * 86400000, sendEmail, logger });
  assert.deepEqual((await a.tick()).sent, ['ai-alert:mtd:2026-10:100']);
  assert.deepEqual((await b.tick()).sent, [], 'another instance does not send it again');
  assert.deepEqual((await a.tick()).sent, []);
  assert.equal(mails.length, 1);
  assert.deepEqual(Object.keys(mails[0]).sort(), ['idempotencyKey', 'subject', 'text', 'to']);
  assert.equal(mails[0].to, 'owner@example.test'); assert.equal(mails[0].idempotencyKey, 'baylink-ai-alert:mtd:2026-10:100');
  assert.doesNotMatch(mails[0].text, /owner@example\.test/);
  // A failed send releases the claim; the next tick retries it.
  month = 151; failing = 1;
  assert.deepEqual((await a.tick()).sent, []);
  assert.equal(store.claimed.has('ai-alert:mtd:2026-10:150'), false);
  assert.deepEqual((await a.tick()).sent, ['ai-alert:mtd:2026-10:150']);
  // Three failures in one process stop that alert there.
  month = 181; failing = 99;
  for (let index = 0; index < 4; index++) await a.tick();
  assert.equal(failing, 96, 'three attempts, then none');
  assert.equal(mails.length, 2);
});

test('with delivery off nothing is sent; one log line per due alert names the alert, not the owner', async () => {
  const lines = [];
  let sent = 0;
  const alerts = createAiSpendAlerts({ governance: { getSpendState: async () => spend(120) }, store: memoryStore(), config: { ...LIVE, NOTIFICATION_DELIVERY_ENABLED: 'false' },
    now: () => NOW, sendEmail: async () => { sent++; }, logger: { info: line => lines.push(line), error: () => {} } });
  assert.equal((await alerts.tick()).reason, 'delivery-disabled');
  await alerts.tick();
  assert.equal(sent, 0);
  assert.deepEqual(lines, ['[ai-alerts] due, not sent (delivery-disabled): ai-alert:mtd:2026-10:100']);
  const testMode = createAiSpendAlerts({ governance: { getSpendState: async () => spend(120) }, store: memoryStore(), config: { ...LIVE, NODE_ENV: 'test' }, now: () => NOW, sendEmail: async () => { sent++; }, logger: { info: () => {} } });
  assert.equal((await testMode.tick()).reason, 'test'); assert.equal(sent, 0);
  testMode.start(); testMode.stop();
  // An unreadable ledger still allows the credit-window alert.
  const ledgerDown = createAiSpendAlerts({ governance: { getSpendState: async () => { throw new Error('private storage fault'); } }, store: memoryStore(), config: LIVE,
    now: () => Date.parse(UNTIL) - 86400000 / 2, sendEmail: async () => { sent++; }, logger: { info: () => {} } });
  assert.deepEqual((await ledgerDown.tick()).sent, ['ai-alert:until:2026-10-30T00:00:00.000Z:1']);
  assert.equal(TICK_MS, 600000);
});

test('the claim store is one atomic upsert per alert on AiGovernance; a lost insert race is not ours', async () => {
  const calls = [];
  let inserted = false;
  const Model = {
    updateOne: async (filter, update, options) => { calls.push({ filter, update, options }); if (filter.id === 'race') throw Object.assign(new Error('E11000'), { code: 11000 }); const first = !inserted; inserted = true; return { acknowledged: true, upsertedCount: first ? 1 : 0, matchedCount: first ? 0 : 1 }; },
    deleteOne: async filter => { calls.push({ deleted: filter }); return { deletedCount: 1 }; },
  };
  const store = governanceAlertStore(Model);
  assert.equal(await store.claim('ai-alert:mtd:2026-10:100', { now: NOW, keepDays: 400 }), true);
  assert.equal(await store.claim('ai-alert:mtd:2026-10:100', { now: NOW, keepDays: 400 }), false);
  assert.equal(await store.claim('race', { now: NOW, keepDays: 1 }), false);
  assert.deepEqual(calls[0].options, { upsert: true, setDefaultsOnInsert: false });
  assert.deepEqual(Object.keys(calls[0].update), ['$setOnInsert']);
  assert.equal(calls[0].update.$setOnInsert.expiresAt.toISOString(), new Date(NOW + 400 * 86400000).toISOString());
  await store.release('ai-alert:mtd:2026-10:100');
  assert.deepEqual(calls.at(-1), { deleted: { id: 'ai-alert:mtd:2026-10:100' } });
  await assert.rejects(governanceAlertStore({ updateOne: async () => { throw new Error('uncertain'); } }).claim('x', { now: NOW, keepDays: 1 }));
});

test('end to end on the governance ledger: a month crossing $100 produces exactly one owner e-mail', async () => {
  const models = createMemoryModels();
  let now = Date.parse('2026-10-05T17:00:00Z');
  const governance = createAiGovernance({ Model: models.AiGovernance, config: { JWT_SECRET: 'alerts-fixture-secret' }, now: () => now });
  const mails = [];
  const alerts = createAiSpendAlerts({ governance, store: memoryStore(), config: LIVE, now: () => now, sendEmail: async mail => { mails.push(mail); }, logger: { info: () => {} } });
  await governance.recordSpend({ priced: true, microUsd: 99_990_000 }); // earlier in the month (that day's hard-cap alert aside)
  now = NOW;
  assert.deepEqual((await alerts.tick()).sent, []);
  await governance.recordSpend({ priced: true, microUsd: 20_000 });
  assert.deepEqual((await alerts.tick()).sent, ['ai-alert:mtd:2026-10:100']);
  await governance.recordSpend({ priced: true, microUsd: 20_000 });
  await alerts.tick();
  assert.equal(mails.length, 1); assert.match(mails[0].text, /\$100\.01/);
});
