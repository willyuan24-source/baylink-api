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
  for (const config of [{ ...LIVE, ANTHROPIC_USE_UNTIL: '' }, { ...LIVE, ANTHROPIC_API_KEY: '' }, { ...LIVE, ANTHROPIC_API_KEY: '', ANTHROPIC_USE_UNTIL: 'soon' }]) assert.deepEqual(ids(dueAlerts({ spend: null, config, now: at(2) })), []);
  // An invalid value has no day count (API-OPS: one "the format is wrong" alert instead, tested below).
  assert.deepEqual(ids(dueAlerts({ spend: null, config: { ...LIVE, ANTHROPIC_USE_UNTIL: 'soon' }, now: at(2) })).filter(id => id.startsWith('ai-alert:until:')), []);
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

// API-OPS follow-ups from API-OPS-KEY: the cutoff is read with readUseUntil (the reading that
// switches Claude off), and a set but invalid value sends one "format is wrong" alert.
test('an invalid ANTHROPIC_USE_UNTIL: one alert naming the problem, never the value; the same reading as anthropicAvailable', () => {
  const { anthropicAvailable } = require('../lib/anthropicBaybay');
  const cases = [['2026-10-30 00:00:00Z', 'spaces', /多了空格/], [' 2026-10-30T00:00:00Z', 'spaces', /多了空格/], ['2026-10-30T00:00:00', 'missing_zone', /没有 Z/],
    ['2026-11-31', 'invalid_date', /不是真实存在的日期/], ['sk-ant-api03-pasted-in-the-wrong-variable', 'format', /不是 YYYY-MM-DD/]];
  for (const [value, problem, wording] of cases) {
    const config = { ...LIVE, ANTHROPIC_USE_UNTIL: value };
    assert.equal(anthropicAvailable(config, NOW), false, 'Claude is already off for this value');
    const alerts = dueAlerts({ spend: null, config, now: NOW });
    assert.equal(alerts.length, 1, value);
    const [alert] = alerts;
    assert.match(alert.id, new RegExp(`^ai-alert:until-invalid:${problem}:[0-9a-f]{12}$`));
    assert.equal(alert.keepDays, 400);
    assert.match(alert.subject, /ANTHROPIC_USE_UNTIL 格式不对/);
    assert.match(alert.text, wording); assert.match(alert.text, /--check-value/); assert.match(alert.text, /2027-04-19T00:00:00Z/);
    assert.ok(!alert.id.includes(value.trim()) && !alert.subject.includes(value.trim()) && !alert.text.includes(value.trim()), 'the value is never repeated');
    // No day counts for a value the API does not accept (the old lenient reading counted " 2026-10-30T00:00:00Z").
    assert.ok(!alert.text.includes('还剩约'));
  }
  // Stable per value; a different wrong value is a new alert; no key, no alert.
  const id = value => dueAlerts({ spend: null, config: { ...LIVE, ANTHROPIC_USE_UNTIL: value }, now: NOW })[0]?.id;
  assert.equal(id('2026-11-31'), id('2026-11-31'));
  assert.notEqual(id('2026-11-31'), id('2026-11-30T00:00:00'));
  assert.deepEqual(dueAlerts({ spend: null, config: { ...LIVE, ANTHROPIC_API_KEY: ' ', ANTHROPIC_USE_UNTIL: '2026-11-31' }, now: NOW }), []);
});

test('the invalid-cutoff alert goes out once, through the same gates (never in tests)', async () => {
  const config = { ...LIVE, ANTHROPIC_USE_UNTIL: '2026-10-30T00:00:00' };
  const store = memoryStore(), mails = [], lines = [];
  const alerts = createAiSpendAlerts({ governance: { getSpendState: async () => null }, store, config, now: () => NOW, sendEmail: async mail => { mails.push(mail); }, logger: { info: () => {} } });
  const [sent] = (await alerts.tick()).sent;
  assert.match(sent, /^ai-alert:until-invalid:missing_zone:/);
  await alerts.tick();
  assert.equal(mails.length, 1); assert.ok(!mails[0].text.includes('2026-10-30T00:00:00'));
  let count = 0;
  const testMode = createAiSpendAlerts({ governance: { getSpendState: async () => null }, store: memoryStore(), config: { ...config, NODE_ENV: 'test' }, now: () => NOW, sendEmail: async () => { count++; }, logger: { info: () => {} } });
  assert.equal((await testMode.tick()).reason, 'test'); assert.equal(count, 0);
  const off = createAiSpendAlerts({ governance: { getSpendState: async () => null }, store: memoryStore(), config: { ...config, NOTIFICATION_DELIVERY_ENABLED: 'false' }, now: () => NOW, sendEmail: async () => { count++; }, logger: { info: line => lines.push(line) } });
  assert.equal((await off.tick()).reason, 'delivery-disabled'); assert.equal(count, 0);
  assert.equal(lines.length, 1); assert.ok(!lines[0].includes('2026-10-30T00:00:00'), 'the log line names the alert id, not the value');
});

const creditState = (extra = {}) => ({ configured: true, totalUsd: 1000, start: '2026-10-23', spentUsd: 225, remainingUsd: 775,
  perDay: { last7: { days: 7, usd: 8 }, last30: { days: 30, usd: 7.6 } }, projected: { basis: 'last7', day: '2027-02-25', at: '2027-02-25T17:00:00.000Z', daysLeft: 96.9 },
  useUntil: { at: '2027-04-19T00:00:00.000Z', daysEarly: 52.3 }, alert: true, ...extra });
const CREDIT_LIVE = { ...LIVE, ANTHROPIC_USE_UNTIL: '2027-04-19T00:00:00Z', AI_CREDIT_TOTAL_USD: '1000', AI_CREDIT_START: '2026-10-23' };

test('credit burn-down: one alert when the run-out is projected more than 14 days before the cutoff', () => {
  const now = Date.parse('2026-11-20T20:00:00Z');
  const [alert, ...rest] = dueAlerts({ spend: null, credit: creditState(), config: CREDIT_LIVE, now });
  assert.deepEqual(rest, []);
  assert.equal(alert.id, 'ai-alert:credit:2026-10-23:1000:2027-04-19T00:00:00.000Z'); assert.equal(alert.keepDays, 400);
  assert.match(alert.subject, /Claude 额度预计 2月25日 用完，比 ANTHROPIC_USE_UNTIL 早约 52 天/);
  for (const part of [/\$1000\.00/, /已用约 \$225\.00/, /剩约 \$775\.00/, /最近 7 天 \$8\.00（7 天）/, /最近 30 天 \$7\.60（30 天）/, /早 14 天以上/, /AI_SPEND_HARD_DAILY_USD/, /AI_CREDIT_TOTAL_USD/, /credit 一栏/]) assert.match(alert.text, part);
  assert.deepEqual(dueAlerts({ spend: null, credit: creditState({ alert: false }), config: CREDIT_LIVE, now }), []);
  assert.deepEqual(dueAlerts({ spend: null, credit: creditState({ configured: false }), config: CREDIT_LIVE, now }), []);
  assert.deepEqual(dueAlerts({ spend: null, credit: creditState(), config: { ...CREDIT_LIVE, ANTHROPIC_API_KEY: '' }, now }), []);
  assert.deepEqual(dueAlerts({ spend: null, credit: null, config: CREDIT_LIVE, now }), []);
  // A changed total, start or cutoff is a new alert id.
  assert.notEqual(dueAlerts({ spend: null, credit: creditState({ totalUsd: 1200 }), config: CREDIT_LIVE, now })[0].id, alert.id);
});

test('credit burn-down end to end on the governance ledger: one e-mail, and the ledger is read only when it can matter', async () => {
  const models = createMemoryModels();
  let now = Date.parse('2026-10-23T17:00:00Z');
  const governance = createAiGovernance({ Model: models.AiGovernance, config: { JWT_SECRET: 'alerts-fixture-secret', ...CREDIT_LIVE }, now: () => now });
  for (let index = 0; index < 28; index++) { now = Date.parse('2026-10-23T17:00:00Z') + index * 86400000; await governance.recordSpend({ priced: true, microUsd: 8e6 }); }
  const mails = [], store = memoryStore();
  const alerts = createAiSpendAlerts({ governance, store, config: CREDIT_LIVE, now: () => now, sendEmail: async mail => { mails.push(mail); }, logger: { info: () => {} } });
  const { sent } = await alerts.tick();
  assert.deepEqual(sent.filter(id => id.startsWith('ai-alert:credit:')), ['ai-alert:credit:2026-10-23:1000:2027-04-19T00:00:00.000Z']);
  await alerts.tick();
  assert.equal(mails.filter(mail => /额度预计/.test(mail.subject)).length, 1);
  // Without both credit values or without a valid cutoff the burn-down is never read.
  let reads = 0;
  const counting = { getSpendState: async () => null, getCreditState: async () => { reads++; return null; } };
  for (const config of [LIVE, { ...CREDIT_LIVE, AI_CREDIT_START: '' }, { ...CREDIT_LIVE, ANTHROPIC_USE_UNTIL: '' }, { ...CREDIT_LIVE, ANTHROPIC_USE_UNTIL: '2027-04-19 00:00' }]) {
    await createAiSpendAlerts({ governance: counting, store: memoryStore(), config, now: () => now, sendEmail: async () => {}, logger: { info: () => {} } }).tick();
  }
  assert.equal(reads, 0);
  // An unreadable burn-down is no alert, not an error.
  const failing = { getSpendState: async () => null, getCreditState: async () => { throw new Error('private storage fault'); } };
  assert.equal((await createAiSpendAlerts({ governance: failing, store: memoryStore(), config: CREDIT_LIVE, now: () => now, sendEmail: async () => {}, logger: { info: () => {} } }).tick()).reason, 'nothing-due');
});
