const test = require('node:test');
const assert = require('node:assert/strict');
const { EventEmitter } = require('node:events');
const mongoose = require('mongoose');
const { createAiGovernance, createAiGovernanceModel, aiExecution } = require('../lib/aiGovernance');
const { createAiRuntimeMetrics, metricModel, COUNTERS, HISTOGRAMS } = require('../lib/aiRuntimeMetrics');
const { fetchAiJson, billingFor } = require('../lib/aiRequest');
const { requestAnthropicJson } = require('../lib/anthropicJson');
const { createMemoryModels } = require('./support/memory-models');

const SECRET = 'isolated-spend-ledger-test-secret';
const NOW = Date.parse('2026-10-08T20:00:00Z');
const claude = (model, usage, extra = {}) => ({ type: 'message', model, role: 'assistant', stop_reason: 'end_turn', content: [{ type: 'text', text: '{"text":"ok"}' }], usage, ...extra });
function response() {
  const res = new EventEmitter();
  res.statusCode = 200; res.writableEnded = false;
  res.status = value => { res.statusCode = value; return res; };
  res.json = () => { res.writableEnded = true; res.emit('finish'); res.emit('close'); return res; };
  return res;
}
async function inRequest(governance, fn, path = '/api/ai/guide-chat') {
  const req = new EventEmitter(); req.path = path; req.ip = 'private-ip';
  const res = response();
  await new Promise((resolve, reject) => { governance.middleware(async () => 'private-account')(req, res, () => Promise.resolve(fn(req, res)).then(resolve, reject)).catch(reject); });
}
const ledger = (models, id) => models.AiGovernance.rows.find(row => row.id === id);

test('ledger documents are additive schema fields with no defaults and the same TTL index', () => {
  const Model = createAiGovernanceModel(mongoose);
  for (const field of ['microUsd', 'pricedCalls', 'unpricedCalls']) {
    assert.ok(Model.schema.path(field), field);
    assert.equal(Model.schema.path(field).defaultValue, undefined, `${field} has no default, so a $inc upsert cannot conflict`);
  }
  assert.ok(Model.schema.indexes().some(([keys, options]) => keys.expiresAt === 1 && options.expireAfterSeconds === 0));
});

test('concurrent spend lands atomically in one Pacific day and one month document; day and month roll over separately', async () => {
  let now = Date.parse('2026-10-31T23:00:00-07:00');
  const models = createMemoryModels();
  const a = createAiGovernance({ Model: models.AiGovernance, config: { JWT_SECRET: SECRET }, now: () => now });
  const b = createAiGovernance({ Model: models.AiGovernance, config: { JWT_SECRET: SECRET }, now: () => now });
  await Promise.all(Array.from({ length: 200 }, (_, index) => (index % 2 ? a : b).recordSpend(index % 10 === 0 ? { priced: false } : { priced: true, microUsd: index })));
  const expected = Array.from({ length: 200 }, (_, index) => index).filter(index => index % 10 !== 0).reduce((sum, value) => sum + value, 0);
  for (const id of ['ai-usd:2026-10-31', 'ai-usd:2026-10']) {
    const row = ledger(models, id);
    assert.equal(row.microUsd, expected, id); assert.equal(row.pricedCalls, 180); assert.equal(row.unpricedCalls, 20);
    assert.equal(models.AiGovernance.rows.filter(item => item.id === id).length, 1);
    assert.equal(row.count, undefined, 'quota fields are not created on ledger documents');
  }
  assert.equal(ledger(models, 'ai-usd:2026-10-31').expiresAt, new Date(now + 62 * 86400000).toISOString());
  assert.equal(ledger(models, 'ai-usd:2026-10').expiresAt, new Date(now + 400 * 86400000).toISOString());
  now = Date.parse('2026-11-01T00:30:00-07:00');
  await a.recordSpend({ priced: true, microUsd: 7 });
  assert.equal(ledger(models, 'ai-usd:2026-11-01').microUsd, 7); assert.equal(ledger(models, 'ai-usd:2026-11').microUsd, 7);
  assert.equal(ledger(models, 'ai-usd:2026-10').microUsd, expected);
  // Malformed amounts and unknown billing never write.
  const before = JSON.stringify(models.AiGovernance.rows);
  for (const billing of [{ priced: true, microUsd: -1 }, { priced: true, microUsd: 1.5 }, { priced: true }, {}, undefined]) await a.recordSpend(billing);
  assert.equal(JSON.stringify(models.AiGovernance.rows), before);
});

test('a lost insert race is retried once as a plain $inc; uncertain storage errors are neither retried nor thrown', async () => {
  const models = createMemoryModels(); const original = models.AiGovernance.updateOne;
  const attempts = [];
  models.AiGovernance.updateOne = async (filter, update, options = {}) => {
    attempts.push({ id: filter.id, upsert: !!options.upsert, setDefaultsOnInsert: options.setDefaultsOnInsert });
    if (options.upsert && filter.id === 'ai-usd:2026-10-08' && attempts.filter(item => item.id === filter.id).length === 1) {
      await original(filter, { $setOnInsert: update.$setOnInsert, $inc: { microUsd: 5, pricedCalls: 1 } }, options); // a concurrent instance won the insert
      throw Object.assign(new Error('E11000 duplicate key'), { code: 11000 });
    }
    return original(filter, update, options);
  };
  const governance = createAiGovernance({ Model: models.AiGovernance, config: { JWT_SECRET: SECRET }, now: () => NOW });
  await governance.recordSpend({ priced: true, microUsd: 11 });
  assert.equal(ledger(models, 'ai-usd:2026-10-08').microUsd, 16); assert.equal(ledger(models, 'ai-usd:2026-10-08').pricedCalls, 2);
  assert.equal(ledger(models, 'ai-usd:2026-10').microUsd, 11);
  assert.deepEqual(attempts.filter(item => item.id === 'ai-usd:2026-10-08').map(item => item.upsert), [true, false]);
  assert.ok(attempts.filter(item => item.upsert).every(item => item.setDefaultsOnInsert === false));
  let failures = 0;
  models.AiGovernance.updateOne = async () => { failures++; throw new Error('uncertain private storage error'); };
  await assert.doesNotReject(governance.recordSpend({ priced: true, microUsd: 3 }));
  assert.equal(failures, 2, 'one attempt per document, no retry of an uncertain write');
});

test('getSpendState reports day and month spend against the soft/hard caps (enforced since API-BB-CUTOVER)', async () => {
  const models = createMemoryModels();
  const governance = createAiGovernance({ Model: models.AiGovernance, config: { JWT_SECRET: SECRET, AI_SPEND_SOFT_DAILY_USD: '0.5', AI_SPEND_HARD_DAILY_USD: '1' }, now: () => NOW });
  assert.deepEqual(await governance.getSpendState(), { day: '2026-10-08', month: '2026-10', dayMicroUsd: 0, monthMicroUsd: 0, dayUsd: 0, monthUsd: 0,
    dayPricedCalls: 0, dayUnpricedCalls: 0, caps: { softDailyUsd: 0.5, hardDailyUsd: 1, enforced: true }, level: 'ok', resetAt: '2026-10-09T07:00:00.000Z' });
  await governance.recordSpend({ priced: true, microUsd: 499999 });
  assert.equal((await governance.getSpendState()).level, 'ok');
  await governance.recordSpend({ priced: true, microUsd: 1 });
  assert.equal((await governance.getSpendState()).level, 'soft');
  await governance.recordSpend({ priced: true, microUsd: 500000 }); await governance.recordSpend({ priced: false });
  const state = await governance.getSpendState();
  assert.equal(state.level, 'hard'); assert.equal(state.dayUsd, 1); assert.equal(state.dayPricedCalls, 3); assert.equal(state.dayUnpricedCalls, 1);
  // claim() is the count quota only; the $ cap is enforced by the middleware's
  // reservation (tests/baybay-cutover.test.js).
  assert.equal(await governance.claim({ ip: 'fixture-ip' }), true);
  const defaults = createAiGovernance({ Model: models.AiGovernance, config: { JWT_SECRET: SECRET }, now: () => NOW });
  assert.deepEqual((await defaults.getSpendState()).caps, { softDailyUsd: 6, hardDailyUsd: 10, enforced: true });
  const reportOnly = createAiGovernance({ Model: models.AiGovernance, config: { JWT_SECRET: SECRET, AI_SPEND_CAPS: 'off' }, now: () => NOW });
  assert.equal((await reportOnly.getSpendState()).caps.enforced, false);
});

test('a governed Claude call records cost, raw cache reads/writes and TTFT in metrics and the day/month ledger', async () => {
  const models = createMemoryModels();
  const metrics = createAiRuntimeMetrics({ Model: models.AiRuntimeMetric, now: () => NOW });
  const governance = createAiGovernance({ Model: models.AiGovernance, config: { JWT_SECRET: SECRET }, now: () => NOW, metrics });
  const usage = { input_tokens: 2000, cache_read_input_tokens: 12000, cache_creation_input_tokens: 3000, output_tokens: 600, server_tool_use: { web_search_requests: 1 } };
  await inRequest(governance, async (_req, res) => {
    await fetchAiJson('https://never-fetched.invalid', { body: JSON.stringify({ model: 'claude-sonnet-5-5' }) }, {
      fetchImpl: async () => { await new Promise(resolve => setTimeout(resolve, 5)); return { ok: true, json: async () => claude('claude-sonnet-5-5', usage) }; } });
    await fetchAiJson('https://never-fetched.invalid', { body: JSON.stringify({ model: 'gpt-6.1-sol' }) }, {
      fetchImpl: async () => ({ ok: true, json: async () => ({ model: 'gpt-6.1-sol', status: 'completed', usage: { input_tokens: 5, output_tokens: 5 } }) }) });
    res.json({ ok: true });
  });
  await metrics.flush();
  // 2000x$2 + 12000x$0.20 + 3000x$2.50 + 600x$10 per million + $0.01 search = 4000+2400+7500+6000+10000 micro-USD.
  const expected = 29900;
  const sonnet = models.AiRuntimeMetric.rows.find(row => row.model === 'claude-sonnet-5-5');
  assert.equal(sonnet.costMicroUsd, expected); assert.equal(sonnet.cacheReadTokens, 12000); assert.equal(sonnet.cacheWriteTokens, 3000);
  assert.equal(sonnet.inputTokens, 17000, 'existing inputTokens keep counting the whole prompt');
  assert.equal(Object.values(sonnet.providerTtft).reduce((a, b) => a + b), 1);
  assert.equal(sonnet.costUnpriced, undefined);
  assert.equal(models.AiRuntimeMetric.rows.find(row => row.model === 'gpt-6.1-sol').costUnpriced, 1);
  assert.equal(ledger(models, 'ai-usd:2026-10-08').microUsd, expected); assert.equal(ledger(models, 'ai-usd:2026-10').microUsd, expected);
  assert.equal(ledger(models, 'ai-usd:2026-10-08').pricedCalls, 1); assert.equal(ledger(models, 'ai-usd:2026-10-08').unpricedCalls, 1);
  assert.equal(models.AiGovernance.rows[0].id, 'ai:2026-10-08', 'the quota document is untouched and still first');
  assert.equal(models.AiGovernance.rows[0].inputTokens, 17005);
  assert.doesNotMatch(JSON.stringify(models.AiGovernance.rows.filter(row => row.id.startsWith('ai-usd:'))), /private|identities|sonnet|gpt/);
});

test('refusals are counted per model and the Haiku refusal retry is visible as a separate Sonnet call', async () => {
  const models = createMemoryModels();
  const metrics = createAiRuntimeMetrics({ Model: models.AiRuntimeMetric, now: () => NOW });
  const governance = createAiGovernance({ Model: models.AiGovernance, config: { JWT_SECRET: SECRET }, now: () => NOW, metrics });
  const replies = [claude('claude-haiku-5-5', { input_tokens: 900, output_tokens: 0 }, { stop_reason: 'refusal', stop_details: { category: 'general_harms' }, content: [] }),
    claude('claude-sonnet-5-5', { input_tokens: 900, output_tokens: 100 })];
  await inRequest(governance, async (_req, res) => {
    await requestAnthropicJson([{ role: 'user', content: 'Sample' }], { config: { BAYBAY_AI_PROVIDER: 'anthropic', ANTHROPIC_API_KEY: 'fixture', BAYBAY_MODEL_HELPERS: 'claude-haiku-5-5' },
      log: () => {}, fetchImpl: async () => ({ ok: true, json: async () => replies.shift() }) });
    res.json({ ok: true });
  }, '/api/ai/post-assist');
  await metrics.flush();
  const haiku = models.AiRuntimeMetric.rows.find(row => row.model === 'claude-haiku-5-5');
  const sonnet = models.AiRuntimeMetric.rows.find(row => row.model === 'claude-sonnet-5-5');
  assert.equal(haiku.feature, 'post_assist'); assert.equal(haiku.providerRefusal, 1); assert.equal(haiku.providerError, 1);
  assert.equal(haiku.costMicroUsd, 90); assert.equal(haiku.providerTtft, undefined, 'refused calls do not enter the TTFT histogram');
  assert.equal(sonnet.providerCompleted, 1); assert.equal(sonnet.providerRefusal, undefined); assert.equal(sonnet.costMicroUsd, 2800);
  assert.equal(models.AiRuntimeMetric.rows.find(row => row.model === 'mixed').requestCompleted, 1);
  assert.equal(ledger(models, 'ai-usd:2026-10-08').microUsd, 2890);
});

test('helper calls inside a governed request infer their route from the request feature', async () => {
  const models = createMemoryModels();
  const governance = createAiGovernance({ Model: models.AiGovernance, config: { JWT_SECRET: SECRET }, now: () => NOW });
  const config = { BAYBAY_AI_PROVIDER: 'anthropic', ANTHROPIC_API_KEY: 'fixture', BAYBAY_MODEL_HELPER_POST_ASSIST: 'claude-sonnet-5-5' };
  const models_ = [];
  for (const path of ['/api/ai/post-assist', '/api/ai/outing-draft']) {
    await inRequest(governance, async (_req, res) => {
      assert.ok(aiExecution().feature);
      await requestAnthropicJson([{ role: 'user', content: 'Sample' }], { config, fetchImpl: async (_url, init) => { models_.push(JSON.parse(init.body).model); return { ok: true, json: async () => claude('claude-opus-5-5', { input_tokens: 1, output_tokens: 1 }) }; } });
      res.json({ ok: true });
    }, path);
  }
  assert.deepEqual(models_, ['claude-sonnet-5-5', 'claude-opus-5-5']);
});

test('first-byte deadline aborts a provider that sends no headers; it is counted as a timeout', async () => {
  const models = createMemoryModels();
  const metrics = createAiRuntimeMetrics({ Model: models.AiRuntimeMetric, now: () => NOW });
  const governance = createAiGovernance({ Model: models.AiGovernance, config: { JWT_SECRET: SECRET }, now: () => NOW, metrics });
  let aborted = false;
  await inRequest(governance, async (_req, res) => {
    const started = Date.now();
    await assert.rejects(fetchAiJson('https://never-fetched.invalid', { body: JSON.stringify({ model: 'claude-opus-5-5' }) }, { timeoutMs: 5000, firstByteMs: 20,
      fetchImpl: (_url, init) => new Promise(() => { init.signal.addEventListener('abort', () => { aborted = true; }); }) }), { code: 'AI_PROVIDER_TIMEOUT', message: /first byte/ });
    assert.ok(Date.now() - started < 2000); assert.equal(aborted, true);
    // Headers that arrive in time are not cut off by the first-byte deadline.
    const value = await fetchAiJson('https://never-fetched.invalid', { body: JSON.stringify({ model: 'claude-opus-5-5' }) }, { timeoutMs: 5000, firstByteMs: 200,
      fetchImpl: async () => ({ ok: true, json: async () => { await new Promise(resolve => setTimeout(resolve, 300)); return claude('claude-opus-5-5', { input_tokens: 1, output_tokens: 1 }); } }) });
    assert.equal(value.model, 'claude-opus-5-5');
    res.json({ ok: true });
  });
  await metrics.flush();
  const row = models.AiRuntimeMetric.rows.find(item => item.model === 'claude-opus-5-5');
  assert.equal(row.providerTimeout, 1); assert.equal(row.providerCompleted, 1);
});

test('metric allowlists include the Claude 5.5 family and the new counters, and billing never stores identifiers', () => {
  for (const model of ['claude-opus-5-5', 'claude-sonnet-5-5', 'claude-haiku-5-5']) assert.equal(metricModel(model), model);
  for (const counter of ['cacheReadTokens', 'cacheWriteTokens', 'providerRefusal', 'costMicroUsd', 'costUnpriced']) assert.ok(COUNTERS.includes(counter), counter);
  assert.ok(HISTOGRAMS.includes('providerTtft'));
  assert.deepEqual(billingFor({ type: 'message', model: 'claude-opus-5-5', id: 'msg_private', usage: { input_tokens: 1000, output_tokens: 0 } }),
    { priced: true, microUsd: 4000, card: 'standard', cacheReadTokens: 0, cacheWriteTokens: 0 });
  assert.deepEqual(billingFor({ status: 'completed', usage: { input_tokens: 1 } }), { priced: false });
  assert.deepEqual(billingFor(null), { priced: false });
});
