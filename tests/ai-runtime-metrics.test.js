const test = require('node:test');
const assert = require('node:assert/strict');
const { EventEmitter } = require('node:events');
const jwt = require('jsonwebtoken');
const mongoose = require('mongoose');
const { createAiRuntimeMetrics, createAiRuntimeMetricModel, metricModel, metricFeature, latencyBucket } = require('../lib/aiRuntimeMetrics');
const { createAiGovernance } = require('../lib/aiGovernance');
const { fetchAiJson } = require('../lib/aiRequest');
const { createBayBayProgressStream } = require('../lib/baybayProgress');
const { createMemoryModels } = require('./support/memory-models');
const { createApplication } = require('../server');
const NOW = Date.parse('2026-10-07T20:00:00Z');
const SECRET = 'isolated-ai-runtime-test-secret';
const setup = (options = {}) => {
  const models = createMemoryModels();
  const metrics = createAiRuntimeMetrics({ Model: models.AiRuntimeMetric, now: () => NOW, ...options });
  return { models, metrics };
};
function response() {
  const res = new EventEmitter();
  res.statusCode = 200; res.output = ''; res.writableEnded = false;
  res.status = value => { res.statusCode = value; return res; };
  res.set = () => res; res.flushHeaders = () => {};
  res.write = value => { res.output += value; return true; };
  res.end = () => { res.writableEnded = true; res.emit('finish'); res.emit('close'); };
  res.json = value => { res.output = JSON.stringify(value); res.end(); return res; };
  return res;
}
async function inRequest(governance, fn) {
  const req = new EventEmitter(); req.path = '/api/ai/guide-chat'; req.ip = 'private-ip';
  const res = response();
  await new Promise((resolve, reject) => { governance.middleware(async () => 'private-account')(req, res, () => Promise.resolve(fn(req, res)).then(resolve, reject)).catch(reject); });
  return { req, res };
}

test('fixed dimensions, schema and finite TTL cannot store prompt, identifiers or arbitrary model labels', async () => {
  assert.equal(metricModel('gpt-4.1-mini-2025-04-14'), 'gpt-4.1-mini');
  for (const value of ['private@account.test', 'none', 'mixed', '$set', 'unknown-model', { secret: true }]) assert.equal(metricModel(value), 'other');
  assert.equal(metricFeature('/api/posts/private-post/translation'), 'post_translation');
  assert.equal(metricFeature('/api/conversations/private-account/ai'), 'conversation_assist');
  assert.equal(metricFeature('/api/ai/private-path'), 'other');
  assert.equal(latencyBucket(250), 'le250'); assert.equal(latencyBucket(251), 'le500'); assert.equal(latencyBucket(180001), 'overflow'); assert.equal(latencyBucket(NaN), null);
  const Model = createAiRuntimeMetricModel(mongoose);
  assert.equal(Model.schema.options.strict, 'throw');
  assert.ok(Model.schema.indexes().some(([keys, options]) => keys.expiresAt === 1 && options.expireAfterSeconds === 0));
  assert.throws(() => new Model({ prompt: 'private' }), /strict mode/);
  const { models, metrics } = setup();
  const req = metrics.startRequest('private feature');
  req.providerStarted('private-account')({ outcome: 'completed', durationMs: 123, usage: { input_tokens: 2, output_tokens: 3, question: 'private question' }, model: 'private-model' });
  req.response({ ok: true, degraded: false, question: 'private question' }); req.end();
  await metrics.flush();
  const row = models.AiRuntimeMetric.rows[0];
  assert.equal(row._id, '2026-10-07:other:other');
  assert.equal(row.expiresAt, '2026-11-06T00:00:00.000Z');
  assert.doesNotMatch(JSON.stringify(models.AiRuntimeMetric.rows), /private|question|account|prompt|userId|ip|createdAt/);
});

test('concurrent instances atomically accumulate into one day/function/model bucket; day rollover is separate', async () => {
  let now = Date.parse('2026-10-08T06:59:59Z');
  const { models, metrics: a } = setup({ now: () => now });
  const b = createAiRuntimeMetrics({ Model: models.AiRuntimeMetric, now: () => now });
  await Promise.all(Array.from({ length: 100 }, async (_, index) => {
    const run = (index % 2 ? a : b).startRequest('guide_chat');
    run.providerStarted('gpt-6.1-sol')({ outcome: 'completed', durationMs: 700, usage: { input_tokens: 5, output_tokens: 2 } });
    run.response({ ok: true, degraded: index % 4 === 0 }); run.end();
  }));
  await Promise.all([a.flush(), b.flush()]);
  assert.equal(models.AiRuntimeMetric.rows.length, 1);
  const row = models.AiRuntimeMetric.rows[0];
  assert.equal(row.providerCompleted, 100); assert.equal(row.requestCompleted, 100); assert.equal(row.requestDegraded, 25);
  assert.equal(row.inputTokens, 500); assert.equal(row.outputTokens, 200); assert.equal(row.providerLatency.le1000, 100);
  assert.deepEqual(a.health(), { failedWrites: 0, droppedWrites: 0, pendingWrites: 0 });
  now += 1000;
  const run = b.startRequest('planner_recommend'); run.response({ ok: true }); run.end(); await b.flush();
  assert.equal(models.AiRuntimeMetric.rows[1].day, '2026-10-08'); assert.equal(models.AiRuntimeMetric.rows[1].model, 'none');
});

test('zero usage is known, absent/invalid input and output are counted independently, retries keep model attribution', async () => {
  const { models, metrics } = setup(); const run = metrics.startRequest('guide_chat');
  run.providerStarted('gpt-6.1-sol')({ outcome: 'error', durationMs: 500 });
  run.providerStarted('gpt-4.1-mini')({ outcome: 'completed', durationMs: 4000, usage: { prompt_tokens: 0, completion_tokens: 0 } });
  run.providerStarted('gpt-4.1-mini')({ outcome: 'incomplete', durationMs: 2000, usage: { input_tokens: 20, output_tokens: -1 } });
  run.providerStarted('gpt-4.1-mini')({ outcome: 'completed', durationMs: 100, usage: { input_tokens: '123', output_tokens: 4 } });
  run.response({ ok: true, degraded: true }); run.end(); await metrics.flush();
  const primary = models.AiRuntimeMetric.rows.find(row => row.model === 'gpt-6.1-sol');
  const fallback = models.AiRuntimeMetric.rows.find(row => row.model === 'gpt-4.1-mini');
  const request = models.AiRuntimeMetric.rows.find(row => row.model === 'mixed');
  assert.equal(primary.providerError, 1); assert.equal(primary.inputUsageMissing, 1); assert.equal(primary.outputUsageMissing, 1);
  assert.equal(fallback.providerCompleted, 2); assert.equal(fallback.providerIncomplete, 1);
  assert.equal(fallback.inputTokens, 20); assert.equal(fallback.outputTokens, 4);
  assert.equal(fallback.inputUsageMissing, 1); assert.equal(fallback.outputUsageMissing, 1);
  assert.equal(request.requestCompleted, 1); assert.equal(request.requestDegraded, 1);
});

test('SSE measures the first written quick card, validated text and complete result independently, never progress as a token', async () => {
  let tick = 0; const { models, metrics } = setup({ clock: () => tick });
  const runtime = metrics.startRequest('guide_chat'), res = response(), stream = createBayBayProgressStream(res, runtime);
  tick = 300; stream.progress({ phase: 'site', status: 'running' });
  stream.quickCard([{ kind: 'event', id: 'bad', url: 'https://bad.test' }]);
  tick = 1200; stream.quickCard([{ kind: 'event', id: 'public', url: '/events/public' }]);
  tick = 9000; stream.quickCard([{ kind: 'event', id: 'public', url: '/events/public' }]);
  tick = 16000; stream.validatedText('A'.repeat(400));
  tick = 31000; stream.result({ ok: true, degraded: true }); runtime.end();
  runtime.end({ cancelled: true }); stream.validatedText('late'); await metrics.flush();
  const row = models.AiRuntimeMetric.rows[0];
  assert.deepEqual(row.firstQuickCard, { le2000: 1 }); assert.deepEqual(row.firstValidatedText, { le30000: 1 });
  assert.deepEqual(row.completeResult, { le60000: 1 }); assert.equal(row.requestCompleted, 1); assert.equal(row.requestDegraded, 1);
  assert.equal(row.providerLatency, undefined); assert.doesNotMatch(JSON.stringify(row), /firstToken|progress|AAAA/);
});

test('disconnects and SSE error envelopes are not successful completions; first-card evidence survives cancellation', async () => {
  const { models, metrics } = setup();
  const governance = createAiGovernance({ Model: models.AiGovernance, config: { JWT_SECRET: SECRET }, metrics });
  await inRequest(governance, async (req, res) => {
    const stream = createBayBayProgressStream(res, req.aiRuntime);
    stream.quickCard([{ kind: 'event', id: 'public', url: '/events/public' }]);
    res.emit('close'); stream.result({ ok: true });
    assert.equal(req.aiSignal.aborted, true);
  });
  await inRequest(governance, async (req, res) => createBayBayProgressStream(res, req.aiRuntime).error({ ok: false, error: 'private error detail' }));
  await metrics.flush(); const row = models.AiRuntimeMetric.rows[0];
  assert.equal(row.requestCancelled, 1); assert.equal(row.requestError, 1); assert.equal(row.requestCompleted, undefined);
  assert.equal(Object.values(row.firstQuickCard).reduce((a, b) => a + b), 1); assert.equal(row.completeResult, undefined);
  assert.doesNotMatch(JSON.stringify(row), /private/);
});

test('provider wrapper distinguishes success, malformed JSON, HTTP errors, incomplete, timeout and upstream cancellation without network', async () => {
  const { models, metrics } = setup();
  const governance = createAiGovernance({ Model: models.AiGovernance, config: { JWT_SECRET: SECRET, AI_USER_DAILY_LIMIT: 100 }, now: () => NOW, metrics });
  const invoke = (fetchImpl, extras = {}) => inRequest(governance, async (_req, res) => {
    try {
      await fetchAiJson('https://never-fetched.invalid', { body: JSON.stringify({ model: 'gpt-6.1-sol', input: 'private content' }), ...extras.options }, { fetchImpl, timeoutMs: 30 });
      res.json({ ok: true });
    } catch (error) { res.status(error.code === 'REQUEST_CANCELLED' ? 499 : 503).json({ ok: false }); }
  });
  await invoke(async () => ({ ok: true, json: async () => ({ model: 'gpt-6.1-sol', status: 'completed', usage: { input_tokens: 10, output_tokens: 5 } }) }));
  await invoke(async () => ({ ok: true, json: async () => { throw new SyntaxError('private provider body'); } }));
  await invoke(async () => ({ ok: false, status: 502 }));
  await invoke(async () => ({ ok: true, json: async () => ({ status: 'incomplete', usage: { input_tokens: 4 } }) }));
  await invoke(async () => new Promise(() => {}));
  const controller = new AbortController();
  await invoke(async () => { queueMicrotask(() => controller.abort()); return new Promise(() => {}); }, { options: { signal: controller.signal } });
  await metrics.flush();
  const row = models.AiRuntimeMetric.rows[0];
  assert.equal(row.providerCompleted, 1); assert.equal(row.providerError, 2); assert.equal(row.providerIncomplete, 1); assert.equal(row.providerTimeout, 1); assert.equal(row.providerCancelled, 1);
  assert.equal(row.inputTokens, 14); assert.equal(row.outputTokens, 5); assert.equal(row.inputUsageMissing, 4); assert.equal(row.outputUsageMissing, 5);
  assert.equal(Object.values(row.providerLatency).reduce((a, b) => a + b), 6);
  assert.doesNotMatch(JSON.stringify(models.AiRuntimeMetric.rows), /private|never-fetched|provider body/);
  assert.equal(models.AiGovernance.rows[0].expiresAt, new Date(NOW + 3 * 86400000).toISOString(), 'existing quota uses the original three-day retention');
});

test('duplicate insertion recovers once, ambiguous write failures are not retried and pending writes stay bounded', async () => {
  const { models } = setup(); const original = models.AiRuntimeMetric.updateOne;
  let attempts = 0;
  models.AiRuntimeMetric.updateOne = async (key, update, options) => {
    attempts++;
    if (attempts === 1) {
      await original(key, { $setOnInsert: update.$setOnInsert }, options);
      throw Object.assign(new Error('duplicate'), { code: 11000 });
    }
    return original(key, update, options);
  };
  const metrics = createAiRuntimeMetrics({ Model: models.AiRuntimeMetric, now: () => NOW });
  metrics.startRequest('guide_chat').end(); await metrics.flush();
  assert.equal(attempts, 2); assert.equal(models.AiRuntimeMetric.rows[0].requestCompleted, 1);
  models.AiRuntimeMetric.updateOne = async () => { attempts++; throw new Error('uncertain private storage error'); };
  metrics.startRequest('guide_chat').end(); await metrics.flush(); assert.equal(attempts, 3); assert.equal(metrics.health().failedWrites, 1);
  let release;
  const blocked = createAiRuntimeMetrics({ Model: { updateOne: () => new Promise(resolve => { release = resolve; }) }, now: () => NOW, maxPending: 1 });
  blocked.startRequest('guide_chat').end(); blocked.startRequest('guide_chat').end();
  assert.deepEqual(blocked.health(), { pendingWrites: 1, failedWrites: 0, droppedWrites: 1 });
  release(); await blocked.flush(); assert.equal(blocked.health().pendingWrites, 0);
});

test('admin-only report has fixed retention and strict output fields; public usage never includes global runtime data', async t => {
  const models = createMemoryModels({ User: [{ id: 'admin', role: 'admin', accountStatus: 'active' }, { id: 'member', role: 'user', accountStatus: 'active' }] });
  models.AiRuntimeMetric.rows.push({ _id: 'private-id', day: '2026-10-07', feature: 'guide_chat', model: 'gpt-6.1-sol', requestCompleted: 7, privateText: 'private', providerLatency: { le250: 1, privateField: 'private' } });
  models.AiRuntimeMetric.rows.push({ _id: 'old', day: '2026-08-01', feature: 'guide_chat', model: 'gpt-6.1-sol', requestCompleted: 999 });
  models.AiGovernance.rows.push({ id: 'ai:2026-10-07', count: 5, identities: { private: 2 }, privateText: 'private' });
  const application = createApplication({ models, config: { NODE_ENV: 'test', JWT_SECRET: SECRET }, aiMetricsNow: () => NOW });
  await new Promise(resolve => application.server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise(resolve => application.io.close(resolve)));
  const get = async (path, id) => {
    const res = await fetch(`http://127.0.0.1:${application.server.address().port}/api${path}`, { headers: id ? { Authorization: `Bearer ${jwt.sign({ id }, SECRET, { expiresIn: '1h' })}` } : {} });
    return { status: res.status, headers: res.headers, data: await res.json() };
  };
  assert.equal((await get('/admin/ai-metrics')).status, 401);
  assert.equal((await get('/admin/ai-metrics', 'member')).status, 403);
  const report = await get('/admin/ai-metrics', 'admin');
  assert.equal(report.status, 200); assert.equal(report.headers.get('cache-control'), 'no-store');
  assert.equal(report.data.runtime.from, '2026-09-08'); assert.equal(report.data.runtime.through, '2026-10-07');
  assert.equal(report.data.runtime.daily.length, 1); assert.equal(report.data.runtime.daily[0].requestCompleted, 7);
  assert.deepEqual(report.data.days, [{ id: 'ai:2026-10-07', count: 5 }]);
  assert.doesNotMatch(JSON.stringify(report.data), /private|999|firstToken/);
  assert.equal((await get('/admin/ai-metrics?prompt=private', 'admin')).status, 400);
  const publicUsage = await get('/ai/usage');
  assert.deepEqual(Object.keys(publicUsage.data).sort(), ['degraded', 'limit', 'remaining', 'resetAt']);
  models.AiRuntimeMetric.find = () => { throw new Error('private storage fault'); };
  const unavailable = await get('/admin/ai-metrics', 'admin');
  assert.equal(unavailable.status, 503); assert.doesNotMatch(JSON.stringify(unavailable.data), /private/);
});
