const test = require('node:test');
const assert = require('node:assert/strict');
const jwt = require('jsonwebtoken');
const { createRateLimiter, proxyTrust, clientIp } = require('../lib/rateLimit');
const { createAiGovernance } = require('../lib/aiGovernance');
const { fetchAiJson } = require('../lib/aiRequest');
const { safetyResponse } = require('../lib/safetyRouting');
const { createApplication } = require('../server');
const { createMemoryModels } = require('./support/memory-models');
const SECRET = 'isolated-audit-security-secret';
const NOW = Date.parse('2026-10-05T19:00:00Z');

async function fixture(t, options = {}) {
  const models = options.models || createMemoryModels();
  const app = createApplication({ ...options, models, config: { NODE_ENV: 'test', JWT_SECRET: SECRET, ...options.config }, plannerNow: options.plannerNow || (() => NOW) });
  await new Promise(resolve => app.server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise(resolve => app.io.close(resolve)));
  const request = async (path, { body, headers = {}, as } = {}) => {
    const response = await fetch(`http://127.0.0.1:${app.server.address().port}/api${path}`, { method: body === undefined ? 'GET' : 'POST', headers: { ...(body !== undefined ? { 'Content-Type': 'application/json' } : {}), ...(as ? { Authorization: `Bearer ${jwt.sign({ id: as }, SECRET, { expiresIn: '1h' })}` } : {}), ...headers }, ...(body !== undefined ? { body: JSON.stringify(body) } : {}) });
    return { status: response.status, data: await response.json(), headers: response.headers };
  };
  return { request, models };
}

test('mixed rate windows expire independently and capacity never evicts an active counter', () => {
  let now = 0;
  const limiter = createRateLimiter({ now: () => now, capacity: 3 });
  assert.equal(limiter.check('same', { windowMs: 100, maxRequests: 1 }), true);
  assert.equal(limiter.check('same', { windowMs: 10000, maxRequests: 1 }), true);
  assert.equal(limiter.check('other', { windowMs: 10000, maxRequests: 1 }), true);
  assert.equal(limiter.check('new', { windowMs: 10000, maxRequests: 1 }), false);
  now = 101;
  assert.equal(limiter.check('same', { windowMs: 100, maxRequests: 1 }), true);
  assert.equal(limiter.check('same', { windowMs: 10000, maxRequests: 1 }), false);
  assert.equal(limiter.check('other', { windowMs: 10000, maxRequests: 1 }), false);
  assert.equal(limiter.size(), 3);
  assert.equal(proxyTrust({ TRUST_PROXY_HOPS: 0 }), false);
  assert.throws(() => proxyTrust({ TRUST_PROXY_HOPS: 'true' }));
  assert.equal(clientIp({ ip: 'trusted', headers: { 'x-forwarded-for': 'forged', 'cf-connecting-ip': 'forged' } }), 'trusted');
});

test('forged leftmost XFF and CF headers cannot evade login rate limits at one trusted edge', async t => {
  const { request } = await fixture(t, { config: { TRUST_PROXY_HOPS: 1 } });
  for (let i = 0; i < 10; i++) {
    const result = await request('/auth/login', { body: { email: `unknown${i}@example.test`, password: 'bad' }, headers: { 'X-Forwarded-For': `203.0.113.${i + 1}, 198.51.100.20`, 'CF-Connecting-IP': `203.0.113.${i + 1}` } });
    assert.equal(result.status, 401);
  }
  assert.equal((await request('/auth/login', { body: { email: 'another@example.test', password: 'bad' }, headers: { 'X-Forwarded-For': '203.0.113.99, 198.51.100.20' } })).status, 429);
});

test('persistent global and identity reservations are atomic, survive new instances and reset at Pacific midnight', async () => {
  const models = createMemoryModels(); let now = Date.parse('2026-10-06T06:59:59Z');
  const settings = { Model: models.AiGovernance, config: { JWT_SECRET: SECRET, AI_DAILY_REQUEST_LIMIT: 3, AI_GUEST_DAILY_LIMIT: 2 }, now: () => now };
  const a = createAiGovernance(settings), b = createAiGovernance(settings);
  const concurrent = await Promise.all(Array.from({ length: 8 }, (_, i) => (i % 2 ? a : b).claim({ ip: 'shared' })));
  assert.equal(concurrent.filter(Boolean).length, 2);
  assert.equal(await b.claim({ userId: 'member', ip: 'shared' }), true);
  assert.equal(await a.claim({ ip: 'another' }), false);
  assert.equal(models.AiGovernance.rows[0].count, 3);
  const serialized = JSON.stringify(models.AiGovernance.rows);
  assert.doesNotMatch(serialized, /shared|member|another/);
  assert.deepEqual(await a.usage({ ip: 'shared' }), { limit: 2, remaining: 0, resetAt: '2026-10-06T07:00:00.000Z', degraded: false });
  now += 1000;
  assert.equal(await a.claim({ ip: 'shared' }), true);
  assert.equal(models.AiGovernance.rows.length, 2);
});

test('usage reset honors winter Pacific midnight and aggregate usage exposes no identity buckets', async t => {
  const models = createMemoryModels({ User: [{ id: 'admin', role: 'admin', accountStatus: 'active' }] });
  const { request } = await fixture(t, { models, plannerNow: () => Date.parse('2026-12-01T19:00:00Z') });
  const usage = await request('/ai/usage');
  assert.equal(usage.status, 200); assert.equal(usage.data.resetAt, '2026-12-02T08:00:00.000Z');
  assert.equal(usage.headers.get('cache-control'), 'no-store');
  assert.equal((await request('/admin/ai-metrics')).status, 401);
  assert.deepEqual((await request('/admin/ai-metrics', { as: 'admin' })).data, { days: [] });
});

test('multilingual emergency and professional resources return before quota and paid providers', async t => {
  let calls = 0;
  const { request, models } = await fixture(t, { ai: { baybay: async () => { calls++; throw new Error('must not call'); } } });
  models.AiGovernance.findOneAndUpdate = async () => { throw new Error('offline'); };
  for (const [locale, message] of [['zh-Hans', '现在胸痛，喘不过气'], ['zh-Hant', '現在呼吸困難'], ['en', 'I want to kill myself'], ['en', 'A child swallowed poison']]) {
    const result = await request('/ai/guide-chat', { body: { message, locale, assistantVersion: 2 } });
    assert.equal(result.status, 200); assert.equal(result.data.safetyRoute, 'emergency');
    assert.match(result.data.answer, /911/); assert.match(result.data.answer, /988/); assert.match(result.data.answer, /1-800-222-1222/);
  }
  const professional = await request('/ai/guide-chat', { body: { message: '如何申请医保', locale: 'zh-Hans' } });
  assert.equal(professional.data.safetyTopic, 'insurance'); assert.equal(professional.data.sources[0].title, 'Covered California');
  assert.equal(calls, 0); assert.equal(models.AiGovernance.rows.length, 0);
  assert.equal(safetyResponse('以前有胸痛，现在没有胸痛，想逛公园'), null);
});

test('small JSON routes reject oversized requests while image writing authenticates first', async t => {
  const { request, models } = await fixture(t);
  assert.equal((await request('/ai/guide-chat', { body: { message: 'a'.repeat(110000) } })).status, 413);
  assert.equal((await request('/posts', { body: { imageUrls: ['a'.repeat(110000)] } })).status, 401);
  assert.equal(models.AiGovernance.rows.length, 0);
});

test('cleaner ingestion and wishing not to live return resources on every safety route before exhausted quota or providers', async t => {
  let calls = 0, reservations = 0;
  const provider = async () => { calls++; throw new Error('must not call'); };
  const { request, models } = await fixture(t, { config: { AI_DAILY_REQUEST_LIMIT: 0 }, ai: { baybay: provider, guideChat: provider, postAssist: provider, outingDraft: provider, planner: { recommend: provider } } });
  models.AiGovernance.updateOne = async () => { reservations++; throw new Error('quota storage offline'); };
  const examples = [
    ['zh-Hans', '孩子误吞清洁剂怎么办'], ['zh-Hant', '孩子誤吞清潔劑怎麼辦'], ['en', 'My child swallowed cleaner'],
    ['zh-Hans', '我不想活了'], ['zh-Hant', '我不想活了怎麼辦'], ['en', "I don't want to live anymore"],
    ['en', 'I do not want to be alive any more'], ['zh-Hant', '朋友現在說不想活下去了'],
  ];
  for (const path of ['/ai/guide-chat', '/planner/recommend', '/ai/post-assist', '/ai/outing-draft']) {
    for (const [locale, message] of examples) {
      const result = await request(path, { body: { message, locale, assistantVersion: 2, stream: true } });
      assert.equal(result.status, 200, `${path}: ${message}`);
      assert.match(result.headers.get('content-type'), /application\/json/);
      assert.equal(result.data.safetyRoute, 'emergency', message);
      assert.ok(result.data.sources.some(source => source.url === 'https://988lifeline.org/'));
      assert.match(result.data.answer, /1-800-222-1222/);
    }
  }
  assert.equal(calls, 0); assert.equal(reservations, 0); assert.equal(models.AiGovernance.rows.length, 0);
});

test('emergency routing separates current disclosures from denials, historical accounts and third-person factual discussion', () => {
  for (const message of [
    '孩子没有误吞清洁剂', '孩子沒有誤吞清潔劑', 'My child did not swallow cleaner',
    '我不是不想活了，只是想安静一下', '我沒有不想活了', '我不想死',
    'I am not suicidal', 'I do not want to die', 'No chest pain and no difficulty breathing', '无胸痛', '無胸痛',
    '我以前不想活了，现在已经恢复', '孩子以前误吞清洁剂，已经康复',
    "In the past I used to think I don't want to live anymore",
    '新聞報導一個孩子誤吞清潔劑', '新闻说他不想活了',
    "Someone in a news article said they don't want to live anymore",
    '請翻譯「我不想活了」', "Translate: I don't want to live anymore",
  ]) assert.equal(safetyResponse(message), null, message);
  for (const message of [
    '我没有胸痛但现在呼吸困难', '我沒有胸痛但是現在呼吸困難', 'No chest pain but I cannot breathe now',
    '以前胸痛现在呼吸困难', '新闻里说有人误吞清洁剂，但是我孩子刚才误吞了清洁剂',
    '朋友刚才说他不想活了', "My friend just said they don't want to live anymore",
  ]) assert.equal(safetyResponse(message)?.safetyRoute, 'emergency', message);
});

test('disconnect propagates abort immediately even when a provider ignores AbortSignal', async () => {
  const controller = new AbortController(); let providerSignal;
  const result = fetchAiJson('https://fixture.invalid', { signal: controller.signal }, { fetchImpl: async (_url, options) => { providerSignal = options.signal; return new Promise(() => {}); }, timeoutMs: 20000 });
  await new Promise(resolve => setImmediate(resolve)); controller.abort();
  await assert.rejects(result, error => error.code === 'REQUEST_CANCELLED');
  assert.equal(providerSignal.aborted, true);
});

test('public posts whitelist fields rather than exposing new stored secrets or moderation metadata', async t => {
  const models = createMemoryModels({ Post: [{ id: 'public', authorId: 'owner', title: 'Community item', description: 'Example', category: '闲置', type: 'provider', city: 'San Francisco', createdAt: 1, status: 'active', isDeleted: false, adminHidden: false, privateNewField: 'secret', adminHiddenReason: 'private', reports: [{ reporterId: 'secret' }], comments: [], likes: [], contactPreference: { mode: 'manual_approve', methods: [{ type: 'email', value: 'private@example.test', enabled: true }] } }] });
  const { request } = await fixture(t, { models });
  const response = await request('/posts/public');
  assert.equal(response.status, 200);
  assert.doesNotMatch(JSON.stringify(response.data), /secret|private@example|adminHiddenReason|reportsCount/);
});
