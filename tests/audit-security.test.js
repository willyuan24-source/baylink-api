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

test('full rate limiter rejects many identities with one expiry check and no scan or index growth', () => {
  const capacity = 2048;
  const limiter = createRateLimiter({ now: () => 0, capacity });
  for (let i = 0; i < capacity; i++) {
    assert.equal(limiter.check(`admitted-${i}`, { windowMs: 100000 - i, maxRequests: 1 }), true);
  }
  const before = limiter.diagnostics();
  const attempts = 10000;
  for (let i = 0; i < attempts; i++) {
    assert.equal(limiter.check(`rejected-${i}`, { windowMs: 100000, maxRequests: 1 }), false);
    const existing = i % capacity;
    assert.equal(limiter.check(`admitted-${existing}`, { windowMs: 100000 - existing, maxRequests: 1 }), false);
  }
  const after = limiter.diagnostics();
  assert.equal(after.expiryChecks - before.expiryChecks, attempts * 2, 'each rejection inspects just the earliest active expiry');
  assert.equal(after.heapComparisons, before.heapComparisons, 'rejections do not walk or mutate the expiry index');
  assert.equal(after.expiredEntries, 0, 'active limits must survive capacity pressure');
  assert.equal(after.expiryQueueSize, capacity, 'unknown identities cannot grow the expiry index');
  assert.equal(limiter.size(), capacity);
  assert.ok(Object.isFrozen(after), 'diagnostics are read-only snapshots');
  assert.doesNotMatch(JSON.stringify(after), /admitted|rejected/, 'diagnostics cannot expose client keys');
});

test('unordered mixed expiries reclaim capacity at the exact boundary without resetting surviving windows', () => {
  let now = 0;
  const limiter = createRateLimiter({ now: () => now, capacity: 5 });
  for (const windowMs of [1000, 50, 500, 100, 75]) {
    assert.equal(limiter.check('shared', { windowMs, maxRequests: 1 }), true);
  }
  now = 49;
  assert.equal(limiter.check('new', { windowMs: 5000, maxRequests: 1 }), false);
  now = 50;
  assert.equal(limiter.check('new', { windowMs: 5000, maxRequests: 1 }), true);
  assert.equal(limiter.check('shared', { windowMs: 75, maxRequests: 1 }), false);
  assert.equal(limiter.check('shared', { windowMs: 50, maxRequests: 1 }), false, 'full capacity stays closed even for a previously expired key');
  assert.equal(limiter.diagnostics().expiredEntries, 1);
  now = 100;
  assert.equal(limiter.check('shared', { windowMs: 50, maxRequests: 1 }), true);
  assert.equal(limiter.check('another', { windowMs: 1000, maxRequests: 1 }), true);
  assert.equal(limiter.check('overflow', { windowMs: 1000, maxRequests: 1 }), false);
  assert.equal(limiter.check('shared', { windowMs: 500, maxRequests: 1 }), false);
  assert.equal(limiter.check('shared', { windowMs: 1000, maxRequests: 1 }), false);
  assert.equal(limiter.diagnostics().expiredEntries, 3);
  assert.equal(limiter.diagnostics().expiryQueueSize, limiter.size());
});

test('repeated fixed-window renewal keeps one bounded expiry entry per counter', () => {
  let now = 0;
  const capacity = 32;
  const limiter = createRateLimiter({ now: () => now, capacity });
  for (let cycle = 0; cycle < 40; cycle++) {
    now = cycle * 100;
    for (let i = 0; i < capacity; i++) {
      assert.equal(limiter.check(`identity-${i}`, { windowMs: 100, maxRequests: 1 }), true);
      assert.equal(limiter.check(`identity-${i}`, { windowMs: 100, maxRequests: 1 }), false);
    }
    assert.equal(limiter.size(), capacity);
    assert.equal(limiter.diagnostics().expiryQueueSize, capacity, 'renewal must not leave stale heap records');
  }
  assert.equal(limiter.diagnostics().expiredEntries, 39 * capacity);
  assert.ok(limiter.diagnostics().heapComparisons < 40 * capacity * 12, 'total expiry/index work stays within an O(admissions log capacity) bound');
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
  const metrics = (await request('/admin/ai-metrics', { as: 'admin' })).data;
  assert.deepEqual(metrics.days, []);
  assert.deepEqual(metrics.runtime.daily, []);
  assert.equal(metrics.runtime.retentionDays, 30);
});

test('usage reads are limited by trusted client IP before identity or quota database reads', async t => {
  const { request, models } = await fixture(t, { config: { TRUST_PROXY_HOPS: 1 } });
  let reads = 0;
  const find = models.AiGovernance.findOne.bind(models.AiGovernance);
  models.AiGovernance.findOne = (...args) => { reads++; return find(...args); };
  for (let i = 0; i < 120; i++) {
    const response = await request('/ai/usage', { headers: { 'X-Forwarded-For': `203.0.113.${i + 1}, 198.51.100.20`, 'CF-Connecting-IP': `203.0.113.${i + 1}` } });
    assert.equal(response.status, 200);
  }
  const blocked = await request('/ai/usage', { headers: { 'X-Forwarded-For': '203.0.113.200, 198.51.100.20' } });
  assert.equal(blocked.status, 429);
  assert.deepEqual(blocked.data, { remaining: null, limit: null, degraded: true, code: 'AI_USAGE_RATE_LIMIT' });
  assert.equal(blocked.headers.get('cache-control'), 'no-store');
  assert.equal(blocked.headers.get('retry-after'), '60');
  assert.equal(reads, 120, 'rate rejection cannot query the quota document');
  assert.equal(models.AiGovernance.rows.length, 0, 'reading usage cannot consume paid quota');
  assert.equal((await request('/ai/usage', { headers: { 'X-Forwarded-For': '198.51.100.21' } })).status, 200);
});

test('post-assist denies new IPs at capacity without evicting restrictions or reserving paid quota', async t => {
  t.mock.timers.enable({ apis: ['Date'], now: NOW });
  const models = createMemoryModels({ User: [{ id: 'member', role: 'user', accountStatus: 'active' }] });
  let calls = 0;
  const { request } = await fixture(t, { models, testRateLimitCapacity: 2, config: { TRUST_PROXY_HOPS: 1 }, ai: { postAssist: async () => { calls++; return { title: 'Looking for a room', description: 'I am looking for a room in Fremont. Please share details.', category: 'rent', type: 'client', quickTags: ['Rental'] }; } } });
  const post = ip => request('/ai/post-assist', { as: 'member', body: { intent: 'Looking for a room in Fremont', language: 'en' }, headers: { 'X-Forwarded-For': ip } });
  for (let i = 0; i < 5; i++) assert.equal((await post('198.51.100.20')).status, 200);
  assert.equal((await post('198.51.100.21')).status, 200);
  assert.equal((await post('198.51.100.22')).status, 429);
  assert.equal((await post('198.51.100.20')).status, 429, 'full capacity must not reset an existing exhausted minute');
  assert.equal(calls, 6); assert.equal(models.AiGovernance.rows[0].count, 6);
  t.mock.timers.tick(60001);
  assert.equal((await post('198.51.100.22')).status, 200, 'expired identities free capacity naturally');
  assert.equal(calls, 7); assert.equal(models.AiGovernance.rows[0].count, 7);
});

test('usage capacity cannot prevent a different interaction from admitting the same new client', async t => {
  const models = createMemoryModels({ User: [{ id: 'member', role: 'user', accountStatus: 'active' }] });
  const { request } = await fixture(t, { models, testRateLimitCapacity: 1, config: { TRUST_PROXY_HOPS: 1 }, ai: { postAssist: async () => ({ title: 'Looking for a room', description: 'I am looking for a room in Fremont. Please share details.', category: 'rent', type: 'client', quickTags: ['Rental'] }) } });
  assert.equal((await request('/ai/usage', { headers: { 'X-Forwarded-For': '198.51.100.20' } })).status, 200);
  assert.equal((await request('/ai/usage', { headers: { 'X-Forwarded-For': '198.51.100.21' } })).status, 429);
  const assisted = await request('/ai/post-assist', { as: 'member', body: { intent: 'Looking for a room in Fremont', language: 'en' }, headers: { 'X-Forwarded-For': '198.51.100.21' } });
  assert.equal(assisted.status, 200);
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

const acuteSynonyms = [
  { kind: 'breathing', locale: 'en', messages: ['I am having trouble breathing right now.', 'I am struggling to breathe right now.', 'I am unable to breathe right now.',
    'Since yesterday I cannot breathe and it is still happening now.', 'A news article discussed breathing issues, but I am now unable to breathe.'],
    other: ['I am not having trouble breathing.', 'I am not struggling to breathe.', 'I used to have trouble breathing but I am fine now.',
      'I am not currently struggling to breathe.', 'I am no longer struggling to breathe.',
      'Translate the phrase: I am now struggling to breathe.', 'What does "I am unable to breathe right now" mean?', 'Which breathing exercises should I do after a walk?', 'What causes trouble breathing?',
      'Yesterday I could not breathe but I am fine now.', 'A news article reports that yesterday someone could not breathe and it is still happening now.',
      'A news article quotes: I am now struggling to breathe.', 'He is asking me to translate: I am now unable to breathe.'] },
  { kind: 'breathing', locale: 'zh-Hans', messages: ['我妈现在喘不上气，怎么办？', '我妈现在透不过气，怎么办？', '我现在呼吸很困难', '我妈昨天开始喘不过气，现在还是这样', '新闻报道有人呼吸困难，但是我现在喘不上气'],
    other: ['我妈现在没有喘不上气', '以前呼吸很困难，现在已经好了', '昨天我妈喘不上气，今天好了', '请翻译「我现在喘不上气」', '翻译「我现在呼吸很困难」', '散步后喘口气应该休息多久？',
      '昨天我妈喘不过气，现在没有这些症状', '新闻报道昨天有人喘不过气，现在还是这样'] },
  { kind: 'breathing', locale: 'zh-Hant', messages: ['我媽現在喘不上氣，怎麼辦？', '我媽現在透不過氣，怎麼辦？', '我現在呼吸很困難', '我媽昨天開始喘不過氣，現在還是這樣', '新聞報導有人呼吸困難，但是我現在喘不上氣'],
    other: ['我媽現在沒有喘不上氣', '以前呼吸很困難，現在已經好了', '昨天我媽喘不上氣，今天好了', '請翻譯「我現在喘不上氣」', '翻譯「我現在呼吸很困難」', '散步後喘口氣應該休息多久？',
      '昨天我媽喘不過氣，現在沒有這些症狀', '新聞報導昨天有人喘不過氣，現在還是這樣'] },
  { kind: 'chest pain', locale: 'en', messages: ['My chest hurts badly right now.', 'I have severe pain in my chest right now.',
    'Yesterday I started having chest pain and it is still happening now.'],
    other: ['My chest does not hurt.', 'I do not have pain in my chest.', 'I do not have severe pain in my chest.', 'I do not have any severe pain in my chest.',
      'In the past I had severe pain in my chest.', 'Yesterday I had pain in my chest.',
      'Translate: My chest hurts badly right now.', 'What does "my chest hurts" mean?', 'What muscles are used for chest exercises?', 'What causes severe pain in the chest?'] },
  { kind: 'chest pain', locale: 'zh-Hans', messages: ['我现在胸口非常疼'],
    other: ['我现在没有胸口非常疼', '以前胸口非常疼，现在恢复了', '请翻译「我现在胸口非常疼」', '如何做胸部拉伸？'] },
  { kind: 'chest pain', locale: 'zh-Hant', messages: ['我現在胸口非常疼'],
    other: ['我現在沒有胸口非常疼', '以前胸口非常疼，現在恢復了', '請翻譯「我現在胸口非常疼」', '如何做胸部伸展？'] },
  { kind: 'self-harm intent', locale: 'en', messages: ['I want to end my life tonight.'],
    other: ['I do not want to end my life.', 'In the past I wanted to end my life.', 'Translate: I now want to end my life tonight.',
      'What does "I want to end my life" mean?', 'How can I make the end of my working life fulfilling?'] },
  { kind: 'self-harm intent', locale: 'zh-Hans', messages: ['我现在想结束自己的生命'],
    other: ['我现在不想结束自己的生命', '以前想结束自己的生命，现在恢复了', '请翻译「我现在想结束自己的生命」', '退休以后怎样安排生活？', '新闻报道他说：我现在想结束自己的生命'] },
  { kind: 'self-harm intent', locale: 'zh-Hant', messages: ['我現在想結束自己的生命'],
    other: ['我現在不想結束自己的生命', '以前想結束自己的生命，現在恢復了', '請翻譯「我現在想結束自己的生命」', '退休以後怎樣安排生活？', '新聞報導他說：我現在想結束自己的生命'] },
];
for (const { kind, locale, messages, other } of acuteSynonyms) {
  test(`${locale}: explicit ${kind} synonyms route urgently while denials, history, quotations and ordinary questions do not`, () => {
    for (const message of messages) {
      const result = safetyResponse(message, locale);
      assert.equal(result?.safetyRoute, 'emergency', message); assert.equal(result.responseMode, 'safety');
      assert.match(result.answer, /911/); assert.match(result.answer, /988/);
    }
    for (const message of other) assert.equal(safetyResponse(message, locale), null, message);
  });
}

for (const kind of ['breathing', 'chest pain', 'self-harm intent']) {
  test(`HTTP ${kind} synonyms in all three languages return before exhausted quota and every paid provider`, async t => {
    let calls = 0, quota = 0, external = 0;
    const provider = async () => { calls++; throw new Error('An emergency must not reach a provider'); };
    const { request, models } = await fixture(t, { config: { AI_DAILY_REQUEST_LIMIT: 0 },
      ai: { baybay: provider, guideChat: provider, postAssist: provider, outingDraft: provider, planner: { recommend: provider } },
      baybayFetch: async () => { external++; throw new Error('No emergency external fetch'); },
      baybaySourceFetch: async () => { external++; throw new Error('No emergency source fetch'); } });
    models.AiGovernance.updateOne = models.AiGovernance.findOneAndUpdate = async () => { quota++; throw new Error('Quota is offline'); };
    for (const path of ['/ai/guide-chat', '/planner/recommend', '/ai/post-assist', '/ai/outing-draft']) {
      for (const { locale, messages } of acuteSynonyms.filter(row => row.kind === kind)) for (const message of messages) {
        const result = await request(path, { body: { message, intent: message, locale, assistantVersion: 2, stream: true } });
        assert.equal(result.status, 200, `${path}: ${message}`); assert.match(result.headers.get('content-type'), /application\/json/);
        assert.equal(result.data.safetyRoute, 'emergency', message); assert.equal(result.data.responseMode, 'safety');
        assert.equal(result.data.degraded, false); assert.match(result.data.answer, /911/); assert.match(result.data.answer, /988/);
        assert.deepEqual(result.data.suggestedGuides, []); assert.deepEqual(result.data.interactiveCards, []);
      }
    }
    assert.equal(calls, 0); assert.equal(quota, 0); assert.equal(external, 0); assert.equal(models.AiGovernance.rows.length, 0);
  });
}

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
