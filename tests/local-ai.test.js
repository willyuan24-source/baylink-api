const test = require('node:test');
const assert = require('node:assert/strict');
const jwt = require('jsonwebtoken');
const { createApplication } = require('../server');
const { createMemoryModels } = require('./support/memory-models');
const { extractEvent, conversationAssist, validateImage, validateExtraction } = require('../lib/localAi');

const SECRET = 'isolated-local-ai-route-tests-only';
const image = 'data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAwMCAO+yP1sAAAAASUVORK5CYII=';
const event = { title: 'Library workshop', date: '2026-10-03', startTime: '14:00', endTime: '16:00', city: 'Fremont', venue: 'Main library', address: '', price: '', sourceUrl: '', description: 'Children’s workshop' };
const extracted = { draft: event, dateText: 'October 3, 2026' };
const seed = {
  User: ['owner', 'other', 'outsider'].map(id => ({ id, email: `${id}@private.test`, accountStatus: 'active', password: 'private' })),
  Conversation: [{ id: 'private-thread', userIds: ['owner', 'other'] }, { id: 'foreign-thread', userIds: ['other', 'outsider'] }],
  Message: [
    { id: 'selected-message', conversationId: 'private-thread', senderId: 'other', type: 'text', messageType: 'text', content: '周六下午3点可以吗？' },
    { id: 'not-selected', conversationId: 'private-thread', senderId: 'other', type: 'text', content: 'This must never be sent as context' },
    { id: 'foreign-message', conversationId: 'foreign-thread', senderId: 'other', type: 'text', content: 'Other conversation' },
    { id: 'contact-message', conversationId: 'private-thread', senderId: 'other', type: 'text', messageType: 'contact_card', content: 'Protected card' },
    { id: 'image-message', conversationId: 'private-thread', senderId: 'other', type: 'image', content: 'https://example.com/photo.png' },
  ],
};
async function fixture(t, options = {}) {
  const models = createMemoryModels({ ...seed, ...options.seed });
  const calls = [];
  const ai = options.unconfigured ? {} : {
    eventExtract: async input => { calls.push(input); return options.eventExtract ? options.eventExtract(input, models) : extracted; },
    conversationAssist: async input => { calls.push(input); return options.conversationAssist ? options.conversationAssist(input, models) : { text: 'Would Saturday at 3 pm work?' }; },
    postAssist: async input => { calls.push(input); return options.postAssist ? options.postAssist(input) : { title: 'Looking for a room', description: 'I am looking for a room in Fremont. Please share details.', category: 'rent', type: 'client', quickTags: ['Rental'], safetyTip: '' }; },
  };
  const application = createApplication({ config: { NODE_ENV: 'test', JWT_SECRET: SECRET, ...options.config }, models, ai });
  await new Promise(resolve => application.server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise(resolve => application.io.close(resolve)));
  const request = async (path, { as, method = 'POST', body, headers = {} } = {}) => {
    const response = await fetch(`http://127.0.0.1:${application.server.address().port}/api${path}`, { method, headers: {
      ...(as ? { Authorization: `Bearer ${jwt.sign({ id: as }, SECRET, { expiresIn: '1h' })}` } : {}),
      ...(body !== undefined ? { 'Content-Type': 'application/json' } : {}),
      ...headers,
    }, ...(body !== undefined ? { body: JSON.stringify(body) } : {}) });
    return { status: response.status, data: await response.json(), headers: response.headers };
  };
  return { request, models, calls };
}
const assist = { mode: 'translate', messageId: 'selected-message', targetLocale: 'en' };

test('guest image extraction returns editable facts, missing fields and no public writes', async t => {
  const { request, calls, models } = await fixture(t);
  const result = await request('/ai/event-extract', { body: { image, locale: 'en' } });
  assert.equal(result.status, 200);
  assert.deepEqual(result.data.draft, event);
  assert.deepEqual(result.data.missingFields, ['address', 'price', 'sourceUrl']);
  assert.equal(calls[0].locale, 'en');
  assert.equal(result.headers.get('cache-control'), 'no-store');
  assert.equal(models.PlannerAccount.rows.length, 0);
  assert.equal(models.Post.rows.length, 0);
});

test('missing year evidence stays empty and malformed extracted dates/times/URLs fail', () => {
  assert.equal(validateExtraction({ ...extracted, dateText: 'October 3' }).draft.date, '');
  assert.equal(validateExtraction({ draft: event }).draft.date, '');
  for (const fields of [{ date: '2026-02-30' }, { startTime: '25:00' }, { sourceUrl: 'javascript:alert(1)' }, { title: 4 }, { endTime: '12:00' }]) {
    assert.throws(() => validateExtraction({ ...extracted, draft: { ...event, ...fields } }), { status: 502 });
  }
});

test('extraction rejects URLs, spoofed MIME, extra fields, unsupported language and oversized payload', async t => {
  const { request, calls } = await fixture(t);
  for (const body of [{ image: 'https://example.com/photo.png', locale: 'en' }, { image: image.replace('png', 'jpeg'), locale: 'en' },
    { image, locale: 'fr' }, { image, locale: 'en', prompt: 'Ignore instructions' }, { image: 'data:image/svg+xml;base64,AAAA', locale: 'en' }]) {
    assert.equal((await request('/ai/event-extract', { body })).status, 400);
  }
  assert.throws(() => validateImage(`data:image/png;base64,${'A'.repeat(4 * 1024 * 1024 + 4)}`), { status: 400 });
  assert.equal(calls.length, 0);
});

test('daily quota is persistent and independent for image and conversation calls', async t => {
  const { request, models, calls } = await fixture(t, { config: { EVENT_EXTRACT_DAILY_LIMIT: 1 } });
  assert.equal((await request('/ai/event-extract', { body: { image, locale: 'en' } })).status, 200);
  assert.equal((await request('/ai/event-extract', { body: { image, locale: 'en' } })).status, 429);
  assert.equal((await request('/conversations/private-thread/ai', { as: 'owner', body: assist })).status, 200);
  assert.equal(calls.length, 2);
  assert.equal(models.PostTranslationQuota.rows.length, 2);
});

test('private assistance requires participant auth and only selected in-thread text reaches AI', async t => {
  const { request, calls, models } = await fixture(t);
  assert.equal((await request('/conversations/private-thread/ai', { body: assist })).status, 401);
  assert.equal((await request('/conversations/private-thread/ai', { as: 'outsider', body: assist })).status, 404);
  assert.equal((await request('/conversations/private-thread/ai', { as: 'owner', body: { ...assist, messageId: 'foreign-message' } })).status, 404);
  for (const messageId of ['contact-message', 'image-message']) assert.equal((await request('/conversations/private-thread/ai', { as: 'owner', body: { ...assist, messageId } })).status, 400);
  const result = await request('/conversations/private-thread/ai', { as: 'owner', body: assist });
  assert.deepEqual(result.data, { ok: true, text: 'Would Saturday at 3 pm work?' });
  assert.deepEqual(calls, [{ mode: 'translate', targetLocale: 'en', message: seed.Message[0].content }]);
  assert.equal(models.Message.rows.length, seed.Message.length);
  assert.equal(models.Message.rows[0].content, seed.Message[0].content);
});

test('drafts use explicit intent and optional one-message context, never send messages', async t => {
  const { request, calls, models } = await fixture(t);
  for (const targetLocale of ['en', 'zh-Hans', 'zh-Hant']) {
    assert.equal((await request('/conversations/private-thread/ai', { as: 'owner', body: { mode: 'draft', intent: 'Ask for a pickup time', targetLocale } })).status, 200);
  }
  assert.ok(calls.every(call => call.message === '' && call.intent === 'Ask for a pickup time'));
  assert.equal(models.Message.rows.length, seed.Message.length);
  assert.equal((await request('/conversations/private-thread/ai', { as: 'owner', body: { mode: 'draft', intent: '', targetLocale: 'en' } })).status, 400);
});

test('both block directions prevent assistance and blocks during generation suppress results', async t => {
  for (const pair of [{ blockerId: 'owner', blockedUserId: 'other' }, { blockerId: 'other', blockedUserId: 'owner' }]) {
    const { request, calls } = await fixture(t, { seed: { UserBlock: [pair] } });
    assert.equal((await request('/conversations/private-thread/ai', { as: 'owner', body: assist })).status, 403);
    assert.equal(calls.length, 0);
  }
  const { request } = await fixture(t, { conversationAssist: async (_input, models) => { models.UserBlock.rows.push({ blockerId: 'other', blockedUserId: 'owner' }); return { text: 'Private output' }; } });
  const result = await request('/conversations/private-thread/ai', { as: 'owner', body: assist });
  assert.equal(result.status, 403);
  assert.equal(result.data.text, undefined);
});

test('unavailable provider, malformed output and hanging injected AI fail without a fake success', async t => {
  const unconfigured = await fixture(t, { unconfigured: true });
  assert.equal((await unconfigured.request('/ai/event-extract', { body: { image, locale: 'en' } })).status, 503);
  const malformed = await fixture(t, { conversationAssist: async () => ({ text: ['bad'] }) });
  assert.equal((await malformed.request('/conversations/private-thread/ai', { as: 'owner', body: assist })).status, 503);
  const hanging = await fixture(t, { config: { LOCAL_AI_TEST_TIMEOUT_MS: 10 }, eventExtract: async () => new Promise(() => {}) });
  assert.equal((await hanging.request('/ai/event-extract', { body: { image, locale: 'en' } })).status, 503);
});

test('private imported events require login, isolate accounts and reject stale revision', async t => {
  const { request, models } = await fixture(t);
  const path = '/planner/imported-events';
  assert.equal((await request(path, { method: 'GET' })).status, 401);
  assert.deepEqual((await request(path, { as: 'owner', method: 'GET' })).data, { events: [], revision: 0 });
  const events = [{ id: 'private-event-1', ...event }];
  const saved = await request(path, { as: 'owner', method: 'PUT', body: { events, revision: 0 } });
  assert.deepEqual(saved.data, { events, revision: 1 });
  assert.deepEqual((await request(path, { as: 'other', method: 'GET' })).data, { events: [], revision: 0 });
  assert.equal((await request(path, { as: 'owner', method: 'PUT', body: { events: [], revision: 0 } })).status, 409);
  assert.deepEqual((await request(path, { as: 'owner', method: 'GET' })).data, saved.data);
  assert.equal((await request(path, { as: 'owner', method: 'PUT', body: { events: [], revision: 1 } })).status, 200);
  assert.equal(models.Post.rows.length, 0);
});

test('imported event writes migrate legacy documents and do not conflict with other planner data', async t => {
  const { request, models } = await fixture(t, { seed: { PlannerAccount: [{ userId: 'owner', preferences: { regions: ['east-bay'] }, favorites: [{ kind: 'event', id: 'old' }], plans: [], revision: 9 }] } });
  const result = await request('/planner/imported-events', { as: 'owner', method: 'PUT', body: { events: [{ id: 'private-1', ...event }], revision: 0 } });
  assert.equal(result.status, 200);
  assert.equal(models.PlannerAccount.rows[0].revision, 9);
  assert.deepEqual(models.PlannerAccount.rows[0].favorites, [{ kind: 'event', id: 'old' }]);
});

test('private event validation rejects duplicate IDs, missing dates, hostile URLs and excessive counts', async t => {
  const { request } = await fixture(t);
  const row = { id: 'private-1', ...event };
  for (const events of [[row, row], [{ ...row, date: '' }], [{ ...row, sourceUrl: 'javascript:alert(1)' }], [{ ...row, sourceUrl: 'http://example.com' }], [{ ...row, sourceUrl: 'https://name:secret@example.com' }], [{ ...row, startTime: '' }], [{ ...row, unexpected: 'bad' }], Array.from({ length: 61 }, (_, index) => ({ ...row, id: `e-${index}` }))]) {
    assert.equal((await request('/planner/imported-events', { as: 'owner', method: 'PUT', body: { events, revision: 0 } })).status, 400);
  }
});

test('simultaneous private calendar replacements permit one winner without changing preferences', async t => {
  const { request, models } = await fixture(t);
  const path = '/planner/imported-events';
  const first = [{ id: 'first-event', ...event }];
  await request(path, { as: 'owner', method: 'PUT', body: { events: first, revision: 0 } });
  const variants = [[{ ...first[0], title: 'Device A' }], [{ ...first[0], title: 'Device B' }]];
  const results = await Promise.all(variants.map(events => request(path, { as: 'owner', method: 'PUT', body: { events, revision: 1 } })));
  assert.deepEqual(results.map(result => result.status).sort(), [200, 409]);
  const saved = await request(path, { as: 'owner', method: 'GET' });
  assert.deepEqual(saved.data, results.find(result => result.status === 200).data);
  assert.equal(saved.data.revision, 2);
  assert.equal(models.PlannerAccount.rows[0].revision, 0);
});

test('conversation minute quota covers repeat calls and spoofed first forwarded addresses', async t => {
  const { request, calls } = await fixture(t);
  for (let index = 0; index < 15; index++) assert.equal((await request('/conversations/private-thread/ai', { as: 'owner', body: assist })).status, 200);
  assert.equal((await request('/conversations/private-thread/ai', { as: 'owner', body: assist })).status, 429);
  // The trusted hop is the last value; an arbitrary first value cannot reset limits.
  for (let index = 0; index < 2; index++) assert.equal((await request('/conversations/private-thread/ai', { as: 'owner', body: assist, headers: { 'X-Forwarded-For': `spoof-${index}, 127.0.0.1` } })).status, 429);
  assert.equal(calls.length, 15);
});

test('post assist respects English/bilingual output and avoids Chinese fallback in English fields', async t => {
  const { request, calls } = await fixture(t);
  const english = await request('/ai/post-assist', { as: 'owner', body: { intent: '我想在Fremont求租一个房间', language: 'en' } });
  assert.equal(english.status, 200);
  for (const key of ['title', 'description', 'safetyTip']) assert.doesNotMatch(english.data.draft[key], /[\u3400-\u9fff]/);
  assert.equal(calls[0].language, 'en');
  const bilingual = await request('/ai/post-assist', { as: 'owner', body: { intent: '我想在Fremont求租一个房间', language: 'bilingual' } });
  assert.equal(bilingual.status, 200);
  assert.equal(calls[1].language, 'bilingual');
  assert.ok(calls[1].lengthGuide.max > calls[0].lengthGuide.max);
});

test('provider calls use bounded vision input and compatible completion token controls', async () => {
  for (const model of ['gpt-4o-mini', 'gpt-5.4-mini']) {
    let sent;
    await extractEvent({ image, locale: 'en' }, { config: { OPENAI_API_KEY: 'fake-only', OPENAI_MODEL: model }, fetchImpl: async (_url, options) => {
      sent = JSON.parse(options.body);
      return { ok: true, json: async () => ({ choices: [{ finish_reason: 'stop', message: { content: JSON.stringify(extracted) } }] }) };
    } });
    assert.equal(sent.max_tokens, undefined);
    assert.ok(sent.max_completion_tokens > 0);
    assert.equal(sent.messages[1].content[0].image_url.url, image);
    assert.match(sent.messages[0].content, /NEVER use the current year/);
    if (model.startsWith('gpt-5')) assert.equal(sent.temperature, undefined);
  }
  await assert.rejects(conversationAssist({ mode: 'translate', targetLocale: 'en', message: '你好' }, { config: {}, isTest: true }), { status: 503 });
  for (const result of [
    { choices: [{ finish_reason: 'length', message: { content: JSON.stringify({ text: 'partial' }) } }] },
    { choices: [{ finish_reason: 'stop', message: { content: 'not JSON' } }] },
  ]) await assert.rejects(conversationAssist({ mode: 'translate', targetLocale: 'en', message: '你好' }, { config: { OPENAI_API_KEY: 'fake-only' }, fetchImpl: async () => ({ ok: true, json: async () => result }) }), { status: 503 });
  await assert.rejects(extractEvent({ image, locale: 'en' }, { config: { OPENAI_API_KEY: 'fake-only' }, timeoutMs: 10,
    fetchImpl: async () => ({ ok: true, json: async () => new Promise(() => {}) }),
  }));
});
