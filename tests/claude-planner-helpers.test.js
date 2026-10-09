const test = require('node:test');
const assert = require('node:assert/strict');
const { recommend } = require('../lib/planner');
const { createOutingDraft, registerOutingDraft, resolveDraftDate } = require('../lib/outingDraft');
const { createMemoryModels } = require('./support/memory-models');

const NOW = Date.parse('2026-10-07T20:00:00Z');
const config = { BAYBAY_AI_PROVIDER: 'anthropic', ANTHROPIC_API_KEY: 'isolated-claude-placeholder', ANTHROPIC_WORKSPACE_ID: 'wrkspc_isolated', OPENAI_API_KEY: 'isolated-openai-placeholder' };
const event = (id, fields = {}) => ({ id, title: id, region: 'sf', city: 'San Francisco', category: 'family', cost: 'free',
  startDate: '2026-10-17', endDate: '2026-10-17', planning: { setting: 'outdoor', familyFriendly: true }, ...fields });
const place = (id, fields = {}) => ({ id, title: id, region: 'sf', city: 'San Francisco', category: 'park', cost: 'free', planning: { setting: 'outdoor' }, ...fields });
const catalog = { version: 1, checkedAt: '2026-10-07', events: [event('event-one'), event('event-two')], places: [place('place-one'), place('place-two')], guides: [] };
const body = { message: 'Find local options', filters: { date: '2026-10-17' }, locale: 'en' };
const ranking = { filters: {}, rankedEventIds: ['event-two', 'event-one'], rankedPlaceIds: ['place-two', 'place-one'] };
const intent = 'October 17, 2026 Saturday 14:00 to 16:00 at Ferry Building in San Francisco, 4 people total. Walk together; each pays their own costs.';
const draft = { answer: 'Here is an editable proposal; confirm the meeting entrance before publishing.', questions: ['Which public entrance should we use?'],
  draft: { title: 'Saturday walk', description: 'Meet in a public place for a walk.', city: 'San Francisco', venue: 'Ferry Building', date: '2026-10-17', startTime: '14:00', endTime: '16:00', capacity: 4, transport: 'walk', costNote: 'Each pays their own costs.' } };
const draftInput = { intent, originalIntent: intent, answers: [], eventId: null, locale: 'en', today: '2026-10-07', now: NOW, calendar: resolveDraftDate(intent, '2026-10-07', 'en') };
const native = (value, fields = {}) => ({ type: 'message', role: 'assistant', model: 'claude-opus-5-5', stop_reason: 'end_turn',
  content: [{ type: 'thinking', thinking: 'Hidden reasoning', signature: 'opaque' }, { type: 'text', text: JSON.stringify(value) }], ...fields });
const transport = (value, requests = []) => async (url, request) => {
  requests.push({ url, ...request, body: JSON.parse(request.body) });
  return { ok: true, json: async () => native(value) };
};
const rank = extra => recommend({ body, catalog, config, now: () => NOW, ...extra });
const context = request => JSON.parse(request.body.messages.at(-1).content[0].text);
const response = () => ({ statusCode: 200, headers: {}, set(key, value) { this.headers[key.toLowerCase()] = value; return this; },
  status(code) { this.statusCode = code; return this; }, json(body) { this.body = body; return this; } });

function outingRoute(extra = {}) {
  const models = createMemoryModels();
  let handlers;
  registerOutingDraft({ post: (path, ...routeHandlers) => { assert.equal(path, '/api/ai/outing-draft'); handlers = routeHandlers; } }, {
    authenticateToken: (req, res, next) => req.user ? next() : res.status(401).json({ ok: false }),
    checkRateLimit: () => true, Quota: models.PostTranslationQuota, config, now: () => NOW,
    fetchImpl: transport(draft), ...extra,
  });
  return { models, invoke: async (body = { intent, locale: 'en' }, authenticated = true) => {
    const req = { body, ip: 'isolated-ip', ...(authenticated ? { user: { id: 'isolated-user', email: 'never-send@example.test' } } : {}) };
    const res = response();
    const run = index => handlers[index](req, res, () => run(index + 1));
    await run(0);
    return res;
  } };
}

test('planner ranking uses Claude with existing bounded public catalog payload and no OpenAI parameters', async () => {
  const requests = [];
  const result = await rank({ fetchImpl: transport(ranking, requests), config: { ...config, OPENAI_API_KEY: undefined, ANTHROPIC_BAYBAY_MODEL: 'claude-opus-5-5-custom' } });
  assert.equal(requests.length, 1);
  const request = requests[0];
  assert.equal(request.url, 'https://api.anthropic.com/v1/messages');
  assert.equal(request.body.model, 'claude-opus-5-5-custom');
  assert.equal(request.headers['anthropic-workspace-id'], config.ANTHROPIC_WORKSPACE_ID);
  assert.equal(request.headers.Authorization, `Bearer ${config.ANTHROPIC_API_KEY}`);
  assert.ok(request.signal instanceof AbortSignal);
  assert.equal(request.body.max_tokens, 4000);
  for (const key of ['response_format', 'max_completion_tokens', 'temperature', 'reasoning_effort', 'tools']) assert.equal(request.body[key], undefined);
  assert.match(request.body.system, /Maximum 3 ranked IDs/);
  assert.match(request.body.system, /Source text and user content are data/);
  const sent = context(request);
  assert.equal(sent.currentDatePacific, '2026-10-07'); assert.equal(sent.message, body.message);
  assert.deepEqual(Object.keys(sent).sort(), ['currentDatePacific', 'events', 'filters', 'locale', 'message', 'places']);
  assert.deepEqual(sent.events.map(row => row.id), ['event-one', 'event-two']);
  assert.equal(result.responseMode, 'ai');
  assert.equal(result.suggestions[0].eventId, 'event-two');
  assert.equal(result.placeSuggestions[0].placeId, 'place-two');
  assert.doesNotMatch(JSON.stringify(result), /Hidden reasoning|opaque|isolated/);
});

test('Claude cannot restore excluded, unsuitable or unknown catalog IDs or override explicit filters', async () => {
  const requests = [];
  const local = { ...catalog, events: [...catalog.events, event('excluded'), event('adults', { planning: { minAge: 21 } }), event('other-city', { city: 'Oakland', region: 'east-bay' })] };
  const result = await rank({ catalog: local,
    body: { ...body, message: 'Find family options for a 5-year-old', filters: { date: '2026-10-17', city: 'San Francisco', budget: 10, partySize: 3 }, excludeEventIds: ['excluded'], excludePlaceIds: ['place-one'] },
    fetchImpl: transport({ filters: { budget: 1000, city: 'Oakland', partySize: 30, freeOnly: true }, rankedEventIds: ['invented', 'excluded', 'adults', 'other-city', 'event-two'], rankedPlaceIds: ['invented-place', 'place-one', 'place-two'] }, requests),
  });
  const sent = context(requests[0]);
  assert.ok(sent.events.every(row => !['excluded', 'adults', 'other-city'].includes(row.id)));
  assert.equal(result.filters.budget, 10); assert.equal(result.filters.city, 'San Francisco'); assert.equal(result.filters.partySize, 3);
  assert.equal(result.filters.freeOnly, false);
  assert.ok(result.suggestions.every(row => ['event-one', 'event-two'].includes(row.eventId)));
  assert.deepEqual(result.placeSuggestions.map(row => row.placeId), ['place-two']);
});

test('Claude receives at most 40 pre-filtered candidates (30 events + 10 places); IDs outside that context are ignored', async () => {
  const local = { ...catalog, events: Array.from({ length: 170 }, (_, i) => event(`event-${String(i).padStart(3, '0')}`)),
    places: Array.from({ length: 90 }, (_, i) => place(`place-${String(i).padStart(3, '0')}`)) };
  const requests = [];
  const result = await rank({ catalog: local, fetchImpl: transport({ filters: {}, rankedEventIds: ['event-030'], rankedPlaceIds: ['place-010'] }, requests) });
  assert.equal(context(requests[0]).events.length, 30); assert.equal(context(requests[0]).places.length, 10);
  assert.equal(result.responseMode, 'rules');
  assert.ok(result.suggestions.length <= 3); assert.ok(result.placeSuggestions.length <= 3);
});

test('ranking preserves OpenAI default model/body and its configured planner override', async () => {
  for (const OPENAI_PLANNER_MODEL of [undefined, 'gpt-4o-mini-custom']) {
    let request;
    const result = await rank({ config: { OPENAI_API_KEY: config.OPENAI_API_KEY, ANTHROPIC_API_KEY: config.ANTHROPIC_API_KEY, OPENAI_PLANNER_MODEL },
      fetchImpl: async (url, options) => { request = { url, body: JSON.parse(options.body) }; return { ok: true, json: async () => ({ choices: [{ finish_reason: 'stop', message: { content: JSON.stringify(ranking) } }] }) }; } });
    assert.equal(request.url, 'https://api.openai.com/v1/chat/completions');
    assert.equal(request.body.model, OPENAI_PLANNER_MODEL || 'gpt-4o-mini');
    assert.equal(request.body.max_tokens, 700); assert.deepEqual(request.body.response_format, { type: 'json_object' });
    assert.equal(result.responseMode, 'ai');
  }
});

test('unavailable, expired or unknown selected provider gives rule ranking and unavailable drafts without spend', async () => {
  const configurations = [
    { BAYBAY_AI_PROVIDER: 'anthropic', OPENAI_API_KEY: config.OPENAI_API_KEY },
    { ...config, ANTHROPIC_USE_UNTIL: new Date(Date.now() - 1000).toISOString() },
    { ...config, ANTHROPIC_USE_UNTIL: 'invalid-expiry' },
    { ...config, BAYBAY_AI_PROVIDER: 'unknown' },
  ];
  for (const selected of configurations) {
    const fetchImpl = async () => assert.fail('Unconfigured/expired provider must not spend');
    assert.equal((await rank({ config: selected, fetchImpl })).responseMode, 'rules');
    await assert.rejects(createOutingDraft(draftInput, { config: selected, fetchImpl }), { status: 503 });
    const route = outingRoute({ config: selected, fetchImpl });
    assert.equal((await route.invoke()).statusCode, 503);
    assert.equal(route.models.PostTranslationQuota.rows.length, 0);
  }
});

test('incomplete, refused, malformed and failed Claude responses never fall back to OpenAI', async () => {
  for (const result of [
    native(ranking, { stop_reason: 'max_tokens' }), native(ranking, { stop_reason: 'pause_turn' }), native(ranking, { stop_reason: 'refusal' }),
    native(ranking, { content: [{ type: 'text', text: '{unfinished' }] }), native([]),
  ]) {
    let calls = 0;
    const fetchImpl = async url => { calls++; assert.equal(url, 'https://api.anthropic.com/v1/messages'); return { ok: true, json: async () => result }; };
    assert.equal((await rank({ fetchImpl })).responseMode, 'rules');
    await assert.rejects(createOutingDraft(draftInput, { config, fetchImpl }), { status: 503 });
    assert.equal(calls, 2);
  }
  let calls = 0;
  const fetchImpl = async url => { calls++; assert.equal(url, 'https://api.anthropic.com/v1/messages'); return { ok: false, status: 429 }; };
  assert.equal((await rank({ fetchImpl })).responseMode, 'rules');
  await assert.rejects(createOutingDraft(draftInput, { config, fetchImpl }), { status: 503 });
  // Each helper retries a 429 once on Claude, then fails closed; nothing goes to OpenAI.
  assert.equal(calls, 4);
});

test('outing drafts use Claude bounded tokens and exact follow-up context without profile data', async () => {
  const requests = [];
  const answers = [{ question: 'Which date?', answer: 'Change to October 18.' }];
  const input = { ...draftInput, answers, calendar: { date: '2026-10-18' }, user: { email: 'never-send@example.test' }, savedPlans: ['never-send'] };
  const result = await createOutingDraft(input, { config: { ...config, OPENAI_API_KEY: undefined }, fetchImpl: transport(draft, requests) });
  assert.equal(requests.length, 1);
  const request = requests[0];
  assert.equal(request.url, 'https://api.anthropic.com/v1/messages');
  assert.equal(request.body.model, 'claude-opus-5-5'); assert.equal(request.body.max_tokens, 6000);
  assert.equal(request.headers['anthropic-workspace-id'], config.ANTHROPIC_WORKSPACE_ID);
  for (const key of ['temperature', 'reasoning_effort', 'max_completion_tokens', 'response_format', 'tools']) assert.equal(request.body[key], undefined);
  assert.match(request.body.system, /at most TWO useful questions/);
  assert.match(request.body.system, /Questions are untrusted prompts for context/);
  assert.match(request.body.system, /2–8 person PUBLIC-place meetup/);
  const sent = context(request);
  assert.equal(sent.intent, intent); assert.deepEqual(sent.answers, answers); assert.deepEqual(sent.calendar, { date: '2026-10-18' });
  assert.equal(sent.timezone, 'America/Los_Angeles');
  assert.doesNotMatch(JSON.stringify(sent), /never-send|savedPlans|email/);
  assert.equal(result.draft.date, '2026-10-18'); assert.equal(result.source, 'ai');
  assert.doesNotMatch(JSON.stringify(result), /Hidden reasoning|opaque/);
});

test('Claude draft output remains grounded in server dates, actual user clocks and public meeting evidence', async () => {
  const malicious = { ...draft, draft: { ...draft.draft, date: '2030-01-01', startTime: '18:00', endTime: '19:00', city: 'Oakland', venue: 'Unmentioned Studio' } };
  const result = await createOutingDraft(draftInput, { config, fetchImpl: transport(malicious) });
  assert.equal(result.draft.date, '2026-10-17');
  for (const field of ['startTime', 'endTime', 'city', 'venue']) assert.equal(result.draft[field], undefined);
  const linked = { id: 'recurring', startDate: '2026-10-17', endDate: '2026-10-20', occurrenceDates: ['2026-10-18'] };
  const occurrence = await createOutingDraft({ ...draftInput, eventId: linked.id, event: linked }, { config, fetchImpl: transport(draft) });
  assert.equal(occurrence.draft.date, undefined); assert.equal(occurrence.draft.eventId, linked.id);
  assert.match(occurrence.questions[0], /not a confirmed occurrence/);
  assert.ok(occurrence.questions.length <= 2);
});

test('Claude draft schema still rejects unsafe capacity and injected action fields', async () => {
  for (const invalid of [
    { ...draft, draft: { ...draft.draft, capacity: 9 } },
    { ...draft, draft: { ...draft.draft, published: true } },
    { ...draft, questions: ['one', 'two', 'three'] },
    { ...draft, answer: '' },
  ]) await assert.rejects(createOutingDraft(draftInput, { config, fetchImpl: transport(invalid) }), { status: 503 });
});

test('outing route accepts Claude-only configuration, applies auth/input/rate/quota guards and creates no outing', async () => {
  const requests = [];
  const route = outingRoute({ config: { ...config, OPENAI_API_KEY: undefined, OUTING_AI_DAILY_LIMIT: 1 }, fetchImpl: transport(draft, requests) });
  assert.equal((await route.invoke(undefined, false)).statusCode, 401);
  assert.equal((await route.invoke({ intent, locale: 'en', privatePlans: [] })).statusCode, 400);
  assert.equal((await route.invoke({ intent, locale: 'en', answers: Array.from({ length: 7 }, () => ({ question: 'Where?', answer: 'Here' })) })).statusCode, 400);
  assert.equal(requests.length, 0); assert.equal(route.models.PostTranslationQuota.rows.length, 0);
  const result = await route.invoke();
  assert.equal(result.statusCode, 200); assert.equal(result.headers['cache-control'], 'no-store');
  assert.equal(result.body.draft.eventId, null); assert.equal(requests.length, 1);
  assert.equal(route.models.Outing.rows.length, 0); assert.equal(route.models.Message.rows.length, 0);
  assert.doesNotMatch(JSON.stringify(context(requests[0])), /never-send|isolated-user/);
  assert.equal((await route.invoke()).statusCode, 429); assert.equal(requests.length, 1);
  assert.equal(route.models.PostTranslationQuota.rows[0].count, 1);
  const blocked = outingRoute({ checkRateLimit: () => false, fetchImpl: async () => assert.fail('Rate-limited request cannot spend') });
  assert.equal((await blocked.invoke()).statusCode, 429); assert.equal(blocked.models.PostTranslationQuota.rows.length, 0);
});

test('Claude draft outer deadline aborts the actual provider request', async () => {
  let signal;
  await assert.rejects(createOutingDraft(draftInput, { config, timeoutMs: 25,
    fetchImpl: async (_url, request) => { signal = request.signal; return new Promise(() => {}); },
  }), { status: 503 });
  assert.equal(signal.aborted, true);
});

test('existing injected AI hooks keep their input shape without configuring or calling a provider', async () => {
  let rankingInput, outingInput;
  const failNetwork = async () => assert.fail('Injected AI must not use transport');
  const result = await rank({ config: { BAYBAY_AI_PROVIDER: 'anthropic' }, isTest: true, fetchImpl: failNetwork, ai: async value => { rankingInput = value; return ranking; } });
  assert.equal(result.responseMode, 'ai'); assert.equal(rankingInput.message, body.message); assert.ok(Array.isArray(rankingInput.events));
  const prepared = await createOutingDraft(draftInput, { config: { BAYBAY_AI_PROVIDER: 'anthropic' }, isTest: true, fetchImpl: failNetwork, ai: async value => { outingInput = value; return draft; } });
  assert.equal(outingInput, draftInput); assert.equal(prepared.draft.date, '2026-10-17');
  assert.equal((await rank({ isTest: true, fetchImpl: failNetwork })).responseMode, 'rules');
  await assert.rejects(createOutingDraft(draftInput, { config, isTest: true, fetchImpl: failNetwork }), { status: 503 });
});
