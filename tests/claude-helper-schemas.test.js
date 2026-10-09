// API-BB-HELPERS: every Claude JSON helper call carries an output schema, HTTP
// 429/529 is retried once with jitter, planner ranking sees <=40 pre-filtered
// candidates, native web search resumes pause_turn, and no Anthropic helper
// payload carries sampling parameters. No network: every transport is a fake.
const test = require('node:test');
const assert = require('node:assert/strict');
const { requestAnthropicJson, retryDelayMs, RETRY_JITTER_MS, RETRY_AFTER_MAX_MS } = require('../lib/anthropicJson');
const { requestAnthropicSearch, normalizeAnthropicSearch, searchPayload, MAX_CONTINUATIONS } = require('../lib/anthropicWebSearch');
const helperSchemas = require('../lib/helperSchemas');
const { translateWithProvider } = require('../lib/postTranslation');
const { createOutingDraft, resolveDraftDate } = require('../lib/outingDraft');
const { recommend, plannerAiSupply, PLANNER_SCHEMA, CLAUDE_CANDIDATE_LIMIT } = require('../lib/planner');
const { extractEvent, conversationAssist } = require('../lib/localAi');
const { createApplication } = require('../server');
const { createMemoryModels } = require('./support/memory-models');
const member = require('./support/member-session');

const config = { BAYBAY_AI_PROVIDER: 'anthropic', ANTHROPIC_API_KEY: 'fixture-helper-key', ANTHROPIC_WORKSPACE_ID: 'wrkspc_fixture', OPENAI_API_KEY: 'fixture-openai-unused' };
const NOW = Date.parse('2026-10-07T20:00:00Z');
const reply = value => ({ type: 'message', role: 'assistant', model: 'claude-opus-5-5', stop_reason: 'end_turn',
  content: [{ type: 'thinking', thinking: '', signature: 'opaque' }, { type: 'text', text: JSON.stringify(value) }], usage: { input_tokens: 10, output_tokens: 5 } });
const ok = value => ({ ok: true, json: async () => value });
const capture = (values, sent = []) => async (url, init) => {
  sent.push({ url, headers: init.headers, body: JSON.parse(init.body) });
  const next = values.length > 1 ? values.shift() : values[0];
  return typeof next === 'function' ? next() : next;
};
const schema = { type: 'object', properties: { text: { type: 'string' } }, required: ['text'], additionalProperties: false };
const messages = [{ role: 'system', content: 'Translate the sample.' }, { role: 'user', content: 'Sample' }];
// The old prompt texts that asked for JSON-only output. A schema replaces them on Claude.
const JSON_ONLY = /Return (?:only |exactly one valid )?JSON|Return JSON only|只输出一个 JSON|one valid JSON object/;

function assertStructuredSchema(node, where = 'schema') {
  if (Array.isArray(node)) return node.forEach((child, index) => assertStructuredSchema(child, `${where}[${index}]`));
  if (!node || typeof node !== 'object') return;
  if (node.type === 'object') {
    assert.equal(node.additionalProperties, false, `${where}: additionalProperties must be false`);
    assert.ok(node.properties && typeof node.properties === 'object', `${where}: properties`);
    for (const key of node.required || []) assert.ok(Object.hasOwn(node.properties, key), `${where}: required ${key}`);
  }
  for (const key of ['minimum', 'maximum', 'minLength', 'maxLength', 'minItems', 'maxItems', 'pattern', '$ref']) assert.equal(node[key], undefined, `${where}: ${key}`);
  for (const [key, child] of Object.entries(node)) {
    if (key === 'properties') for (const [name, property] of Object.entries(child)) assertStructuredSchema(property, `${where}.${name}`);
    else if (key !== 'enum' && key !== 'required') assertStructuredSchema(child, `${where}.${key}`);
  }
}
function assertHelperBody(body, route) {
  assert.equal(body.output_config.format.type, 'json_schema', `${route}: output_config.format`);
  assertStructuredSchema(body.output_config.format.schema, route);
  assert.ok(['low', 'medium', 'high'].includes(body.output_config.effort), `${route}: explicit effort`);
  for (const key of ['temperature', 'top_p', 'top_k', 'response_format', 'max_completion_tokens', 'reasoning_effort']) assert.equal(body[key], undefined, `${route}: ${key}`);
  assert.doesNotMatch(body.system || '', JSON_ONLY, `${route}: no "return only JSON" text`);
}

test('every helper schema is a valid structured-output schema', () => {
  const schemas = {
    translation: helperSchemas.POST_TRANSLATION_SCHEMA,
    postAssist: helperSchemas.postAssistSchema({ categories: new Set(['rent', 'other']), covers: ['/a.png'] }),
    outing: helperSchemas.OUTING_DRAFT_SCHEMA, planner: PLANNER_SCHEMA,
    extract: helperSchemas.EVENT_EXTRACT_SCHEMA, conversation: helperSchemas.CONVERSATION_TEXT_SCHEMA,
  };
  for (const [name, value] of Object.entries(schemas)) { assert.equal(value.type, 'object', name); assertStructuredSchema(value, name); }
  assert.deepEqual(schemas.postAssist.properties.category.enum, ['rent', 'other']);
  // Optional draft fields stay optional: an unknown field is omitted, never invented.
  assert.equal(helperSchemas.OUTING_DRAFT_SCHEMA.properties.draft.required, undefined);
  assert.deepEqual(helperSchemas.EVENT_EXTRACT_SCHEMA.properties.draft.required, helperSchemas.EVENT_FIELDS);
});

test('a JSON helper call without a schema is refused before any spend', async () => {
  let calls = 0;
  for (const bad of [undefined, null, {}, { type: 'array', items: {} }, 'schema']) {
    await assert.rejects(requestAnthropicJson(messages, { config, schema: bad, fetchImpl: async () => { calls++; return ok(reply({ text: 'x' })); } }),
      { status: 500, code: 'AI_SCHEMA_REQUIRED' });
  }
  assert.equal(calls, 0);
});

test('the shared helper sends the schema as output_config.format and no JSON-only system text', async () => {
  const sent = [];
  assert.deepEqual(await requestAnthropicJson(messages, { config, schema, fetchImpl: capture([ok(reply({ text: 'Done' }))], sent) }), { text: 'Done' });
  assert.equal(sent[0].body.system, 'Translate the sample.');
  assert.deepEqual(sent[0].body.output_config.format, { type: 'json_schema', schema });
  // Without a system message no empty system field is sent.
  await requestAnthropicJson([{ role: 'user', content: 'Sample' }], { config, schema, fetchImpl: capture([ok(reply({ text: 'Done' }))], sent) });
  assert.equal(Object.hasOwn(sent[1].body, 'system'), false);
});

test('every helper caller sends its route, a schema and no sampling parameters; models and effort keep the legacy defaults', async () => {
  const sent = [];
  const fetchFor = value => capture([ok(reply(value))], sent);
  // Post translation.
  const source = { title: 'Fremont 房间出租', description: '月租 $1900。', budget: '$1900/月', timeInfo: '10月1日起' };
  await translateWithProvider(source, { config, fetchImpl: fetchFor({ title: 'Room in Fremont', description: 'Rent $1900.', budget: '$1900/month', timeInfo: 'From 10/1' }) });
  // Outing draft.
  const intent = 'October 17, 2026 Saturday 14:00 at Ferry Building in San Francisco, 4 people total.';
  await createOutingDraft({ intent, originalIntent: intent, answers: [], eventId: null, locale: 'en', today: '2026-10-07', now: NOW, calendar: resolveDraftDate(intent, '2026-10-07', 'en') },
    { config, fetchImpl: fetchFor({ answer: 'Editable proposal; confirm details.', questions: [], draft: { title: 'Walk' } }) });
  // Planner ranking.
  const event = id => ({ id, title: id, region: 'sf', city: 'San Francisco', category: 'family', cost: 'free', startDate: '2026-10-17', endDate: '2026-10-17', planning: { setting: 'outdoor', familyFriendly: true } });
  await recommend({ body: { message: 'Find local options', filters: { date: '2026-10-17' }, locale: 'en' }, catalog: { version: 1, checkedAt: '2026-10-07', events: [event('e-1')], places: [], guides: [] },
    config, now: () => NOW, fetchImpl: fetchFor({ filters: {}, rankedEventIds: ['e-1'], rankedPlaceIds: [] }) });
  // Event screenshot and conversation assist.
  const image = 'data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAwMCAO+yP1sAAAAASUVORK5CYII=';
  const draft = { title: 'Workshop', date: '', startTime: '', endTime: '', city: '', venue: '', address: '', price: '', sourceUrl: '', description: '' };
  await extractEvent({ image, locale: 'en' }, { config, fetchImpl: fetchFor({ draft, dateText: '' }) });
  await conversationAssist({ mode: 'translate', targetLocale: 'en', message: 'Sample' }, { config, fetchImpl: fetchFor({ text: 'Sample' }) });
  await conversationAssist({ mode: 'draft', targetLocale: 'en', message: '', intent: 'Ask about the time' }, { config, fetchImpl: fetchFor({ text: 'What time works?' }) });
  assert.equal(sent.length, 6);
  sent.forEach((request, index) => {
    assertHelperBody(request.body, `call ${index}`);
    // Defaults stay as today: ANTHROPIC_BAYBAY_MODEL (unset -> Opus 5.5) at the legacy effort.
    assert.equal(request.body.model, 'claude-opus-5-5'); assert.equal(request.body.output_config.effort, 'medium');
  });
  assert.deepEqual(Object.keys(sent[0].body.output_config.format.schema.properties), ['title', 'description', 'budget', 'timeInfo']);
  assert.ok(sent[1].body.output_config.format.schema.properties.draft.properties.capacity);
  assert.deepEqual(sent[2].body.output_config.format.schema, PLANNER_SCHEMA);
  assert.ok(sent[3].body.output_config.format.schema.properties.dateText);
  assert.deepEqual(sent[4].body.output_config.format.schema, helperSchemas.CONVERSATION_TEXT_SCHEMA);
  assert.match(sent[4].body.system, /Put the translation in text/); assert.match(sent[5].body.system, /Put the reply in text/);
  // Each caller names its own route: a per-route model override moves exactly that helper.
  const routes = { HELPER_TRANSLATE: 0, HELPER_OUTING: 1, HELPER_PLANNER: 2, HELPER_EVENT_EXTRACT: 3, HELPER_CONVERSATION: 4 };
  for (const [route, index] of Object.entries(routes)) {
    const overridden = [];
    const override = { ...config, [`BAYBAY_MODEL_${route}`]: 'claude-haiku-5-5', [`BAYBAY_EFFORT_${route}`]: 'low' };
    const replies = [reply({ title: 'Room in Fremont', description: 'Rent $1900.', budget: '$1900/month', timeInfo: 'From 10/1' }), reply({ answer: 'Editable proposal.', questions: [], draft: {} }),
      reply({ filters: {}, rankedEventIds: [], rankedPlaceIds: [] }), reply({ draft, dateText: '' }), reply({ text: 'Sample' })];
    const run = [
      () => translateWithProvider(source, { config: override, fetchImpl: capture([ok(replies[0])], overridden) }),
      () => createOutingDraft({ intent, originalIntent: intent, answers: [], eventId: null, locale: 'en', today: '2026-10-07', now: NOW, calendar: resolveDraftDate(intent, '2026-10-07', 'en') }, { config: override, fetchImpl: capture([ok(replies[1])], overridden) }),
      () => recommend({ body: { message: 'Find local options', filters: { date: '2026-10-17' }, locale: 'en' }, catalog: { version: 1, checkedAt: '2026-10-07', events: [event('e-1')], places: [], guides: [] }, config: override, now: () => NOW, fetchImpl: capture([ok(replies[2])], overridden) }),
      () => extractEvent({ image, locale: 'en' }, { config: override, fetchImpl: capture([ok(replies[3])], overridden) }),
      () => conversationAssist({ mode: 'translate', targetLocale: 'en', message: 'Sample' }, { config: override, fetchImpl: capture([ok(replies[4])], overridden) }),
    ][index];
    await run();
    assert.deepEqual([overridden[0].body.model, overridden[0].body.output_config.effort], ['claude-haiku-5-5', 'low'], route);
    assert.ok(overridden[0].body.max_tokens >= 4000, `${route}: Haiku max_tokens floor`);
  }
});

test('post-assist on Claude sends the post-assist schema on its own route, without the JSON-only line; OpenAI keeps it', async t => {
  const draft = { title: 'Looking for a used desk', description: 'I am looking for a used desk in Fremont for under $100. Please share its dimensions and a pickup time.', category: 'used', type: 'client', area: 'Fremont', budget: '$100', timeInfo: '', quickTags: ['Desk'], safetyTip: '', coverSuggestion: '/default-covers/07_求购二手.png' };
  const run = async (extra, response) => {
    const calls = [];
    const app = createApplication({ config: { NODE_ENV: 'test', JWT_SECRET: member.SECRET, ...config, ...extra }, models: createMemoryModels({ User: [member.user] }),
      postAssistFetch: async (url, options) => { calls.push({ url, body: JSON.parse(options.body) }); return ok(response); } });
    await new Promise(resolve => app.server.listen(0, '127.0.0.1', resolve));
    t.after(() => new Promise(resolve => app.io.close(resolve)));
    const result = await fetch(`http://127.0.0.1:${app.server.address().port}/api/ai/post-assist`, { method: 'POST', headers: { 'Content-Type': 'application/json', ...member.headers() },
      body: JSON.stringify({ intent: 'Looking for a used desk in Fremont for under $100.', language: 'en' }) });
    return { status: result.status, calls };
  };
  const claude = await run({ BAYBAY_MODEL_HELPER_POST_ASSIST: 'claude-sonnet-5-5', BAYBAY_EFFORT_HELPER_POST_ASSIST: 'low' }, reply(draft));
  assert.equal(claude.status, 200);
  const body = claude.calls[0].body;
  assertHelperBody(body, 'post-assist');
  assert.deepEqual([body.model, body.output_config.effort], ['claude-sonnet-5-5', 'low'], 'the call names helper_post_assist');
  const properties = body.output_config.format.schema.properties;
  assert.deepEqual(properties.category.enum, ['rent', 'used', 'moving', 'cleaning', 'ride', 'repair', 'translation', 'part-time', 'other']);
  assert.equal(properties.coverSuggestion.enum.length, 16); assert.deepEqual(properties.type.enum, ['client', 'provider']);
  assert.match(body.system, /必须严格返回以下 JSON 字段/, 'the field list stays; only the JSON-only line is removed');
  const openai = await run({ BAYBAY_AI_PROVIDER: undefined }, { choices: [{ finish_reason: 'stop', message: { content: JSON.stringify(draft) } }] });
  assert.equal(openai.status, 200);
  assert.match(openai.calls[0].body.messages[0].content, /- 只输出一个 JSON 对象，不要 Markdown，不要解释\n\n地区判断/);
  assert.equal(body.system, openai.calls[0].body.messages[0].content.replace('- 只输出一个 JSON 对象，不要 Markdown，不要解释\n', ''));
});

test('HTTP 429 and 529 are retried once after a jittered pause; other failures are not', async () => {
  for (const status of [429, 529]) {
    const sent = [], pauses = [], logs = [];
    const result = await requestAnthropicJson(messages, { config, schema, random: () => 0.5, sleep: async ms => { pauses.push(ms); }, log: line => logs.push(line),
      fetchImpl: capture([{ ok: false, status }, ok(reply({ text: 'After retry' }))], sent) });
    assert.deepEqual(result, { text: 'After retry' });
    assert.equal(sent.length, 2); assert.deepEqual(sent[0].body, sent[1].body, 'the retry repeats the identical request');
    assert.deepEqual(pauses, [750]);
    assert.deepEqual(JSON.parse(logs[0].replace('[ai-retry] ', '')), { route: 'helper_other', status, delayMs: 750 });
    assert.doesNotMatch(logs[0], /Sample|Translate/);
  }
  for (const status of [400, 401, 403, 404, 500, 503]) {
    const sent = [];
    await assert.rejects(requestAnthropicJson(messages, { config, schema, sleep: async () => assert.fail('no pause'), fetchImpl: capture([{ ok: false, status }], sent) }),
      error => error.providerStatus === status && error.message === `AI provider HTTP ${status}`);
    assert.equal(sent.length, 1, `HTTP ${status} is not retried`);
  }
  // Only one retry: a second 429 fails the call.
  const sent = [];
  await assert.rejects(requestAnthropicJson(messages, { config, schema, sleep: async () => {}, log: () => {}, fetchImpl: capture([{ ok: false, status: 429 }], sent) }), { providerStatus: 429 });
  assert.equal(sent.length, 2);
});

test('the retry pause is jittered within bounds, honours a short retry-after and skips a long one or a short deadline', async () => {
  const [low, high] = RETRY_JITTER_MS;
  assert.equal(retryDelayMs({ providerStatus: 429 }, () => 0), low);
  assert.ok(retryDelayMs({ providerStatus: 529 }, () => 0.999) < high);
  for (let i = 0; i < 200; i++) { const delay = retryDelayMs({ providerStatus: 429 }); assert.ok(delay >= low && delay < high, String(delay)); }
  assert.equal(retryDelayMs({ providerStatus: 429, retryAfterMs: 3000 }, () => 0), 3000);
  assert.equal(retryDelayMs({ providerStatus: 429, retryAfterMs: RETRY_AFTER_MAX_MS + 1000 }), null);
  assert.equal(retryDelayMs({ providerStatus: 500 }), null); assert.equal(retryDelayMs(new Error('AI request timed out')), null);
  // retry-after travels from the HTTP response headers.
  const pauses = [];
  await requestAnthropicJson(messages, { config, schema, random: () => 0, sleep: async ms => { pauses.push(ms); }, log: () => {},
    fetchImpl: capture([{ ok: false, status: 429, headers: new Headers({ 'retry-after': '2' }) }, ok(reply({ text: 'ok' }))]) });
  assert.deepEqual(pauses, [2000]);
  const long = [];
  await assert.rejects(requestAnthropicJson(messages, { config, schema, sleep: async () => assert.fail('no pause'),
    fetchImpl: capture([{ ok: false, status: 529, headers: new Headers({ 'retry-after': '30' }) }], long) }), { providerStatus: 529 });
  assert.equal(long.length, 1);
  // A deadline that leaves under 3 s after the pause is not retried.
  const short = [];
  await assert.rejects(requestAnthropicJson(messages, { config, schema, timeoutMs: 2000, sleep: async () => assert.fail('no pause'), fetchImpl: capture([{ ok: false, status: 429 }], short) }), { providerStatus: 429 });
  assert.equal(short.length, 1);
});

test('a caller that disconnects during the retry pause gets the original failure and no second call', async () => {
  const controller = new AbortController(), sent = [];
  await assert.rejects(requestAnthropicJson(messages, { config, schema, signal: controller.signal, log: () => {},
    sleep: (ms, signal) => new Promise((_, reject) => { controller.abort(); signal.addEventListener('abort', () => reject(new Error('aborted')), { once: true }); if (signal.aborted) reject(new Error('aborted')); }),
    fetchImpl: capture([{ ok: false, status: 429 }], sent) }), { providerStatus: 429 });
  assert.equal(sent.length, 1);
});

test('the Haiku refusal retry and the 429 retry are independent and each happen at most once', async () => {
  const sent = [];
  const result = await requestAnthropicJson(messages, { config: { ...config, BAYBAY_MODEL_HELPERS: 'claude-haiku-5-5' }, schema, sleep: async () => {}, log: () => {},
    fetchImpl: capture([{ ok: false, status: 529 }, ok({ ...reply({}), model: 'claude-haiku-5-5', stop_reason: 'refusal', content: [] }), ok({ ...reply({ text: 'Sonnet' }), model: 'claude-sonnet-5-5' })], sent) });
  assert.deepEqual(result, { text: 'Sonnet' });
  assert.deepEqual(sent.map(item => item.body.model), ['claude-haiku-5-5', 'claude-haiku-5-5', 'claude-sonnet-5-5']);
  for (const item of sent) assertHelperBody(item.body, item.body.model);
});

test('planner ranking on Claude sends at most 40 compact candidates; OpenAI and injected rankers keep 160 + 80 full rows', async () => {
  const event = (id, fields = {}) => ({ id, title: `Event ${id}`, summary: 'Long summary text', region: 'sf', city: 'San Francisco', category: 'family', cost: 'free',
    startDate: '2026-10-10', endDate: '2026-10-31', occurrenceDates: undefined, planning: { setting: 'outdoor', familyFriendly: true }, ...fields });
  const place = id => ({ id, title: `Place ${id}`, summary: 'Long summary', region: 'sf', city: 'San Francisco', category: 'park', cost: 'free', planning: { setting: 'outdoor' } });
  const many = (make, count, prefix) => Array.from({ length: count }, (_, i) => make(`${prefix}-${String(i).padStart(3, '0')}`));
  // Split: up to 30 events + 10 places, either side taking the other's unused share.
  for (const [events, places, expected] of [[100, 100, [30, 10]], [100, 3, [37, 3]], [5, 100, [5, 35]], [0, 100, [0, 40]], [100, 0, [40, 0]], [4, 2, [4, 2]]]) {
    const supply = plannerAiSupply(many(event, events, 'e'), many(place, places, 'p'), { compact: true, today: '2026-10-07' });
    assert.deepEqual([supply.events.length, supply.places.length], expected, `${events}/${places}`);
    assert.ok(supply.events.length + supply.places.length <= CLAUDE_CANDIDATE_LIMIT);
  }
  const compact = plannerAiSupply([event('e-1')], [place('p-1')], { compact: true, today: '2026-10-07' });
  assert.deepEqual(compact.events, [{ id: 'e-1', title: 'Event e-1', city: 'San Francisco', category: 'family', date: '2026-10-10' }]);
  assert.deepEqual(compact.places, [{ id: 'p-1', title: 'Place p-1', city: 'San Francisco', category: 'park' }]);
  assert.equal(plannerAiSupply([event('e-1')], [], { compact: true, date: '2026-10-17', today: '2026-10-07' }).events[0].date, '2026-10-17');
  assert.equal(plannerAiSupply([event('e-1', { occurrenceDates: ['2026-10-12', '2026-10-24'] })], [], { compact: true, today: '2026-10-13' }).events[0].date, '2026-10-24');

  const catalog = { version: 1, checkedAt: '2026-10-07', events: many(event, 170, 'e'), places: many(place, 90, 'p'), guides: [] };
  const body = { message: 'Family day out in San Francisco', filters: { date: '2026-10-17' }, locale: 'en' };
  const sent = [];
  await recommend({ body, catalog, config, now: () => NOW, fetchImpl: capture([ok(reply({ filters: {}, rankedEventIds: ['e-000'], rankedPlaceIds: [] }))], sent) });
  const payload = JSON.parse(sent[0].body.messages[0].content[0].text);
  assert.equal(payload.events.length + payload.places.length, 40);
  assert.ok(payload.events.every(row => Object.keys(row).join() === 'id,title,city,category,date' && row.date === '2026-10-17'));
  assert.ok(payload.places.every(row => Object.keys(row).join() === 'id,title,city,category'));
  assert.ok(JSON.stringify(payload).length < 6000, 'the ranking prompt stays small');
  assertHelperBody(sent[0].body, 'planner');
  assert.match(sent[0].body.system, /title, city, category and date/); assert.match(sent[0].body.system, /Maximum 3 ranked IDs/);

  let injected;
  await recommend({ body, catalog, config, now: () => NOW, ai: async value => { injected = value; return { filters: {}, rankedEventIds: [], rankedPlaceIds: [] }; } });
  assert.deepEqual([injected.events.length, injected.places.length], [160, 80]);
  assert.ok(injected.events[0].summary && injected.events[0].planning);
  let openai;
  await recommend({ body, catalog, config: { ...config, BAYBAY_AI_PROVIDER: 'openai' }, now: () => NOW, fetchImpl: async (url, init) => {
    openai = { url, body: JSON.parse(init.body) };
    return ok({ choices: [{ finish_reason: 'stop', message: { content: JSON.stringify({ filters: {}, rankedEventIds: [], rankedPlaceIds: [] }) } }] });
  } });
  assert.equal(openai.url, 'https://api.openai.com/v1/chat/completions');
  const openaiPayload = JSON.parse(openai.body.messages[1].content);
  assert.deepEqual([openaiPayload.events.length, openaiPayload.places.length], [160, 80]);
  assert.match(openai.body.messages[0].content, /^Parse the requested Bay Area day plan\. Return only JSON \{filters:/);
});

test('a ranked ID outside the 40 supplied candidates is ignored', async () => {
  const event = id => ({ id, title: id, region: 'sf', city: 'San Francisco', category: 'family', cost: 'free', startDate: '2026-10-17', endDate: '2026-10-17', planning: { setting: 'outdoor', familyFriendly: true } });
  const catalog = { version: 1, checkedAt: '2026-10-07', events: Array.from({ length: 60 }, (_, i) => event(`e-${String(i).padStart(2, '0')}`)), places: [], guides: [] };
  const body = { message: 'Find local options', filters: { date: '2026-10-17' }, locale: 'en' };
  const outside = await recommend({ body, catalog, config, now: () => NOW, fetchImpl: capture([ok(reply({ filters: {}, rankedEventIds: ['e-55'], rankedPlaceIds: [] }))]) });
  assert.equal(outside.responseMode, 'rules');
  const inside = await recommend({ body, catalog, config, now: () => NOW, fetchImpl: capture([ok(reply({ filters: {}, rankedEventIds: ['e-39'], rankedPlaceIds: [] }))]) });
  assert.equal(inside.responseMode, 'ai'); assert.equal(inside.suggestions[0].eventId, 'e-39');
});

const source = { url: 'https://museum.org/visit', title: 'Example Museum' };
const searchStart = [
  { type: 'thinking', thinking: '', signature: 'opaque-1' },
  { type: 'server_tool_use', id: 'srvtoolu_1', name: 'web_search', input: { query: 'SF museum' } },
  { type: 'web_search_tool_result', tool_use_id: 'srvtoolu_1', content: [{ type: 'web_search_result', ...source, encrypted_content: 'opaque' }] },
];
const answer = [{ type: 'text', text: 'The museum lists weekend hours.', citations: [{ type: 'web_search_result_location', ...source, encrypted_index: 'idx', cited_text: 'Hours' }] }];
const searchReply = (content, stop_reason = 'end_turn') => ({ type: 'message', role: 'assistant', model: 'claude-opus-5-5', stop_reason, content, usage: { input_tokens: 20, output_tokens: 10 } });

test('native web search resumes a pause_turn with the paused assistant content and joins the turn', async () => {
  const payload = searchPayload({ query: 'SF museum hours', locale: 'en' }, { config, instructions: 'Answer briefly.', scope: { city: 'San Francisco', timezone: 'America/Los_Angeles' } });
  assert.equal(payload.max_tokens, 8000);
  for (const field of ['temperature', 'top_p', 'top_k']) assert.equal(payload[field], undefined);
  const sent = [];
  const response = await requestAnthropicSearch(payload, { config, fetchImpl: capture([ok(searchReply(searchStart, 'pause_turn')), ok(searchReply(answer))], sent) });
  assert.equal(sent.length, 2);
  const [first, second] = sent.map(item => item.body);
  assert.deepEqual(first, payload);
  // Same request, plus the paused assistant turn verbatim; no extra user text.
  assert.deepEqual({ ...second, messages: undefined }, { ...first, messages: undefined });
  assert.deepEqual(second.messages, [...payload.messages, { role: 'assistant', content: searchStart }]);
  assert.equal(response.stop_reason, 'end_turn');
  assert.deepEqual(response.content, [...searchStart, ...answer]);
  const normalized = normalizeAnthropicSearch(response);
  assert.equal(normalized.status, 'completed');
  assert.match(normalized.output.at(-1).content[0].text, /weekend hours/);
  assert.equal(normalized.output.at(-1).content[0].annotations[0].url, source.url);
});

test('pause_turn is resumed at most twice, never after the deadline, and an unresumed pause stays incomplete', async () => {
  const payload = searchPayload({ query: 'SF museum hours', locale: 'en' }, { config, instructions: 'Answer briefly.', scope: { city: 'San Francisco', timezone: 'America/Los_Angeles' } });
  const sent = [];
  const paused = await requestAnthropicSearch(payload, { config, fetchImpl: capture([ok(searchReply(searchStart, 'pause_turn'))], sent) });
  assert.equal(sent.length, 1 + MAX_CONTINUATIONS);
  assert.equal(paused.stop_reason, 'pause_turn');
  assert.equal(sent.at(-1).body.messages.at(-1).content.length, searchStart.length * MAX_CONTINUATIONS);
  assert.throws(() => normalizeAnthropicSearch(paused), { code: 'web_incomplete_response' });
  // Deadline too short for another call: no continuation spend.
  const short = [];
  const slow = async () => { await new Promise(resolve => setTimeout(resolve, 20)); return ok(searchReply(searchStart, 'pause_turn')); };
  const result = await requestAnthropicSearch(payload, { config, timeoutMs: 1000, fetchImpl: capture([slow], short) });
  assert.equal(short.length, 1); assert.equal(result.stop_reason, 'pause_turn');
  // Other stop reasons are never resumed.
  for (const stop of ['max_tokens', 'refusal', 'end_turn']) {
    const once = [];
    await requestAnthropicSearch(payload, { config, fetchImpl: capture([ok(searchReply(searchStart, stop))], once) });
    assert.equal(once.length, 1, stop);
  }
});

test('no Anthropic helper or web-search payload carries temperature, top_p or top_k for any helper model', async () => {
  for (const model of ['claude-opus-5-5', 'claude-sonnet-5-5', 'claude-haiku-5-5']) {
    const sent = [];
    await requestAnthropicJson(messages, { config: { ...config, BAYBAY_MODEL_HELPERS: model, BAYBAY_FALLBACKS: 'default' }, schema, fetchImpl: capture([ok({ ...reply({ text: 'x' }), model })], sent) });
    const body = sent[0].body;
    for (const key of ['temperature', 'top_p', 'top_k']) assert.equal(Object.hasOwn(body, key), false, `${model} ${key}`);
    assertHelperBody(body, model);
  }
  const web = searchPayload({ query: 'q' }, { config: { ...config, BAYBAY_MODEL_WEB: 'claude-sonnet-5-5' }, instructions: 'x', scope: {} });
  for (const key of ['temperature', 'top_p', 'top_k']) assert.equal(Object.hasOwn(web, key), false, key);
});
