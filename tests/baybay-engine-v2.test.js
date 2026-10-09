// API-BB-ENGINE: BAYBAY_ENGINE=v2 router, single-call fast path, v2 retrieval and
// the frozen-system cache layout. Every test is offline ($0): Anthropic is a fixture.
const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const { createBayBayAssistant } = require('../lib/baybayAgent');
const { routeBayBay, baybayEngine } = require('../lib/baybayRouter');
const { FROZEN_SYSTEM, systemBlocks, FAST_FORMAT, parseFastDraft, assembleAnswer, readerProse, fastProblems } = require('../lib/baybayFastPath');
const { buildFastEvidence, readerDate } = require('../lib/baybayEvidence');
const { createAnthropicBaybay } = require('../lib/anthropicBaybay');
const { namedEntitiesV2, queryAliases } = require('../lib/entityAliases');
const { loadPlannerCatalog } = require('../lib/planner');
const { createPublicContext } = require('../lib/publicContext');
const { ROUTE_NAMES, aiRoute, requestControls, KNOWN_MODELS } = require('../lib/aiModels');

const NOW = Date.parse('2026-10-08T17:00:00Z'); // Thu 2026-10-08 10:00 PDT
const TODAY = '2026-10-08';
const guides = require('../data/guide-catalog.json');
const catalog = loadPlannerCatalog();
const discoveries = { ...require('../data/discoveries.json'), english: require('../data/discoveries.en.json') };
const publicContext = createPublicContext({ guideCatalog: guides });
const base = { BAYBAY_AI_PROVIDER: 'anthropic', ANTHROPIC_API_KEY: 'fixture-anthropic-only', BAYBAY_STATE_SECRET: 'private-test-task-secret-0123456789', BAYBAY_DAILY_RUN_LIMIT: '1000' };
const quota = () => ({ updateOne: async () => ({}), findOneAndUpdate: async () => ({ count: 1 }) });
const message = (content, stop_reason = 'end_turn', usage = {}) => ({ type: 'message', id: 'msg-fixture', model: 'claude-sonnet-5-5', role: 'assistant', stop_reason, content, usage: { input_tokens: 40, output_tokens: 60, ...usage } });
const fast = (answer, usage) => message([{ type: 'text', text: JSON.stringify({ lead: 'L', points: [], candidateIds: [], followups: [], coverage: [], gap: '', ...answer }) }], 'end_turn', usage);
const reply = value => ({ ok: true, status: 200, json: async () => value, clone() { return this; }, text: async () => JSON.stringify(value) });
const hash = value => crypto.createHash('sha256').update(JSON.stringify(value)).digest('hex');
function assistantWith({ config = {}, respond }) {
  const sent = [];
  const assistant = createBayBayAssistant({ config: { ...base, BAYBAY_ENGINE: 'v2', ...config }, guideCatalog: guides, catalog, now: () => NOW, isTest: false, Quota: quota(),
    fetchImpl: async (url, init) => { assert.equal(url, 'https://api.anthropic.com/v1/messages'); const body = JSON.parse(init.body); sent.push(body); return respond(body, sent.length); } });
  return { assistant, sent };
}
const page = (currentPath, locale = 'zh-Hans') => publicContext.resolve({ context: { currentPath }, currentPath, today: TODAY, locale });
const run = (assistant, text, { currentPath = '/', locale = 'zh-Hans', searchMode = 'site', member = false, history = [] } = {}) => assistant.run({ message: text, locale, currentPath, history,
  pageContext: page(currentPath, locale), searchMode, webAccess: { allowed: member } });

// ---------------------------------------------------------------- router

test('router table: plans, plan edits, named stops and live web use the agent; everything else is one fast call', () => {
  const cases = [
    [{ emergency: true, state: { goal: 'information' } }, 'emergency'],
    [{ outing: true, state: {} }, 'outing'],
    [{ state: { goal: 'day-plan' } }, 'agent', 'day_plan'],
    [{ state: { goal: 'information' }, edit: { kind: 'replace', index: 1 } }, 'agent', 'plan_edit'],
    [{ state: { goal: 'information' }, edit: { kind: 'invalidated' } }, 'fast', 'site_answer'],
    [{ state: { goal: 'discover' }, explicitCandidateIds: ['a', 'b'] }, 'agent', 'named_stops'],
    [{ state: { goal: 'discover' }, explicitCandidateIds: ['a'] }, 'fast', 'site_answer'],
    [{ state: { goal: 'information' }, planFollowup: true }, 'agent', 'plan_followup'],
    [{ state: { goal: 'information' }, searchMode: 'web' }, 'agent', 'live_web'],
    [{ state: { goal: 'information' }, searchMode: 'smart', timely: true }, 'agent', 'live_web'],
    [{ state: { goal: 'information' }, searchMode: 'smart', timely: false }, 'fast', 'site_answer'],
    [{ state: { goal: 'information' }, searchMode: 'site', timely: true }, 'fast', 'site_answer'],
    [{ state: { goal: 'information' }, professional: { topic: 'medicare' } }, 'fast', 'professional_topic'],
    [{ state: { goal: 'discover' } }, 'fast', 'site_answer'],
  ];
  for (const [turn, path, reason] of cases) {
    const routed = routeBayBay(turn);
    assert.equal(routed.path, path, JSON.stringify(turn)); if (reason) assert.equal(routed.reason, reason);
  }
  assert.equal(routeBayBay({ state: {}, professional: { topic: 'tax' } }).route, 'baybay_professional', 'professional topics never use the fast (possibly Haiku) route');
  assert.equal(routeBayBay({ state: {} }).route, 'baybay_fast');
  assert.deepEqual(['v2', 'V2', ' v2 ', 'v1', '', undefined, 'v3'].map(value => baybayEngine({ BAYBAY_ENGINE: value })), ['v2', 'v2', 'v2', 'v1', 'v1', 'v1', 'v1']);
});

// ---------------------------------------------------------------- caching layout (RC-19/RC-22)

test('system block 1 is byte-identical across modes, locales, routes and paths, carries cache_control and has no date', async () => {
  const systems = [];
  const { assistant, sent } = assistantWith({ respond: (body, count) => reply(body.tools?.length && count % 2 === 1 && body.tool_choice?.type === 'auto'
    ? message([{ type: 'tool_use', id: `tool-${count}`, name: 'search_site', input: { query: 'Berkeley' } }], 'tool_use') : fast({ lead: '可以。' })) });
  await run(assistant, '蓝天使这周末飞吗');
  await run(assistant, 'Any free museum days in SF this month?', { locale: 'en' });
  await run(assistant, '灣區這週末有什麼免費的親子活動？', { locale: 'zh-Hant' });
  await run(assistant, 'Medicare A 部分和 B 部分有什么区别？我该选哪个？');
  await run(assistant, '还有吗', { currentPath: '/events/santana-row-glass-pumpkin-2026' });
  await run(assistant, '周六带孩子在 Berkeley 安排一天行程，不开车');
  await run(assistant, '今天 BART 有没有大面积延误？', { searchMode: 'smart', member: true });
  for (const body of sent) systems.push(hash(body.system));
  assert.ok(sent.length >= 8);
  assert.equal(new Set(systems).size, 1, 'one frozen system prefix');
  assert.deepEqual(sent[0].system, systemBlocks());
  assert.deepEqual(sent[0].system[0].cache_control, { type: 'ephemeral' });
  assert.equal(sent[0].system.length, 1);
  // No date, time or request data: a different clock or user yields the same bytes.
  const later = [];
  const other = createBayBayAssistant({ config: { ...base, BAYBAY_ENGINE: 'v2' }, guideCatalog: guides, catalog, now: () => Date.parse('2026-11-20T23:30:00Z'), isTest: false, Quota: quota(),
    fetchImpl: async (_url, init) => { later.push(JSON.parse(init.body)); return reply(fast({ lead: 'ok' })); } });
  await other.run({ message: 'What free things can I do in Oakland this weekend?', locale: 'en', currentPath: '/', pageContext: page('/', 'en'), searchMode: 'site', webAccess: { allowed: false } });
  assert.equal(hash(later[0].system), systems[0]);
  assert.doesNotMatch(FROZEN_SYSTEM, /10月8日|2026-10-08|11月20日|2026-11-20|Thursday|Friday/);
  assert.ok(FROZEN_SYSTEM.length > 2400, 'over the 512-token minimum cacheable prefix');
  // Routes and paths differ only after the cached prefix.
  const fastCalls = sent.filter(body => !body.tools), agentCalls = sent.filter(body => body.tools);
  assert.ok(fastCalls.length >= 5 && agentCalls.length >= 2);
  for (const body of fastCalls) { assert.equal(body.tool_choice, undefined); assert.equal(body.cache_control, undefined); }
  for (const body of agentCalls) {
    assert.deepEqual(body.cache_control, { type: 'ephemeral' }, 'agent runs use top-level automatic caching');
    assert.deepEqual(body.tools.map(tool => tool.name), [...body.tools.map(tool => tool.name)].sort(), 'tools are name-sorted');
  }
  const siteTools = agentCalls.filter(body => body.tools.length === 2), memberTools = agentCalls.filter(body => body.tools.length > 2);
  assert.ok(siteTools.length && memberTools.length);
  assert.equal(new Set(siteTools.map(body => hash(body.tools))).size, 1, 'one site tool prefix');
  assert.equal(new Set(memberTools.map(body => hash(body.tools))).size, 1, 'one member tool prefix');
  // Conditional rules sit after the user turn as a role:system message.
  const professional = sent.find(body => JSON.stringify(body.messages).includes('Professional-topic guard'));
  assert.equal(professional.messages[0].role, 'user'); assert.equal(professional.messages[1].role, 'system');
  assert.match(professional.messages[1].content[0].text, /1-800-434-0222/);
});

test('an agent run: call 2 replays call 1 unchanged and adds only the new turn; evidence is never sent twice', async () => {
  // Two model rounds: the research call, then the final synthesis (tool_choice none).
  const { assistant, sent } = assistantWith({ config: { BAYBAY_MAX_MODEL_ROUNDS: '2' }, respond: (body, count) => reply(count === 1
    ? message([{ type: 'tool_use', id: 'tool-1', name: 'search_site', input: { query: 'Berkeley 植物园' } }], 'tool_use', { cache_creation_input_tokens: 3000 })
    // The final answer cites the plan stop's own record (its evidence ref), as the plan guard requires.
    : fast({ lead: '可以安排半天。', points: [{ text: `先去校园和植物园 [[${JSON.parse(sent[0].messages[0].content[0].text).evidence.find(item => item.title.startsWith('Berkeley 校园')).ref}]]`, cardIds: [] }], candidateIds: ['berkeley'] }, { cache_read_input_tokens: 3000 })) });
  const result = await run(assistant, '周六带孩子在 Berkeley 安排一天行程，不开车');
  assert.equal(result.route.path, 'agent'); assert.equal(sent.length, 2);
  const [first, second] = sent;
  assert.deepEqual(second.messages.slice(0, first.messages.length), first.messages, 'append-only: call 1 is a prefix of call 2');
  const added = second.messages.slice(first.messages.length);
  assert.deepEqual(added.map(row => row.role), ['assistant', 'user', 'user', 'system']);
  assert.equal(added[1].content[0].type, 'tool_result');
  const firstBytes = JSON.stringify(first.messages).length, delta = JSON.stringify(added).length;
  assert.ok(JSON.stringify(second.messages).length <= firstBytes + delta + 2);
  // The first turn's evidence (by id) does not reappear in the tool result or the final delta.
  const firstIds = new Set([...JSON.stringify(first.messages).matchAll(/"id":"(s-[0-9a-f]{16})"/g)].map(match => match[1]));
  const repeated = [...JSON.stringify(added).matchAll(/"id":"(s-[0-9a-f]{16})"/g)].map(match => match[1]).filter(id => firstIds.has(id));
  assert.deepEqual(repeated, []);
  assert.match(added[3].content[0].text, /Research is complete/);
  assert.deepEqual(second.tool_choice, { type: 'none' }); assert.deepEqual(second.tools, first.tools);
  assert.deepEqual(result.research.modelResponses.map(row => row.cacheReadTokens), [0, 3000], 'raw cache reads are recorded per call');
  assert.deepEqual(result.research.modelResponses.map(row => row.cacheWriteTokens), [3000, 0]);
});

// ---------------------------------------------------------------- fast path

test('fast path: one call, no tools, lead-first schema, max_tokens >= 4,000, explicit effort; legacy answer assembled from lead and points', async () => {
  const { assistant, sent } = assistantWith({ respond: () => reply(fast({ lead: '会飞：航空展是10月9日至11日 [[e1]]', points: [{ text: 'Marina Green 免费观看 [[e1]]', cardIds: ['e1'] }, { text: '每天中午12点至下午4点', cardIds: [] }], candidateIds: ['e1'], followups: ['那在哪看最好？'] })) });
  const result = await run(assistant, '蓝天使这周末飞吗');
  assert.equal(sent.length, 1);
  const [body] = sent;
  assert.equal(body.tools, undefined); assert.equal(body.max_tokens, 4000); assert.equal(body.output_config.effort, 'low'); assert.equal(body.model, 'claude-sonnet-5-5');
  assert.deepEqual(Object.keys(body.output_config.format.schema.properties), ['lead', 'points', 'candidateIds', 'followups', 'coverage', 'gap'], 'lead comes first');
  for (const key of ['temperature', 'top_p', 'top_k', 'thinking']) assert.equal(Object.hasOwn(body, key), false, key);
  const user = JSON.parse(body.messages[0].content[0].text);
  assert.equal(user.today, '10月8日（周四）');
  assert.ok(user.evidence.length >= 1 && user.evidence.length <= 10);
  assert.ok(user.evidence.every(item => item.text.length <= 400), 'items are at most 400 characters');
  assert.equal(user.evidence[0].title.startsWith('San Francisco Fleet Week'), true, 'the alias names Fleet Week first');
  assert.match(user.evidence[0].page, /^https:\/\/www\.baylink\.us\/events\/san-francisco-fleet-week-2026$/);
  assert.match(user.evidence[0].when, /10月4日（周日） 至 10月12日（周一）/);
  assert.equal(result.route.path, 'fast'); assert.equal(result.engine, 'v2');
  assert.equal(result.lead, '会飞：航空展是10月9日至11日 [1]');
  assert.deepEqual(result.points.map(point => point.text), ['Marina Green 免费观看 [1]', '每天中午12点至下午4点']);
  assert.deepEqual(result.points[0].cardIds, ['event:san-francisco-fleet-week-2026']);
  assert.equal(result.answer, '会飞：航空展是10月9日至11日 [1]\n\n1. Marina Green 免费观看 [1]\n2. 每天中午12点至下午4点');
  assert.equal(result.localMatches[0].id, 'san-francisco-fleet-week-2026');
  assert.deepEqual(result.followups, ['那在哪看最好？']);
  assert.equal(result.sources[0].url, 'https://www.baylink.us/events/san-francisco-fleet-week-2026', 'the BAYLINK page is the cited source');
});

test('fast path retries once on Claude Sonnet 5.5 low after invalid JSON, and a Haiku fast route never sends disabled thinking to Sonnet', async () => {
  const { assistant, sent } = assistantWith({ config: { BAYBAY_MODEL_FAST: 'claude-haiku-5-5', BAYBAY_EFFORT_FAST: 'low', BAYBAY_THINKING_FAST: 'disabled' },
    respond: (body, count) => reply(count === 1 ? message([{ type: 'text', text: 'not json' }]) : fast({ lead: '站内有这篇指南。' })) });
  const result = await run(assistant, '养老金怎么查');
  assert.equal(sent.length, 2);
  assert.equal(sent[0].model, 'claude-haiku-5-5'); assert.deepEqual(sent[0].thinking, { type: 'disabled' }); assert.equal(sent[0].max_tokens, 4000);
  assert.equal(sent[1].model, 'claude-sonnet-5-5'); assert.equal(sent[1].thinking, undefined); assert.equal(sent[1].output_config.effort, 'low');
  assert.match(sent[1].messages.at(-1).content[0].text, /not valid JSON/);
  assert.ok(result.research.warnings.includes('fast_retry_invalid_output'));
  assert.equal(result.lead, '站内有这篇指南。'); assert.equal(result.degraded, false);
});

test('a "site has no record" answer about the page being viewed is retried, and the guard names the dates and that it ended', async () => {
  const { assistant, sent } = assistantWith({ respond: () => reply(fast({ lead: '站内没有收录这个活动的后续场次。' })) });
  const result = await run(assistant, '还有吗', { currentPath: '/events/santana-row-glass-pumpkin-2026' });
  assert.equal(sent.length, 2, 'one retry');
  assert.match(sent[1].messages.at(-1).content[0].text, /currentPage or an evidence record is what the user asked about/);
  assert.ok(result.research.warnings.includes('false_negative_corrected'));
  assert.match(result.answer, /^站内已收录「Santana Row 玻璃南瓜艺术节」（10月2日（周五） 至 10月4日（周日））/);
  assert.match(result.answer, /已经结束/);
  assert.doesNotMatch(result.answer, /20\d\d-\d\d-\d\d/);
  assert.equal(result.lead, undefined, 'a guard rewrite keeps only the legacy answer');
  assert.deepEqual(result.pageEntity, { kind: 'event', id: 'santana-row-glass-pumpkin-2026', title: 'Santana Row 玻璃南瓜艺术节' });
});

test('a guarded professional topic answers in one call on the professional route, cites the official contact by ref and keeps its phone number', async () => {
  const { assistant, sent } = assistantWith({ config: { BAYBAY_MODEL_FAST: 'claude-haiku-5-5' }, respond: () => reply(fast({ lead: 'A 和 B 通常不是二选一。', points: [{ text: 'A 部分是住院保险，B 部分是门诊保险。', cardIds: [] }, { text: '可免费咨询 HICAP [[r1]]', cardIds: [] }] })) });
  const result = await run(assistant, 'Medicare A 部分和 B 部分有什么区别？我该选哪个？');
  assert.equal(sent.length, 1); assert.equal(sent[0].model, 'claude-sonnet-5-5', 'never Haiku (RC-20)');
  assert.equal(result.route.reason, 'professional_topic'); assert.equal(result.safetyRoute, 'professional');
  const user = JSON.parse(sent[0].messages[0].content[0].text);
  assert.equal(user.evidence[0].ref, 'r1'); assert.match(user.evidence[0].text, /1-800-434-0222/);
  assert.match(result.answer, /1-800-434-0222/, 'the finish() floor appends the missing phone number');
  assert.equal(result.points.at(-1).text.includes('1-800-434-0222'), true, 'the appended contact becomes the last point');
});

test('ISO dates and region codes become reader dates and names; parse and assembly helpers', () => {
  assert.equal(readerProse('核对日期是 2026-09-28，在 south-bay', 'zh-Hans'), '核对日期是 9月28日（周一），在 南湾');
  assert.equal(readerProse('Open 2026-10-17 in east-bay', 'en'), 'Open Sat, Oct 17 in East Bay');
  assert.equal(readerDate('2026-10-17', 'zh-Hant'), '10月17日（週六）');
  const draft = parseFastDraft({ status: 'completed', output: [{ type: 'message', role: 'assistant', content: [{ type: 'output_text', text: JSON.stringify({ lead: '会。', points: [{ text: 'A', cardIds: ['e1', 7] }], candidateIds: ['e1'], followups: ['x', 'y', 'z'], coverage: [], gap: '日期待官方确认。' }) }] }] });
  assert.deepEqual(draft.points, [{ text: 'A', cardIds: ['e1'] }]); assert.equal(draft.followups.length, 2);
  assert.equal(assembleAnswer(draft), '会。\n\nA\n\n日期待官方确认。');
  assert.equal(parseFastDraft({ status: 'incomplete', output: [] }), null);
  assert.equal(parseFastDraft({ status: 'completed', output: [{ type: 'message', role: 'assistant', content: [{ type: 'output_text', text: '{"answer":"legacy"}' }] }] }), null);
  assert.deepEqual(fastProblems(null), ['invalid_output']);
  assert.deepEqual(fastProblems({ lead: '站内没有收录这个活动。', points: [], gap: '' }, { named: [{}] }), ['false_negative']);
  assert.equal(FAST_FORMAT.schema.additionalProperties, false);
});

// ---------------------------------------------------------------- adapter

test('role:system items fall back to a user-turn <system-reminder> after a 400 that says the role is unsupported, and stay converted for the run', async () => {
  const sent = [];
  const request = createAnthropicBaybay({ config: { ANTHROPIC_API_KEY: 'fixture' }, route: 'baybay_fast', fetchImpl: async (_url, init) => {
    const body = JSON.parse(init.body); sent.push(body);
    if (sent.length === 1) return { ok: false, status: 400, clone() { return this; }, text: async () => JSON.stringify({ type: 'error', error: { type: 'invalid_request_error', message: "role 'system' is not supported on this model" } }), json: async () => ({}) };
    return reply(fast({ lead: 'ok' }));
  } });
  const result = await request({ system: systemBlocks(), input: [{ role: 'user', content: 'Q' }, { role: 'system', content: 'Rule X' }], tools: [], text: { format: FAST_FORMAT } });
  assert.equal(sent.length, 2);
  assert.equal(sent[0].messages[1].role, 'system');
  assert.deepEqual(sent[1].messages[1], { role: 'user', content: [{ type: 'text', text: '<system-reminder>\nRule X\n</system-reminder>' }] });
  assert.equal(result.transport.systemRole, 'reminder');
  // Any other 400 is not retried.
  let calls = 0;
  const other = createAnthropicBaybay({ config: { ANTHROPIC_API_KEY: 'fixture' }, route: 'baybay_fast', fetchImpl: async () => { calls++; return { ok: false, status: 400, clone() { return this; }, text: async () => '{"error":{"message":"max_tokens too large"}}', json: async () => ({}) }; } });
  await assert.rejects(other({ system: systemBlocks(), input: [{ role: 'user', content: 'Q' }, { role: 'system', content: 'Rule' }], tools: [] }), /HTTP 400/);
  assert.equal(calls, 1);
});

test('no Anthropic payload carries temperature, top_p or top_k (RC-18), on any route or model, v1 or v2', async () => {
  const bodies = [];
  const fetchImpl = async (_url, init) => { bodies.push(JSON.parse(init.body)); return reply(fast({ lead: 'ok' })); };
  for (const route of ROUTE_NAMES.filter(name => name.startsWith('baybay_') && name !== 'baybay_web' && name !== 'baybay_legacy')) for (const model of KNOWN_MODELS) {
    const config = { ANTHROPIC_API_KEY: 'fixture', [`BAYBAY_MODEL_${aiRoute(route, {}).route.replace(/^baybay_/, '').toUpperCase()}`]: model };
    await createAnthropicBaybay({ config, fetchImpl, route })({ system: systemBlocks(), input: [{ role: 'user', content: 'Q' }], tools: [], temperature: 0.2, top_p: 0.5, top_k: 3, text: { format: FAST_FORMAT } });
    await createAnthropicBaybay({ config, fetchImpl, route })({ instructions: 'v1', input: [{ role: 'user', content: 'Q' }], tools: [{ type: 'function', name: 't', description: 'd', parameters: { type: 'object', properties: {}, required: [], additionalProperties: false } }], temperature: 0.2, top_p: 0.5, top_k: 3 });
    assert.ok(requestControls(aiRoute(route, config), model).effort);
  }
  assert.ok(bodies.length >= 18);
  for (const body of bodies) for (const key of ['temperature', 'top_p', 'top_k']) assert.equal(Object.hasOwn(body, key), false, key);
  for (const body of bodies) assert.ok(['low', 'medium', 'high'].includes(body.output_config.effort), 'effort is explicit');
});

test('BAYBAY_ENGINE unset keeps the v1 request: an instructions string as system, tools on every call, no cache_control', async () => {
  const sent = [];
  const assistant = createBayBayAssistant({ config: base, guideCatalog: guides, catalog, now: () => NOW, isTest: false, Quota: quota(), fetchImpl: async (_url, init) => {
    sent.push(JSON.parse(init.body));
    return reply(message([{ type: 'text', text: JSON.stringify({ answer: 'v1 answer', candidateIds: [], followups: [], coverage: [] }) }]));
  } });
  const result = await run(assistant, '蓝天使这周末飞吗');
  assert.equal(typeof sent[0].system, 'string'); assert.ok(Array.isArray(sent[0].tools) && sent[0].tools.length);
  assert.equal(sent[0].cache_control, undefined); assert.equal(sent[0].max_tokens, 6000);
  assert.equal(result.engine, undefined); assert.equal(result.lead, undefined); assert.equal(result.answer, 'v1 answer');
});

// ---------------------------------------------------------------- retrieval v2

const evidence = (text, { currentPath = '/', locale = 'zh-Hans', state = {} } = {}) => {
  const pageContext = page(currentPath, locale);
  return buildFastEvidence({ query: text, originalQuery: text, state: { goal: 'information', ...state }, guideCatalog: guides, catalog, discoveries, today: TODAY, currentPath, locale,
    selectedGuideUrls: pageContext.contextReferences.filter(ref => ref.kind === 'guide').map(ref => ref.url),
    pageKeys: pageContext.contextReferences.map(ref => `${ref.kind}:${ref.id}`), pageTitles: pageContext.contextReferences.filter(ref => ref.kind !== 'guide').map(ref => ref.title) });
};
const keys = result => result.items.map(item => `${item.kind}:${item.id}`);

test('aliases name the entity: 蓝天使 / 舰队周 -> Fleet Week, "Santana Row 那个玻璃南瓜展" -> the glass-pumpkin festival, Chez Maeju -> the opening', () => {
  assert.deepEqual(queryAliases('舰队周在哪看').ids, ['fleet-week']);
  assert.deepEqual(queryAliases('养老金怎么查').ids, ['social-security']);
  const named = query => namedEntitiesV2(query, catalog, { discoveries }).map(item => `${item.kind}:${item.row.id}`);
  assert.ok(named('蓝天使这周末飞吗').includes('event:san-francisco-fleet-week-2026'));
  assert.ok(named('海军周哪天').includes('event:san-francisco-fleet-week-2026'));
  assert.ok(named('Santana Row 那个玻璃南瓜展这周六还有吗？').includes('event:santana-row-glass-pumpkin-2026'));
  assert.ok(named('Chez Maeju 开了吗').includes('opening:oakland-chez-maeju-soft-opening-2026'));
  assert.deepEqual(named('明天下午想去 Berkeley 走走'), [], 'a bare city never names an entity');
  const santana = evidence('Santana Row 那个玻璃南瓜展这周六还有吗？几点开门？', { state: { date: '2026-10-10' } });
  assert.equal(keys(santana)[0], 'event:santana-row-glass-pumpkin-2026');
  assert.equal(santana.items[0].status, '已结束'); assert.equal(santana.items[0].mismatch, 'date_mismatch');
  assert.ok(keys(santana).includes('event:los-gatos-magical-glass-pumpkin-2026'), 'a current similar option is offered');
});

test('county-aware city recall: San Jose finds the Santa Clara County line; Fremont newcomers get the ACWD directory section', () => {
  const sanJose = evidence('我妈七十岁不会英文，住 San Jose，想找中文的老人活动', { state: { goal: 'discover', city: 'San Jose' } });
  assert.ok(sanJose.items.some(item => /408-350-3200/.test(item.text)), 'Santa Clara County AAA line');
  const fremont = evidence('我刚搬到 Fremont，第一周要办哪些事？', { state: { goal: 'newcomer', city: 'Fremont' } });
  assert.ok(fremont.items.some(item => /ACWD|Alameda County Water/.test(item.text)));
  const berkeley = evidence('明天下午想去 Berkeley 走走', { state: { city: 'Berkeley', date: '2026-10-09' } });
  assert.ok(keys(berkeley).includes('place:berkeley'));
  assert.ok(berkeley.items.every(item => !/household-bills|farmers-market/.test(item.id)), 'a shared bigram (下午) no longer pulls unrelated guides');
  const food = evidence('加一个吃饭的地方，两个人预算 50 刀', { state: { city: 'Berkeley', date: '2026-10-09' } });
  assert.ok(keys(food).some(key => /top-dog|hoagies|cere-tea/.test(key)), 'Berkeley food openings are recalled');
});

test('offers and openings are indexed in both locales, inside the asked city or region; every item is at most 400 characters', () => {
  const museums = evidence('Any free museum days in SF this month?', { locale: 'en', state: { city: 'San Francisco' } });
  assert.ok(keys(museums).includes('offer:sfmoma-family-oct25'));
  assert.ok(!keys(museums).includes('offer:sonoma-county-museum-family-oct10'), 'a Santa Rosa offer is not an SF answer');
  assert.ok(museums.items.length <= 10);
  for (const result of [museums, evidence('蓝天使这周末飞吗'), evidence('IKEA 热饮要会员吗')]) for (const item of result.items) {
    assert.ok(item.text.length <= 400, item.id); assert.match(item.page || '', /^https:\/\//);
    assert.doesNotMatch(item.when || '', /20\d\d-\d\d-\d\d/);
  }
  const pastPage = evidence('还有吗', { currentPath: '/events/santana-row-glass-pumpkin-2026' });
  assert.ok(!keys(pastPage).includes('event:santana-row-glass-pumpkin-2026'), 'the page itself is currentPage, not an item');
  assert.ok(keys(pastPage).includes('event:los-gatos-magical-glass-pumpkin-2026'), 'retrieval follows the page subject');
});

test('a member asking to open or re-check an official page keeps the agent loop; a guest asking the same gets one site-only call', async () => {
  const { assistant, sent } = assistantWith({ respond: () => reply(fast({ lead: '按站内资料回答。' })) });
  const member = await run(assistant, '帮我打开 Fremont 图书馆办卡的官方页面，看看要带什么证件', { searchMode: 'smart', member: true });
  assert.equal(member.route.path, 'agent'); assert.equal(member.route.reason, 'live_web'); assert.ok(sent[0].tools.length > 2);
  sent.length = 0;
  const guest = await run(assistant, '帮我打开 Fremont 图书馆办卡的官方页面，看看要带什么证件');
  assert.equal(guest.route.path, 'fast'); assert.equal(sent[0].tools, undefined);
});
