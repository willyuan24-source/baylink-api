// API-BB-CUTOVER: v2 by default, the daily $ caps enforced, pause mode and the
// capabilities contract. Every test is offline ($0): providers are fixtures.
const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const { EventEmitter } = require('node:events');
const jwt = require('jsonwebtoken');
const { createAiGovernance, aiExecution, reserveAiCall, aiRefusal, governProviders } = require('../lib/aiGovernance');
const { fetchAiJson } = require('../lib/aiRequest');
const { createBayBayAssistant } = require('../lib/baybayAgent');
const { registerPlannerWebSearch, normalizeWebSearchError, WEB_SEARCH_FAILURES } = require('../lib/plannerWebSearch');
const { createOutingDraft } = require('../lib/outingDraft');
const { budgetNotice, noticeBanners, pacificResetAt, spendCapsEnforced, LOCALES } = require('../lib/aiBudget');
const { loadPlannerCatalog } = require('../lib/planner');
const { createPublicContext } = require('../lib/publicContext');
const { createMemoryModels } = require('./support/memory-models');

const SECRET = 'cutover-fixture-session-secret';
const NOW = Date.parse('2026-10-08T17:00:00Z'); // Thu 2026-10-08 10:00 PDT
const TODAY = '2026-10-08';
const RESETS = '2026-10-09T07:00:00.000Z';
const guides = require('../data/guide-catalog.json');
const catalog = loadPlannerCatalog();
const publicContext = createPublicContext({ guideCatalog: guides });
const base = { BAYBAY_AI_PROVIDER: 'anthropic', ANTHROPIC_API_KEY: 'fixture-anthropic-only', BAYBAY_STATE_SECRET: 'private-test-task-secret-0123456789', BAYBAY_DAILY_RUN_LIMIT: '1000' };
const quota = () => ({ updateOne: async () => ({}), findOneAndUpdate: async () => ({ count: 1 }) });
const reply = value => ({ ok: true, status: 200, json: async () => value, clone() { return this; }, text: async () => JSON.stringify(value) });
const fastMessage = (answer = {}) => ({ type: 'message', id: 'msg-fixture', model: 'claude-sonnet-5-5', role: 'assistant', stop_reason: 'end_turn',
  content: [{ type: 'text', text: JSON.stringify({ lead: '会飞，周六周日下午表演[[e1]]。', points: [], candidateIds: [], followups: [], coverage: [], gap: '', ...answer }) }], usage: { input_tokens: 40, output_tokens: 60 } });
const spendState = (level, extra = {}) => ({ day: TODAY, level, caps: { softDailyUsd: 6, hardDailyUsd: 10, enforced: true }, ...extra });
const page = (currentPath, locale = 'zh-Hans') => publicContext.resolve({ context: { currentPath }, currentPath, today: TODAY, locale });
const hanPost = (id, authorId) => ({ id, authorId, title: 'Fremont 房间出租', description: '周末可看房。', budget: '', timeInfo: '', isDeleted: false, adminHidden: false, status: 'active', contactPreference: { methods: [] } });
const PNG = 'data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAwMCAO+yP1sAAAAASUVORK5CYII=';

function assistantWith({ config = {}, budget, webSearch, Quota = quota(), respond = () => reply(fastMessage()) } = {}) {
  const sent = [], searches = [];
  const assistant = createBayBayAssistant({ config: { ...base, ...config }, guideCatalog: guides, catalog, now: () => NOW, isTest: false, Quota, budget,
    webSearch: webSearch || (async input => { searches.push(input); return { answer: '', sources: [], checkedAt: new Date(NOW).toISOString() }; }),
    fetchImpl: async (_url, init) => { const body = JSON.parse(init.body); sent.push(body); return respond(body, sent.length); } });
  return { assistant, sent, searches };
}
const ask = (assistant, message, { currentPath = '/', locale = 'zh-Hans', searchMode = 'site', member = false } = {}) => assistant.run({ message, locale, currentPath,
  pageContext: page(currentPath, locale), searchMode, webAccess: { allowed: member } });

// ---------------------------------------------------------------- notices

test('notices and banners exist in all three locales, name no amount, and reset at Pacific midnight', () => {
  for (const kind of ['ai_daily_budget', 'ai_paused', 'ai_budget_reduced']) {
    const banners = noticeBanners(kind);
    assert.deepEqual(Object.keys(banners), LOCALES);
    for (const locale of LOCALES) {
      assert.equal(budgetNotice(kind, locale).text, banners[locale]);
      assert.doesNotMatch(banners[locale], /\$|\d+\s*(?:美元|USD)/, 'readers never see dollar amounts');
    }
    assert.doesNotMatch(banners.en, /[一-鿿]/, 'the English banner has no CJK');
  }
  assert.match(noticeBanners('ai_daily_budget')['zh-Hans'], /今日 AI 名额已满/);
  assert.match(noticeBanners('ai_paused')['zh-Hans'], /^AI 助手暂停，以下为站内资料/);
  assert.equal(budgetNotice('unknown', 'en'), null);
  // DST (UTC-7) and standard time (UTC-8).
  assert.equal(pacificResetAt('2026-10-08'), RESETS);
  assert.equal(pacificResetAt('2026-11-10'), '2026-11-11T08:00:00.000Z');
  assert.equal(pacificResetAt('2026-11-01'), '2026-11-02T08:00:00.000Z');
  assert.deepEqual(['', undefined, 'on', 'OFF', ' off '].map(value => spendCapsEnforced({ AI_SPEND_CAPS: value })), [true, true, true, false, false]);
});

// ---------------------------------------------------------------- governance: caps at the provider boundary

function response() {
  const res = new EventEmitter();
  res.statusCode = 200; res.writableEnded = false;
  res.status = value => { res.statusCode = value; return res; };
  res.json = body => { res.body = body; res.writableEnded = true; res.emit('finish'); res.emit('close'); return res; };
  return res;
}
/** Run `fn` inside one governed request; resolves to fn's result (or its error). */
function governed(governance, fn, { path = '/api/ai/guide-chat', locale } = {}) {
  const req = new EventEmitter(); req.path = path; req.ip = 'private-ip'; req.body = locale ? { locale } : {};
  const res = response();
  return new Promise((resolve, reject) => {
    governance.middleware(async () => null)(req, res, () => Promise.resolve().then(() => fn(req, res)).then(value => { res.json({ ok: true }); resolve(value); }, error => { res.json({ ok: false }); reject(error); })).catch(reject);
  });
}
const ledgerAt = (models, microUsd, day = TODAY) => models.AiGovernance.rows.push({ id: `ai-usd:${day}`, microUsd, pricedCalls: 1, expiresAt: new Date(NOW + 62 * 86400000).toISOString() },
  { id: `ai-usd:${day.slice(0, 7)}`, microUsd, pricedCalls: 1, expiresAt: new Date(NOW + 400 * 86400000).toISOString() });
const claudeReply = { type: 'message', model: 'claude-sonnet-5-5', role: 'assistant', stop_reason: 'end_turn', content: [{ type: 'text', text: '{}' }], usage: { input_tokens: 1, output_tokens: 1 } };
const webBody = JSON.stringify({ model: 'claude-sonnet-5-5', tools: [{ type: 'web_search_20260318', name: 'web_search', max_uses: 2 }], messages: [] });
const plainBody = JSON.stringify({ model: 'claude-sonnet-5-5', messages: [] });

test('hard cap: no provider call is reserved or sent, nothing is claimed, and the 429 is honest in the reader\'s locale', async () => {
  const models = createMemoryModels(); ledgerAt(models, 10_000_000);
  const governance = createAiGovernance({ Model: models.AiGovernance, config: { JWT_SECRET: SECRET }, now: () => NOW });
  let fetched = 0;
  const call = () => fetchAiJson('https://api.anthropic.com/v1/messages', { method: 'POST', body: plainBody }, { fetchImpl: async () => { fetched++; return reply(claudeReply); } });
  await assert.rejects(governed(governance, call), error => error.status === 429 && error.code === 'AI_DAILY_BUDGET' && /今日 AI 名额已满/.test(error.message));
  await assert.rejects(governed(governance, call, { locale: 'en' }), error => error.code === 'AI_DAILY_BUDGET' && /^Today's AI capacity is used up/.test(error.message));
  await assert.rejects(governed(governance, call, { locale: 'zh-Hant' }), error => /今日 AI 名額已滿/.test(error.message));
  // A web-search body past the hard cap gets the day's refusal, not the soft cap's "暂停联网查询".
  await assert.rejects(governed(governance, () => fetchAiJson('https://api.anthropic.com/v1/messages', { method: 'POST', body: webBody }, { fetchImpl: async () => { fetched++; return reply(claudeReply); } })),
    error => error.status === 429 && error.code === 'AI_DAILY_BUDGET');
  // The refusal is kept for the request, for routes that report provider failures generically.
  assert.equal(await governed(governance, async () => { await call().catch(() => {}); return aiRefusal()?.code; }), 'AI_DAILY_BUDGET');
  assert.equal(await governed(governance, async () => aiRefusal()), null, 'a request with no refused call has none');
  assert.equal(fetched, 0);
  assert.equal(models.AiGovernance.rows.find(row => row.id === `ai:${TODAY}`), undefined, 'no quota document: the visitor\'s daily count is untouched');
  // AI_SPEND_CAPS=off: report only, the call goes through.
  const reportOnly = createAiGovernance({ Model: models.AiGovernance, config: { JWT_SECRET: SECRET, AI_SPEND_CAPS: 'off' }, now: () => NOW });
  await governed(reportOnly, call);
  assert.equal(fetched, 1);
  assert.equal((await reportOnly.getSpendState()).level, 'hard');
  assert.equal(await reportOnly.budgetLevel(), 'ok');
});

test('soft cap: web-search requests are refused before they are sent; other calls proceed', async () => {
  const models = createMemoryModels(); ledgerAt(models, 6_500_000);
  const governance = createAiGovernance({ Model: models.AiGovernance, config: { JWT_SECRET: SECRET }, now: () => NOW });
  const bodies = [];
  const fetchImpl = async (_url, init) => { bodies.push(JSON.parse(init.body)); return reply(claudeReply); };
  await governed(governance, () => fetchAiJson('https://api.anthropic.com/v1/messages', { method: 'POST', body: plainBody }, { fetchImpl }));
  await assert.rejects(governed(governance, () => fetchAiJson('https://api.anthropic.com/v1/messages', { method: 'POST', body: webBody }, { fetchImpl })),
    error => error.status === 429 && error.code === 'AI_WEB_BUDGET' && /暂停联网查询/.test(error.message));
  // OpenAI web search tools are recognised the same way.
  await assert.rejects(governed(governance, () => fetchAiJson('https://api.openai.com/v1/responses', { method: 'POST', body: JSON.stringify({ model: 'gpt-5.4-mini', tools: [{ type: 'web_search_preview' }] }) }, { fetchImpl })),
    error => error.code === 'AI_WEB_BUDGET');
  assert.equal(bodies.length, 1); assert.equal(bodies[0].tools, undefined);
  assert.equal(models.AiGovernance.rows.find(row => row.id === `ai:${TODAY}`).count, 1, 'a refused web search claims nothing');
  // Under the soft cap a web search outside a governed request (no context) is not refused here.
  assert.equal(aiExecution(), undefined);
  await assert.doesNotReject(reserveAiCall({ webSearch: true }));
});

test('planner web search: a capped day is refused before the rate limits and quota, as a non-retryable 429 web_daily_limit with no cooldown', async () => {
  const quotaRow = models => models.PostTranslationQuota.rows.find(row => row.id.startsWith('planner-web-search:'));
  const service = (models, config = {}) => {
    const seen = { limits: 0, provider: 0 };
    const { search } = registerPlannerWebSearch({ post() {} }, { Quota: models.PostTranslationQuota, checkRateLimit: () => { seen.limits++; return true; },
      config: { OPENAI_API_KEY: 'fixture-openai-only', ...config }, now: () => NOW,
      // Governed like server.js's injected providers.
      ai: governProviders({ search: async () => { seen.provider++; throw new Error('must not be called'); } }).search });
    return { search, seen };
  };
  for (const [microUsd, code] of [[6_500_000, 'AI_WEB_BUDGET'], [10_000_000, 'AI_DAILY_BUDGET']]) {
    const models = createMemoryModels(); ledgerAt(models, microUsd);
    const governance = createAiGovernance({ Model: models.AiGovernance, config: { JWT_SECRET: SECRET }, now: () => NOW });
    const { search, seen } = service(models);
    for (const locale of ['zh-Hans', 'en']) {
      const error = await governed(governance, () => search({ query: 'Berkeley library card', locale }, 'private-ip')).catch(failure => failure);
      assert.equal(error.code, code); assert.equal(error.status, 429);
      const safe = normalizeWebSearchError(error);
      assert.equal(safe.code, 'web_daily_limit'); assert.equal(safe.status, 429); assert.equal(WEB_SEARCH_FAILURES[safe.code].retryable, false);
    }
    assert.deepEqual(seen, { limits: 0, provider: 0 }, 'no rate-limit count and no provider call');
    assert.equal(quotaRow(models), undefined, 'the route\'s daily web quota is untouched');
    assert.equal(models.AiGovernance.rows.find(row => row.id === `ai:${TODAY}`), undefined, 'the visitor\'s AI count is untouched');
  }
  // A refusal inside the provider call (the visitor's AI count is used up) is the same
  // honest 429, and it does not put the query on the 30 s failure cooldown.
  const models = createMemoryModels();
  const governance = createAiGovernance({ Model: models.AiGovernance, config: { JWT_SECRET: SECRET, AI_GUEST_DAILY_LIMIT: '1' }, now: () => NOW });
  await governed(governance, () => reserveAiCall());
  const { search, seen } = service(models);
  for (let attempt = 0; attempt < 2; attempt++) {
    await assert.rejects(governed(governance, () => search({ query: 'Berkeley library card', locale: 'en' }, 'private-ip')),
      error => error.code === 'web_daily_limit' && error.status === 429);
  }
  assert.equal(seen.provider, 0);
  for (const code of ['AI_WEB_BUDGET', 'AI_DAILY_BUDGET', 'AI_DAILY_LIMIT']) assert.equal(normalizeWebSearchError({ code, message: 'private detail' }).code, 'web_daily_limit');
  assert.equal(normalizeWebSearchError({ code: 'AI_CALL_LIMIT' }).code, 'web_provider_unavailable', 'other refusals keep their mapping');
});

test('outing draft: a capped Claude call is the honest 429, not the generic 503 "please try again"', async () => {
  const input = { intent: '周六下午在 Berkeley 散步，三个人', answers: [], locale: 'zh-Hans', today: TODAY, now: NOW };
  const config = { BAYBAY_AI_PROVIDER: 'anthropic', ANTHROPIC_API_KEY: 'fixture-anthropic-only' };
  let fetched = 0;
  const fetchImpl = async () => { fetched++; return reply(claudeReply); };
  const models = createMemoryModels(); ledgerAt(models, 10_000_000);
  const governance = createAiGovernance({ Model: models.AiGovernance, config: { JWT_SECRET: SECRET }, now: () => NOW });
  await assert.rejects(governed(governance, () => createOutingDraft(input, { config, fetchImpl }), { path: '/api/ai/outing-draft', locale: 'en' }),
    error => error.status === 429 && error.code === 'AI_DAILY_BUDGET' && /^Today's AI capacity is used up/.test(error.message));
  // The visitor's AI count used up: the same honest 429.
  const counted = createMemoryModels();
  const limited = createAiGovernance({ Model: counted.AiGovernance, config: { JWT_SECRET: SECRET, AI_GUEST_DAILY_LIMIT: '1' }, now: () => NOW });
  await governed(limited, () => reserveAiCall());
  await assert.rejects(governed(limited, () => createOutingDraft(input, { config, fetchImpl }), { path: '/api/ai/outing-draft' }),
    error => error.status === 429 && error.code === 'AI_DAILY_LIMIT');
  assert.equal(fetched, 0);
  // Any other provider failure keeps the generic 503.
  const open = createAiGovernance({ Model: createMemoryModels().AiGovernance, config: { JWT_SECRET: SECRET }, now: () => NOW });
  await assert.rejects(governed(open, () => createOutingDraft(input, { config, fetchImpl: async () => { fetched++; return { ok: false, status: 500, json: async () => ({}), text: async () => '' }; } }), { path: '/api/ai/outing-draft' }),
    error => error.status === 503 && /could not prepare this draft/.test(error.message));
  assert.equal(fetched, 1);
});

test('the spend level is cached for 30 s, bumped by each priced call, re-read on a new day, and fails open', async () => {
  const models = createMemoryModels(); ledgerAt(models, 5_999_000);
  let now = NOW, reads = 0;
  const original = models.AiGovernance.findOne;
  models.AiGovernance.findOne = query => { reads++; return original(query); };
  const governance = createAiGovernance({ Model: models.AiGovernance, config: { JWT_SECRET: SECRET }, now: () => now });
  assert.equal(await governance.budgetLevel(), 'ok'); assert.equal(reads, 2);
  await Promise.all([governance.budgetLevel(), governance.spendLevel(), governance.budgetLevel()]);
  assert.equal(reads, 2, 'one read per 30 s per instance');
  await governance.recordSpend({ priced: true, microUsd: 2000 });
  assert.equal(await governance.budgetLevel(), 'soft', 'a priced call moves the cached level at once'); assert.equal(reads, 2);
  await governance.recordSpend({ priced: true, microUsd: 4_000_000 });
  assert.equal(await governance.budgetLevel(), 'hard');
  now += 31000; assert.equal(await governance.budgetLevel(), 'hard'); assert.equal(reads, 4);
  // The ledger becomes unreadable: the same day keeps the last known state...
  models.AiGovernance.findOne = () => { throw new Error('private storage fault'); };
  now += 31000; assert.equal(await governance.budgetLevel(), 'hard');
  // ...and a new Pacific day with no readable ledger is not capped.
  now = Date.parse('2026-10-09T08:00:00Z');
  assert.equal(await governance.budgetLevel(), 'ok');
  assert.equal(await governance.spendLevel(), null);
});

test('a slow ledger read is waited on for at most 1.5 s, and still refreshes the cache when it lands', async () => {
  const models = createMemoryModels(); ledgerAt(models, 6_500_000);
  const original = models.AiGovernance.findOne;
  let release;
  const gate = new Promise(resolve => { release = resolve; });
  models.AiGovernance.findOne = query => ({ lean: () => gate.then(() => original(query).lean()) });
  const governance = createAiGovernance({ Model: models.AiGovernance, config: { JWT_SECRET: SECRET }, now: () => NOW });
  const started = Date.now();
  assert.equal(await governance.budgetLevel(), 'ok', 'no state yet: not capped');
  const waited = Date.now() - started;
  assert.ok(waited >= 1400 && waited < 3000, `waited ${waited} ms`);
  release(); await new Promise(resolve => setTimeout(resolve, 10));
  assert.equal(await governance.budgetLevel(), 'soft', 'the late read filled the cache');
});

test('12 concurrent governed AI requests by default (was 6); the 13th gets AI_CONCURRENCY_LIMIT', async () => {
  const models = createMemoryModels();
  const governance = createAiGovernance({ Model: models.AiGovernance, config: { JWT_SECRET: SECRET }, now: () => NOW });
  const open = [];
  for (let index = 0; index < 13; index++) {
    const req = new EventEmitter(); req.path = '/api/ai/guide-chat'; req.ip = 'private-ip'; req.body = {};
    const res = response();
    let entered = false;
    await governance.middleware(async () => null)(req, res, () => { entered = true; });
    open.push({ res, entered });
  }
  assert.equal(open.filter(row => row.entered).length, 12);
  assert.equal(open[12].res.statusCode, 429); assert.equal(open[12].res.body.code, 'AI_CONCURRENCY_LIMIT');
  const configured = createAiGovernance({ Model: models.AiGovernance, config: { JWT_SECRET: SECRET, AI_CONCURRENCY_LIMIT: '2' }, now: () => NOW });
  let admitted = 0;
  for (let index = 0; index < 3; index++) { const req = new EventEmitter(); req.path = '/api/ai/guide-chat'; req.body = {}; await configured.middleware(async () => null)(req, response(), () => { admitted++; }); }
  assert.equal(admitted, 2);
});

// ---------------------------------------------------------------- the assistant: pause, caps and the run limit

const emergency = '我妈晕倒了叫不醒';

test('hard cap: no model call, a site answer with the 今日 AI 名额已满 notice; the emergency card is unchanged', async () => {
  const { assistant, sent } = assistantWith({ budget: async () => spendState('hard') });
  const result = await ask(assistant, '蓝天使这周末飞吗');
  assert.equal(sent.length, 0);
  assert.equal(result.ok, true); assert.equal(result.degraded, true);
  assert.deepEqual(result.notice, { kind: 'ai_daily_budget', text: noticeBanners('ai_daily_budget')['zh-Hans'], resumesAt: RESETS });
  assert.ok(result.research.warnings.includes('ai_daily_budget'));
  assert.equal(result.engine, 'v2'); assert.deepEqual(result.research.modelResponses, []);
  for (const locale of ['en', 'zh-Hant']) assert.equal((await ask(assistant, 'Fleet Week this weekend?', { locale })).notice.text, noticeBanners('ai_daily_budget')[locale]);
  const card = await ask(assistant, emergency);
  assert.equal(card.safetyRoute, 'emergency'); assert.match(card.answer, /^请立即拨打 911/);
  assert.equal(card.notice, undefined); assert.equal(sent.length, 0);
});

test('paused (BAYBAY_PAUSED, ANTHROPIC_USE_UNTIL passed, missing key): no model call and the AI 助手暂停 notice', async () => {
  for (const config of [{ BAYBAY_PAUSED: 'true' }, { BAYBAY_PAUSED: ' TRUE ' }, { ANTHROPIC_USE_UNTIL: '2026-10-01T00:00:00Z' }, { ANTHROPIC_API_KEY: '' }]) {
    const { assistant, sent } = assistantWith({ config, budget: async () => spendState('ok') });
    const result = await ask(assistant, '蓝天使这周末飞吗');
    assert.equal(sent.length, 0, JSON.stringify(config));
    assert.deepEqual(result.notice, { kind: 'ai_paused', text: 'AI 助手暂停，以下为站内资料。' }, JSON.stringify(config));
    assert.ok(result.research.warnings.includes('ai_paused'));
    assert.equal((await ask(assistant, emergency)).safetyRoute, 'emergency');
  }
  // BAYBAY_PAUSED=false (or anything else) is not a pause.
  const { assistant, sent } = assistantWith({ config: { BAYBAY_PAUSED: 'false' } });
  assert.equal((await ask(assistant, '蓝天使这周末飞吗')).notice, undefined); assert.equal(sent.length, 1);
});

test('soft cap: a member\'s Smart question is answered from site evidence on the fast path, with no web search and an honest notice', async () => {
  const { assistant, sent, searches } = assistantWith({ budget: async () => spendState('soft') });
  const result = await ask(assistant, '这周末旧金山有什么最新的免费活动？', { searchMode: 'smart', member: true });
  assert.equal(searches.length, 0, 'no web search under the soft cap');
  assert.equal(sent.length, 1); assert.equal(result.route.path, 'fast');
  assert.deepEqual(result.notice, { kind: 'ai_budget_reduced', text: noticeBanners('ai_budget_reduced')['zh-Hans'], resumesAt: RESETS });
  assert.equal(result.retrieval.requestedMode, 'site');
  assert.ok(!(sent[0].tools || []).length, 'the fast call carries no tools');
  // The same question without a cap goes to the member's live-web agent run.
  const normal = assistantWith({ budget: async () => spendState('ok') });
  const live = await ask(normal.assistant, '这周末旧金山有什么最新的免费活动？', { searchMode: 'smart', member: true });
  assert.equal(live.route.path, 'agent'); assert.equal(live.notice, undefined); assert.ok(normal.searches.length >= 1);
});

test('soft cap: a day plan is one fast call (route reason budget_fast_only); a guest gets no notice', async () => {
  const { assistant, sent } = assistantWith({ budget: async () => spendState('soft') });
  const plan = await ask(assistant, '周六带孩子在 Berkeley 安排一天行程，不开车');
  assert.equal(sent.length, 1); assert.deepEqual(plan.route, { path: 'fast', reason: 'budget_fast_only' });
  assert.ok(plan.research.warnings.includes('budget_fast_only'));
  assert.equal(plan.notice, undefined, 'a guest was already site-only');
  const normal = assistantWith({});
  const agentPlan = await ask(normal.assistant, '周六带孩子在 Berkeley 安排一天行程，不开车');
  assert.equal(agentPlan.route.path, 'agent');
});

test('soft cap: an edit of the plan in scope (换掉第二站) keeps the agent path with the previous plan and site-only tools', async () => {
  let level = 'ok';
  const { assistant, sent, searches } = assistantWith({ budget: async () => spendState(level) });
  const first = await ask(assistant, '周六带孩子在 Berkeley 安排一天行程，三站，不开车');
  assert.equal(first.route.path, 'agent'); assert.equal(first.assistantPlan.stops.length, 3);
  level = 'soft'; sent.length = 0;
  const edit = await assistant.run({ message: '换掉第二站', locale: 'zh-Hans', currentPath: '/', pageContext: page('/'), searchMode: 'smart', webAccess: { allowed: true }, sessionToken: first.assistantSessionToken });
  assert.equal(edit.route.path, 'agent'); assert.ok(!edit.research.warnings.includes('budget_fast_only'));
  assert.equal(edit.notice.kind, 'ai_budget_reduced'); assert.equal(edit.retrieval.requestedMode, 'site');
  const context = JSON.parse(sent[0].messages[0].content[0].text);
  assert.deepEqual(context.planEdit && { kind: context.planEdit.kind, index: context.planEdit.index }, { kind: 'replace', index: 1 });
  assert.ok(context.previousPlan?.selectedIds?.length === 3, 'the agent gets the previous plan');
  for (const body of sent) assert.deepEqual((body.tools || []).map(tool => tool.name).sort(), ['create_plan', 'search_site'], 'site-only tools, no web search');
  assert.equal(searches.length, 0);
  // Without a plan in scope the same words stay on the one fast call.
  const fresh = await ask(assistant, '换掉第二站');
  assert.equal(fresh.route.path, 'fast');
});

test('the BayBay daily run limit defaults to 1000 and, when reached, gives the same daily notice', async () => {
  const filters = [];
  const full = { updateOne: async () => ({}), findOneAndUpdate: async filter => { filters.push(filter); return null; } };
  const { assistant, sent } = assistantWith({ config: { BAYBAY_DAILY_RUN_LIMIT: undefined }, Quota: full });
  const result = await ask(assistant, '蓝天使这周末飞吗');
  assert.deepEqual(filters[0].count, { $lt: 1000 });
  assert.equal(sent.length, 0);
  assert.equal(result.notice.kind, 'ai_daily_budget');
  assert.ok(result.research.warnings.includes('baybay_run_limit'));
  // A quota store that cannot answer is not reported as a used-up day.
  const broken = assistantWith({ Quota: { updateOne: async () => { throw new Error('private storage fault'); }, findOneAndUpdate: async () => null } });
  const unknown = await ask(broken.assistant, '蓝天使这周末飞吗');
  assert.equal(unknown.notice, undefined); assert.ok(unknown.research.warnings.includes('quota_unavailable'));
});

test('caps that are off or unreadable never block, and the budget hook does not change a normal request or result', async () => {
  const digest = value => crypto.createHash('sha256').update(JSON.stringify(value)).digest('hex');
  const strip = result => ({ ...result, assistantSessionToken: undefined, research: { ...result.research, elapsedMs: undefined, timings: undefined, modelResponses: result.research.modelResponses.map(row => ({ ...row, elapsedMs: undefined })) } });
  const runs = [];
  for (const budget of [undefined, async () => spendState('ok'), async () => spendState('hard', { caps: { enforced: false } }), async () => { throw new Error('ledger down'); }, () => null]) {
    for (const engine of ['v2', 'v1']) {
      const { assistant, sent } = assistantWith({ config: { BAYBAY_ENGINE: engine }, budget, respond: body => reply(body.output_config?.format ? fastMessage() : { ...fastMessage(), content: [{ type: 'text', text: JSON.stringify({ answer: '会飞。', candidateIds: [], followups: [], coverage: [] }) }] }) });
      const result = await ask(assistant, '蓝天使这周末飞吗');
      runs.push({ engine, sent: digest(sent), result: digest(strip(result)), notice: result.notice });
    }
  }
  for (const engine of ['v2', 'v1']) {
    const rows = runs.filter(row => row.engine === engine);
    assert.ok(rows.every(row => row.sent === rows[0].sent && row.result === rows[0].result && row.notice === undefined), engine);
  }
});

test('status(): the capabilities contract for the pause banner, the reduced mode and guests', async () => {
  const ok = await assistantWith({ budget: async () => spendState('ok') }).assistant.status();
  assert.equal(ok.enabled, true); assert.equal(ok.engine, 'v2'); assert.equal(ok.pause, null); assert.equal(ok.reduced, null);
  assert.deepEqual(ok.tools, ['site', 'web', 'sources', 'weather', 'plans']);
  const guest = await assistantWith({ budget: async () => spendState('ok') }).assistant.status({ webAccess: { allowed: false } });
  assert.deepEqual(guest.tools, ['site', 'plans']); assert.equal(guest.routeEstimates, false); assert.equal(guest.enabled, true);
  const soft = await assistantWith({ budget: async () => spendState('soft') }).assistant.status();
  assert.equal(soft.enabled, true); assert.deepEqual(soft.tools, ['site', 'plans']); assert.equal(soft.pause, null);
  assert.deepEqual(soft.reduced, { reason: 'daily_budget_soft', kind: 'ai_budget_reduced', banner: noticeBanners('ai_budget_reduced'), resumesAt: RESETS });
  const hard = await assistantWith({ budget: async () => spendState('hard') }).assistant.status();
  assert.equal(hard.enabled, false); assert.deepEqual(hard.tools, ['site']);
  assert.deepEqual(hard.pause, { reason: 'daily_budget', kind: 'ai_daily_budget', banner: noticeBanners('ai_daily_budget'), resumesAt: RESETS,
    actions: [{ id: 'call-911', label: '911', href: 'tel:911' }, { id: 'call-211', label: '211', href: 'tel:211' }] });
  assert.equal(hard.pause.actions[0].href, 'tel:911', 'the 911 action comes first');
  const reasons = [];
  for (const config of [{ BAYBAY_PAUSED: 'true' }, { ANTHROPIC_USE_UNTIL: '2026-10-01T00:00:00Z' }, { BAYBAY_AI_PROVIDER: 'unknown' }]) {
    const status = await assistantWith({ config }).assistant.status();
    assert.equal(status.enabled, false); assert.equal(status.pause.kind, 'ai_paused'); assert.equal(status.pause.resumesAt, undefined);
    reasons.push(status.pause.reason);
  }
  assert.deepEqual(reasons, ['paused', 'provider_unavailable', 'provider_unavailable']);
  // BAYBAY_AGENT_ENABLED=false is not a pause: guide-chat answers on its legacy model path,
  // so there is no "AI 助手暂停" banner; only the $ caps, which govern that path too, show.
  const disabled = { BAYBAY_AGENT_ENABLED: 'false', BAYBAY_PAUSED: 'true' };
  const off = await assistantWith({ config: disabled, budget: async () => spendState('ok') }).assistant.status();
  assert.equal(off.enabled, false); assert.equal(off.pause, null); assert.equal(off.reduced, null);
  assert.equal((await assistantWith({ config: disabled, budget: async () => spendState('soft') }).assistant.status()).reduced.kind, 'ai_budget_reduced');
  const offHard = await assistantWith({ config: disabled, budget: async () => spendState('hard') }).assistant.status();
  assert.equal(offHard.pause.reason, 'daily_budget'); assert.equal(offHard.pause.kind, 'ai_daily_budget');
  // capabilities() (guide-chat's routing switch) is unchanged by the budget.
  assert.equal(assistantWith({ budget: async () => spendState('hard') }).assistant.capabilities().enabled, true);
  // Engine reporting follows the effective engine.
  assert.equal((await assistantWith({ config: { BAYBAY_ENGINE: 'v1' } }).assistant.status()).engine, 'v1');
});

// ---------------------------------------------------------------- server.js

test('server: past the hard cap the capabilities pause, BayBay answers without a model, the 911 card is unchanged and helpers get an honest 429', async t => {
  const { createApplication } = require('../server');
  const models = createMemoryModels({ User: [{ id: 'admin', role: 'admin', accountStatus: 'active' }, { id: 'member', role: 'user', accountStatus: 'active', email: 'member@example.test' }],
    Post: [hanPost('han-post', 'member')] });
  ledgerAt(models, 10_000_000);
  const calls = { baybay: 0, postAssist: 0, outing: 0, web: 0, translation: 0, extract: 0 };
  const app = createApplication({ config: { NODE_ENV: 'test', JWT_SECRET: SECRET, BAYBAY_AI_PROVIDER: 'anthropic', ANTHROPIC_API_KEY: 'fixture-anthropic-only' },
    models, plannerNow: () => NOW,
    ai: { baybay: async () => { calls.baybay++; throw new Error('must not be called'); }, postAssist: async () => { calls.postAssist++; return {}; },
      outingDraft: async () => { calls.outing++; return {}; }, plannerWebSearch: async () => { calls.web++; return {}; },
      postTranslation: async () => { calls.translation++; return {}; }, eventExtract: async () => { calls.extract++; return {}; } } });
  await new Promise(resolve => app.server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise(resolve => app.io.close(resolve)));
  const url = path => `http://127.0.0.1:${app.server.address().port}/api${path}`;
  const auth = id => ({ Authorization: `Bearer ${jwt.sign({ id }, SECRET, { expiresIn: '1h' })}` });
  const post = (path, body, headers = {}) => fetch(url(path), { method: 'POST', headers: { 'Content-Type': 'application/json', ...headers }, body: JSON.stringify(body) });

  const capabilities = await (await fetch(url('/ai/baybay-capabilities'))).json();
  assert.equal(capabilities.enabled, false); assert.equal(capabilities.engine, 'v2');
  assert.equal(capabilities.pause.reason, 'daily_budget'); assert.equal(capabilities.pause.resumesAt, RESETS);
  assert.match(capabilities.pause.banner['zh-Hans'], /今日 AI 名额已满/); assert.equal(capabilities.webRequiresAuth, true);
  assert.doesNotMatch(JSON.stringify(capabilities), /\$|microUsd|dayUsd/, 'no spend figures in the public endpoint');

  const answer = await (await post('/ai/guide-chat', { message: '蓝天使这周末飞吗', assistantVersion: 2, searchMode: 'site' })).json();
  assert.equal(answer.ok, true); assert.equal(answer.degraded, true); assert.equal(answer.notice.kind, 'ai_daily_budget');
  const card = await (await post('/ai/guide-chat', { message: emergency, assistantVersion: 2, searchMode: 'site' })).json();
  assert.equal(card.safetyRoute, 'emergency'); assert.match(card.answer, /^请立即拨打 911/);
  assert.equal(calls.baybay, 0);

  const draft = await post('/ai/post-assist', { intent: '想在 Fremont 找人帮忙搬家，周六上午', language: 'en' }, auth('member'));
  assert.equal(draft.status, 429);
  const body = await draft.json();
  assert.equal(body.code, 'AI_DAILY_BUDGET'); assert.match(body.error, /今日 AI 名额已满/); assert.equal(calls.postAssist, 0);

  // Outing drafts and the planner web search: the honest 429 before their own quotas are spent.
  const outing = await post('/ai/outing-draft', { intent: '周六下午在 Berkeley 散步，三个人', locale: 'en' }, auth('member'));
  assert.equal(outing.status, 429);
  assert.match((await outing.json()).error, /^Today's AI capacity is used up/);
  const web = await post('/planner/web-search', { query: 'Berkeley library card', locale: 'en' }, auth('member'));
  assert.equal(web.status, 429);
  const webBody = await web.json();
  assert.equal(webBody.code, 'web_daily_limit'); assert.equal(webBody.retryable, false);
  // Post translation and event-screenshot AI: the same honest 429, before their own quotas.
  const translation = await post('/posts/han-post/translation', { target: 'en' });
  assert.equal(translation.status, 429);
  assert.match((await translation.json()).error, /^Today's AI capacity is used up/);
  const extract = await post('/ai/event-extract', { image: PNG, locale: 'zh-Hant' });
  assert.equal(extract.status, 429);
  assert.match((await extract.json()).error, /今日 AI 名額已滿/);
  assert.deepEqual([calls.outing, calls.web, calls.translation, calls.extract], [0, 0, 0, 0]);
  assert.deepEqual(models.PostTranslationQuota.rows.map(row => row.id), [], 'no draft, web, translation or local AI quota spent');
  assert.equal(models.PostTranslation.rows.length, 0, 'no translation failure is cached for the post');

  const metrics = await (await fetch(url('/admin/ai-metrics'), { headers: auth('admin') })).json();
  assert.equal(metrics.spend.level, 'hard'); assert.equal(metrics.spend.dayUsd, 10); assert.equal(metrics.spend.caps.enforced, true);
  assert.equal(metrics.spend.resetAt, RESETS);
});

test('server: a translation whose provider call is refused for the day is an honest 429 and caches no failure for the post', async t => {
  const { createApplication } = require('../server');
  const models = createMemoryModels({ User: [{ id: 'owner', role: 'user', accountStatus: 'active' }], Post: [hanPost('first', 'owner'), hanPost('second', 'owner')] });
  let translated = 0;
  // One governed AI call per guest per day: the second post's provider call is refused (AI_DAILY_LIMIT).
  const app = createApplication({ config: { NODE_ENV: 'test', JWT_SECRET: SECRET, AI_GUEST_DAILY_LIMIT: '1' }, models, plannerNow: () => NOW,
    ai: { postTranslation: async () => { translated++; return { title: 'Room for rent in Fremont', description: 'Viewings on weekends.', budget: '', timeInfo: '' }; } } });
  await new Promise(resolve => app.server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise(resolve => app.io.close(resolve)));
  const translate = id => fetch(`http://127.0.0.1:${app.server.address().port}/api/posts/${id}/translation`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ target: 'en' }) });
  assert.equal((await translate('first')).status, 200);
  for (let attempt = 0; attempt < 2; attempt++) {
    const refused = await translate('second');
    assert.equal(refused.status, 429, 'not the generic 503 "unavailable"');
    assert.match((await refused.json()).error, /今日 AI 额度已用完/);
  }
  assert.equal(translated, 1);
  assert.ok(!models.PostTranslation.rows.some(row => row.kind === 'failure'), 'no negative cache for the refused post');
});

test('server: below the caps the capabilities report v2 with no pause; guests are offered site and plan tools', async t => {
  const { createApplication } = require('../server');
  const app = createApplication({ config: { NODE_ENV: 'test', JWT_SECRET: SECRET, BAYBAY_AI_PROVIDER: 'anthropic', ANTHROPIC_API_KEY: 'fixture-anthropic-only' }, models: createMemoryModels(), plannerNow: () => NOW });
  await new Promise(resolve => app.server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise(resolve => app.io.close(resolve)));
  const capabilities = await (await fetch(`http://127.0.0.1:${app.server.address().port}/api/ai/baybay-capabilities`)).json();
  assert.equal(capabilities.enabled, true); assert.equal(capabilities.engine, 'v2'); assert.equal(capabilities.pause, null); assert.equal(capabilities.reduced, null);
  assert.deepEqual(capabilities.tools, ['site', 'plans']); assert.equal(capabilities.webAccess.allowed, false);
});
