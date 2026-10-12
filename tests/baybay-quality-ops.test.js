// API-BB-QUALITY operations: quota UX (captain item a, BBENG-04), the 10/30 cutoff
// warning (BBENG-05), failure reasons and route/draft/status metrics (item f, BBENG-06/08),
// a streamed retry after a failed first call (BBL-02). $0: local fixtures only.
const test = require('node:test');
const assert = require('node:assert/strict');
const { createBayBayAssistant } = require('../lib/baybayAgent');
const { loadPlannerCatalog } = require('../lib/planner');
const { createPublicContext } = require('../lib/publicContext');
const { budgetError, scheduledPause, aiUntilOf } = require('../lib/aiBudget');
const { createAiRuntimeMetrics, eventLoopMonitor } = require('../lib/aiRuntimeMetrics');
const { failureReason } = require('../lib/baybayQuality');
const { createMemoryModels } = require('./support/memory-models');

const guides = require('../data/guide-catalog.json');
const catalog = loadPlannerCatalog();
const publicContext = createPublicContext({ guideCatalog: guides });
const base = { BAYBAY_AI_PROVIDER: 'anthropic', ANTHROPIC_API_KEY: 'fixture-anthropic-only', BAYBAY_STATE_SECRET: 'private-test-task-secret-0123456789', BAYBAY_DAILY_RUN_LIMIT: '1000', BAYBAY_ENGINE: 'v2' };
const quota = () => ({ updateOne: async () => ({}), findOneAndUpdate: async () => ({ count: 1 }) });
const reply = answer => ({ type: 'message', id: 'msg-fixture', model: 'claude-sonnet-5-5', role: 'assistant', stop_reason: 'end_turn',
  content: [{ type: 'text', text: JSON.stringify({ lead: '蓝天使周六下午飞。', points: [{ text: '在 Marina Green 免费看。', cardIds: [] }], candidateIds: [], followups: [], coverage: [], gap: '', ...answer }) }], usage: { input_tokens: 40, output_tokens: 60 } });
function sse(message) {
  const event = (name, data) => `event: ${name}\ndata: ${JSON.stringify(data)}\n\n`;
  const text = message.content[0].text;
  let body = event('message_start', { type: 'message_start', message: { ...message, content: [], stop_reason: null } }) + event('content_block_start', { type: 'content_block_start', index: 0, content_block: { type: 'text', text: '' } });
  for (let index = 0; index < text.length; index += 5) body += event('content_block_delta', { type: 'content_block_delta', index: 0, delta: { type: 'text_delta', text: text.slice(index, index + 5) } });
  body += event('content_block_stop', { type: 'content_block_stop', index: 0 }) + event('message_delta', { type: 'message_delta', delta: { stop_reason: 'end_turn' }, usage: { output_tokens: 60 } }) + event('message_stop', { type: 'message_stop' });
  return new Response(body, { status: 200, headers: { 'content-type': 'text/event-stream' } });
}
const assistant = (fetchImpl, config = {}, now = () => Date.parse('2026-10-12T16:00:00Z')) => createBayBayAssistant({ config: { ...base, ...config }, guideCatalog: guides, catalog, now, isTest: false, Quota: quota(), fetchImpl });
const ask = (bot, message, locale = 'zh-Hans', drafts = []) => bot.run({ message, locale, currentPath: '/', pageContext: publicContext.resolve({ context: { currentPath: '/' }, currentPath: '/', today: '2026-10-12', locale }),
  searchMode: 'site', webAccess: { allowed: false }, onDraft: event => drafts.push(event) });

test('governance refusals in the reader locale: daily count, concurrency and an unreadable quota store (503)', () => {
  assert.match(budgetError('AI_DAILY_LIMIT', 'zh-Hans').message, /今日 AI 额度已用完/);
  assert.match(budgetError('AI_DAILY_LIMIT', 'zh-Hant').message, /今日 AI 額度已用完/);
  assert.match(budgetError('AI_DAILY_LIMIT', 'en').message, /used today's AI answers/);
  assert.equal(budgetError('AI_CONCURRENCY_LIMIT', 'zh-Hans').message, 'BayBay 正忙，请稍后再试。');
  assert.equal(budgetError('AI_CONCURRENCY_LIMIT', 'en').status, 429);
  const unreadable = budgetError('AI_QUOTA_UNAVAILABLE', 'zh-Hant');
  assert.equal(unreadable.status, 503); assert.match(unreadable.message, /暫時無法確認/);
});

test('a BayBay call refused by today\'s AI quota is not retried and returns the ai_daily_budget notice', async () => {
  let calls = 0;
  const bot = assistant(async () => { calls++; throw Object.assign(new Error('今日 AI 额度已用完'), { status: 429, code: 'AI_DAILY_LIMIT' }); });
  const result = await ask(bot, '蓝天使这周末飞吗');
  assert.equal(calls, 1, 'no retry after a quota refusal');
  assert.equal(result.notice?.kind, 'ai_daily_budget'); assert.match(result.notice.text, /今日 AI 名额已满/);
  assert.ok(result.research.warnings.includes('ai_daily_limit'));
  assert.deepEqual(result.research.modelResponses[0].failure, { kind: 'quota', status: 429, code: 'AI_DAILY_LIMIT' });
  const english = await ask(assistant(async () => { throw Object.assign(new Error('x'), { status: 503, code: 'AI_QUOTA_UNAVAILABLE' }); }), 'Is the Blue Angels show on this weekend?', 'en');
  assert.equal(english.notice?.kind, 'ai_paused'); assert.match(english.notice.text, /paused/);
});

test('a failed first call records why (HTTP 529), pauses briefly, and the retry streams the lead when nothing was drafted', async () => {
  let calls = 0;
  const bot = assistant(async (_url, init) => {
    calls++;
    if (calls === 1) return new Response(JSON.stringify({ type: 'error', error: { type: 'overloaded_error', message: 'Overloaded' } }), { status: 529 });
    return JSON.parse(init.body).stream ? sse(reply({})) : new Response(JSON.stringify(reply({})), { status: 200 });
  });
  const drafts = [];
  const started = Date.now();
  const result = await ask(bot, '这周六旧金山有什么适合全家的活动？', 'zh-Hans', drafts);
  assert.equal(calls, 2);
  assert.ok(Date.now() - started >= 550, 'a short pause before retrying an overloaded provider');
  assert.deepEqual(result.research.modelResponses[0].failure, { kind: 'http', status: 529 });
  assert.ok(result.research.warnings.includes('fast_retry_call_failed'));
  assert.ok(drafts.length >= 1 && drafts[0].field === 'lead' && drafts[0].seq === 1, 'the retry streamed its lead');
  assert.equal(result.corrected, false);
});

test('failure reasons are a fixed vocabulary, never provider text', () => {
  assert.deepEqual(failureReason(new Error('AI provider HTTP 429')), { kind: 'http', status: 429 });
  assert.deepEqual(failureReason(Object.assign(new Error('AI request timed out'), { code: 'AI_PROVIDER_TIMEOUT' })), { kind: 'timeout', code: 'AI_PROVIDER_TIMEOUT' });
  assert.deepEqual(failureReason(new Error('private provider message about a user')), { kind: 'other' });
});

test('BBENG-05: capabilities carry aiUntil, and pauseScheduled with Pacific-time banners in the last 7 days', async () => {
  const config = { ANTHROPIC_USE_UNTIL: '2026-10-30T00:00:00Z' };
  assert.equal(aiUntilOf(config), '2026-10-30T00:00:00.000Z'); assert.equal(aiUntilOf({ ANTHROPIC_USE_UNTIL: 'soon' }), null);
  const early = await assistant(async () => reply({}), config).status({ webAccess: { allowed: false } });
  assert.equal(early.aiUntil, '2026-10-30T00:00:00.000Z'); assert.equal(early.pauseScheduled, undefined); assert.equal(early.pause, null);
  const late = await assistant(async () => reply({}), config, () => Date.parse('2026-10-25T16:00:00Z')).status({ webAccess: { allowed: false } });
  assert.equal(late.pauseScheduled.kind, 'ai_pause_scheduled');
  assert.equal(late.pauseScheduled.banner['zh-Hans'], 'AI 助手预计 10月29日（周四）17:00 起暂停；之后仍可查看站内资料，紧急情况请直接拨打 911。');
  assert.match(late.pauseScheduled.banner.en, /Thu, Oct 29, 5:00 PM PT/);
  // After the cutoff (provider availability reads the real clock): the honest pause, no schedule.
  const after = await assistant(async () => reply({}), { ANTHROPIC_USE_UNTIL: '2026-10-01T00:00:00Z' }).status({ webAccess: { allowed: false } });
  assert.equal(after.pause.reason, 'provider_unavailable'); assert.equal(after.pause.kind, 'ai_paused'); assert.equal(after.pauseScheduled, undefined);
  assert.equal(after.aiUntil, '2026-10-01T00:00:00.000Z');
  assert.equal(scheduledPause({}, Date.now()), null);
  // No cutoff configured: nothing new in the contract.
  const plain = await assistant(async () => reply({})).status({ webAccess: { allowed: false } });
  assert.equal(plain.aiUntil, undefined); assert.equal(plain.pauseScheduled, undefined);
});

test('ai-metrics: route, drafts, corrections, retries and provider statuses are fixed counters; the event-loop report is numeric', async () => {
  const models = createMemoryModels();
  const metrics = createAiRuntimeMetrics({ Model: models.AiRuntimeMetric, now: () => Date.parse('2026-10-12T16:00:00Z') });
  const req = metrics.startRequest('guide_chat');
  req.providerStarted('claude-sonnet-5-5')({ outcome: 'error', durationMs: 900, status: 529 });
  req.providerStarted('claude-sonnet-5-5')({ outcome: 'completed', durationMs: 3000, usage: { input_tokens: 10, output_tokens: 20 } });
  req.outcome({ path: 'fast', reason: 'site_answer', drafted: true, corrected: true, warnings: ['model_unavailable', 'fast_retry_call_failed'] });
  req.response({ ok: true }); req.end();
  const pro = metrics.startRequest('guide_chat');
  pro.outcome({ path: 'fast', reason: 'professional_topic' }); pro.response({ ok: true }); pro.end();
  const clarify = metrics.startRequest('guide_chat');
  clarify.outcome({ path: 'clarification' }); clarify.response({ ok: true }); clarify.end();
  await metrics.flush();
  const total = key => models.AiRuntimeMetric.rows.reduce((sum, row) => sum + (row[key] || 0), 0);
  assert.equal(total('providerStatus529'), 1); assert.equal(total('routeFast'), 1); assert.equal(total('routeProfessional'), 1); assert.equal(total('routeDeterministic'), 1);
  assert.equal(total('draftStreamed'), 1); assert.equal(total('draftCorrected'), 1); assert.equal(total('fastRetry'), 1); assert.equal(total('firstCallFailed'), 1);
  const report = eventLoopMonitor().report();
  assert.ok(Number.isInteger(report.samples) && Number.isInteger(report.sinceMs));
  for (const key of ['p50Ms', 'p99Ms', 'maxMs', 'meanMs']) if (key in report) assert.ok(Number.isInteger(report[key]) || report[key] === null, key);
});
