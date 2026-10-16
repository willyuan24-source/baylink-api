// API-BB-QUALITY stacked on API-HOTFIX: the places where the two lanes meet.
// - SAFETY-2's 911-first floor (HOTFIX) still wins when BB-QUALITY's quota refusal ends the
//   fast call without a retry, and when BB-QUALITY's no-city question would ask instead.
// - BB-QUALITY's follow-up turn rules ride after the user turn, and BBENG-03 (HOTFIX) keeps
//   every request body free of a role:system message before a user turn, on the agent's
//   day-plan follow-up and on its recovery after a 529.
// Every test is offline ($0): Anthropic is a fixture.
const test = require('node:test');
const assert = require('node:assert/strict');
const { createBayBayAssistant } = require('../lib/baybayAgent');
const { loadPlannerCatalog } = require('../lib/planner');
const { createPublicContext } = require('../lib/publicContext');

const NOW = Date.parse('2026-10-12T16:00:00Z'); // Mon 2026-10-12 09:00 PDT
const TODAY = '2026-10-12';
const guides = require('../data/guide-catalog.json');
const catalog = loadPlannerCatalog();
const publicContext = createPublicContext({ guideCatalog: guides });
const base = { BAYBAY_AI_PROVIDER: 'anthropic', ANTHROPIC_API_KEY: 'fixture-anthropic-only', BAYBAY_STATE_SECRET: 'private-test-task-secret-0123456789', BAYBAY_DAILY_RUN_LIMIT: '1000', BAYBAY_ENGINE: 'v2' };
const quota = () => ({ updateOne: async () => ({}), findOneAndUpdate: async () => ({ count: 1 }) });
const message = content => ({ type: 'message', id: 'msg-fixture', model: 'claude-sonnet-5-5', role: 'assistant', stop_reason: 'end_turn', content, usage: { input_tokens: 40, output_tokens: 60 } });
const fast = answer => message([{ type: 'text', text: JSON.stringify({ lead: 'L', points: [], candidateIds: [], followups: [], coverage: [], gap: '', ...answer }) }]);
const reply = value => ({ ok: true, status: 200, json: async () => value, clone() { return this; }, text: async () => JSON.stringify(value) });
const overloaded = { ok: false, status: 529, clone() { return this; }, text: async () => '{"type":"error","error":{"type":"overloaded_error","message":"Overloaded"}}', json: async () => ({}) };
const firstSentence = answer => answer.split(/(?<=[。.])\s*/)[0];
const systemPlacementOk = body => body.messages.every((row, index, rows) => row.role !== 'system' || index === rows.length - 1 || rows[index + 1].role === 'assistant');
const operatorText = body => body.messages.filter(row => row.role === 'system' || /^<system-reminder>/.test(row.content?.[0]?.text || '')).map(row => row.content[0].text).join('\n');

function assistantWith({ config = {}, respond }) {
  const sent = [];
  const assistant = createBayBayAssistant({ config: { ...base, ...config }, guideCatalog: guides, catalog, now: () => NOW, isTest: false, Quota: quota(),
    fetchImpl: async (_url, init) => { const body = JSON.parse(init.body); sent.push(body); return respond(body, sent.length); } });
  return { assistant, sent };
}
const run = (assistant, text, { locale = 'zh-Hans', history = [], quickCards = [] } = {}) => assistant.run({ message: text, locale, currentPath: '/', history,
  pageContext: publicContext.resolve({ context: { currentPath: '/' }, currentPath: '/', today: TODAY, locale }), searchMode: 'site', webAccess: { allowed: false },
  onQuickCard: cards => { quickCards.push(cards); } });

test('a quota refusal on a possible emergency: no retry, the daily notice, and the 911-first floor with no site cards', async () => {
  let calls = 0;
  const { assistant } = assistantWith({ respond: () => { calls++; throw Object.assign(new Error('今日 AI 额度已用完'), { status: 429, code: 'AI_DAILY_LIMIT' }); } });
  const quickCards = [];
  const result = await run(assistant, '我妈血糖很低，人有点迷糊', { quickCards });
  assert.equal(calls, 1, 'BB-QUALITY: a quota refusal is not retried');
  assert.equal(result.notice?.kind, 'ai_daily_budget', 'BB-QUALITY: the daily notice explains the missing model answer');
  assert.equal(result.emergencyFloor, 'general', 'HOTFIX: the floor replaces the degraded answer');
  assert.match(firstSentence(result.answer), /911/);
  assert.deepEqual(result.localMatches, []); assert.deepEqual(result.sources, []); assert.deepEqual(quickCards, []);
  assert.equal(result.fallbackHelp.actions[0].href, 'tel:911');
});

test('a no-city 附近 ask with a possible emergency sign gets the 911-first floor, not the no-city question', async () => {
  let calls = 0;
  const { assistant } = assistantWith({ respond: () => { calls++; return reply(fast({ lead: '附近的药店有……' })); } });
  const quickCards = [];
  const result = await run(assistant, '附近哪里有药店？我妈血糖很低，人有点迷糊', { quickCards });
  assert.equal(calls, 0, 'the no-city question makes no model call');
  assert.equal(result.emergencyFloor, 'general');
  assert.match(firstSentence(result.answer), /911/);
  assert.doesNotMatch(result.answer, /哪个城市/);
  assert.deepEqual(result.localMatches, []); assert.deepEqual(quickCards, []);
  // Without the sign it is BB-QUALITY's one short question (C11), still with no cards.
  const plain = await run(assistant, '附近有什么好吃的？');
  assert.equal(plain.emergencyFloor, undefined);
  assert.match(plain.answer, /哪个城市/); assert.deepEqual(plain.localMatches, []);
});

test('follow-up turn rules ride after the user turn; no body has a role:system message before a user turn (day-plan follow-up, recovery after a 529)', async () => {
  const history = [{ role: 'user', content: '这周末带 4 岁和 7 岁的孩子在东湾玩，有什么免费的活动？' }, { role: 'assistant', content: '可以去湖边公园。' }];
  const first = assistantWith({ respond: () => reply(fast({ lead: '可以这样安排。' })) });
  const planned = await run(first.assistant, '帮我排成周六半天，我们坐 BART 去', { history });
  assert.equal(planned.route.path, 'agent', 'BB-QUALITY: 排成周六半天 is a day plan');
  for (const body of first.sent) assert.ok(systemPlacementOk(body), JSON.stringify(body.messages.map(row => row.role)));
  assert.match(operatorText(first.sent[0]), /This is a follow-up turn/, 'BB-QUALITY: the carry rule is sent');
  // The failed call does not extend history, so the retry would send user > system(rules) >
  // user(researchComplete): HOTFIX's adapter sends the rules as a <system-reminder> instead.
  const recovered = assistantWith({ respond: (_body, count) => count === 1 ? overloaded : reply(fast({ lead: '可以安排半天。' })) });
  await run(recovered.assistant, '帮我排成周六半天，我们坐 BART 去', { history });
  assert.ok(recovered.sent.length >= 2, `${recovered.sent.length} calls`);
  for (const body of recovered.sent) assert.ok(systemPlacementOk(body), JSON.stringify(body.messages.map(row => row.role)));
  // API-BB-6: a new site day plan is one call, user turn then the rules as the last message (native role:system is
  // allowed there); the retry after a 529 resends that same turn, so the rules are never before a user turn.
  const last = recovered.sent.at(-1).messages;
  assert.ok(last.every((row, index) => row.role !== 'system' || index === last.length - 1 || last[index + 1].role === 'assistant'), JSON.stringify(last.map(row => row.role)));
  assert.match(operatorText(recovered.sent.at(-1)), /This is a follow-up turn/);
});
