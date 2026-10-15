// API-BB-4B (first-sentence speed): the boot warm-up runs the synchronous pre-model stages on
// fixed questions without any model, quota or network call, and changes no answer: the caches
// it fills are pure. $0: every provider and quota is a fixture.
const test = require('node:test');
const assert = require('node:assert/strict');
const { createBayBayAssistant } = require('../lib/baybayAgent');
const { loadPlannerCatalog } = require('../lib/planner');
const { createPublicContext } = require('../lib/publicContext');
const guides = require('../data/guide-catalog.json');
const englishGuides = require('../data/guide-catalog.en.json');

const NOW = Date.parse('2026-10-14T19:00:00Z'); // Wed 2026-10-14 12:00 PDT
const TODAY = '2026-10-14';
const catalog = loadPlannerCatalog();
const publicContext = createPublicContext({ guideCatalog: guides });
// isTest false so the quota claims run (fixtures) and the model is called; BAYBAY_WARM off so only the explicit warmUp() warms.
const config = { BAYBAY_AI_PROVIDER: 'anthropic', ANTHROPIC_API_KEY: 'fixture-anthropic-only', BAYBAY_STATE_SECRET: 'api-bb-4b-task-secret-0123456789abcd', BAYBAY_ENGINE: 'v2', BAYBAY_WARM: 'off' };
const reply = { type: 'message', id: 'msg-fixture', model: 'claude-sonnet-5-5', role: 'assistant', stop_reason: 'end_turn', usage: { input_tokens: 10, output_tokens: 10 },
  content: [{ type: 'text', text: JSON.stringify({ lead: 'L', points: [{ text: 'P [[e1]]', cardIds: ['e1'] }], candidateIds: [], followups: [], coverage: [], gap: '' }) }] };
function assistantWith() {
  const sent = [], providerCalls = [];
  const assistant = createBayBayAssistant({ config, guideCatalog: guides, englishGuideCatalog: englishGuides, catalog, now: () => NOW, isTest: false,
    Quota: { updateOne: async () => ({}), findOneAndUpdate: async () => ({ count: 1 }) },
    fetchImpl: async (url, init) => {
      providerCalls.push(url); sent.push(init.body);
      return { ok: true, status: 200, json: async () => reply, clone() { return this; }, text: async () => JSON.stringify(reply) };
    } });
  return { assistant, sent, providerCalls };
}
const ask = (assistant, message, locale) => assistant.run({ message, locale, currentPath: '/', history: [], searchMode: 'site', webAccess: { allowed: false },
  pageContext: publicContext.resolve({ context: { currentPath: '/' }, currentPath: '/', today: TODAY, locale }) });
const withoutTimes = value => JSON.parse(JSON.stringify(value, (key, field) => /Ms$/.test(key) ? undefined : field));

test('the warm-up runs every warm-up question through the pre-model stages, with no provider call', async () => {
  const { assistant, providerCalls } = assistantWith();
  assert.deepEqual(await assistant.warmUp(), { warmed: 11, failed: 0 });
  assert.deepEqual(await assistant.warmUp(), { warmed: 11, failed: 0 }, 'a second run (the periodic re-warm) works the same');
  assert.equal(providerCalls.length, 0);
});

test('a warmed assistant answers exactly as a fresh one (the caches the warm-up fills are pure)', async () => {
  const fresh = assistantWith(), warmed = assistantWith();
  await warmed.assistant.warmUp();
  for (const [message, locale] of [['这周六旧金山有什么适合全家的免费活动？', 'zh-Hans'], ['Are there any free museum days in San Francisco this weekend?', 'en'],
    ['這週末灣區有華人社區的活動嗎？比如中文講座', 'zh-Hant'], ['刚搬到 Sunnyvale，第一周要办哪些事？', 'zh-Hans']]) {
    const before = fresh.sent.length, after = warmed.sent.length;
    const a = await ask(fresh.assistant, message, locale), b = await ask(warmed.assistant, message, locale);
    assert.deepEqual(warmed.sent.slice(after), fresh.sent.slice(before), `${message}: the provider request bodies match byte for byte`);
    assert.deepEqual(withoutTimes(b), withoutTimes(a), message);
  }
  assert.ok(fresh.sent.length >= 4 && warmed.sent.length === fresh.sent.length, 'every question reached the (fixture) model');
});
