// API-BB-4B (first-sentence speed): the boot warm-up runs the synchronous pre-model stages on
// fixed questions without any model, quota or network call, and changes no answer: the caches
// it fills are pure. It is opt-in (only the production server starts it). $0: every provider
// and quota is a fixture.
const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');
const { execFileSync } = require('node:child_process');
const { createBayBayAssistant, warmInterval } = require('../lib/baybayAgent');
const { loadPlannerCatalog } = require('../lib/planner');
const { createPublicContext } = require('../lib/publicContext');
const guides = require('../data/guide-catalog.json');
const englishGuides = require('../data/guide-catalog.en.json');

const NOW = Date.parse('2026-10-14T19:00:00Z'); // Wed 2026-10-14 12:00 PDT
const TODAY = '2026-10-14';
const catalog = loadPlannerCatalog();
const publicContext = createPublicContext({ guideCatalog: guides });
// isTest false so the quota claims run (fixtures) and the model is called.
const config = { BAYBAY_AI_PROVIDER: 'anthropic', ANTHROPIC_API_KEY: 'fixture-anthropic-only', BAYBAY_STATE_SECRET: 'api-bb-4b-task-secret-0123456789abcd', BAYBAY_ENGINE: 'v2' };
const reply = { type: 'message', id: 'msg-fixture', model: 'claude-sonnet-5-5', role: 'assistant', stop_reason: 'end_turn', usage: { input_tokens: 10, output_tokens: 10 },
  content: [{ type: 'text', text: JSON.stringify({ lead: 'L', points: [{ text: 'P [[e1]]', cardIds: ['e1'] }], candidateIds: [], followups: [], coverage: [], gap: '' }) }] };
function assistantWith(extra = {}) {
  const sent = [], providerCalls = [];
  const assistant = createBayBayAssistant({ config: { ...config, ...extra }, guideCatalog: guides, englishGuideCatalog: englishGuides, catalog, now: () => NOW, isTest: false,
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
const QUESTIONS = [['这周六旧金山有什么适合全家的免费活动？', 'zh-Hans'], ['Are there any free museum days in San Francisco this weekend?', 'en'],
  ['這週末灣區有華人社區的活動嗎？比如中文講座', 'zh-Hant'], ['刚搬到 Sunnyvale，第一周要办哪些事？', 'zh-Hans']];
async function answerAll({ assistant, sent }) {
  const answers = [];
  for (const [message, locale] of QUESTIONS) answers.push(withoutTimes(await ask(assistant, message, locale)));
  return { answers, sent };
}

if (process.env.BAYBAY_4B_FRESH_CHILD === '1') {
  // Child mode: a process whose module caches were never warmed answers the questions.
  answerAll(assistantWith()).then(out => process.stdout.write(JSON.stringify(out)));
} else {
  test('the warm-up runs every warm-up question through the pre-model stages, with no provider call', async () => {
    const { assistant, providerCalls } = assistantWith();
    assert.deepEqual(await assistant.warmUp(), { warmed: 11, failed: 0 });
    assert.deepEqual(await assistant.warmUp(), { warmed: 11, failed: 0 }, 'a second run (the periodic re-warm) works the same');
    assert.equal(providerCalls.length, 0);
  });

  test('an assistant never warms on its own: only startWarmUp() (the production server) schedules it', async () => {
    const { assistant } = assistantWith();
    await new Promise(resolve => setTimeout(resolve, 1200));
    assert.deepEqual(assistant.warmStatus(), { started: false, runs: 0, warmed: 0, failed: 0 });
    assert.equal(assistantWith({ BAYBAY_WARM: 'off' }).assistant.startWarmUp(), false, 'BAYBAY_WARM=off');
    const logs = [];
    assert.equal(assistant.startWarmUp({ log: line => logs.push(line) }), true);
    assert.equal(assistant.startWarmUp(), false, 'started once per assistant');
    for (let i = 0; i < 200 && !assistant.warmStatus().runs; i++) await new Promise(resolve => setTimeout(resolve, 50));
    assert.deepEqual(assistant.warmStatus(), { started: true, runs: 1, warmed: 11, failed: 0 });
    assert.deepEqual(logs, [], 'no warning when every question warmed');
  });

  test('the idle re-warm interval: default 15 min, at least 60 s, 0 or invalid = never', () => {
    assert.equal(warmInterval({}), 900000);
    assert.equal(warmInterval({ BAYBAY_WARM_INTERVAL_MS: '' }), 900000);
    assert.equal(warmInterval({ BAYBAY_WARM_INTERVAL_MS: '1' }), 60000);
    assert.equal(warmInterval({ BAYBAY_WARM_INTERVAL_MS: '120000' }), 120000);
    assert.equal(warmInterval({ BAYBAY_WARM_INTERVAL_MS: '0' }), 0);
    assert.equal(warmInterval({ BAYBAY_WARM_INTERVAL_MS: 'soon' }), 0);
    assert.equal(warmInterval({ BAYBAY_WARM_INTERVAL_MS: '-5' }), 0);
  });

  test('a warmed process answers exactly as a process that never warmed (the caches the warm-up fills are pure)', async () => {
    // The fresh side runs in a child process: in this process the module-level caches are already warm.
    const fresh = JSON.parse(execFileSync(process.execPath, [path.join(__dirname, path.basename(__filename))], {
      env: { ...process.env, BAYBAY_4B_FRESH_CHILD: '1' }, maxBuffer: 256 * 1024 * 1024, encoding: 'utf8' }));
    const warmed = assistantWith();
    await warmed.assistant.warmUp();
    const after = await answerAll(warmed);
    assert.equal(after.sent.length, QUESTIONS.length, 'every question reached the (fixture) model');
    after.sent.forEach((body, index) => assert.equal(body, fresh.sent[index], `${QUESTIONS[index][0]}: the provider request body matches byte for byte`));
    after.answers.forEach((answer, index) => assert.deepEqual(answer, fresh.answers[index], QUESTIONS[index][0]));
  });
}
