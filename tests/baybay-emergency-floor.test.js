// SAFETY-2 (re-audit 10-11, gaps G29): when BayBay has no model answer (provider down,
// paused, past the daily limit), a question that may be an emergency gets 911 in its
// first sentence (with 988 for self-harm, Poison Control for a poisoning) and no site
// cards: no listing, guide excerpt, page card or early quick card. Deterministic, $0.
const test = require('node:test');
const assert = require('node:assert/strict');
const { createBayBayAssistant } = require('../lib/baybayAgent');
const { possibleEmergencyTopic, emergencyFloor } = require('../lib/safetyRouting');
const { createPublicContext } = require('../lib/publicContext');
const catalog = require('../data/planner-catalog.json');
const guideCatalog = require('../data/guide-catalog.json');
const englishGuideCatalog = require('../data/guide-catalog.en.json');

const NOW = Date.parse('2026-10-08T17:00:00Z');
const publicContext = createPublicContext({ guideCatalog });
const firstSentence = answer => answer.split(/(?<=[。.])\s*/)[0];

function assistant({ config = {}, ai, Quota } = {}) {
  const calls = { model: 0, quickCards: [] };
  const instance = createBayBayAssistant({ config: { JWT_SECRET: 'isolated-emergency-floor', BAYBAY_STATE_SECRET: 'isolated-emergency-floor-state', ...config },
    catalog, guideCatalog, englishGuideCatalog, isTest: true, now: () => NOW, Quota,
    ai: ai || (async () => { calls.model++; throw Object.assign(new Error('Provider unavailable in this fixture'), { status: 503 }); }) });
  const ask = (message, { locale = 'zh-Hans', history = [], currentPath = '/' } = {}) => instance.run({ message, locale, history, searchMode: 'site', currentPath,
    pageContext: publicContext.resolve({ context: { currentPath }, currentPath, today: '2026-10-08', locale }), onQuickCard: cards => { calls.quickCards.push(cards); } });
  return { calls, ask };
}

// [locale, message, history, topic, first-sentence pattern]
const FLOOR_CASES = [
  ['zh-Hans', '我妈血糖很低，人有点迷糊', [], 'general', /^如果情况紧急或有人突然身体不适，请立即拨打 911。$/],
  ['zh-Hans', '我爸舌头发硬说话不清', [], 'stroke', /911/],
  ['zh-Hans', '我妈突然看不清东西，头很痛', [], 'general', /911/],
  ['zh-Hans', '孩子吃东西噎住了', [], 'general', /911/],
  ['zh-Hant', '我媽血糖很低，人有點迷糊', [], 'general', /^如果情況緊急或有人突然身體不適，請立即撥打 911。$/],
  ['en', 'My grandma is confused and sweating a lot', [], 'general', /^If this is an emergency or someone is suddenly unwell, call 911 now\.$/],
  // The previous user turn was a card topic; the follow-up alone is not.
  ['zh-Hans', '他现在一个人在家，我该怎么办', [{ role: 'user', content: '朋友说要自杀' }, { role: 'assistant', content: '请立即拨打 911。' }], 'self-harm', /911.*988/],
  ['zh-Hans', '然后呢', [{ role: 'user', content: '孩子把洗衣凝珠吃进去了' }, { role: 'assistant', content: '请立即拨打 911。' }], 'poisoning', /911.*1-800-222-1222/],
  ['en', 'What should I do next?', [{ role: 'user', content: 'My friend is talking about killing herself' }, { role: 'assistant', content: 'Call 911 now.' }], 'self-harm', /911.*988/],
];

test('possibleEmergencyTopic: urgent signs, FAST signs and the previous turn below the card; ordinary questions stay null', () => {
  for (const [, message, history, topic] of FLOOR_CASES) assert.equal(possibleEmergencyTopic(message, history), topic, message);
  for (const message of ['周末带孩子去哪玩', "I'm confused about Clipper fares", '停车很头疼，周末去哪', '我腿抽筋了，怎么缓解', '看不清地图上的字，有大字版吗', '湾区找室友要注意什么'])
    assert.equal(possibleEmergencyTopic(message), null, message);
});

test('emergencyFloor: 911 in the first sentence, 988 or Poison Control there too for those topics, and the matching call buttons', () => {
  for (const locale of ['zh-Hans', 'zh-Hant', 'en']) {
    for (const [topic, extra, href] of [['self-harm', /988/, 'tel:988'], ['poisoning', /1-800-222-1222/, 'tel:+18002221222'], ['ingestion', /1-800-222-1222/, 'tel:+18002221222'], ['gas', /911/, null], ['general', /911/, null]]) {
      const floor = emergencyFloor(topic, locale), first = firstSentence(floor.answer);
      assert.match(first, /911/, `${topic}/${locale}: ${first}`); assert.match(first, extra, `${topic}/${locale}: ${first}`);
      assert.match(floor.answer, /211/);
      assert.equal(floor.actions[0].href, 'tel:911'); assert.equal(floor.actions.at(-1).href, 'tel:211');
      if (href) assert.ok(floor.actions.some(action => action.href === href), `${topic}: ${href}`);
      if (locale === 'en') assert.doesNotMatch(floor.answer, /[一-鿿]/);
    }
  }
});

test('provider down: a possible emergency gets the 911-first floor and no site cards, sources, guides, page card or quick card', async () => {
  for (const [locale, message, history, topic, first] of FLOOR_CASES) {
    const f = assistant();
    const result = await f.ask(message, { locale, history, currentPath: '/events' });
    assert.equal(result.degraded, true, message);
    assert.equal(result.emergencyFloor, topic, message);
    assert.match(firstSentence(result.answer), first, `${message}: ${result.answer}`);
    assert.deepEqual(result.localMatches, [], message);
    assert.deepEqual(result.sources, [], message);
    assert.deepEqual(result.suggestedGuides, [], message);
    assert.deepEqual(result.contextReferences, [], message);
    assert.deepEqual(result.followups, [], message);
    assert.equal(result.fallbackHelp.actions[0].href, 'tel:911', message);
    assert.deepEqual(f.calls.quickCards, [], `${message}: no early site card`);
  }
});

test('paused and past the daily run limit: the same floor, before any model call', async () => {
  // A quota store that is full: the run-limit claim fails, as it does past BAYBAY_DAILY_RUN_LIMIT.
  const full = { updateOne: async () => ({}), findOneAndUpdate: async () => null };
  for (const [label, options] of [['paused', { config: { BAYBAY_PAUSED: 'true' } }], ['run limit', { Quota: full }]]) {
    let modelCalls = 0;
    const f = assistant({ ...options, ai: async () => { modelCalls++; throw new Error('the model must not be called'); } });
    const result = await f.ask('他现在一个人在家，我该怎么办', { history: [{ role: 'user', content: '朋友说要自杀' }, { role: 'assistant', content: '请立即拨打 911。' }] });
    assert.equal(result.emergencyFloor, 'self-harm', label);
    assert.equal(modelCalls, 0, label);
    assert.ok(result.notice, `${label}: the pause or daily-limit notice still shows`);
    assert.match(firstSentence(result.answer), /911.*988/);
    assert.deepEqual(result.localMatches, []);
    assert.deepEqual(result.fallbackHelp.actions.map(action => action.href), ['tel:911', 'tel:988', 'tel:211']);
  }
});

test('a model answer is not replaced, and an ordinary question keeps its ordinary degraded answer', async () => {
  const answered = assistant({ ai: async () => ({ status: 'completed', model: 'gpt-5.4', output: [{ type: 'message', role: 'assistant', content: [{ type: 'output_text',
    text: JSON.stringify({ answer: '如果她意识不清，请马上打 911；低血糖时可以先给含糖饮料。', candidateIds: [], followups: [] }) }] }] }) });
  const withModel = await answered.ask('我妈血糖很低，人有点迷糊');
  assert.equal(withModel.emergencyFloor, undefined);
  assert.match(withModel.answer, /含糖饮料/);
  const f = assistant();
  const ordinary = await f.ask('Any underwater basket weaving meetups?', { locale: 'en' });
  assert.equal(ordinary.emergencyFloor, undefined);
  assert.doesNotMatch(ordinary.answer, /911/);
  assert.equal(ordinary.fallbackHelp, undefined);
});
