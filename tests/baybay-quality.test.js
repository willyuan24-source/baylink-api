// API-BB-QUALITY: multi-turn carry (BBL-07), free/family recall (BBL-06), the no-city
// clarifier (C11), the newcomer checklist (B8), English cards (I18N-SEO-01), the
// lead/points consistency repair and drafts on professional routes (RC-21). $0: the
// provider is a local fixture.
const test = require('node:test');
const assert = require('node:assert/strict');
const { createBayBayAssistant } = require('../lib/baybayAgent');
const { resolveTaskState } = require('../lib/baybayState');
const { inferFilters, loadPlannerCatalog } = require('../lib/planner');
const { buildFastEvidence } = require('../lib/baybayEvidence');
const { createPublicContext } = require('../lib/publicContext');
const { cardInLocale, nearbyClarifier, turnRules, leadConsistency } = require('../lib/baybayQuality');

const TODAY = '2026-10-12';
const guides = require('../data/guide-catalog.json');
const catalog = loadPlannerCatalog();
const publicContext = createPublicContext({ guideCatalog: guides });
const CJK = /[㐀-鿿]/;

function conversation(turns, carry) {
  let previous, result;
  const states = [];
  for (const [message, searchContext = {}] of turns) {
    result = resolveTaskState({ message, previous, today: TODAY, catalog, searchContext, carry });
    previous = result.state; states.push(result.state);
  }
  return states;
}

test('v2 carry: the 7-year-old stays, 排成半天 is a plan, Caltrain / VTA are transit, 每人 $20 is a per-person budget, 下午 is kept', () => {
  const w1 = conversation([['这周末带 4 岁和 7 岁的孩子在东湾玩，有什么免费的活动？', { region: 'east-bay' }], ['只挑一个最适合 4 岁的，上午去还是下午去好？'], ['帮我排成周六半天，我们坐 BART 去', { region: 'east-bay', date: '2026-10-17' }]], true);
  assert.deepEqual(w1[1].childAges, [4, 7]);
  assert.deepEqual(w1[2].childAges, [4, 7]); assert.equal(w1[2].goal, 'day-plan'); assert.equal(w1[2].travelMode, 'transit'); assert.equal(w1[2].date, '2026-10-17');
  const m1 = conversation([['明天下午想在 Palo Alto 附近走走，就我们两个大人', { city: 'Palo Alto', date: '2026-10-13' }], ['加一个吃晚饭的地方，两个人预算 60 刀以内'], ['不想开车了，改成坐 Caltrain 能到的']], true);
  assert.equal(m1[2].travelMode, 'transit'); assert.equal(m1[2].budget, 60); assert.equal(m1[2].partySize, 2); assert.ok(m1[2].preferences.includes('time-of-day:afternoon'));
  const kids = conversation([['这周日想带 3 岁和 8 岁两个孩子去半岛玩', { region: 'peninsula' }], ['预算每人 20 刀以内'], ['下午两点以后出发，有什么推荐？']], true);
  assert.equal(kids[1].budget, 20); assert.equal(kids[1].budgetScope, 'person'); assert.equal(kids[2].startTime, '14:00'); assert.deepEqual(kids[2].childAges, [3, 8]);
  const en = conversation([['Any free things to do in San Jose this Saturday with my 5-year-old?'], ['We will take VTA light rail. Which one is easiest to reach?']], true);
  assert.equal(en[0].freeOnly, true); assert.equal(en[1].travelMode, 'transit'); assert.deepEqual(en[1].childAges, [5]);
  const free = conversation([['这周六旧金山有什么适合全家的活动？', { city: 'San Francisco', date: '2026-10-17' }], ['一家四口预算 50 刀以内，哪些完全免费？']], true);
  assert.equal(free[1].freeOnly, true); assert.equal(free[1].budget, 50); assert.equal(free[1].partySize, 4);
  // An explicit change still replaces the household; a comparison of two modes sets none.
  assert.deepEqual(conversation([['带 4 岁和 7 岁的孩子去 Berkeley 玩'], ['这次只带 4 岁的去']], true)[1].childAges, [4]);
  assert.equal(conversation([['周六去 Palo Alto'], ['开车还是坐 Caltrain 更方便？']], true)[1].travelMode, null);
  assert.equal(conversation([['周六去 Palo Alto'], ['我不想坐 Caltrain']], true)[1].travelMode, null);
});

test('v1 keeps its state resolution: without carry the same turns resolve as before', () => {
  const w1 = conversation([['这周末带 4 岁和 7 岁的孩子在东湾玩，有什么免费的活动？', { region: 'east-bay' }], ['只挑一个最适合 4 岁的，上午去还是下午去好？']], false);
  assert.deepEqual(w1[1].childAges, [4]);
  const m1 = conversation([['明天下午想在 Palo Alto 附近走走，就我们两个大人', { city: 'Palo Alto', date: '2026-10-13' }], ['不想开车了，改成坐 Caltrain 能到的']], false);
  assert.equal(m1[1].travelMode, null); assert.ok(!m1[1].preferences.some(value => value.startsWith('time-of-day:')));
});

test('安排一下周六 is this Saturday, not next week (一下 + 周六); 下周六 is still next week', () => {
  assert.equal(inferFilters('那帮我安排一下周六下午的行程，最多两站', TODAY, { selectedTopic: 'any' }).date, '2026-10-17');
  assert.equal(inferFilters('帮我看一下周日', TODAY, { selectedTopic: 'any' }).date, '2026-10-18');
  assert.equal(inferFilters('下周六去哪', TODAY, { selectedTopic: 'any' }).date, '2026-10-24');
  assert.equal(inferFilters('安排一下周末', '2026-10-11', { selectedTopic: 'any' }).date, '2026-10-11');
  assert.equal(inferFilters('下周末', '2026-10-11', { selectedTopic: 'any' }).date, '2026-10-17');
});

test('free and family follow-ups see every fitting event of the day: 10/17 SF free events, the science festival first for a family', () => {
  const family = conversation([['这周六旧金山有什么适合全家的活动？', { city: 'San Francisco', date: '2026-10-17' }]], true)[0];
  const first = buildFastEvidence({ query: '这周六旧金山有什么适合全家的活动？', state: family, guideCatalog: guides, catalog, today: TODAY, audience: true });
  assert.equal(first.items[0].id, 'sf-bay-area-science-festival-2026');
  const free = conversation([['这周六旧金山有什么适合全家的活动？', { city: 'San Francisco', date: '2026-10-17' }], ['一家四口预算 50 刀以内，哪些完全免费？']], true)[1];
  const ids = buildFastEvidence({ query: '一家四口预算 50 刀以内，哪些完全免费？', state: free, guideCatalog: guides, catalog, today: TODAY, audience: true }).items.map(item => item.id);
  for (const id of ['sf-bay-area-science-festival-2026', 'sf-filbookfest-2026', 'sf-sunnydale-pumpkin-fest-2026', 'sfpl-omi-history-day-oct17-2026']) assert.ok(ids.includes(id), id);
  // Without the option (v1 retrieval and the existing callers) nothing changes.
  const plain = buildFastEvidence({ query: '一家四口预算 50 刀以内，哪些完全免费？', state: free, guideCatalog: guides, catalog, today: TODAY }).items.map(item => item.id);
  assert.notDeepEqual(plain, ids);
});

test('cards in the reader locale: English titles and summaries for events, places and guides; zh-Hant event titles', () => {
  const events = catalog.events, places = catalog.places;
  const hands = events.find(row => row.id === 'sunnyvale-hands-on-arts-2026');
  const card = cardInLocale({ kind: 'event', id: hands.id, title: hands.title, summary: hands.summary }, { locale: 'en', row: hands, kind: 'event' });
  assert.doesNotMatch(`${card.title} ${card.summary}`, CJK); assert.match(card.title, /Hands on the Arts/);
  const bridge = places.find(row => row.id === 'golden-gate');
  const place = cardInLocale({ kind: 'place', id: bridge.id, title: bridge.title, summary: bridge.summary }, { locale: 'en', row: bridge, kind: 'place' });
  assert.equal(place.title, 'Golden Gate Bridge & Fort Point'); assert.doesNotMatch(place.summary, CJK); assert.ok(place.summary);
  const science = events.find(row => row.id === 'sf-bay-area-science-festival-2026');
  assert.equal(cardInLocale({ kind: 'event', id: science.id, title: science.title }, { locale: 'zh-Hant', row: science, kind: 'event' }).title, '灣區科學節：到 UCSF 動手做實驗');
  const zh = { kind: 'event', id: science.id, title: science.title };
  assert.equal(cardInLocale(zh, { locale: 'zh-Hans', row: science }), zh);
});

test('lead consistency: a count that differs from the listed options loses the number; a choice is not followed by "cannot judge"', () => {
  const points = n => Array.from({ length: n }, (_, index) => ({ text: `点 ${index}`, cardIds: [`e${index + 1}`] }));
  assert.equal(leadConsistency({ lead: '周六东湾有两场免费活动，适合孩子。', points: points(3) }).draft.lead, '周六东湾有免费活动，适合孩子。');
  assert.equal(leadConsistency({ lead: 'Yes, two free South Bay family events are listed for Sat, Oct 17.', points: points(3) }, { locale: 'en' }).draft.lead, 'Yes, free South Bay family events are listed for Sat, Oct 17.');
  assert.deepEqual(leadConsistency({ lead: '周六有三项免费活动。', points: points(3) }).repairs, []);
  assert.deepEqual(leadConsistency({ lead: '两个孩子都适合的有三项。', points: points(3) }).repairs, []);
  const choice = leadConsistency({ lead: '坐渡轮去 Sausalito 更省脚力。', points: [{ text: '现有资料不能判断哪个更省力。', cardIds: [] }, { text: '选平路、能坐下的地方。', cardIds: [] }] });
  assert.deepEqual(choice.repairs, ['lead_choice']); assert.equal(choice.draft.points.length, 1);
});

test('turn rules: follow-ups keep every condition and choose; free asks list every free record; transit names the system; newcomers get the SSN step', () => {
  const followup = turnRules({ message: '我爸膝盖不好，哪个更合适？', state: {}, followup: true }).join('\n');
  assert.match(followup, /follow-up turn/); assert.match(followup, /choose/);
  assert.match(turnRules({ message: '哪些完全免费？', state: { freeOnly: true } }).join('\n'), /Never say only one, or none, is free/);
  assert.match(turnRules({ message: '改坐 Caltrain', state: { travelMode: 'transit' } }).join('\n'), /Never invent station names/);
  assert.match(turnRules({ message: '我们一家刚移民来湾区，第一个月要先办哪些事？', state: {} }).join('\n'), /Social Security number from SSA/);
  assert.deepEqual(turnRules({ message: '蓝天使这周末飞吗', state: {} }), []);
  assert.equal(nearbyClarifier('附近有什么好吃的', { state: { city: 'Fremont' } }), null);
  assert.equal(nearbyClarifier('附近有什么好吃的', { state: {}, hasPage: true }), null);
  assert.match(nearbyClarifier('Any good food near me?', { state: {}, locale: 'en' }), /Which Bay Area city/);
});

// ---- the assistant (BAYBAY_ENGINE=v2, a local provider fixture) --------------------
const base = { BAYBAY_AI_PROVIDER: 'anthropic', ANTHROPIC_API_KEY: 'fixture-anthropic-only', BAYBAY_STATE_SECRET: 'private-test-task-secret-0123456789', BAYBAY_DAILY_RUN_LIMIT: '1000' };
const quota = () => ({ updateOne: async () => ({}), findOneAndUpdate: async () => ({ count: 1 }) });
const reply = answer => ({ type: 'message', id: 'msg-fixture', model: 'claude-sonnet-5-5', role: 'assistant', stop_reason: 'end_turn',
  content: [{ type: 'text', text: JSON.stringify({ lead: 'L', points: [], candidateIds: [], followups: [], coverage: [], gap: '', ...answer }) }], usage: { input_tokens: 40, output_tokens: 60 } });
function assistantWith(answer) {
  const sent = [];
  const assistant = createBayBayAssistant({ config: { ...base, BAYBAY_ENGINE: 'v2' }, guideCatalog: guides, catalog, now: () => Date.parse('2026-10-12T16:00:00Z'), isTest: false, Quota: quota(),
    fetchImpl: async (_url, init) => { const body = JSON.parse(init.body); sent.push(body); return { ok: true, status: 200, json: async () => reply(typeof answer === 'function' ? answer(body) : answer) }; } });
  return { assistant, sent };
}
const ask = async (assistant, message, { locale = 'zh-Hans', history = [], sessionToken } = {}) => {
  const cards = [], progress = [], drafts = [];
  const result = await assistant.run({ message, locale, history, sessionToken, currentPath: '/', pageContext: publicContext.resolve({ context: { currentPath: '/' }, currentPath: '/', today: TODAY, locale }),
    searchMode: 'site', webAccess: { allowed: false }, onQuickCard: value => cards.push(...value), onProgress: value => progress.push(value), onDraft: value => drafts.push(value) });
  return { result, cards, progress, drafts };
};

test('附近有什么好吃的 with no place known: one short question, no model call, no cards; a known city still answers', async () => {
  const { assistant, sent } = assistantWith({ lead: '有。' });
  const { result, cards } = await ask(assistant, '附近有什么好吃的');
  assert.equal(sent.length, 0); assert.deepEqual(cards, []); assert.deepEqual(result.localMatches, []);
  assert.equal(result.route.path, 'clarification'); assert.match(result.answer, /哪个城市/); assert.ok(result.answer.length <= 80);
  const known = await ask(assistant, 'Fremont 附近有什么好吃的');
  assert.ok(sent.length >= 1); assert.equal(known.result.route.path, 'fast');
});

test('English questions get English quick cards and entity cards (no Chinese title or summary)', async () => {
  const { assistant } = assistantWith(body => ({ lead: 'Two free events.', points: [{ text: 'Hands on the Arts [[e1]]', cardIds: ['e1'] }], candidateIds: ['e1'] }));
  const { result, cards } = await ask(assistant, 'Any free family events in the South Bay this Saturday?', { locale: 'en' });
  assert.ok(cards.length >= 1);
  for (const card of [...cards, ...result.localMatches]) assert.doesNotMatch(`${card.title} ${card.summary || ''}`, CJK, card.title);
});

test('the follow-up rules reach the model after the user turn; system block 1 is untouched', async () => {
  const { assistant, sent } = assistantWith({ lead: '选丰收节。', points: [{ text: '上午人少。', cardIds: [] }] });
  const first = await ask(assistant, '这周末带 4 岁和 7 岁的孩子在东湾玩，有什么免费的活动？');
  await ask(assistant, '只挑一个最适合 4 岁的，上午去还是下午去好？', { sessionToken: first.result.assistantSessionToken,
    history: [{ role: 'user', content: '这周末带 4 岁和 7 岁的孩子在东湾玩，有什么免费的活动？' }, { role: 'assistant', content: first.result.answer }] });
  const last = sent.at(-1);
  const rules = last.messages.filter(row => row.role === 'system').map(row => typeof row.content === 'string' ? row.content : row.content.map(part => part.text).join('')).join('\n')
    || last.messages.at(-1).content.map?.(part => part.text).join('');
  assert.match(rules, /follow-up turn/); assert.match(rules, /choose/); assert.match(rules, /every record in evidence that is free/);
  assert.equal(JSON.stringify(last.system), JSON.stringify(sent[0].system));
  assert.deepEqual(JSON.parse(last.messages[0].content[0]?.text ?? last.messages[0].content).state.childAges, [4, 7]);
});

test('professional topics found by the new detectors never stream drafts (RC-21) and run on the professional route', async () => {
  for (const message of ['孩子发烧 38.5 度两天了，要不要给他吃抗生素？', '我 H-1B 被裁员了，60 天宽限期内找不到工作会怎样？', '刚拿移民签证来美国，社安号 SSN 怎么申请？']) {
    const { assistant, sent } = assistantWith({ lead: '一般来说……', points: [{ text: '请咨询专业人士。', cardIds: [] }] });
    const { result, drafts } = await ask(assistant, message);
    assert.deepEqual(drafts, [], message); assert.equal(result.route.reason, 'professional_topic', message);
    assert.ok(sent.every(body => body.stream === undefined), message);
  }
});

test('BBL-02: the first progress frame is sent before the budget read and retrieval', async () => {
  const { assistant } = assistantWith({ lead: '有。' });
  const { progress } = await ask(assistant, '蓝天使这周末飞吗');
  assert.deepEqual(progress[0], { phase: 'site', status: 'running' });
});

test('BBENG-12: system block 1 names only the fields the v2 user turn sends and carries no literal example date', () => {
  const { FROZEN_SYSTEM } = require('../lib/baybayFastPath');
  for (const absent of ['localMatches', 'contextReferences', 'contextUsed', 'sourceUrl', 'verifiedAt', '10月17日', 'Oct 17', '2026-']) assert.ok(!FROZEN_SYSTEM.includes(absent), absent);
  for (const present of ['currentPage', 'otherSelected', 'evidence', 'state', 'recentConversation', 'M月D日（周X）']) assert.ok(FROZEN_SYSTEM.includes(present), present);
  assert.match(FROZEN_SYSTEM, /The lead is the answer, not a count/);
});
