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
  // A named anchor is not asked again: 斯坦福附近, SFO 附近, near Stanford.
  for (const message of ['斯坦福附近有什么好吃的', 'SFO 附近有什么吃的', 'near Stanford, where to eat?']) assert.equal(nearbyClarifier(message, { state: {} }), null, message);
  // "这个活动免费吗？" about one item does not get the list-every-free-record rule.
  assert.deepEqual(turnRules({ message: '这个活动免费吗？', state: { goal: 'information' } }), []);
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

test('professional topics found by the new detectors stream their lead only (H03, was none under RC-21) and run on the professional route', async () => {
  for (const message of ['孩子发烧 38.5 度两天了，要不要给他吃抗生素？', '我 H-1B 被裁员了，60 天宽限期内找不到工作会怎样？', '刚拿移民签证来美国，社安号 SSN 怎么申请？']) {
    const { assistant, sent } = assistantWith({ lead: '一般来说……', points: [{ text: '请咨询专业人士。', cardIds: [] }] });
    const { result, drafts } = await ask(assistant, message);
    assert.deepEqual([...new Set(drafts.map(draft => draft.field))], drafts.length ? ['lead'] : [], message); assert.equal(result.route.reason, 'professional_topic', message);
    assert.ok(sent.filter(body => body.stream === true).length <= 1, message);
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

test('answer shape: padding from another region is dropped only when an in-area pick remains; a gap that repeats a point is dropped; a poem request gets the writing rule', () => {
  const { dropOffArea } = require('../lib/baybayQuality');
  const areas = { e1: 'east-bay', e2: 'sf' };
  const draft = { lead: '奥克兰周六有免费活动。', points: [{ text: 'Chabot 望远镜夜免费[[e1]]', cardIds: ['e1'] }, { text: '旧金山 Randall 免费[[e2]]', cardIds: ['e2'] }, { text: '出门前看天气。', cardIds: [] }], candidateIds: ['e1', 'e2'], gap: '' };
  const trimmed = dropOffArea(draft, { region: 'east-bay', areaOf: ref => areas[ref] || null });
  assert.equal(trimmed.dropped, 1); assert.deepEqual(trimmed.draft.candidateIds, ['e1']); assert.equal(trimmed.draft.points.length, 2);
  // The only recommendation is elsewhere: kept (it is the answer, not padding).
  const only = { ...draft, points: [draft.points[1], draft.points[2]] };
  assert.equal(dropOffArea(only, { region: 'east-bay', areaOf: ref => areas[ref] || null }).dropped, 0);
  assert.equal(dropOffArea(draft, { region: 'all', areaOf: ref => areas[ref] || null }).dropped, 0);
  const gap = leadConsistency({ lead: '可以去 Coyote Hills。', points: [{ text: 'Coyote Hills 免费入园，开放时间请以官方页面为准。', cardIds: [] }, { text: '带零食。', cardIds: [] }], gap: '开放时间请以官方页面为准。' });
  assert.deepEqual(gap.repairs, ['gap_repeat']); assert.equal(gap.draft.gap, '');
  assert.deepEqual(leadConsistency({ lead: '可以。', points: [{ text: '甲', cardIds: [] }, { text: '乙', cardIds: [] }], gap: 'Happy Hollow 陪同者是否免费，请看官方页面。' }).repairs, []);
  assert.match(turnRules({ message: '帮我写一首关于金门大桥的诗', state: {} }).join('\n'), /piece of writing/);
});

test('the new detectors stay linear: 500-character pathological inputs finish in under 50 ms', () => {
  const { professionalTopics } = require('../lib/safetyRouting');
  const pads = [' ', '一', '我', '的', 'a ', 'take the ', '每人 ', '预算 ', '排成 ', '，', '坐 ', '附近 '];
  for (const pad of pads) for (const head of ['', '预算', '每人', '排成', '坐', 'take ', '，', '我家']) {
    const text = (head + pad.repeat(Math.ceil(500 / pad.length))).slice(0, 499) + '!';
    // Best of three, as in tests/redos.test.js (which also times these detectors in a child
    // process): one garbage collection while the whole suite runs is not a regression.
    const ms = Math.min(...[0, 1, 2].map(() => {
      const started = process.hrtime.bigint();
      nearbyClarifier(text, { state: {} }); turnRules({ message: text, state: { freeOnly: true, travelMode: 'transit', goal: 'newcomer' }, followup: true });
      leadConsistency({ lead: text, points: [{ text, cardIds: ['e1'] }, { text, cardIds: [] }], gap: text }); professionalTopics(text);
      return Number(process.hrtime.bigint() - started) / 1e6;
    }));
    assert.ok(ms < 50, `${JSON.stringify(head)} + ${JSON.stringify(pad)}: ${ms.toFixed(1)} ms`);
  }
});

test('the San Jose county line stays in the evidence of a services ask (it leads the city queue)', () => {
  const state = conversation([['San Jose 有没有讲中文的长者服务？我妈想找人陪她参加活动', { city: 'San Jose' }]], true)[0];
  const items = buildFastEvidence({ query: 'San Jose 有没有讲中文的长者服务？我妈想找人陪她参加活动', state, guideCatalog: guides, catalog, today: TODAY, audience: true }).items;
  assert.ok(items.some(item => /408-350-3200/.test(item.text)), items.map(item => item.id).join(', '));
});

test('B8: a newcomer setup answer without the SSN step gets it appended last (the guide-only answer of the live eval)', async () => {
  const { ensureNewcomerSsn } = require('../lib/baybayQuality');
  const draft = { lead: '第一周先稳住住处、出行和通讯。', points: [{ text: '先把住处稳定下来。', cardIds: [] }, { text: '办图书馆卡。', cardIds: [] }], gap: '' };
  const added = ensureNewcomerSsn(draft, { message: '我是新移民，刚到湾区第一周要办什么？', state: { goal: 'information' } });
  assert.equal(added.added, true); assert.equal(added.draft.points.length, 3); assert.match(added.draft.points[2].text, /社安号（SSN）.*1-800-772-1213/);
  assert.equal(ensureNewcomerSsn({ ...draft, gap: '社安号以 SSA 为准。' }, { message: '我是新移民，刚到湾区第一周要办什么？' }).added, false);
  assert.equal(ensureNewcomerSsn(draft, { message: '这周末去哪玩？', state: { goal: 'discover' } }).added, false);
  assert.match(ensureNewcomerSsn(draft, { message: 'We just moved here, what should we set up first?', locale: 'en' }).draft.points.at(-1).text, /Social Security number/);
  // Through the assistant: the appended point reaches the answer and its shape.
  const { assistant } = assistantWith({ lead: '第一周先稳住住处。', points: [{ text: '住处先稳定。', cardIds: [] }] });
  const result = await assistant.run({ message: '我是新移民，刚到湾区第一周要办什么？', locale: 'zh-Hans', currentPath: '/', searchMode: 'site', webAccess: { allowed: false },
    pageContext: publicContext.resolve({ context: { currentPath: '/' }, currentPath: '/', today: TODAY, locale: 'zh-Hans' }) });
  assert.match(result.answer, /社安号（SSN）/); assert.ok(result.research.warnings.includes('answer_newcomer_ssn_added'));
  assert.match(result.points.at(-1).text, /SSA/);
});
