// API-FIX5 (audit 10-13): H11 degraded floor, H72 degraded cards and English floors, H38
// spaced clock times, H39 card day, H17 Chinese-community facet, H10 BayBay's own AI share
// and H03 latency (background monitor index, claims beside retrieval). $0: every provider,
// source and quota is a fixture.
const test = require('node:test');
const assert = require('node:assert/strict');
const { EventEmitter } = require('node:events');
const { createApplication } = require('../server');
const { createBayBayAssistant } = require('../lib/baybayAgent');
const { createAiGovernance, reserveAiCall, aiExecution } = require('../lib/aiGovernance');
const { resolveTaskState } = require('../lib/baybayState');
const { buildFastEvidence, modelItems } = require('../lib/baybayEvidence');
const { loadPlannerCatalog } = require('../lib/planner');
const { createPublicContext } = require('../lib/publicContext');
const { createMemoryModels } = require('./support/memory-models');
const guides = require('../data/guide-catalog.json');
const englishGuides = require('../data/guide-catalog.en.json');

const NOW = Date.parse('2026-10-13T19:00:00Z'); // Tue 2026-10-13 12:00 PDT
const TODAY = '2026-10-13';
const catalog = loadPlannerCatalog();
const publicContext = createPublicContext({ guideCatalog: guides });
const CJK = /[㐀-鿿]/;
const SECRET = 'api-fix5-test-secret-0123456789abcdef';
const base = { BAYBAY_AI_PROVIDER: 'anthropic', ANTHROPIC_API_KEY: 'fixture-anthropic-only', BAYBAY_STATE_SECRET: 'api-fix5-task-secret-0123456789abcd', BAYBAY_ENGINE: 'v2' };
const quota = () => ({ updateOne: async () => ({}), findOneAndUpdate: async () => ({ count: 1 }) });
const claude = answer => ({ type: 'message', id: 'msg-fixture', model: 'claude-sonnet-5-5', role: 'assistant', stop_reason: 'end_turn', usage: { input_tokens: 10, output_tokens: 10 },
  content: [{ type: 'text', text: JSON.stringify({ lead: 'L', points: [], candidateIds: [], followups: [], coverage: [], gap: '', ...answer }) }] });
function assistantWith({ answer, fail = false, ...extra } = {}) {
  const sent = [];
  const assistant = createBayBayAssistant({ config: base, guideCatalog: guides, englishGuideCatalog: englishGuides, catalog, now: () => NOW, isTest: false, Quota: quota(), ...extra,
    fetchImpl: async (_url, init) => {
      sent.push(JSON.parse(init.body));
      if (fail) return { ok: false, status: 503, json: async () => ({ error: { type: 'overloaded_error' } }), clone() { return this; }, text: async () => '' };
      const message = claude(answer || {});
      return { ok: true, status: 200, json: async () => message, clone() { return this; }, text: async () => JSON.stringify(message) };
    } });
  return { assistant, sent };
}
const ask = (assistant, message, { locale = 'zh-Hans', sessionToken, onQuickCard } = {}) => assistant.run({ message, locale, currentPath: '/', history: [], sessionToken, onQuickCard,
  pageContext: publicContext.resolve({ context: { currentPath: '/' }, currentPath: '/', today: TODAY, locale }), searchMode: 'site', webAccess: { allowed: false } });
const userTurn = body => JSON.parse(body.messages.find(message => message.role === 'user').content.find?.(block => block.type === 'text')?.text ?? body.messages.find(message => message.role === 'user').content);

// ---------------------------------------------------------------- H11 / H72

test('H11/H72: with the model down, a health worry gets 911/211 first and no event, offer or opening card, in every language', async () => {
  const { assistant } = assistantWith({ fail: true });
  for (const [locale, message, call] of [
    ['zh-Hans', '孩子起疹子了，嗓子有点紧，周末还能去旧金山玩吗？', '请立即拨打 911'],
    ['zh-Hant', '孩子起疹子了，嗓子有點緊，週末還能去舊金山玩嗎？', '請立即撥打 911'],
    ['en', 'My dad has chest tightness, should we still go to the fair in San Francisco this weekend?', 'call 911 now'],
  ]) {
    const quick = [];
    const result = await ask(assistant, message, { locale, onQuickCard: cards => quick.push(...cards) });
    assert.equal(result.degraded, true, message);
    assert.ok(result.answer.includes(call), `${message}: ${result.answer}`);
    assert.match(result.answer, /211/);
    assert.deepEqual(result.localMatches.filter(card => card.kind !== 'guide'), [], `${message}: no event cards`);
    assert.deepEqual(quick, [], `${message}: no preview cards beside a health worry`);
    assert.deepEqual(result.fallbackHelp.actions.map(action => action.href), ['tel:911', 'tel:211']);
    if (locale === 'en') assert.doesNotMatch(result.answer, CJK);
  }
});

test('H72: a degraded professional answer shows no event cards and an English degraded answer has no Chinese text', async () => {
  const { assistant } = assistantWith({ fail: true });
  const mediCal = await ask(assistant, '我爸妈 68 岁刚拿绿卡来湾区，可以申请 Medi-Cal 吗？去哪里申请？');
  assert.equal(mediCal.safetyRoute, 'professional');
  assert.equal(mediCal.degraded, true);
  assert.deepEqual(mediCal.localMatches.filter(card => ['event', 'offer', 'opening'].includes(card.kind)), []);
  const english = await ask(assistant, 'Is the Exploratorium free for kids this weekend?', { locale: 'en' });
  assert.equal(english.degraded, true);
  assert.doesNotMatch(english.answer, CJK, english.answer);
});

// ---------------------------------------------------------------- H38 / H39

test('H38: a space between the number and 点 (or 时) is the same clock; 小时 and a later count are not', () => {
  const state = message => resolveTaskState({ message, today: TODAY, carry: true }).state;
  assert.equal(state('帮我排个周六的行程，我们坐 BART 去，下午 4 点前回家').finishBy, '16:00');
  assert.equal(state('我们下午 3 点半前要回到家').finishBy, '15:30');
  assert.equal(state('下午 4 时前回家').finishBy, '16:00');
  assert.equal(state('带 6 岁孩子 上午 10 点 出发').startTime, '10:00');
  assert.equal(state('下午4点前回家').finishBy, '16:00', 'unspaced, as before');
  assert.equal(state('两个小时就好').finishBy, null);
  // Review of 3efe2b8: spaced minutes and 半 keep their minutes; a bare finish hour at or before
  // the start is the afternoon; 周六10点 is 10:00 (六10 is not an hour).
  assert.equal(state('我们 3 点 15 分出发，周六').startTime, '03:15');
  assert.equal(state('周六 10 点 半出发').startTime, '10:30');
  assert.deepEqual([state('周六 10 点出发，5 点前回家').startTime, state('周六 10 点出发，5 点前回家').finishBy], ['10:00', '17:00']);
  assert.deepEqual([state('周六10点出发，5点前回家').startTime, state('周六10点出发，5点前回家').finishBy], ['10:00', '17:00']);
  assert.equal(state('周六 10 点出发，11 点前回家').finishBy, '11:00', 'a later bare hour stays as said');
  assert.equal(state('周六晚上 8 点出发，6 点前回家').finishBy, null, 'a finish that cannot follow the start is dropped');
  assert.equal(state('我们 9 点出发，下午 4 点前回家').finishBy, '16:00');
});

test('H39: event cards in a Saturday answer carry that Saturday (date), so a twice-weekly market shows Saturday, not today', async () => {
  const { assistant } = assistantWith({ answer: { lead: '周六有几项免费活动。', points: [{ text: '示例[[e1]]。', cardIds: ['e1', 'e2', 'e3'] }], candidateIds: ['e1', 'e2', 'e3'] } });
  const result = await ask(assistant, '这周六旧金山有什么适合全家的免费活动？');
  assert.equal(result.taskState.date, '2026-10-17');
  const events = result.localMatches.filter(card => card.kind === 'event');
  assert.ok(events.length >= 2, JSON.stringify(result.localMatches));
  for (const card of events) assert.equal(card.date, '2026-10-17', card.id);
  // The market itself (Tue/Thu/Sat), asked about on Saturday.
  const market = catalog.events.find(row => row.id === 'ferry-plaza-farmers-market-2026-autumn');
  assert.ok(market.occurrenceDates.includes('2026-10-17') && !market.occurrenceDates.includes('2026-10-16'));
});

// ---------------------------------------------------------------- H17

test('H17: a Chinese-community ask lists the Chinese-language events first and keeps the constraint on 明天有吗', async () => {
  const first = resolveTaskState({ message: '這週末灣區有華人社區的活動嗎？比如重陽節敬老、中文講座之類的', today: TODAY, carry: true }).state;
  assert.equal(first.community, 'chinese');
  const weekend = buildFastEvidence({ query: '這週末灣區有華人社區的活動嗎', originalQuery: '這週末灣區有華人社區的活動嗎？比如重陽節敬老、中文講座之類的', state: first, guideCatalog: guides, catalog, today: TODAY, locale: 'zh-Hant', audience: true });
  // API-SYNC-3b brought the six SF Chinese-community programmes WEB-HOLDOUT had held back; three are on Saturday 10/17,
  // so the four community records are Saturday's, SF Chinatown first (date, then id). Millbrae's Sunday storytime no longer
  // makes the four (communityRecall has no per-day turn as audienceRecall does; follow-up for API-BB-4B in API-SYNC-3B PR.md).
  assert.deepEqual(weekend.items.slice(0, 4).map(item => item.id), ['sfpl-chinatown-creative-saturdays-fall-2026', 'sfpl-marina-wild-goose-qigong-oct-2026', 'sfpl-richmond-hk-film-the-killer-2026', 'sjpl-berryessa-mandarin-ell-club-fall-2026']);
  const next = resolveTaskState({ message: '明天下午就有空，明天有嗎？', previous: first, today: TODAY, carry: true }).state;
  assert.equal(next.community, 'chinese', 'the follow-up keeps the facet');
  assert.equal(next.date, '2026-10-14');
  const tomorrow = buildFastEvidence({ query: '明天有嗎', originalQuery: '明天下午就有空，明天有嗎？', state: next, guideCatalog: guides, catalog, today: TODAY, locale: 'zh-Hant', audience: true });
  const nearest = modelItems(tomorrow.items).filter(item => /NOT on the asked day/.test(item.note || ''));
  assert.deepEqual(nearest.map(item => item.title).slice(0, 1), ['华埠分馆周六午后：中文书法、填色与桌游']);
  for (const id of ['sfpl-chinatown-creative-saturdays-fall-2026', 'sjpl-berryessa-mandarin-ell-club-fall-2026']) assert.ok(!tomorrow.candidates.some(row => row.id === id), `a nearest record on another day is not a plan candidate: ${id}`);
  // Asking for the answer in Chinese is not a community ask; 不限语言 clears it.
  assert.equal(resolveTaskState({ message: '请用中文回答：周末去哪', today: TODAY, carry: true }).state.community, undefined);
  assert.ok(!resolveTaskState({ message: '不限语言，周末有什么活动', previous: first, today: TODAY, carry: true }).state.community);
  // A plain ask has no facet and no community recall.
  const plain = resolveTaskState({ message: '这周末湾区有什么活动', today: TODAY, carry: true }).state;
  assert.equal(plain.community, undefined);
});

test('H17: the v2 turn carries the facet in its state and a Chinese-community rule', async () => {
  const { assistant, sent } = assistantWith({ answer: { lead: '这周末有两场中文活动。', points: [{ text: '示例[[e1]]。', cardIds: ['e1', 'e2'] }], candidateIds: ['e1', 'e2'] } });
  const first = await ask(assistant, '這週末灣區有華人社區的活動嗎？比如重陽節敬老、中文講座之類的', { locale: 'zh-Hant' });
  assert.equal(first.taskState.community, 'chinese');
  assert.ok(first.localMatches.some(card => card.id === 'sfpl-chinatown-creative-saturdays-fall-2026'));
  sent.length = 0;
  const follow = await ask(assistant, '明天下午就有空，明天有嗎？', { locale: 'zh-Hant', sessionToken: first.assistantSessionToken });
  assert.equal(follow.taskState.community, 'chinese');
  const body = sent[0];
  assert.equal(userTurn(body).state.community, 'chinese');
  assert.ok(JSON.stringify(body.messages).includes('Chinese-language or Chinese-community events'), 'the turn rule rides with the turn, not in the cached system block');
  assert.ok(!JSON.stringify(body.system).includes('Chinese-community'));
});

// Review of 3efe2b8: the facet is for event and activity asks. A doctor, a school, a shop or
// a restaurant that mentions 中文 / 华人 / Chinese neither sets nor keeps it.
const NOT_COMMUNITY_EVENT_ASKS = [
  ['zh-Hans', '有没有会说中文的儿科医生'], ['zh-Hans', '中文学校怎么报名'], ['zh-Hans', '附近有什么华人超市'],
  ['zh-Hant', '有沒有會說中文的兒科醫生'], ['zh-Hant', '中文學校怎麼報名'], ['zh-Hant', '附近有什麼華人超市'],
  ['en', 'best Chinese restaurant in Cupertino'], ['en', 'Is there a Mandarin-speaking pediatrician in San Jose?'],
];
const CHINESE_EVENT_IDS = new Set(['sjpl-berryessa-mandarin-ell-club-fall-2026', 'smcl-millbrae-chinese-storytime-oct-2026',
  // The SF Chinese-community programmes that reach the API from API-SYNC-3b.
  'sfpl-chinatown-creative-saturdays-fall-2026', 'sfpl-marina-wild-goose-qigong-oct-2026', 'sfpl-richmond-hk-film-the-killer-2026', 'sfpl-excelsior-multilingual-tech-help-2026',
  'chsa-lily-qi-book-talk-nov8-2026', 'sfpl-chinese-book-club-nov14-2026', 'sfpl-richmond-hk-film-hard-boiled-2026']);

test('H17 review: a doctor, school, supermarket or restaurant ask never sets the Chinese-community facet, in every language', () => {
  for (const [, message] of NOT_COMMUNITY_EVENT_ASKS) assert.equal(resolveTaskState({ message, today: TODAY, carry: true }).state.community, undefined, message);
  // Event asks still set it, in every language.
  for (const message of ['这周六有什么华人活动', '這週六有什麼華人活動', 'Any Chinese story time this Saturday?', 'Are there any Mandarin-speaking community events in the Bay Area this weekend?'])
    assert.equal(resolveTaskState({ message, today: TODAY, carry: true }).state.community, 'chinese', message);
  // A later ask about something else ends it; a bare follow-up keeps it.
  const first = resolveTaskState({ message: '这周六有什么华人活动', today: TODAY, carry: true }).state;
  for (const message of ['有没有会说中文的儿科医生', 'Cupertino 有什么好的儿科医生', '中文学校怎么报名', '附近有什么華人超市'])
    assert.equal(resolveTaskState({ message, previous: first, today: TODAY, carry: true }).state.community, undefined, message);
  for (const message of ['明天有吗？', '那周日呢', '帮我把前两个排成一天'])
    assert.equal(resolveTaskState({ message, previous: first, today: TODAY, carry: true }).state.community, 'chinese', message);
});

test('H17 review: those asks get no Chinese-event preview cards, records or turn rule (the L1 case still leads with Chinese-community events)', async () => {
  for (const [locale, message] of NOT_COMMUNITY_EVENT_ASKS) {
    const { assistant, sent } = assistantWith({ answer: { lead: '可以。' } });
    const previews = [];
    const result = await ask(assistant, message, { locale, onQuickCard: cards => { previews.push(...cards); } });
    assert.ok(!previews.some(card => CHINESE_EVENT_IDS.has(card.id)), `${message}: ${previews.map(card => card.id)}`);
    assert.ok(!(result.localMatches || []).some(card => CHINESE_EVENT_IDS.has(card.id)), message);
    assert.ok(!JSON.stringify(sent).includes('Chinese-language or Chinese-community events'), message);
  }
  const state = resolveTaskState({ message: '这周六有什么华人活动', today: TODAY, carry: true }).state;
  const saturday = buildFastEvidence({ query: '这周六有什么华人活动', originalQuery: '这周六有什么华人活动', state, guideCatalog: guides, catalog, today: TODAY, locale: 'zh-Hans', audience: true });
  // Saturday 10/17 has four: SF Chinatown, Marina qigong, the Richmond Cantonese film (API-SYNC-3b) and Berryessa.
  assert.deepEqual(saturday.items.slice(0, 4).map(item => item.id), ['sfpl-chinatown-creative-saturdays-fall-2026', 'sfpl-marina-wild-goose-qigong-oct-2026', 'sfpl-richmond-hk-film-the-killer-2026', 'sjpl-berryessa-mandarin-ell-club-fall-2026']);
});

// ---------------------------------------------------------------- H10

function governed(governance, fn, path) {
  const req = new EventEmitter(); req.path = path; req.ip = 'fixture-visitor'; req.body = {};
  const res = new EventEmitter(); res.statusCode = 200; res.writableEnded = false; res.status = code => { res.statusCode = code; return res; }; res.set = () => res;
  res.json = body => { res.writableEnded = true; res.emit('finish'); return body; };
  return new Promise((resolve, reject) => governance.middleware(async () => null)(req, res, () => Promise.resolve().then(fn).then(value => { res.json({}); resolve(value); }, error => { res.json({}); reject(error); })));
}

test('H10: BayBay has its own daily share; /plan and translation spend the shared one, and each claim reports what is left', async () => {
  const models = createMemoryModels();
  const governance = createAiGovernance({ Model: models.AiGovernance, config: { JWT_SECRET: SECRET, AI_GUEST_DAILY_LIMIT: '1', AI_GUEST_BAYBAY_DAILY_LIMIT: '3' }, now: () => NOW });
  await governed(governance, () => reserveAiCall(), '/api/planner/recommend');
  await assert.rejects(governed(governance, () => reserveAiCall(), '/api/posts/p1/translation'), error => error.code === 'AI_DAILY_LIMIT');
  const left = [];
  for (let n = 0; n < 3; n++) left.push(await governed(governance, async () => { await reserveAiCall(); return aiExecution().quota; }, '/api/ai/guide-chat'));
  assert.deepEqual(left.map(row => row.remaining), [2, 1, 0], 'the shared share was used up; BayBay still answered three times');
  assert.equal(left[0].limit, 3);
  assert.match(left[0].resetAt, /^2026-10-14T07:00:00/);
  await assert.rejects(governed(governance, () => reserveAiCall(), '/api/ai/guide-chat'), error => error.code === 'AI_DAILY_LIMIT');
  const usage = await governance.usage({ ip: 'fixture-visitor' });
  assert.equal(usage.remaining, 0);
  assert.deepEqual({ remaining: usage.baybay.remaining, limit: usage.baybay.limit }, { remaining: 0, limit: 3 });
});

test('H10: a guide-chat answer returns quota {remaining, limit, resetAt} from its own claim', async t => {
  const fastText = JSON.stringify({ lead: '金门公园这周末有免费活动。', points: [], candidateIds: [], followups: [], coverage: [], gap: '' });
  const app = createApplication({ config: { NODE_ENV: 'test', JWT_SECRET: SECRET, BAYBAY_AI_PROVIDER: 'anthropic', ANTHROPIC_API_KEY: 'fixture', AI_GUEST_BAYBAY_DAILY_LIMIT: '5', BAYBAY_STATE_SECRET: 'api-fix5-http-task-secret-0123456789' },
    models: createMemoryModels(), plannerNow: () => NOW,
    ai: { baybay: async () => ({ status: 'completed', model: 'claude-sonnet-5-5', usage: { input_tokens: 10, output_tokens: 10 }, output: [{ type: 'message', role: 'assistant', content: [{ type: 'output_text', text: fastText }] }] }) } });
  await new Promise(resolve => app.server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise(resolve => app.io.close(resolve)));
  const origin = `http://127.0.0.1:${app.server.address().port}`;
  const chat = async message => (await fetch(`${origin}/api/ai/guide-chat`, { method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ message, assistantVersion: 2, searchMode: 'site', locale: 'zh-Hans' }) })).json();
  const first = await chat('旧金山这周末有什么活动');
  const second = await chat('金门公园这周末有什么免费活动');
  assert.deepEqual([first.quota?.remaining, second.quota?.remaining], [4, 3], JSON.stringify(first.quota));
  assert.equal(first.quota.limit, 5);
  const usage = await (await fetch(`${origin}/api/ai/usage`)).json();
  assert.equal(usage.baybay.remaining, 3);
});

test('H03 review: a refused run share makes no model call and leaves the visitor\'s BayBay AI share unspent', async t => {
  const fastText = JSON.stringify({ lead: '金门公园这周末有免费活动。', points: [], candidateIds: [], followups: [], coverage: [], gap: '' });
  let calls = 0;
  const app = createApplication({ config: { NODE_ENV: 'test', JWT_SECRET: SECRET, BAYBAY_AI_PROVIDER: 'anthropic', ANTHROPIC_API_KEY: 'fixture', AI_GUEST_BAYBAY_DAILY_LIMIT: '5', BAYBAY_VISITOR_RUN_LIMIT: '1', BAYBAY_STATE_SECRET: 'api-fix5-http-task-secret-0123456789' },
    models: createMemoryModels(), plannerNow: () => NOW,
    ai: { baybay: async () => { calls++; return { status: 'completed', model: 'claude-sonnet-5-5', usage: { input_tokens: 10, output_tokens: 10 }, output: [{ type: 'message', role: 'assistant', content: [{ type: 'output_text', text: fastText }] }] }; } } });
  await new Promise(resolve => app.server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise(resolve => app.io.close(resolve)));
  const origin = `http://127.0.0.1:${app.server.address().port}`;
  const chat = async message => (await fetch(`${origin}/api/ai/guide-chat`, { method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ message, assistantVersion: 2, searchMode: 'site', locale: 'zh-Hans' }) })).json();
  const left = async () => (await (await fetch(`${origin}/api/ai/usage`)).json()).baybay.remaining;
  await chat('旧金山这周末有什么活动');
  assert.equal(calls, 1);
  assert.equal(await left(), 4);
  await chat('金门公园这周末有什么免费活动');
  assert.equal(calls, 1, 'no model call once the visitor\'s run share is spent');
  await new Promise(resolve => setTimeout(resolve, 50));
  assert.equal(await left(), 4, 'the refused run left the AI share where it was');
});

// ---------------------------------------------------------------- H03

test('H03: a question never waits for a slow source-monitor list; the index lands in the background and flags later answers', async () => {
  let release, reads = 0;
  const rows = new Promise(resolve => { release = resolve; });
  const { assistant } = assistantWith({ answer: { lead: '可以。' }, monitorStatus: () => { reads++; return rows; } });
  const started = Date.now();
  const cold = await ask(assistant, '这周末旧金山有什么适合孩子的免费活动？');
  assert.ok(Date.now() - started < 1500, 'the cold wait is bounded (MONITOR_COLD_WAIT_MS)');
  assert.ok(cold.research.timings.monitorMs <= 400, `${cold.research.timings.monitorMs} ms`);
  const url = cold.evidence.map(row => row.url).find(value => /^https:\/\//.test(value));
  release([{ url, reviewStatus: 'pending' }]);
  await new Promise(resolve => setImmediate(resolve));
  const warm = await ask(assistant, '这周末旧金山有什么适合孩子的免费活动？');
  assert.equal(warm.research.timings.monitorMs, 0);
  assert.equal(warm.evidence.find(row => row.url === url)?.needsReview, true);
  assert.equal(reads, 1, 'one read, started at boot; a fresh index is not read again');
});

test('H03: the run-share claim starts beside retrieval and an existing quota row costs one round trip', async () => {
  const calls = [];
  const rows = new Map();
  const Quota = {
    updateOne: async ({ id }) => { calls.push(`upsert ${id.split(':')[0]}`); if (!rows.has(id)) rows.set(id, { count: 0 }); return {}; },
    findOneAndUpdate: async ({ id, count }) => { calls.push(`claim ${id.split(':')[0]}`); const row = rows.get(id); if (!row || !(row.count < count.$lt)) return null; row.count++; return { ...row }; },
  };
  const { assistant } = assistantWith({ answer: { lead: '可以。' }, Quota });
  await ask(assistant, '旧金山这周末有什么活动');
  calls.length = 0;
  await ask(assistant, '金门公园这周末有什么免费活动');
  assert.deepEqual(calls, ['claim baybay-run', 'claim baybay-agent'], 'no upsert once today\'s rows exist');
});
