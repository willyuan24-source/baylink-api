// API-BB-7: the follow-ups of the API-BB-6 live check (10-16) and eval block O. Shipped data with a fixed day; a fixture
// provider, no network.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { createBayBayAssistant } = require('../lib/baybayAgent');
const { loadPlannerCatalog } = require('../lib/planner');
const { createPublicContext, loadDiscoveryCatalog } = require('../lib/publicContext');
const { resolveTaskState } = require('../lib/baybayState');
const { buildFastEvidence, modelItems } = require('../lib/baybayEvidence');
const { normalizeGuideQuery } = require('../lib/guideLocale');
const { englishClock } = require('../lib/baybayQuality');
const { professionalTopics, professionalFollowup, professionalResponse } = require('../lib/safetyRouting');
const { buildItinerary } = require('../lib/baybayPlan');
const { sseFor, sseResponse } = require('./support/anthropic-sse');
const guides = require('../data/guide-catalog.json');
const guidesEn = require('../data/guide-catalog.en.json');

const planner = loadPlannerCatalog();
const discoveries = { ...loadDiscoveryCatalog(), english: loadDiscoveryCatalog(undefined, true) };
const LIVE = '2026-10-16T21:02:00-07:00';

// The fixture model: plan stops when there is a plan, else the first four event / place / offer items in evidence order.
function fixtureAnswer(body) {
  const user = JSON.parse(body.messages[0].content[0].text);
  const stops = user.currentPlan?.stops || [];
  if (stops.length) return { lead: '可以这样走。', points: stops.map(stop => ({ text: `${stop.title} [[${stop.refs[0]}]]`, cardIds: [] })), candidateIds: stops.map(stop => stop.id), followups: [], coverage: [], gap: '' };
  const items = (user.evidence || []).filter(item => ['event', 'place', 'offer', 'opening'].includes(item.kind)).slice(0, 4);
  return { lead: items[0] ? `先看 ${items[0].title}。` : '有这些选择。', points: items.map(item => ({ text: `${item.title} [[${item.ref}]]`, cardIds: [item.ref] })), candidateIds: [], followups: [], coverage: [], gap: '' };
}
function fixture({ now = LIVE, respond = fixtureAnswer } = {}) {
  const sent = [];
  const message = text => ({ type: 'message', id: 'msg-fixture', model: 'claude-sonnet-5-5', role: 'assistant', stop_reason: 'end_turn', content: [{ type: 'text', text }], usage: { input_tokens: 40, output_tokens: 60 } });
  const reply = value => ({ ok: true, status: 200, json: async () => value, clone() { return this; }, text: async () => JSON.stringify(value) });
  const today = new Intl.DateTimeFormat('sv-SE', { timeZone: 'America/Los_Angeles' }).format(new Date(now));
  const assistant = createBayBayAssistant({ config: { BAYBAY_AI_PROVIDER: 'anthropic', ANTHROPIC_API_KEY: 'fixture-anthropic-only', BAYBAY_STATE_SECRET: 'api-bb-7-isolated-secret-0123456789', BAYBAY_DAILY_RUN_LIMIT: '1000' },
    guideCatalog: guides, englishGuideCatalog: guidesEn, catalog: planner, now: () => Date.parse(now), isTest: false, Quota: { findOneAndUpdate: async () => ({ count: 1 }), updateOne: async () => ({}) },
    fetchImpl: async (url, init) => {
      sent.push(init.body);
      const body = JSON.parse(init.body);
      const answer = message(JSON.stringify(await respond(body, sent.length)));
      return body.stream ? sseResponse(sseFor(answer)) : reply(answer);
    } });
  const run = (text, { locale = /[㐀-鿿]/.test(text) ? 'zh-Hans' : 'en', ...extra } = {}) => assistant.run({ message: text, locale, currentPath: locale === 'en' ? '/en' : '/', history: [], searchMode: 'site', webAccess: { allowed: false },
    pageContext: createPublicContext({ guideCatalog: guides }).resolve({ context: { currentPath: '/' }, currentPath: '/', today, locale }), ...extra });
  const evidence = () => JSON.parse(JSON.parse(sent[0]).messages[0].content[0].text).evidence || [];
  return { sent, run, evidence };
}
const stateOf = (message, previous, today = '2026-10-16') => resolveTaskState({ message, previous, today, carry: true, catalog: planner }).state;
const fast = (message, locale, today = '2026-10-16') => {
  const state = stateOf(message, undefined, today);
  const site = buildFastEvidence({ query: normalizeGuideQuery(message), originalQuery: message, state, guideCatalog: locale === 'en' ? guidesEn : guides, catalog: planner, discoveries, today, locale, audience: true });
  return { state, items: site.items, model: modelItems(site.items) };
};

// ---- L09: the family signal and indoor family options ----
test('亲子 / 带娃 / 孩子 / 小朋友 / with kids / family is a family signal in task state, kept by a follow-up; no kids clears it', () => {
  for (const message of ['这周末如果下雨，San Jose 有什么室内亲子活动？', '這週末下雨，San Jose 有什麼室內親子活動？', '周六带娃去哪', '小朋友周日能去哪玩', 'It might rain this weekend. Any indoor things to do with kids in San Jose?', 'Family things to do in Oakland on Saturday?', '周六带 5 岁孩子去 Oakland'])
    assert.equal(stateOf(message).family, true, message);
  for (const message of ['周六 Oakland 有什么好玩的？', 'I need a family doctor in Fremont', 'Any farmers markets in the East Bay on Saturday morning?']) assert.equal(stateOf(message).family, undefined, message);
  const first = stateOf('12月5号带娃去哪');
  assert.equal(stateOf('那周日呢', first).family, true, 'a follow-up keeps it');
  assert.equal(stateOf('这次不带孩子，周六 Oakland 有什么？', first).family, undefined, 'no kids clears it');
});

test('live L09: a rainy San Jose family ask leads with fully indoor family places, notes part-outdoor ones, and never takes the adults\' dinner theatre (zh-Hans, zh-Hant, en)', async () => {
  for (const [message, locale] of [['这周末如果下雨，San Jose 有什么室内亲子活动？', 'zh-Hans'], ['這週末下雨，San Jose 有什麼室內親子活動？', 'zh-Hant'], ['It might rain this weekend. Any indoor things to do with kids in San Jose?', 'en'], ['Rainy weekend in San Jose with kids, indoor ideas?', 'en']]) {
    const { run, evidence } = fixture();
    const result = await run(message, { locale });
    assert.equal(result.taskState.family, true, message);
    assert.equal(result.taskState.setting, 'indoor', message);
    const items = evidence();
    const rowOf = item => planner.places.find(row => row.title === item.title || (row.aliases || []).includes(item.title)) || planner.events.find(row => row.title === item.title || (row.aliases || []).includes(item.title));
    const entities = items.filter(item => ['event', 'place'].includes(item.kind));
    // The first entity is a fully indoor place, and at least three indoor or part-indoor family options are in the evidence.
    assert.equal(rowOf(entities[0])?.planning?.setting, 'indoor', `${message}: ${entities.map(item => item.title).join(' | ')}`);
    const indoor = entities.filter(item => ['indoor', 'mixed'].includes(rowOf(item)?.planning?.setting));
    assert.ok(indoor.length >= 3, `${message}: ${indoor.map(item => item.title).join(' | ')}`);
    for (const item of entities.filter(row => rowOf(row)?.planning?.setting === 'mixed')) assert.match(item.note || '', /Part outdoors/, item.title);
    // The fixture answer's first point is an indoor place; no adults' evening record anywhere in the payload.
    assert.ok(result.points.length >= 3, message);
    assert.ok(!(result.evidence || []).some(row => /Funeral For a Gangster|悬疑晚餐|懸疑晚餐/.test(row.title)), `${message}: ${(result.evidence || []).map(row => row.title).join(' | ')}`);
  }
});

// ---- X1: the day's storytime on a dated family ask ----
test('live X1: 12月5日东湾 family ask has the Oakland Main storytime in the top five evidence and in the answer\'s points (zh-Hans, en)', async () => {
  for (const [message, locale] of [['12月5日东湾有什么适合孩子的活动', 'zh-Hans'], ['What can kids do in the East Bay on December 5?', 'en']]) {
    const { run } = fixture();
    const result = await run(message, { locale });
    const story = title => /奥克兰总馆周六亲子故事时间|family storytime at Oakland/i.test(title || '');
    const rank = (result.evidence || []).findIndex(row => story(row.title));
    assert.ok(rank >= 0 && rank < 5, `${message}: rank ${rank + 1}: ${(result.evidence || []).slice(0, 8).map(row => row.title).join(' | ')}`);
    assert.ok(result.points.some(point => story(point.text)), `${message}: ${result.points.map(point => point.text).join(' | ')}`);
  }
  // Before (base a976e0c): 9th of 10 model items, 11th of 40 in the payload evidence.
  const { model } = fast('12月5日东湾有什么适合孩子的活动', 'zh-Hans', '2026-10-16');
  assert.ok(model.slice(0, 5).some(item => /奥克兰总馆周六亲子故事时间/.test(item.title)), model.map(item => item.title).join(' | '));
  assert.ok(model.some(item => /Pleasanton/.test(item.title)) && model.some(item => /Danville/.test(item.title)), 'the one-off parade and book sale stay');
});

// ---- L06: the asked part of the day and closing times ----
test('live L06: an afternoon walk ask does not lead with (or see) a market that closes at 14:00; a market ask keeps it with a closing note (zh-Hans, zh-Hant, en)', async () => {
  for (const [message, locale] of [['周日下午想在 Fremont 带爸妈散散步，有什么好去处？', 'zh-Hans'], ['週日下午想在 Fremont 帶爸媽散散步，有什麼好去處？', 'zh-Hant'], ['Where can I take my parents for a walk in Fremont on Sunday afternoon?', 'en']]) {
    const { run, evidence } = fixture();
    const result = await run(message, { locale });
    assert.ok(!evidence().some(item => /Irvington/.test(item.title)), `${message}: ${evidence().map(item => item.title).join(' | ')}`);
    assert.doesNotMatch(result.lead, /Irvington|市集|market/i, message);
  }
  // The market named: kept, with its closing time.
  const { model } = fast('周日下午 Fremont 有农夫市集吗？', 'zh-Hans');
  const market = model.find(item => /Irvington/.test(item.title));
  assert.ok(market, model.map(item => item.title).join(' | '));
  assert.match(market.note, /^Closes at 14:00, before the asked part of the day/);
  // A morning ask is not narrowed.
  assert.ok(fast('周日上午 Fremont 有农夫市集吗？', 'zh-Hans').model.some(item => /Irvington/.test(item.title) && !/Closes at/.test(item.note || '')));
});

// ---- L07: plan stop times, links, flags and route ----
test('live L07: the day plan uses a record\'s own session times, links event stops to their page, flags official-site links as external, and keeps stops on one route', async () => {
  const { run, sent } = fixture();
  const result = await run('周六想带爸妈在旧金山玩半天，坐公交，帮我排个行程');
  const stops = result.assistantPlan.stops;
  assert.ok(stops.length >= 3, stops.map(stop => stop.title).join(' | '));
  for (const stop of stops) {
    if (stop.kind === 'event') assert.match(stop.path || '', /^\/events\/[a-z0-9-]+$/, `${stop.title}: an event stop links to its BAYLINK page`);
    assert.equal(stop.external, /^https?:\/\//.test(stop.path || ''), `${stop.title}: ${stop.path} external ${stop.external}`);
  }
  // No stop more than 3 km from every other stop when the stops have locations (the Mission Bay festival was 不顺路).
  const located = stops.filter(stop => Number.isFinite(stop.location?.lat));
  const km = (a, b) => Math.hypot((a.lat - b.lat) * 111, (a.lng - b.lng) * 111 * Math.cos(a.lat * Math.PI / 180));
  for (const stop of located) assert.ok(located.some(other => other !== stop && km(stop.location, other.location) <= 3), stop.title);
  assert.ok(stops.every(stop => stop.location), 'every chosen stop has a known location');
  assert.equal(sent.length, 1);
  // A record whose only times are its sessions: the science festival's 11:00–16:00 is an opening window, not "missing hours".
  const festival = planner.events.find(row => row.id === 'sf-bay-area-science-festival-2026');
  const plan = buildItinerary({ state: { date: '2026-10-17', city: 'San Francisco' }, candidates: [{ ...festival, kind: 'event' }], selectedIds: [`event:${festival.id}`], now: Date.parse(LIVE) });
  assert.deepEqual(plan.stops[0].openingWindows, [{ open: '11:00', close: '16:00' }]);
  assert.ok(!plan.checks.some(check => check.code === 'opening_hours'), JSON.stringify(plan.checks.map(check => check.code)));
  // The planner hand-off keeps catalog places whose link is their official site.
  assert.ok(result.assistantPlan.handoff && result.assistantPlan.handoff.stops.length === stops.length, JSON.stringify(result.assistantPlan.handoff));
});

test('a day plan puts a stop that closes by 15:00 first and keeps same-spot stops together', () => {
  const market = planner.events.find(row => row.id === 'ferry-plaza-farmers-market-2026-autumn');
  const ferry = planner.places.find(row => row.id === 'venue-ferry-building');
  const chinatown = planner.places.find(row => row.id === 'chinatown');
  const plan = buildItinerary({ state: { date: '2026-10-17', city: 'San Francisco' }, candidates: [{ ...chinatown, kind: 'place' }, { ...ferry, kind: 'place' }, { ...market, kind: 'event' }], now: Date.parse(LIVE) });
  assert.deepEqual(plan.stops.map(stop => stop.entityId), ['ferry-plaza-farmers-market-2026-autumn', 'venue-ferry-building', 'chinatown']);
});

// ---- English times ----
test('English readers get 12-hour times: weekly schedules, the asked day\'s session and a net on the answer', () => {
  const { model } = fast('Any farmers markets in the East Bay on Saturday morning?', 'en');
  const grand = model.find(item => /Grand Lake/.test(item.title));
  assert.equal(grand.when, 'Every Saturday 9am–2pm · next listed: Sat, Oct 17');
  const story = fast('What can kids do in the East Bay on December 5?', 'en').model.find(item => /family storytime at Oakland/i.test(item.title));
  assert.match(story.when, /^Sat, Dec 5 10:30–11am /);
  for (const [text, want] of [['Grand Lake runs Saturdays 9:00-14:00 at Splash Pad Park.', 'Grand Lake runs Saturdays 9am–2pm at Splash Pad Park.'], ['Doors 18:30, show 19:00 to 21:30.', 'Doors 6:30pm, show 7–9:30pm.'],
    ['Storytime 10:30–11:00 [[e2]]', 'Storytime 10:30–11am [[e2]]'], ['Open 12:00-17:00', 'Open 12–5pm'], ['Already 9am–2pm and 10:30 am.', 'Already 9am–2pm and 10:30 am.'], ['Score 3:1, ratio 16:9 at 2:30pm', 'Score 3:1, ratio 16:9 at 2:30pm']]) assert.equal(englishClock(text), want);
  // Chinese answers keep 24-hour times.
  const { englishClockRepair } = require('../lib/baybayQuality');
  assert.equal(englishClockRepair({ lead: '周六 9:00–14:00', points: [], gap: '' }, { locale: 'zh-Hans' }).repaired, false);
});

test('an English answer that copies 24-hour times reaches the reader in 12-hour times (L08)', async () => {
  const { run } = fixture({ respond: body => {
    const items = JSON.parse(body.messages[0].content[0].text).evidence;
    const ref = items.find(item => /Grand Lake/.test(item.title))?.ref || 'e1';
    return { lead: 'Yes, Grand Lake in Oakland runs Saturdays 9:00-14:00.', points: [{ text: `Grand Lake runs Saturdays 9:00-14:00 at Splash Pad Park [[${ref}]]`, cardIds: [ref] }], candidateIds: [], followups: [], coverage: [], gap: '' };
  } });
  const result = await run('Any farmers markets in the East Bay on Saturday morning?', { locale: 'en' });
  assert.equal(result.lead, 'Yes, Grand Lake in Oakland runs Saturdays 9am–2pm.');
  assert.doesNotMatch(result.answer, /\b\d{1,2}:00-\d{1,2}:00\b/);
  assert.ok(result.research.warnings.includes('answer_english_clock_repaired'));
});

// ---- Block O dev types (state and guard) ----
test('block O dev: ages said as "almost N" and 快N岁, a weekday inside an event name, neighbourhoods, a zero budget', () => {
  assert.deepEqual(stateOf('My son is two, almost three. Is there a toddler storytime in Fremont this Saturday?').childAges, [2]);
  assert.deepEqual(stateOf('女儿三岁多，快四岁了，这周六 Oakland 有什么适合她的活动？').childAges, [3]);
  assert.deepEqual(stateOf('孩子快五岁了，周六 Fremont 去哪？').childAges, [4]);
  assert.deepEqual(stateOf('孩子快滿五歲，週六 Fremont 去哪？').childAges, [4]);
  assert.deepEqual(stateOf('She is 7, almost 8 hours of sleep is enough, any events Saturday in Oakland?').childAges, [], 'almost 8 hours is not an age');
  for (const [message, date, ages, city] of [['Oakland的2026年12月12日Family Saturday活动，我带6岁的孩子去，门票写5美元，能只带10美元吗？', '2026-12-12', [6], 'Oakland'],
    ['On December 12, 2026 at the Berkeley Super Sunday craft fair with my 9-year-old; parking is 8 dollars, is 10 enough?', '2026-12-12', [9], 'Berkeley']]) {
    const state = stateOf(message);
    assert.deepEqual([state.date, state.childAges, state.city], [date, ages, city], message);
  }
  // A real second date is still two dates.
  assert.equal(stateOf('12月12日或12月13日 Oakland 有什么亲子活动？').date, null);
  for (const [message, city] of [['周六想带孩子去 Mission District 逛逛，有什么活动？', 'San Francisco'], ['我住Richmond District，週日附近圖書館有中文活動嗎？', 'San Francisco'], ['Anything fun for kids in Willow Glen this weekend?', 'San Jose'],
    ['Richmond 周六有什么活动？', 'Richmond'], ['Inner Sunset 周日有什么亲子活动？', 'San Francisco']]) assert.equal(stateOf(message).city, city, message);
  const zh = stateOf('预算改成0了，城市和孩子都不变，还有哪些能去？', stateOf('周六带6岁孩子在 San Jose 玩，门票预算100美元，有什么推荐？'));
  assert.deepEqual([zh.budget, zh.freeOnly, zh.childAges, zh.city], [0, true, [6], 'San Jose']);
  const en = stateOf('Actually we have no money for tickets now. Same city and kid.', stateOf('Saturday in Oakland with my 7-year-old. We can pay for tickets. Ideas?'));
  assert.deepEqual([en.budget, en.freeOnly, en.childAges, en.city], [0, true, [7], 'Oakland']);
});

test('block O dev: Social Security credits are SSA; a withheld deposit is legal; a follow-up without its topic noun keeps the guard', () => {
  for (const message of ['我在 Oakland 打工三年了，社安积分够不够领退休金？', '社會安全退休金要幾個積分？', 'How many Social Security credits do I need to get retirement benefits?']) assert.deepEqual(professionalTopics(message), ['ssa'], message);
  // A Medicare question that mentions Social Security retirement stays Medicare (block N dev N-15).
  for (const message of ['我爸还没领社安退休金，65岁时 Medicare 会自动生效吗？', 'My mom is not on Social Security retirement yet; does Medicare start by itself at 65?']) assert.deepEqual(professionalTopics(message), ['medicare'], message);
  const credits = professionalResponse('How many Social Security credits do I need to get retirement benefits?', 'en', { guideCatalog: guides, englishGuideCatalog: guidesEn });
  assert.deepEqual(credits.safety.resources.map(row => row.id), ['ssa-benefits']);
  assert.deepEqual(credits.safety.guides.map(row => row.slug), ['bay-area-social-security-retirement-preparation-guide']);
  assert.deepEqual(professionalResponse('我想办社安卡', 'zh-Hans', { guideCatalog: guides }).safety.resources.map(row => row.id), ['ssa'], 'an SSN question keeps the card resource');
  for (const message of ['我在 Fremont 退租了，房东扣了我一大半押金说是清洁费，也没给收据，正常吗？', '房東把押金都扣了', 'I moved out a month ago and the landlord still has not sent back the security deposit.', 'The landlord is taking money out of my deposit for cleaning.'])
    assert.ok(professionalTopics(message).includes('legal'), message);
  for (const message of ['去 San Mateo On Ice 租冰鞋要交押金吗？', 'Do I need a deposit to rent skates?']) assert.ok(!professionalTopics(message).includes('legal'), message);
  const history = text => [{ role: 'user', content: text }, { role: 'assistant', content: '…' }];
  assert.deepEqual(professionalFollowup('她不会用电脑，也不想开网上账号，还有什么办法？', history('我住 San Jose，想帮妈妈申请 Medi-Cal。'))?.topics, ['insurance']);
  assert.deepEqual(professionalFollowup('He says he will mail a list of charges next month. Can he wait that long?', history('My landlord in Oakland kept my whole security deposit.'))?.topics, ['legal']);
  assert.deepEqual(professionalFollowup('他還能怎麼辦？', history('我爸想申請 Medicare'))?.topics, ['medicare']);
  for (const message of ['这周末带孩子去 San Jose 哪里玩？', 'Any free museums in San Francisco this Sunday?']) assert.equal(professionalFollowup(message, history('想帮爸爸在线申请 Medi-Cal。')), null, message);
});

test('eval block O: 40 cases in 50 turns, dev and held-out fixed before any code change, with golds the catalog can meet', async () => {
  const { pathToFileURL } = require('node:url');
  const { validateCases } = await import(pathToFileURL(path.join(__dirname, '..', 'scripts', 'eval', 'gold.mjs')).href);
  const book = JSON.parse(fs.readFileSync(path.join(__dirname, '..', 'scripts', 'eval', 'cases-O-bb7.json'), 'utf8'));
  assert.equal(book.block, 'O'); assert.equal(book.pinnedNow, '2026-10-16T10:00:00-07:00');
  assert.equal(validateCases(book.cases), 50);
  assert.equal(book.cases.length, 40);
  assert.equal(book.cases.filter(item => item.split === 'dev').length, 21);
  // Each of block N's seven held-out failure types has dev and held-out cases.
  for (const tag of ['age_almost', 'dated_city_age', 'neighbourhood_city', 'ssa_benefits', 'deposit', 'budget_zero', 'followup_topic'])
    for (const split of ['dev', 'held-out']) assert.ok(book.cases.some(item => item.split === split && item.tags.includes(tag)), `${tag} ${split}`);
  const corpus = ['guide-catalog.json', 'guide-catalog.en.json', 'planner-catalog.json'].map(file => fs.readFileSync(path.join(__dirname, '..', 'data', file), 'utf8')).join('\n');
  for (const turn of book.cases.flatMap(item => item.turns)) for (const rule of turn.gold.evidenceIncludes || []) assert.ok([].concat(rule).some(source => new RegExp(source, 'iu').test(corpus)), `${turn.id}: ${rule}`);
  const arms = JSON.parse(fs.readFileSync(path.join(__dirname, '..', 'scripts', 'eval', 'arms.json'), 'utf8'));
  assert.deepEqual(arms.sets.bb7, { blocks: ['O'], arms: ['v2-code-defaults'], baselineArm: 'v2-code-defaults' });
});

// ---- Review 10-16 (round 1) ----
test('review: dotted a.m. / p.m. times stay as written; 24-hour times still become 12-hour', () => {
  for (const text of ['Runs 9:00 a.m.-2:00 p.m.', '4:30 p.m.', '10:30 a.m. daily', 'Opens 10:30 a.m.', 'Office hours 8:00 a.m. to 5:00 p.m.']) assert.equal(englishClock(text), text);
  assert.equal(englishClock('Open 9:00-14:00, doors 18:30.'), 'Open 9am–2pm, doors 6:30pm.');
});

test('review: an outing after a professional turn is not a professional follow-up (zh-Hans, zh-Hant, en); professional follow-ups still are', () => {
  const history = message => [{ role: 'user', content: message }, { role: 'assistant', content: '…' }];
  for (const [message, before] of [
    ['她周六想去动物园，可以吗？', '我住 San Jose，想帮妈妈申请 Medi-Cal。'],
    ['她週六想去動物園，可以嗎？', '我住 San Jose，想幫媽媽申請 Medi-Cal。'],
    ['Can we take her to the zoo this Saturday?', 'I live in San Jose and want to help my mom apply for Medi-Cal.'],
    ['她喜欢画画，周六有什么画画课？', '我爸想申请 Medicare'],
    ['她喜歡畫畫，週六有什麼畫畫課？', '我爸想申請 Medicare'],
    ['She likes painting. Any art classes on Saturday?', 'My dad wants to sign up for Medicare.'],
    ['那她明天想去吃早茶，哪家好？', '我爸的绿卡快过期了，怎么续？'],
    ['那她明天想去飲茶，哪家好？', '我爸的綠卡快過期了，怎麼續？'],
    ['Then she wants dim sum tomorrow. Which place is good?', 'My dad\'s green card expires soon. How do we renew it?'],
  ]) assert.equal(professionalFollowup(message, history(before)), null, message);
  for (const [message, before, topic] of [
    ['他英文不好，可以找誰用中文問？', '我爸剛滿65歲，想問 Medicare 怎麼報名。', 'medicare'],
    ['She lost the renewal letter. What now?', 'How do I renew my mom\'s Medi-Cal in Fremont?', 'insurance'],
    ['她不會用電腦，還有什麼辦法？', '想幫媽媽申請 Medi-Cal。', 'insurance'],
  ]) assert.deepEqual(professionalFollowup(message, history(before))?.topics, [topic], message);
});

test('review: a chosen stop order is kept; the engine\'s own order does not put a 12:00 session before a museum that is open from the start', () => {
  const museum = planner.places.find(row => row.id === 'venue-sfmoma');
  const pumpkin = planner.events.find(row => row.id === 'sf-sunnydale-pumpkin-fest-2026');
  const candidates = [{ ...museum, kind: 'place' }, { ...pumpkin, kind: 'event' }];
  const state = { date: '2026-10-17', city: 'San Francisco', startTime: '10:00' };
  const chosen = buildItinerary({ state, candidates, selectedIds: [`place:${museum.id}`, `event:${pumpkin.id}`], now: Date.parse(LIVE) });
  assert.deepEqual(chosen.stops.map(stop => stop.entityId), [museum.id, pumpkin.id]);
  const reversed = buildItinerary({ state, candidates, selectedIds: [`event:${pumpkin.id}`, `place:${museum.id}`], now: Date.parse(LIVE) });
  assert.deepEqual(reversed.stops.map(stop => stop.entityId), [pumpkin.id, museum.id], 'the user\'s own order, even when it is not the best');
  const auto = buildItinerary({ state, candidates, now: Date.parse(LIVE) });
  assert.deepEqual(auto.stops.map(stop => stop.entityId), [museum.id, pumpkin.id]);
});

test('review: a 3-stop Oakland plan does not visit the OMCA twice (Lake Merritt and venue-omca share the spot and page)', () => {
  const ids = ['venue-oakland-main-library', 'lake-merritt', 'venue-omca'];
  const candidates = ids.map(id => ({ ...planner.places.find(row => row.id === id), kind: 'place' }));
  const plan = buildItinerary({ state: { date: '2026-10-18', city: 'Oakland', startTime: '10:00' }, candidates, now: Date.parse(LIVE) });
  const chosen = plan.stops.map(stop => stop.entityId);
  assert.ok(!(chosen.includes('lake-merritt') && chosen.includes('venue-omca')), chosen.join(' | '));
});

test('review: family asks keep family-friendly evening and fair records; only grown-up evening records are dropped', () => {
  const { adultEvening } = require('../lib/baybayEvidence');
  const row = id => planner.events.find(item => item.id === id);
  for (const id of ['pacific-coast-fog-fest-2026', 'san-jose-365-night-market-october-2026', 'sf-sundown-beetlejuice-2026', 'oakland-autumn-lights-festival-2026', 'roundup-schulz-pearls-jubilee-2026']) assert.equal(adultEvening(row(id)), false, id);
  for (const id of ['sj-funeral-gangster-dinner-2026', 'tiburon-wine-festival-2026', 'r2-vallejo-wonder-after-dark-2026']) assert.equal(adultEvening(row(id)), true, id);
});

test('review: task state false positives (neighbourhood beside a named city, no money for parking, a 0-50 range, "almost 3" o\'clock)', () => {
  for (const [message, city] of [['Any events at Parkside Hall in San Jose this Saturday?', 'San Jose'], ['周六 San Jose Parkside Hall 有什么活动？', 'San Jose'],
    ['Where can I get a good tenderloin steak in San Jose?', 'San Jose'], ['Saturday storytime at the Berryessa branch library?', 'San Jose'], ['Kids events in the Tenderloin on Saturday?', 'San Francisco']]) assert.equal(stateOf(message).city, city, message);
  assert.notEqual(stateOf('Camping at Lake Berryessa this weekend?').city, 'San Jose');
  for (const message of ['I have no money worries, just want the best museum in SF on Sunday', 'No money for parking, so we will take BART. Any museums in SF on Saturday?',
    '预算0-50美元，周六旧金山有什么博物馆？', 'Our budget is 0-20 dollars per person, museums in SF Saturday?']) assert.notEqual(stateOf(message).freeOnly, true, message);
  for (const message of ['It is almost 3, any coffee shop open near Fremont BART?', 'We live almost 5 blocks from Fremont BART, anything on Saturday?',
    'My kid is one of the performers at the Saturday show in Fremont, any parking?', 'The market has nearly 15 stalls, is the Saturday market in Fremont good?']) assert.deepEqual(stateOf(message).childAges, [], message);
  assert.equal(stateOf('It is almost 3, any coffee shop open near Fremont BART?').family, undefined);
  assert.deepEqual(stateOf('Our daughter is almost 6. Any kids events in Palo Alto this Saturday?').childAges, [5]);
  assert.deepEqual(stateOf('She is turning 5 years old soon; Saturday ideas in Oakland?').childAges, [4]);
});

test('review L09: an indoor family ask gives each place\'s recorded hours for the asked day; an evening ask leaves out places that close at 18:00', () => {
  for (const [message, locale, want] of [['这周六 San Jose 下雨，有什么室内亲子活动？', 'zh-Hans', '周六 11:00–18:00'], ['這週六 San Jose 下雨，有什麼室內親子活動？', 'zh-Hant', '週六 11:00–18:00'], ['Indoor things to do with kids in San Jose this Saturday?', 'en', 'Saturday 11am–6pm']]) {
    const sjma = fast(message, locale).model.find(item => /San José Museum of Art/.test(item.title));
    assert.equal(sjma?.when, want, message);
  }
  const evening = fast('这周六晚上 San Jose 有什么适合带孩子的活动？', 'zh-Hans').model;
  assert.ok(!evening.some(item => /San José Museum of Art|King, Jr\. Library/.test(item.title)), evening.map(item => item.title).join(' | '));
});

test('review X1 / L07 in zh-Hant and en: the storytime is in the top five; the plan keeps stops on one route and hands every site stop off', async () => {
  const { run } = fixture();
  const result = await run('12月5日東灣有什麼適合孩子的活動', { locale: 'zh-Hant' });
  const rank = (result.evidence || []).findIndex(row => /奥克兰总馆周六亲子故事时间|奧克蘭總館週六親子故事時間/.test(row.title || ''));
  assert.ok(rank >= 0 && rank < 5, `rank ${rank + 1}: ${(result.evidence || []).slice(0, 8).map(row => row.title).join(' | ')}`);
  const km = (a, b) => Math.hypot((a.lat - b.lat) * 111, (a.lng - b.lng) * 111 * Math.cos(a.lat * Math.PI / 180));
  for (const [message, locale] of [['週六想帶爸媽在舊金山玩半天，坐公車，幫我排個行程', 'zh-Hant'], ['Plan a Saturday half day in San Francisco with my parents by bus', 'en'], ['周六想带爸妈在旧金山玩半天，坐公交，帮我排个行程', 'zh-Hans']]) {
    const plan = (await fixture().run(message, { locale })).assistantPlan;
    const stops = plan.stops;
    assert.ok(stops.length >= 2, `${message}: ${stops.map(stop => stop.title).join(' | ')}`);
    const located = stops.filter(stop => Number.isFinite(stop.location?.lat));
    assert.ok(located.length >= 2, `${message}: ${stops.map(stop => stop.title).join(' | ')}`);
    for (const stop of located) assert.ok(located.some(other => other !== stop && km(stop.location, other.location) <= 3), `${message}: ${stop.title}`);
    const ids = stops.map(stop => stop.entityId);
    assert.ok(!(ids.includes('sf-bay-area-science-festival-2026') && ids.includes('sf-marina-library-open-house-oct17-2026')), `${message}: ${ids.join(' | ')}`);
    assert.ok(plan.handoff, `${message}: a dated plan has a hand-off`);
    assert.deepEqual(plan.handoff.stops.map(stop => stop.id), stops.map(stop => stop.entityId), message);
  }
});

// ---- Review round 2 (10-17) ----

const MEDI = { 'zh-Hans': '我住 San Jose，想帮妈妈申请 Medi-Cal。', 'zh-Hant': '我住 San Jose，想幫媽媽申請 Medi-Cal。', en: 'I want to help my mom apply for Medi-Cal in San Jose.' };
const GREEN = { 'zh-Hans': '我爸的绿卡快过期了，怎么续？', 'zh-Hant': '我爸的綠卡快過期了，怎麼續？', en: 'My dad\'s green card expires soon. How do we renew it?' };
const OUTING_AFTER_PROFESSIONAL = [
  [MEDI, { en: 'What else can she do on Saturday in San Jose?', 'zh-Hans': '她周六在 San Jose 还能做什么？', 'zh-Hant': '她週六在 San Jose 還能做什麼？' }],
  [MEDI, { en: 'Is the farmers market still open on Saturday?', 'zh-Hans': '周六农夫市集还开吗？', 'zh-Hant': '週六農夫市集還開嗎？' }],
  [MEDI, { 'zh-Hans': '她周六还能去图书馆吗？', 'zh-Hant': '她週六還能去圖書館嗎？', en: 'Can she still go to the library on Saturday?' }],
  [MEDI, { 'zh-Hans': '她还能去图书馆参加故事会吗？', 'zh-Hant': '她還能去圖書館參加故事會嗎？', en: 'Can she still go to the library for storytime?' }],
  [MEDI, { 'zh-Hans': '还有什么地方可以带她去？', 'zh-Hant': '還有什麼地方可以帶她去？', en: 'Where else can we take her?' }],
  [MEDI, { en: 'Instead, can we go to the library on Sunday?', 'zh-Hans': '那改成周日去图书馆可以吗？', 'zh-Hant': '那改成週日去圖書館可以嗎？' }],
  [GREEN, { en: 'Can he still go hiking on Sunday?', 'zh-Hans': '他周日还能去爬山吗？', 'zh-Hant': '他週日還能去爬山嗎？' }],
];

test('review 2: an outing follow-up with a day, a date or an outing place does not take the turn before\'s professional guard (zh-Hans, zh-Hant, en)', () => {
  const history = message => [{ role: 'user', content: message }, { role: 'assistant', content: '…' }];
  for (const [before, asks] of OUTING_AFTER_PROFESSIONAL) for (const locale of ['zh-Hans', 'zh-Hant', 'en'])
    assert.equal(professionalFollowup(asks[locale], history(before[locale])), null, asks[locale]);
  for (const message of ['What else can she do in San Jose this weekend?', 'Can he still go to the beach tomorrow?', '她明天还能去市场买菜吗？', '南瓜灯怎么做？', 'Is it still open on December 5?'])
    assert.equal(professionalFollowup(message, history(MEDI.en)), null, message);
  // Professional follow-ups still carry, with a day when they name a professional action.
  for (const [message, before, topic] of [
    ['她不会用电脑，也不想开网上账号，还有什么办法？', MEDI['zh-Hans'], 'insurance'], ['他還能怎麼辦？', '我爸想申請 Medicare', 'medicare'],
    ['What now?', MEDI.en, 'insurance'], ['He says he will mail a list of charges next month. Can he wait that long?', 'My landlord in Oakland kept my whole security deposit.', 'legal'],
    ['她还能申请吗？', MEDI['zh-Hans'], 'insurance'], ['她還能申請嗎？', MEDI['zh-Hant'], 'insurance'], ['Can she still apply?', MEDI.en, 'insurance'],
    ['她周六还能去办公室申请吗？', MEDI['zh-Hans'], 'insurance'], ['她週六還能去辦公室申請嗎？', MEDI['zh-Hant'], 'insurance'], ['Can she still apply on Saturday?', MEDI.en, 'insurance'],
    ['What else can I do?', MEDI.en, 'insurance'], ['还有什么地方可以申请？', MEDI['zh-Hans'], 'insurance'], ['我该怎么做？', MEDI['zh-Hans'], 'insurance'], ['他还能等吗？', GREEN['zh-Hans'], 'immigration'],
  ]) assert.deepEqual(professionalFollowup(message, history(before))?.topics, [topic], message);
});

test('review 2: end to end, the outing follow-up is a site answer and the professional follow-up keeps its guard', async () => {
  for (const [before, ask, locale, professional] of [[MEDI.en, 'What else can she do on Saturday in San Jose?', 'en', false], [MEDI['zh-Hans'], '她周六还能去图书馆吗？', 'zh-Hans', false],
    [MEDI['zh-Hant'], '她不會用電腦，還有什麼辦法？', 'zh-Hant', true]]) {
    const result = await fixture().run(ask, { locale, history: [{ role: 'user', content: before }, { role: 'assistant', content: '…' }] });
    assert.equal(result.safetyRoute === 'professional', professional, `${ask}: ${result.safetyRoute} ${result.route?.reason}`);
  }
});

test('review 2: a neighbourhood beside its own city is that city, not a second one (Richmond District / Outer Richmond and San Francisco)', () => {
  for (const message of ['周六旧金山 Richmond District 有什么亲子活动？', 'Outer Richmond, San Francisco: anything for kids on Sunday?', 'Richmond District SF events Saturday?',
    'Kids storytime at the Richmond District library in San Francisco this Saturday?']) {
    const result = resolveTaskState({ message, today: '2026-10-16', carry: true, catalog: planner });
    assert.equal(result.state.city, 'San Francisco', `${message}: ${result.state.city} ${result.clarification || ''}`);
    assert.ok(!result.clarification, `${message}: ${result.clarification}`);
  }
  const home = stateOf('我住旧金山 Richmond District，周日附近图书馆有中文活动吗？');
  assert.equal(home.city, 'San Francisco');
  assert.equal(stateOf('Richmond events this Saturday?').city, 'Richmond', 'Richmond alone is the East Bay city');
  assert.equal(stateOf('Any events at Parkside Hall in San Jose this Saturday?').city, 'San Jose');
});

test('review 2: "9:00 a.m" without its final dot stays as written; "she says it is almost 3" is not an age', () => {
  for (const text of ['Open 9:00 a.m', 'Open 9:00 a.m.', 'Closes 4:30 p.m']) assert.equal(englishClock(text), text);
  assert.deepEqual(stateOf('She says it is almost 3 already, any cafes in Fremont?').childAges, []);
  assert.deepEqual(stateOf('She is almost 3. Any storytime in Fremont on Saturday?').childAges, [2]);
  assert.deepEqual(stateOf('She\'s almost 3, any storytime in Fremont on Saturday?').childAges, [2]);
});
