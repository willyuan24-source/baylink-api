// API-BB-6: the acceptance lines of the live check after API-BB-5 (10-15) and eval block N. Shipped data with a
// fixed day; a fixture provider, no network.
const test = require('node:test');
const assert = require('node:assert/strict');
const { createBayBayAssistant } = require('../lib/baybayAgent');
const { systemBlocks } = require('../lib/baybayFastPath');
const { loadPlannerCatalog } = require('../lib/planner');
const { createPublicContext } = require('../lib/publicContext');
const { sseFor, sseResponse } = require('./support/anthropic-sse');
const guides = require('../data/guide-catalog.json');
const guidesEn = require('../data/guide-catalog.en.json');

const planner = loadPlannerCatalog();
// Input tokens of a request body, fitted to the 11 live-check calls of 10-15 (their prompts replayed on the live
// commit c6adad7: within -5% .. +8% of the provider's own input_tokens; L07 20,028 live, 19,590 estimated). The eval
// harness's dry-run estimate (characters / 3) reads 13,671 for that L07 call, a third too low for Chinese text.
const CJK = /[　-〿㐀-鿿＀-￯]/g;
const estimatedTokens = text => { const cjk = (text.match(CJK) || []).length; return Math.round(1.449 * cjk + 0.3596 * (text.length - cjk)); };

function fixture({ respond, config = {}, now = '2026-10-15T18:30:00-07:00' } = {}) {
  const sent = [];
  const message = text => ({ type: 'message', id: 'msg-fixture', model: 'claude-sonnet-5-5', role: 'assistant', stop_reason: 'end_turn', content: [{ type: 'text', text }], usage: { input_tokens: 40, output_tokens: 60 } });
  const reply = value => ({ ok: true, status: 200, json: async () => value, clone() { return this; }, text: async () => JSON.stringify(value) });
  const today = new Intl.DateTimeFormat('sv-SE', { timeZone: 'America/Los_Angeles' }).format(new Date(now));
  const assistant = createBayBayAssistant({ config: { BAYBAY_AI_PROVIDER: 'anthropic', ANTHROPIC_API_KEY: 'fixture-anthropic-only', BAYBAY_STATE_SECRET: 'api-bb-6-isolated-secret-0123456789', BAYBAY_DAILY_RUN_LIMIT: '1000', ...config },
    guideCatalog: guides, englishGuideCatalog: guidesEn, catalog: planner, now: () => Date.parse(now), isTest: false, Quota: { findOneAndUpdate: async () => ({ count: 1 }), updateOne: async () => ({}) },
    fetchImpl: async (url, init) => {
      sent.push(init.body);
      const body = JSON.parse(init.body);
      const answer = message(JSON.stringify(await respond(body, sent.length)));
      return body.stream ? sseResponse(sseFor(answer)) : reply(answer);
    } });
  const run = (text, { locale = /[㐀-鿿]/.test(text) ? 'zh-Hans' : 'en', ...extra } = {}) => assistant.run({ message: text, locale, currentPath: locale === 'en' ? '/en' : '/', history: [], searchMode: 'site', webAccess: { allowed: false },
    pageContext: createPublicContext({ guideCatalog: guides }).resolve({ context: { currentPath: '/' }, currentPath: '/', today, locale }), ...extra });
  return { sent, run };
}
// A plan answer as the model would write it: a lead, one point per stop citing that stop's first ref, the stops kept.
const planAnswer = body => {
  const view = JSON.parse(body.messages[0].content[0].text).currentPlan;
  const stops = view?.stops || [];
  return { lead: '周六半天可以这样走。', points: stops.map(stop => ({ text: `${stop.title} [[${stop.refs[0]}]]`, cardIds: [] })), candidateIds: stops.map(stop => stop.id), followups: [], coverage: [], gap: '' };
};

test('live L07: the one-call site day plan sends the fast path\'s request shape, under 8,000 input tokens, and keeps its stops', async () => {
  const asks = [['周六想带爸妈在旧金山玩半天，坐公交，帮我排个行程', 'zh-Hans'], ['这周六带 5 岁和 10 岁的孩子在 Oakland 玩一天，帮我排个行程', 'zh-Hans'],
    ['Plan a Saturday in San Jose with two kids, we will drive', 'en'], ['幫我排一下週日在 Berkeley 的一日遊，不開車', 'zh-Hant'], ['周六 Palo Alto 一日游，帮我安排一下', 'zh-Hans'],
    ['Can you plan a full day in San Francisco this Sunday for my parents? We take BART.', 'en']];
  for (const [ask, locale] of asks) {
    const { sent, run } = fixture({ respond: planAnswer });
    const drafts = [];
    const result = await run(ask, { locale, onDraft: event => drafts.push({ event, results: 0 }) });
    assert.equal(sent.length, 1, `${ask}: one call`);
    const body = JSON.parse(sent[0]);
    assert.ok(result.research.warnings.includes('day_plan_single_call'), ask);
    // The fast path's request shape: the frozen system block with its own breakpoint (a cache read shared with every
    // fast-path answer), no tools, no top-level breakpoint (nothing in this run reads the rest again), one user turn.
    assert.deepEqual(body.system, systemBlocks());
    assert.equal(body.tools, undefined); assert.equal(body.tool_choice, undefined); assert.equal(body.cache_control, undefined);
    assert.deepEqual(body.messages.map(row => row.role), ['user', 'system']);
    assert.ok(!sent[0].includes('researchComplete'), 'no final-round turn');
    const tokens = estimatedTokens(sent[0]);
    assert.ok(tokens <= 8000, `${ask}: ${tokens} estimated input tokens`);
    // Plan quality: at least three stops when the catalog has them, each one point; the lead streams before the result.
    assert.ok(result.assistantPlan.stops.length >= 3, `${ask}: ${result.assistantPlan.stops.map(stop => stop.title).join(' | ')}`);
    assert.equal(result.points.length, result.assistantPlan.stops.length, ask);
    assert.ok(drafts.some(({ event }) => event.field === 'lead'), `${ask}: a streamed lead`);
    assert.equal(result.degraded, false, `${ask}: ${result.research.warnings.join(',')}`);
    // One card per stop that has a BAYLINK page (an event page, or a place's guide), in visiting order.
    const view = JSON.parse(body.messages[0].content[0].text).currentPlan;
    const paged = result.assistantPlan.stops.filter(stop => stop.kind === 'event' || planner.places.find(row => row.id === (stop.entityId || stop.id))?.guideSlug);
    assert.ok(result.localMatches.length >= paged.length, `${ask}: ${result.localMatches.length} cards for ${paged.length} stops with a page`);
    for (const stop of view.stops) assert.ok(stop.refs.length >= 1, `${ask}: ${stop.title} has a ref to cite`);
  }
});

test('planView: each stop once with its refs and unconfirmed checks; no repeated admission rows or check messages', async () => {
  const { sent, run } = fixture({ respond: planAnswer });
  await run('周六想带爸妈在旧金山玩半天，坐公交，帮我排个行程');
  const user = JSON.parse(JSON.parse(sent[0]).messages[0].content[0].text);
  const view = user.currentPlan;
  assert.ok(view.stops.length >= 3);
  for (const stop of view.stops) {
    assert.deepEqual(Object.keys(stop).filter(key => ['sourceIds', 'sourceUrls', 'admissionFacts', 'location', 'path', 'guideSlug'].includes(key)), [], 'no source plumbing');
    if (stop.unconfirmed) assert.ok(stop.unconfirmed.every(code => /^[a-z_]+$/.test(code)), JSON.stringify(stop.unconfirmed));
  }
  // A stop's check message is not repeated in open; the plan's own checks and the full budget rows are not sent.
  for (const value of view.open) assert.ok(!view.stops.some(stop => value.includes(`「${stop.title}」`)), value);
  assert.equal(view.checks, undefined); assert.equal(view.budget.admissionFacts, undefined); assert.equal(view.handoff, undefined);
  assert.ok(JSON.stringify(view).length < 3500, `${JSON.stringify(view).length} characters`);
  // Evidence: the stops' records in full, the other items shortened.
  const stopIds = new Set(view.stops.map(stop => stop.id));
  assert.ok(user.evidence.length >= 3 && user.candidates === undefined);
  for (const item of user.evidence) if (!view.stops.some(stop => stop.refs.includes(item.ref))) assert.ok(item.text.length <= 121, `${item.ref} ${item.text.length}`);
  assert.ok(stopIds.size >= 3);
});

test('plan edits, follow-ups and BAYBAY_DAY_PLAN_FAST=off keep the agent rounds with the site tools and the top-level cache', async () => {
  const { sent, run } = fixture({ config: { BAYBAY_DAY_PLAN_FAST: 'off', BAYBAY_MAX_MODEL_ROUNDS: '1' }, respond: () => ({ lead: '可以。', points: [{ text: 'a', cardIds: [] }], candidateIds: [], followups: [], coverage: [], gap: '' }) });
  await run('周六想带爸妈在旧金山玩半天，坐公交，帮我排个行程');
  const body = JSON.parse(sent[0]);
  assert.deepEqual(body.tools.map(tool => tool.name), ['create_plan', 'search_site']);
  assert.deepEqual(body.cache_control, { type: 'ephemeral' });
  assert.ok(sent.some(raw => raw.includes('researchComplete')));
});

// ---- Line 2: a weekly market's listed dates are not its season (live 10-15, L06 and L08) ----
const { buildFastEvidence, modelItems } = require('../lib/baybayEvidence');
const { resolveTaskState } = require('../lib/baybayState');
const { loadDiscoveryCatalog } = require('../lib/publicContext');
const { normalizeGuideQuery } = require('../lib/guideLocale');
const { listingWindowRepair } = require('../lib/baybayQuality');
const discoveries = { ...loadDiscoveryCatalog(), english: loadDiscoveryCatalog(undefined, true) };
const marketItems = (message, locale, today = '2026-10-15') => {
  const state = resolveTaskState({ message, today, carry: true }).state;
  const site = buildFastEvidence({ query: normalizeGuideQuery(message), originalQuery: message, state, guideCatalog: locale === 'en' ? guidesEn : guides, catalog: planner, discoveries, today, locale, audience: true });
  return modelItems(site.items).filter(item => /farmers|农夫市集|農夫市集/i.test(item.title));
};

test('weekly markets: the model sees the weekly schedule and the next listed date, never the listing window, in zh-Hans, zh-Hant and en', () => {
  const MARKETS = { 'Grand Lake': /Grand Lake/, 'Downtown Berkeley': /Downtown Berkeley|Berkeley 市中心/, Irvington: /Irvington/ };
  const asks = [['Any farmers markets in the East Bay on Saturday morning?', 'en', ['Grand Lake', 'Downtown Berkeley']], ['周六上午东湾有农夫市集吗？', 'zh-Hans', ['Grand Lake', 'Downtown Berkeley']],
    ['週六上午東灣有農夫市集嗎？', 'zh-Hant', ['Grand Lake', 'Downtown Berkeley']], ['Is there a farmers market in Fremont on Sunday?', 'en', ['Irvington']],
    ['周日 Fremont 有农夫市集吗？', 'zh-Hans', ['Irvington']], ['週日 Fremont 有農夫市集嗎？', 'zh-Hant', ['Irvington']]];
  for (const [message, locale, names] of asks) {
    const items = marketItems(message, locale);
    for (const name of names) {
      const item = items.find(row => MARKETS[name].test(row.title));
      assert.ok(item, `${message}: ${name} in ${items.map(row => row.title).join(' | ')}`);
      const view = `${item.when}\n${item.text}`;
      // Not the window's last date (12/12 for the Saturday markets, 12/13 for Irvington), not "M/D–M/D", not 至 / through.
      assert.doesNotMatch(view, /12\s*月\s*1[23]\s*日|Dec(?:ember)?\.? 1[23]\b|12\/1[23]|\d{1,2}\/\d{1,2}\s*[–-]\s*\d{1,2}\/\d{1,2}|至|through/, `${message}: ${name}: ${view.slice(0, 160)}`);
      assert.match(item.when, locale === 'en' ? /^(?:Year-round, every|Every) (?:Saturday|Sunday) \d{1,2}:\d{2}–\d{1,2}:\d{2} · next listed: (?:Sat, Oct 17|Sun, Oct 18)$/ : /^(?:全年)?每[周週][六日] \d{1,2}:\d{2}–\d{1,2}:\d{2}；下一次：10月1[78]日（[周週][六日]）$/, item.when);
      // "Year-round" only where the record's own text says so (Irvington: 全年每周日开); never for Grand Lake or Berkeley.
      assert.equal(/全年|Year-round/.test(item.when), name === 'Irvington', `${name}: ${item.when}`);
      assert.match(item.note, /not its season/);
    }
  }
  // A one-off event keeps its dates; so does an ordinary multi-day event.
  const oneOff = modelItems(buildFastEvidence({ query: '12月5日 Pleasanton 游行', originalQuery: '12月5日 Pleasanton 游行', state: resolveTaskState({ message: '12月5日 Pleasanton 游行', today: '2026-10-15', carry: true }).state, guideCatalog: guides, catalog: planner, discoveries, today: '2026-10-15', locale: 'zh-Hans', audience: true }).items)
    .find(item => /Pleasanton/.test(item.title) && item.kind === 'event');
  assert.ok(oneOff && /12月5日/.test(oneOff.when) && !oneOff.note, JSON.stringify(oneOff && { when: oneOff.when, note: oneOff.note }));
});

test('weekly markets: an answer that still reads a listed date as the season is repaired, in the lead and the points; the asked day stays', async () => {
  const windows = [{ start: '2026-10-17', end: '2026-12-12', next: '2026-10-17' }, { start: '2026-10-18', end: '2026-12-13', next: '2026-10-18' }];
  for (const [text, locale, want] of [
    ['Yes, Oakland and Berkeley both have Saturday morning farmers markets starting Sat, Oct 17.', 'en', 'Yes, Oakland and Berkeley both have Saturday morning farmers markets.'],
    ['Grand Lake runs every Saturday from Sat, Oct 17 through Sat, Dec 12, 9 am–2 pm.', 'en', 'Grand Lake runs every Saturday, 9 am–2 pm.'],
    ['Irvington 农夫市集从10月18日（周日）开始，每周日 9:00–14:00。', 'zh-Hans', 'Irvington 农夫市集，每周日 9:00–14:00。'],
    ['Irvington 農夫市集10月18日（週日）至12月13日（週日）每週日開。', 'zh-Hant', 'Irvington 農夫市集每週日開。'],
    ['Grand Lake 周六市集 10/17 起，9:00–14:00。', 'zh-Hans', 'Grand Lake 周六市集，9:00–14:00。'],
  ]) {
    const result = listingWindowRepair({ lead: text, points: [{ text, cardIds: [] }], gap: '' }, { windows, locale });
    assert.equal(result.repaired, true, text);
    assert.equal(result.draft.lead, want); assert.equal(result.draft.points[0].text, want);
  }
  // The asked day itself, with or without its weekday, is not a season claim.
  for (const text of ['这周六 10月17日 Grand Lake 有市集，9:00–14:00。', 'Saturday, Oct 17: Grand Lake, 9 am–2 pm.', '週日（10月18日）Irvington 有市集。']) {
    assert.equal(listingWindowRepair({ lead: text, points: [], gap: '' }, { windows, locale: /[㐀-鿿]/.test(text) ? 'zh-Hans' : 'en' }).repaired, false, text);
  }
  // End to end: the L08 lead as the model wrote it on 10-15 reaches the reader without "starting Sat, Oct 17".
  const { run } = fixture({ now: '2026-10-15T18:30:00-07:00', respond: body => {
    const items = JSON.parse(body.messages[0].content[0].text).evidence;
    const ref = items.find(item => /Grand Lake/.test(item.title))?.ref || 'e1';
    return { lead: 'Yes, Oakland and Berkeley both have Saturday morning farmers markets starting Sat, Oct 17.', points: [{ text: `Grand Lake, every Saturday from Sat, Oct 17 through Sat, Dec 12, 9 am–2 pm [[${ref}]]`, cardIds: [ref] }], candidateIds: [], followups: [], coverage: [], gap: '' };
  } });
  const result = await run('Any farmers markets in the East Bay on Saturday morning?', { locale: 'en' });
  assert.equal(result.lead, 'Yes, Oakland and Berkeley both have Saturday morning farmers markets.');
  assert.doesNotMatch(result.answer, /starting|through Sat, Dec 12|Dec 12/);
  assert.ok(result.research.warnings.includes('answer_listing_window_repaired'));
});

// ---- Line 3: a rainy-day / indoor family ask (live 10-15, L09) ----
const indoorItems = (message, locale) => {
  const today = '2026-10-15';
  const state = resolveTaskState({ message, today, carry: true }).state;
  const site = buildFastEvidence({ query: normalizeGuideQuery(message), originalQuery: message, state, guideCatalog: locale === 'en' ? guidesEn : guides, catalog: planner, discoveries, today, locale, audience: true });
  return { state, items: site.items, model: modelItems(site.items) };
};

test('L09 rainy San Jose: at least three concrete indoor family options with places (and dates for events), no adult events, no sure class', () => {
  for (const [message, locale] of [['这周末如果下雨，San Jose 有什么室内亲子活动？', 'zh-Hans'], ['這週末下雨，San Jose 有什麼室內親子活動？', 'zh-Hant'], ['It might rain this weekend. Any indoor things to do with kids in San Jose?', 'en']]) {
    const { state, items, model } = indoorItems(message, locale);
    assert.equal(state.setting, 'indoor', message);
    const indoor = items.filter(item => ['event', 'place'].includes(item.catalogKind) && item.row?.city === 'San Jose' && ['indoor', 'mixed'].includes(item.row.planning?.setting));
    assert.ok(indoor.length >= 3, `${message}: ${indoor.map(item => item.title).join(' | ')}`);
    for (const item of indoor.filter(row => row.catalogKind === 'event')) assert.ok(item.when, `${item.title} has its date`);
    // A part-indoor museum (The Egyptian Museum and its garden) is not lost to the indoor filter any more.
    assert.ok(items.some(item => /rosicrucian|venue-sjma|venue-sj-king-library/.test(item.catalogId || '')), message);
    // No adults-only or adult-audience events padding a family ask.
    for (const id of ['sjpl-berryessa-mandarin-ell-club-fall-2026', 'sj-funeral-gangster-dinner-2026', 'sj-rush-2026']) assert.ok(!items.some(item => item.catalogId === id), `${message}: ${id}`);
    // A class with no confirmed session is shown as one to check and book.
    for (const item of model.filter(row => row.kind === 'offer' && /iPad|Apple/.test(`${row.title} ${row.text}`))) assert.match(item.note || '', /never as a sure session/);
  }
});

test('an indoor family ask in a thin city widens to nearby cities in the same area and says so; a full city does not', () => {
  for (const [message, locale, city] of [['这周末下雨，Fremont 有什么室内亲子活动？', 'zh-Hans', 'Fremont'], ['Rainy weekend in Milpitas: any indoor places for kids?', 'en', 'Milpitas']]) {
    const { items, model } = indoorItems(message, locale);
    const nearby = model.filter(item => /not (?:Fremont|Milpitas): the site has few indoor family records/.test(item.note || ''));
    assert.ok(nearby.length >= 3, `${message}: ${model.map(item => `${item.title}|${item.city}`).join(' ; ')}`);
    for (const item of nearby) { assert.notEqual(item.city, city); assert.match(item.note, new RegExp(`In ${item.city}, not ${city}`)); }
    const region = resolveTaskState({ message, today: '2026-10-15', carry: true }).state.region;
    for (const item of items.filter(row => row.nearby)) assert.equal(item.row.region, region, `${item.title} stays in ${region}`);
  }
  const { model } = indoorItems('这周末如果下雨，San Jose 有什么室内亲子活动？', 'zh-Hans');
  assert.ok(!model.some(item => /few indoor family records/.test(item.note || '')), 'San Jose has enough of its own');
});

// ---- Line 4: two-turn date carry and the 12/5 East Bay family ask (live 10-15, X1 / X2) ----
test('12月5号带娃去哪 then 那周日呢 resolves to Sunday 12/6 (and its English and zh-Hant forms)', async () => {
  for (const [first, second, locale] of [['12月5号带娃去哪', '那周日呢', 'zh-Hans'], ['12月5號帶娃去哪', '那週日呢', 'zh-Hant'], ['Where can I take the kids on December 5?', 'What about Sunday?', 'en']]) {
    const { run } = fixture({ respond: () => ({ lead: locale === 'en' ? 'A few ideas.' : '可以去这些地方。', points: [{ text: 'a', cardIds: [] }], candidateIds: [], followups: [], coverage: [], gap: '' }) });
    const one = await run(first, { locale });
    assert.equal(one.taskState.date, '2026-12-05', first);
    const two = await run(second, { locale, sessionToken: one.assistantSessionToken, history: [{ role: 'user', content: first }, { role: 'assistant', content: one.answer.slice(0, 1200) }] });
    assert.equal(two.taskState.date, '2026-12-06', `${first} -> ${second}: ${JSON.stringify(two.taskState.dateRange || two.taskState.date)}`);
  }
});

test('12月5日东湾有什么适合孩子的活动: the Oakland library storytimes are in the evidence with their 12/5 session first', () => {
  for (const [message, locale, day] of [['12月5日东湾有什么适合孩子的活动', 'zh-Hans', /^12月5日（周六） 10:30–11:00（列出的日期：/], ['What can kids do in the East Bay on December 5?', 'en', /^Sat, Dec 5 10:30–11:00 \(dates listed: /]]) {
    const { model } = indoorItems(message, locale);
    const story = model.find(item => /奥克兰总馆周六亲子故事时间|family storytime at Oakland/i.test(item.title));
    assert.ok(story, `${message}: ${model.map(item => item.title).join(' | ')}`);
    assert.match(story.when, day);
    // The day's one-off events stay ahead of the weekly series.
    assert.ok(model.findIndex(item => /Pleasanton/.test(item.title)) < model.indexOf(story), model.map(item => item.title).join(' | '));
  }
});

// ---- Block N dev findings ----
test('block N dev: sudden vision loss with stumbling is a 911 stroke emergency; a landlord lockout is a legal question', () => {
  const { currentEmergencyTopic, professionalTopics, emergencyResponse } = require('../lib/safetyRouting');
  for (const message of ['My partner in Oakland suddenly cannot see properly and is stumbling badly. They say there is no pain. Should we drive to a clinic later?',
    'My dad suddenly can\'t see and keeps falling over', 'Mom suddenly lost her vision and is staggering', '外婆突然看不清东西，走路摇摇晃晃', '爺爺忽然看不見，站不住']) {
    assert.equal(currentEmergencyTopic(message), 'stroke', message);
  }
  // Stumbling alone (a toddler on skates, after a cold) is not the BE-FAST pair.
  for (const message of ['The kids keep stumbling when they learn to skate, any rink tips?', 'My toddler is stumbling a lot after a cold, should I worry?', '孩子学走路摇摇晃晃正常吗']) {
    assert.equal(currentEmergencyTopic(message), null, message);
  }
  const reply = emergencyResponse('My partner suddenly cannot see properly and is stumbling badly.', 'en');
  assert.match(reply?.answer || '', /^.{0,40}911/, 'the 911 template leads');
  for (const message of ['我在Berkeley租房，房東傳訊息說明天換鎖，沒看過法院文件', '房东趁我上班把门锁换了，把我锁在门外', 'My landlord changed the locks while I was at work', 'The property manager shut off our water to make us leave']) {
    assert.ok(professionalTopics(message).includes('legal'), message);
  }
  for (const message of ['我想给新家换锁，推荐锁匠', 'How much does it cost to change the locks after moving in?']) assert.ok(!professionalTopics(message).includes('legal'), message);
});

test('帮我排行程 and 排个一天的行程 are day plans; a ranking (排行榜) is not', () => {
  for (const message of ['下周六带孩子去 San Mateo 玩一天，帮我排行程，下午 4 点前回家', '帮我排个一天的行程', '周六帮我排一下行程', '幫我排個週六的行程'])
    assert.equal(resolveTaskState({ message, today: '2026-10-15', carry: true }).state.goal, 'day-plan', message);
  assert.notEqual(resolveTaskState({ message: '湾区餐厅排行榜', today: '2026-10-15', carry: true }).state.goal, 'day-plan');
});
