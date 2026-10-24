const test = require('node:test');
const assert = require('node:assert/strict');
const { loadPlannerCatalog, priceOf, admissionLowerBound } = require('../lib/planner');
const { loadDiscoveryCatalog, createPublicContext } = require('../lib/publicContext');
const { resolveTaskState } = require('../lib/baybayState');
const { buildFastEvidence, buildSiteEvidence, modelItems } = require('../lib/baybayEvidence');
const { normalizeGuideQuery } = require('../lib/guideLocale');
const { loadWeekendPicks, picksForAsk } = require('../lib/weekendPicks');
const { createBayBayAssistant } = require('../lib/baybayAgent');
const guides = require('../data/guide-catalog.json');
const guidesEn = require('../data/guide-catalog.en.json');
const picksFile = require('../data/weekend-picks.json');

// API-SYNC-3j from web 164241a8 (web #58–#73): the UI-9 typography pass (a space between Chinese words and Latin names or
// numbers, "10 月 10 日" written 10/10, Medi-Cal with a non-breaking hyphen), the B2 photos' record keys (Fruitvale's own
// photo, the 2021–2022 SAP Center and OMCA venue photos), and the unchanged picks re-exported on 10/23. The web keeps its
// picture registry (record-photo-pins.json, venue photos, NOT_FOR_LEAD) to itself: BayBay's cards name a record by
// `kind:id` and the web resolves its picture (web src/features/baybay/answer-cards.ts). Production loaders and the
// shipped data files with fixed days; no model, no network. A later sync that changes one of these rows on purpose
// updates the pin from the web data, the source of truth.
const FRI = '2026-10-23', SAT = '2026-10-24', WED = '2026-10-28';
const planner = loadPlannerCatalog();
const discoveries = { ...loadDiscoveryCatalog(), english: loadDiscoveryCatalog(undefined, true) };
const event = id => planner.events.find(row => row.id === id);
// As the engine does (lib/baybayEngine/router.js and evidence.js): the query is normalizeGuideQuery(message), the guide
// catalog is the reader's locale.
const evidence = (message, today, locale = /[㐀-鿿]/.test(message) ? 'zh-Hans' : 'en') => buildFastEvidence({ query: normalizeGuideQuery(message), originalQuery: message,
  state: resolveTaskState({ message, today, catalog: planner, carry: true }).state, guideCatalog: locale === 'en' ? guidesEn : guides, catalog: planner, discoveries, today, locale, audience: true });
const itemIds = result => result.items.map(item => `${item.kind}:${item.id}`);
const candidateIds = result => (result.candidates || []).map(row => row.id);
const modelItem = (result, key) => { const index = itemIds(result).indexOf(key); return index < 0 ? undefined : modelItems(result.items)[index]; };

const CHERRYLAND = 'acl-cherryland-chinese-storytimes-oct24-2026';
const LUMAFEST = 'r2-petaluma-lumafest-20261024';
const PLANNING_DAY = 'sf-financial-planning-day-oct24-2026';
const DUMPLINGS = 'sf-world-of-dumplings-2026';
const OMCA = 'oakland-omca-dia-muertos-2026';
const MCM = 'mcm-halloween-spectacular-20261031';
const FRUITVALE = 'nov2026-fruitvale-dia-muertos';
const CHINATOWN = 'sfpl-chinatown-creative-saturdays-fall-2026';
const ALTARES = 'san-jose-avenida-altares-2026';
const FOSTER_CITY = 'smcl-foster-city-nidhi-chanani-2026';
const WARRIORS = 'sf-warriors-heat-november-2026';
const SAP_CENTER = ['sj-sharks-flames-nov2-2026', 'sj-don-omar-nov-2026', 'sj-mon-laferte-nov-2026', 'sj-smashing-pumpkins-nov-2026'];

test('the picks file of 10/23: 10/24–25 and 10/31–11/1 in the editor\'s order, each pick on the days it runs', () => {
  assert.equal(picksFile.generatedAt, '2026-10-23');
  assert.deepEqual([...loadWeekendPicks().keys()], ['2026-10-24', '2026-10-31']);
  const order = start => picksFile.weekends.find(row => row.start === start).picks.map(pick => [pick.rank, pick.id, pick.dates.join(' ')]);
  assert.deepEqual(order('2026-10-24'), [[1, CHERRYLAND, '2026-10-24'], [2, LUMAFEST, '2026-10-24'], [3, PLANNING_DAY, '2026-10-24'],
    [4, DUMPLINGS, '2026-10-25'], [5, OMCA, '2026-10-25']]);
  assert.deepEqual(order('2026-10-31'), [[1, MCM, '2026-10-31'], [2, FRUITVALE, '2026-11-01'], [3, CHINATOWN, '2026-10-31'],
    [4, ALTARES, '2026-10-31'], [5, FOSTER_CITY, '2026-11-01']]);
  // Halloween Saturday lifts its three picks, All Saints' Sunday its two, each at its editor rank; the weekend all five.
  assert.deepEqual([...picksForAsk({ date: '2026-10-31' })], [[MCM, 0], [CHINATOWN, 2], [ALTARES, 3]]);
  assert.deepEqual([...picksForAsk({ date: '2026-11-01' })], [[FRUITVALE, 1], [FOSTER_CITY, 4]]);
  assert.deepEqual([...picksForAsk({ date: null, dateRange: { start: '2026-10-31', end: '2026-11-01' } })].map(([id]) => id), [MCM, CHINATOWN, ALTARES, FRUITVALE, FOSTER_CITY]);
  // Chinatown Creative Saturdays is the adults' pick (成人); Fruitvale is not a family audience.
  assert.deepEqual(event(CHINATOWN).audience, ['成人']);
  assert.deepEqual(event(FRUITVALE).audience, ['湾区居民与访客']);
});

test('BayBay on the deploy day and the next weekend: the picks lead in the editor\'s order; family asks never get the adults\' pick', () => {
  // Saturday 10/24 itself: "today" is the picks' Saturday, "tomorrow" their Sunday.
  for (const message of ['今天带孩子去哪玩', 'Where can I take the kids today?']) {
    const result = evidence(message, SAT);
    assert.deepEqual(candidateIds(result).slice(0, 2), [CHERRYLAND, LUMAFEST], message);
    assert.ok(![...itemIds(result), ...candidateIds(result)].some(id => id.endsWith(PLANNING_DAY)), message);
  }
  const tomorrow = evidence('明天带孩子去哪玩', SAT);
  assert.equal(candidateIds(tomorrow)[0], OMCA);
  assert.ok(![...itemIds(tomorrow), ...candidateIds(tomorrow)].some(id => [CHERRYLAND, LUMAFEST, PLANNING_DAY].some(pick => id.endsWith(pick))));
  // Wednesday 10/28, the Halloween weekend: family asks get MCM, the Avenida de los Altares and the Foster City author
  // visit, never the adults' Chinatown Creative Saturdays; an ask that is not about children gets all five in order.
  for (const message of ['这周末带孩子去哪玩', 'Family things to do this weekend']) {
    const result = evidence(message, WED);
    assert.deepEqual(candidateIds(result).slice(0, 3), [MCM, ALTARES, FOSTER_CITY], message);
    assert.ok(![...itemIds(result), ...candidateIds(result)].some(id => id.endsWith(CHINATOWN)), message);
  }
  assert.deepEqual(candidateIds(evidence('这周六带孩子去哪玩？', WED)).slice(0, 2), [MCM, ALTARES]);
  for (const message of ['11月1日周日带孩子去哪玩', 'What can kids do on Sunday November 1?']) {
    const result = evidence(message, WED);
    assert.equal(candidateIds(result)[0], FOSTER_CITY, message);
    assert.ok(![...itemIds(result), ...candidateIds(result)].some(id => [MCM, ALTARES, CHINATOWN].some(pick => id.endsWith(pick))), message);
  }
  assert.deepEqual(candidateIds(evidence('这周末有什么好玩的', WED)).slice(0, 5), [MCM, FRUITVALE, CHINATOWN, ALTARES, FOSTER_CITY]);
});

test('B2\'s record keys: Fruitvale\'s own photo, the new SAP Center and OMCA venue photos; the Chase Center corner is no pick\'s picture', () => {
  // ① the record's own image, the first rung the web's cover resolver tries (DECISIONS 21/22).
  assert.equal(event(FRUITVALE).imageKey, 'official-nov2026-fruitvale-dia-muertos');
  for (const id of SAP_CENTER) assert.equal(event(id).imageKey, 'venue-sap-center', id);
  assert.equal(event('oakland-omca-friday-finale-2026').imageKey, 'venue-omca');
  assert.ok(!planner.events.some(row => ['roundup-sap-center', 'region-omca', 'november-community'].includes(row.imageKey) && (SAP_CENTER.includes(row.id) || ['oakland-omca-friday-finale-2026', FRUITVALE].includes(row.id))));
  // The records B2 pins a picture on keep their own keys (the pin is tried after them, web record-photo-pins.json).
  for (const id of [DUMPLINGS, CHERRYLAND, PLANNING_DAY, 'windsor-trick-or-treat-trail-2026', 'sfpl-western-addition-open-house-oct24-2026', 'danville-scarecrow-stroll-2026']) assert.equal(event(id).imageKey, `official-${id}`, id);
  // ZooLights and Portola Valley's lantern walk have no own picture: the web shows the pinned stock photo.
  for (const id of ['sfzoo-zoolights-2026', 'smcl-portola-valley-mid-autumn-lantern-2026']) assert.equal(event(id).imageKey, '', id);
  // roundup-chase-center is in the web's NOT_FOR_LEAD list (#73): it stays the own key of the two Chase Center records, as on
  // the web, and none of the ten picks carries it; every pick has its own organiser photo or none.
  assert.deepEqual(planner.events.filter(row => row.imageKey === 'roundup-chase-center').map(row => row.id).sort(), ['sf-journey-final-frontier-november-2026', WARRIORS]);
  for (const weekend of picksFile.weekends) for (const pick of weekend.picks) assert.ok([`official-${pick.id}`, ''].includes(event(pick.id).imageKey), pick.id);
});

test('BayBay\'s cards name the record the web pins its picture on, and carry no picture of their own', async () => {
  const config = { BAYBAY_AI_PROVIDER: 'anthropic', ANTHROPIC_API_KEY: 'fixture-anthropic-only', BAYBAY_STATE_SECRET: 'private-test-task-secret-0123456789', BAYBAY_DAILY_RUN_LIMIT: '1000', BAYBAY_ENGINE: 'v2' };
  const quota = { updateOne: async () => ({}), findOneAndUpdate: async () => ({ count: 1 }) };
  const context = createPublicContext({ guideCatalog: guides });
  // The fields a card has (lib/baybayEngine/evidence.js itemCard); none of them is an image.
  const CARD_FIELDS = new Set(['kind', 'id', 'title', 'url', 'summary', 'startDate', 'endDate', 'date', 'temporalStatus']);
  const cases = [
    // [ask, Bay Area now, the web's record-photo-pins.json key (or the record's own key) the card must name]
    ['旧金山饺子节在哪里', `${FRI}T12:00:00-07:00`, `event:${DUMPLINGS}`],
    ['老人坐Muni免费吗', `${FRI}T12:00:00-07:00`, 'offer:sfmta-free-muni-seniors'],
    ['这周六带孩子去哪玩？', `${FRI}T12:00:00-07:00`, `event:${CHERRYLAND}`],
    ['Fruitvale 亡灵节是哪天', `${WED}T12:00:00-07:00`, `event:${FRUITVALE}`],
    ['Warriors 主场对 Miami Heat 什么时候', `${FRI}T12:00:00-07:00`, `event:${WARRIORS}`],
  ];
  for (const [message, nowIso, key] of cases) {
    const now = Date.parse(nowIso), today = nowIso.slice(0, 10), [kind, id] = key.split(':');
    // The model picks the record's evidence item, as a real answer recommending it would. The engine catches a provider
    // error and falls back (lib/baybayEngine/stream.js), so the mock only records what it saw; the checks run after `run`.
    let calls = 0, found = false;
    const assistant = createBayBayAssistant({ config, guideCatalog: guides, now: () => now, isTest: false, Quota: quota,
      fetchImpl: async (url, init) => {
        calls++;
        const body = JSON.parse(init.body);
        const input = body.messages.filter(row => row.role === 'user').map(row => typeof row.content === 'string' ? row.content : row.content.map(part => part.text || '').join('\n')).join('\n');
        const item = (JSON.parse(input.split('\n---\n').at(-1)).evidence || []).find(row => String(row.page || '').endsWith(`/${id}`));
        found = Boolean(item);
        const value = { type: 'message', id: 'msg-sync-1023', model: 'claude-sonnet-5-5', role: 'assistant', stop_reason: 'end_turn', usage: { input_tokens: 40, output_tokens: 60 },
          content: [{ type: 'text', text: JSON.stringify({ lead: '站内有这一条。', points: [{ text: '详见卡片。', cardIds: item ? [item.ref] : [] }], candidateIds: item ? [item.ref] : [], followups: [], coverage: [], gap: '' }) }] };
        return { ok: true, status: 200, json: async () => value, clone() { return this; }, text: async () => JSON.stringify(value) };
      } });
    const preview = [];
    const result = await assistant.run({ message, locale: 'zh-Hans', currentPath: '/', history: [], searchMode: 'site', webAccess: { allowed: false },
      pageContext: context.resolve({ context: { currentPath: '/' }, currentPath: '/', today, locale: 'zh-Hans' }), onQuickCard: cards => preview.push(...cards) });
    // One model call, the record in its evidence, and no failed response: a fallback answer cannot pass.
    assert.equal(calls, 1, `${message}: model calls`);
    assert.ok(found, `${message}: ${key} reaches the model`);
    const responses = result.research?.modelResponses || [];
    assert.ok(responses.length >= 1 && responses.every(row => !row.failure), `${message}: model responses ${JSON.stringify(responses.map(row => row.failure || row.status))}`);
    assert.ok(preview.some(card => `${card.kind}:${card.id}` === key), `${message}: preview ${preview.map(card => `${card.kind}:${card.id}`).join(', ')}`);
    assert.deepEqual(result.localMatches.map(card => `${card.kind}:${card.id}`), [key], message);
    if (kind === 'event') assert.equal(result.localMatches[0].url, `/events/${id}`, message);
    for (const card of [...preview, ...result.localMatches]) for (const field of Object.keys(card)) assert.ok(CARD_FIELDS.has(field), `${message}: card field ${field}`);
  }
});

test('the typography pass: spaced titles, tiers and dates reach the model, read the same, and asks typed without spaces still find them', () => {
  const titles = [
    ['Burlingame Downtown秋日节是哪天？', FRI, 'burlingame-downtown-fall-fest-2026', 'Burlingame Downtown 秋日节与装扮活动'],
    ['Los Altos第50届节日灯光游行是哪天', WED, 'octnov-los-altos-lights-parade-2026', 'Los Altos 第 50 届节日灯光游行'],
    ['Big Break湿地散步11月有几场', WED, 'nov2026-big-break-nature-walk', 'Big Break 湿地散步：11 月四个场次'],
    ['Sips and Stars 21岁以上吗', WED, 'november-north-sips-stars-2026', 'Sips and Stars：21 岁以上酒与星空之夜'],
  ];
  for (const [message, today, id, title] of titles) {
    assert.equal(event(id).title, title);
    const item = modelItem(evidence(message, today), `event:${id}`);
    assert.ok(item, message);
    assert.equal(item.title, title, message);
  }
  // Prices with spaces parse as before (lib/planner.js priceOf and admissionLowerBound read the same values).
  const sugarloaf = event('november-north-sugarloaf-public-star-party-2026');
  assert.equal(sugarloaf.costLabel, '成人 $15；62 岁以上/学生 $10；6–12 岁 $5；5 岁及以下免费；另加 $10/车停车');
  assert.deepEqual([priceOf(sugarloaf), admissionLowerBound(sugarloaf)], [null, 5]);
  assert.deepEqual([priceOf(event(OMCA)), admissionLowerBound(event(OMCA))], [10, 10]);
  const yoga = event('nov2026-presidio-free-yoga');
  assert.equal(yoga.costLabel, '课程免费；须预约，限 50 人；停车另付');
  assert.deepEqual([priceOf(yoga), admissionLowerBound(yoga)], [0, 0]);
  // "11月1／8／15／22／29日" is now one date per session; a session-day ask still finds the market.
  const market = event('nov2026-fort-mason-farmers-market');
  assert.equal(market.dateLabel, '11/1、11/8、11/15、11/22、11/29 9:30–13:30');
  assert.ok(itemIds(evidence('11月15日 Fort Mason 有农夫市集吗', WED)).includes('event:nov2026-fort-mason-farmers-market'));
  // The Medicare guide's titles write Medi-Cal with a non-breaking hyphen (U+2011); the search text folds it to "-"
  // (lib/baybayEvidence.js normalize), so asks typed with "-" lead with the guide as before the sync (next test).
  assert.equal(guidesEn.find(row => row.slug === 'bay-area-medicare-hicap-medi-cal-guide').title, 'Understanding Medicare and Medi\u2011Cal in the Bay Area: start with free HICAP counseling');
  assert.equal(guides.find(row => row.slug === 'bay-area-medicare-hicap-medi-cal-guide').title, '在湾区弄清 Medicare、Medi\u2011Cal：先找免费 HICAP 咨询');
  for (const message of ['How do I apply for Medi-Cal?', 'Medicare and Medi-Cal help for my parents']) {
    assert.equal(itemIds(evidence(message, FRI))[0], 'guide:bay-area-medicare-hicap-medi-cal-guide', message);
  }
  for (const message of ['Medi-Cal 怎么申请', '白卡怎么申请']) assert.ok(itemIds(evidence(message, FRI)).includes('guide:bay-area-medicare-hicap-medi-cal-guide'), message);
});

const MEDICARE_GUIDE = 'bay-area-medicare-hicap-medi-cal-guide';
// search_site, the v2 research tool, as lib/baybayEngine/research.js calls it: the model's query, the reader's guides.
const siteSearch = (query, today = FRI) => buildSiteEvidence({ query, state: resolveTaskState({ message: query, today, catalog: planner, carry: true }).state,
  guideCatalog: /[㐀-鿿]/.test(query) ? guides : guidesEn, catalog: planner, today, v2: true });
const siteGuides = result => (result.sources || []).map(row => String(row.url || '').replace(/^\/guides\//, '').replace(/#.*$/, ''));

test('Medi\u2011Cal written with U+2011 searches as Medi-Cal: the first evidence gather and search_site lead with the Medicare guide as before the sync', () => {
  // On the synced titles without the fold, these asks led with the dental guide (Medi-Cal in its text) or lost the
  // Medicare guide from search_site's first four results; with base b2ba941 data they led with it (lanes/API-SYNC-3J/work/probe-site-*.txt).
  for (const message of ['Medi-Cal 怎么申请', 'Medi-Cal 申请', '白卡怎么申请', 'Medi-Cal application', 'Medi\u2011Cal 怎么申请']) {
    assert.equal(itemIds(evidence(message, FRI))[0], `guide:${MEDICARE_GUIDE}`, message);
  }
  for (const query of ['Medi-Cal 申请', 'Medi-Cal 怎么申请', 'Medi-Cal application', 'How do I apply for Medi-Cal?', '白卡怎么申请']) {
    assert.equal(siteGuides(siteSearch(query))[0], MEDICARE_GUIDE, query);
  }
  assert.ok(siteGuides(siteSearch('白卡 Medi-Cal 老人')).slice(0, 4).includes(MEDICARE_GUIDE));
  // A dental ask still leads with the dental guide.
  assert.equal(siteGuides(siteSearch('Medi-Cal 牙医'))[0], 'bay-area-dental-care-insurance-low-cost-guide');
});
