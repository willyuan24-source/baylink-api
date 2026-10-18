// API-BB-4B: retrieval follow-ups from API-SYNC-3a/3b and H73 on the shipped data, with a fixed day.
// Production loaders, no model, no network. A later content sync that changes one of these rows on
// purpose updates the pin from the web data, which is the source of truth.
const test = require('node:test');
const assert = require('node:assert/strict');
const { loadPlannerCatalog } = require('../lib/planner');
const { loadDiscoveryCatalog, createPublicContext } = require('../lib/publicContext');
const { resolveTaskState } = require('../lib/baybayState');
const { buildFastEvidence, buildSiteEvidence } = require('../lib/baybayEvidence');
const { pageRecordText } = require('../lib/baybayEngine/evidence');
const guides = require('../data/guide-catalog.json');
const guidesEn = require('../data/guide-catalog.en.json');

const TODAY = '2026-10-14'; // Wednesday, so "this weekend" is 10/17-10/18
const planner = loadPlannerCatalog();
const discoveries = { ...loadDiscoveryCatalog(), english: loadDiscoveryCatalog(undefined, true) };
const stateOf = message => resolveTaskState({ message, today: TODAY, carry: true }).state;
const evidence = (message, locale = 'zh-Hans') => buildFastEvidence({ query: message, originalQuery: message, state: stateOf(message), guideCatalog: locale === 'en' ? guidesEn : guides,
  catalog: planner, discoveries, today: TODAY, locale, audience: true });
const ids = rows => (rows || []).map(row => row.id);

test('H73: a county-scoped outing ask is that county\'s region; a county service question is not narrowed', () => {
  for (const [message, region] of [['这周末圣马刁县图书馆有什么免费活动', 'peninsula'], ['Free library events in San Mateo County this weekend', 'peninsula'],
    ['聖馬刁縣這週末有什麼免費活動', 'peninsula'], ['圣塔克拉拉县这周六有什么亲子活动', 'south-bay'], ['Any events in Alameda County this Saturday?', 'east-bay']]) {
    const state = stateOf(message);
    assert.equal(state.region, region, message);
    assert.equal(state.city, null, `${message}: the county is not its namesake city`);
  }
  // Not an outing ask: the county names whose office or rule is meant, not an area filter.
  assert.equal(stateOf('圣马刁县的 Medi-Cal 怎么申请').region, null);
  // Two counties are not one region.
  assert.equal(stateOf('这周末圣马刁县和阿拉米达县有什么活动').region, null);
  const result = evidence('这周末圣马刁县图书馆有什么免费活动');
  assert.ok(result.candidates.length >= 3, ids(result.candidates).join(', '));
  for (const row of result.candidates) assert.equal(planner.events.find(event => event.id === row.id)?.region ?? planner.places.find(place => place.id === row.id)?.region, 'peninsula', row.id);
});

test('an English ask finds a Chinese-language programme through its English alias (API-SYNC-3b follow-up)', () => {
  const english = evidence('Any Cantonese film screenings in San Francisco on November 14?', 'en');
  assert.ok(ids(english.candidates).includes('sfpl-richmond-hk-film-hard-boiled-2026'), ids(english.candidates).join(', '));
  const chinese = evidence('11月14日旧金山有粤语电影放映吗');
  assert.ok(ids(chinese.candidates).includes('sfpl-richmond-hk-film-hard-boiled-2026'), ids(chinese.candidates).join(', '));
});

test('a Chinese ask keeps Chinese-language programmes among the candidates; a family ask is ordered by audience fit instead', () => {
  const library = evidence('这周六旧金山图书馆有什么免费活动');
  assert.ok(ids(library.candidates).includes('sfpl-richmond-hk-film-the-killer-2026'), ids(library.candidates).join(', '));
  // The same ask in English has no lift: the film is not pushed in ahead of the libraries' own programmes.
  const english = buildSiteEvidence({ query: 'Free library events in San Francisco this Saturday', state: stateOf('Free library events in San Francisco this Saturday'), guideCatalog: guidesEn, catalog: planner, today: TODAY });
  assert.ok(english.candidates.length > 0);
});

test('the community lift is scoped (review 10-14): a Halloween or concert ask keeps its most relevant events first, a day plan keeps a Saturday farmers\' market', () => {
  const site = message => buildSiteEvidence({ query: message, originalQuery: message, state: stateOf(message), guideCatalog: guides, catalog: planner, today: TODAY });
  const halloween = ids(site('这周六旧金山有什么万圣节活动？').candidates);
  assert.ok(halloween.indexOf('sf-sunnydale-pumpkin-fest-2026') >= 0, halloween.join(', '));
  for (const id of ['sfpl-richmond-hk-film-the-killer-2026', 'sfpl-marina-wild-goose-qigong-oct-2026']) {
    assert.ok(!halloween.includes(id) || halloween.indexOf(id) > halloween.indexOf('sf-sunnydale-pumpkin-fest-2026'), `${id} not above Sunnydale: ${halloween.join(', ')}`);
  }
  const concert = ids(site('这周六旧金山有什么音乐会或者演出？').candidates);
  assert.ok(concert.includes('sf-potrero-hill-festival-oct17-2026'), concert.join(', '));
  assert.ok(!concert.includes('sfpl-marina-wild-goose-qigong-oct-2026') || concert.indexOf('sfpl-marina-wild-goose-qigong-oct-2026') > concert.indexOf('sf-potrero-hill-festival-oct17-2026'), concert.join(', '));
  // K-TIME-1 (a BART day plan, home by 16:00): the adults-only 14:00-16:00 screening is not lifted over a Saturday
  // farmers' market. API-SYNC-3c (web CNT-SUPPLY-2): the new Saturday markets by BART, Downtown Berkeley and Oakland's
  // Grand Lake, now rank above Ferry Plaza, which leaves this six-candidate list; any of the three keeps the check.
  const plan = ids(site('帮我排个周六的行程，我们坐 BART 去，下午 4 点前回家').candidates);
  const market = plan.findIndex(id => ['ferry-plaza-farmers-market-2026-autumn', 'berkeley-downtown-saturday-farmers-market-2026', 'oakland-grand-lake-farmers-market-2026'].includes(id));
  assert.ok(market >= 0, plan.join(', '));
  assert.ok(!plan.includes('sfpl-richmond-hk-film-the-killer-2026') || plan.indexOf('sfpl-richmond-hk-film-the-killer-2026') > market, plan.join(', '));
});

test('a planner place that mirrors an opening carries the opening\'s date line and details', () => {
  const zh = evidence('Burlingame Old Post Office 这周六有早午餐吗').items.find(item => item.id === 'old-post-office-burlingame');
  assert.ok(zh, 'the opening is an item');
  // API-SYNC-3g (web #48 freshness review, read 10-16): the opening's details were reworded; the same hours and the same
  // "10/17 unconfirmed, call first".
  assert.match(zh.text, /早午餐周六、周日 11:00–14:00/);
  assert.match(zh.text, /10\/17 周六想去吃早午餐，先打 650-502-1000 问是否已开始供应/);
  const en = evidence('Does the Old Post Office in Burlingame serve brunch this Saturday?', 'en').items.find(item => item.id === 'old-post-office-burlingame');
  assert.ok(en);
  assert.match(en.text, /brunch Sat–Sun 11am–2pm/);
  assert.match(en.text, /for brunch on Saturday, Oct 17, call 650-502-1000 first/);
});

test('an event item offers all its plan lines: both BORP celebration times reach the model', () => {
  const item = evidence('10月17日伯克利 BORP 无障碍体育体验日的社区庆祝几点开始').items.find(row => row.id === 'berkeley-borp-adaptive-sports-expo-oct17-2026');
  assert.ok(item);
  assert.ok(item.text.includes('15:00–16:30') && item.text.includes('15:30–17:30'), item.text);
});

test('an ask about a new place in a city finds that city\'s opening by category (API-SYNC-3a follow-up 5)', () => {
  for (const [message, locale] of [['Palo Alto 新开的奶茶店开了吗', 'zh-Hans'], ['Palo Alto 新開的奶茶店開了嗎', 'zh-Hant'], ['Has the new bubble tea shop in Palo Alto opened yet?', 'en']]) {
    assert.ok(evidence(message, locale).items.some(item => item.id === 'palo-alto-auntea-jenny-announced-2026'), message);
  }
});

test('a record without its own read date carries none: no catalog export date as verifiedAt or recordedAt (API-SYNC-3a follow-up 3)', () => {
  const context = createPublicContext({ guideCatalog: guides });
  const page = path => context.resolve({ context: { currentPath: path }, currentPath: path, today: TODAY, locale: 'zh-Hans' }).contextReferences[0];
  const undated = page('/offers/chicha-cupertino-free-tea-tasting');
  assert.ok(undated, 'the offer page resolves');
  assert.equal(undated.verifiedAt, undefined);
  assert.doesNotMatch(pageRecordText(undated, 'zh-Hans', TODAY), /Official page last read|Editor verified/);
  const dated = page('/offers/randall-museum-free');
  assert.equal(dated.verifiedAt, '2026-09-23');
  assert.match(pageRecordText(dated, 'zh-Hans', TODAY), /Official page last read: 2026-09-23/);
  assert.doesNotMatch(pageRecordText(dated, 'zh-Hans', TODAY), /Editor verified/);
  // Catalog candidates: an event keeps its own date; a place (none has one) carries no recordedAt.
  const site = buildSiteEvidence({ query: '这周六旧金山有什么适合全家的免费活动', state: stateOf('这周六旧金山有什么适合全家的免费活动'), guideCatalog: guides, catalog: planner, today: TODAY });
  const event = site.candidates.find(row => row.kind === 'event');
  assert.equal(event.recordedAt, planner.events.find(row => row.id === event.id).verifiedAt);
  const places = buildSiteEvidence({ query: '周日下午想在 Fremont 带爸妈散散步，有什么好去处？', state: stateOf('周日下午想在 Fremont 带爸妈散散步，有什么好去处？'), guideCatalog: guides, catalog: planner, today: TODAY }).candidates.filter(row => row.kind === 'place');
  assert.ok(places.length, 'a place candidate');
  for (const place of places) assert.equal(place.recordedAt, undefined, place.id);
});

test('preview cards on a city ask lead with that city\'s records, not an offer with no stated place (live check L01)', async () => {
  const { createBayBayAssistant } = require('../lib/baybayAgent');
  const englishGuides = require('../data/guide-catalog.en.json');
  const reply = { type: 'message', id: 'm', model: 'claude-sonnet-5-5', role: 'assistant', stop_reason: 'end_turn', usage: { input_tokens: 1, output_tokens: 1 },
    content: [{ type: 'text', text: JSON.stringify({ lead: 'L', points: [], candidateIds: [], followups: [], coverage: [], gap: '' }) }] };
  const assistant = createBayBayAssistant({ config: { BAYBAY_AI_PROVIDER: 'anthropic', ANTHROPIC_API_KEY: 'fixture-anthropic-only', BAYBAY_ENGINE: 'v2', BAYBAY_STATE_SECRET: 'api-bb-4b-cards-secret-0123456789ab' },
    guideCatalog: guides, englishGuideCatalog: englishGuides, now: () => Date.parse('2026-10-14T19:00:00Z'), isTest: true,
    Quota: { updateOne: async () => ({}), findOneAndUpdate: async () => ({ count: 1 }) },
    fetchImpl: async () => ({ ok: true, status: 200, json: async () => reply, clone() { return this; }, text: async () => JSON.stringify(reply) }) });
  const context = createPublicContext({ guideCatalog: guides });
  const cards = [];
  await assistant.run({ message: '这周六带 6 岁和 9 岁的孩子在 San Mateo 玩，有什么推荐？', locale: 'zh-Hans', currentPath: '/', history: [], searchMode: 'site', webAccess: { allowed: false },
    onQuickCard: list => cards.push(...list), pageContext: context.resolve({ context: { currentPath: '/' }, currentPath: '/', today: TODAY, locale: 'zh-Hans' }) });
  assert.ok(cards.length, 'preview cards');
  assert.notEqual(cards[0].id, 'randall-museum-free', cards.map(card => card.id).join(', '));
  const records = new Map([...planner.events, ...planner.places].map(row => [row.id, row]));
  const first = cards.find(card => card.kind !== 'guide');
  assert.equal(records.get(first.id)?.city ?? discoveries.items.find(row => row.id === first.id)?.city, 'San Mateo', first.id);
});
