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

test('a planner place that mirrors an opening carries the opening\'s date line and details', () => {
  const zh = evidence('Burlingame Old Post Office 这周六有早午餐吗').items.find(item => item.id === 'old-post-office-burlingame');
  assert.ok(zh, 'the opening is an item');
  assert.match(zh.text, /周末早午餐 11:00–14:00/);
  assert.match(zh.text, /10\/17 周六是否供应未能确认/);
  const en = evidence('Does the Old Post Office in Burlingame serve brunch this Saturday?', 'en').items.find(item => item.id === 'old-post-office-burlingame');
  assert.ok(en);
  assert.match(en.text, /weekend brunch runs 11 am–2 pm/);
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
