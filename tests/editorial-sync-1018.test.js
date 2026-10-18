const test = require('node:test');
const assert = require('node:assert/strict');
const jwt = require('jsonwebtoken');
const { createApplication } = require('../server');
const { createMemoryModels } = require('./support/memory-models');
const { loadPlannerCatalog, eventOccursOn } = require('../lib/planner');
const { loadDiscoveryCatalog } = require('../lib/publicContext');
const { resolveTaskState } = require('../lib/baybayState');
const { buildFastEvidence, modelItems } = require('../lib/baybayEvidence');
const { normalizeGuideQuery } = require('../lib/guideLocale');
const { loadWeekendPicks, picksForAsk } = require('../lib/weekendPicks');
const guides = require('../data/guide-catalog.json');
const guidesEn = require('../data/guide-catalog.en.json');
const eventCatalog = require('../data/event-catalog.json');
const discoveriesZh = require('../data/discoveries.json');
const discoveriesEn = require('../data/discoveries.en.json');
const registry = require('../data/source-registry.json');
const picksFile = require('../data/weekend-picks.json');

// API-SYNC-3h from web 6aecf9fb9 (web #49, Wave 7 A): the editor's weekend picks file (WEB-PICKS-EXPORT), the region of four
// one-venue offers (CNT-REGION-4), the 2027 figures and the Thanksgiving-to-New-Year holiday hours guide (CNT-YEAREND), the
// 11/28–12/13 weekend review and the 2027 Lunar New Year events (CNT-WEEKEND-1128). What the synced catalogs change for
// saves and for BayBay's fast evidence. Production loaders and the shipped data files with fixed days; no model, no
// network. A later sync that changes one of these rows on purpose updates the pin from the web data, the source of truth.
const NOW = Date.parse('2026-10-22T19:00:00Z'); // Thu 2026-10-22 12:00 PDT
const TODAY = '2026-10-22';
const SECRET = 'api-sync-3h-isolated-test-secret-0123456789';
const planner = loadPlannerCatalog();
const discoveries = { ...loadDiscoveryCatalog(), english: loadDiscoveryCatalog(undefined, true) };
const event = id => planner.events.find(row => row.id === id);
const discovery = (kind, id, english = false) => (english ? discoveriesEn : discoveriesZh).items.find(row => row.kind === kind && row.id === id);
// As the engine does (lib/baybayEngine/router.js and evidence.js): the query is normalizeGuideQuery(message), the guide
// catalog is the reader's locale.
const evidence = (message, today = TODAY, locale = /[㐀-鿿]/.test(message) ? 'zh-Hans' : 'en') => buildFastEvidence({ query: normalizeGuideQuery(message), originalQuery: message,
  state: resolveTaskState({ message, today, catalog: planner, carry: true }).state, guideCatalog: locale === 'en' ? guidesEn : guides, catalog: planner, discoveries, today, locale, audience: true });
const itemIds = result => result.items.map(item => `${item.kind}:${item.id}`);
const candidateIds = result => (result.candidates || []).map(row => row.id);
const CJK = /[㐀-鿿]/;
const NEW_EVENTS = ['smcl-portola-valley-sewing-machine-basics-2026', 'sunnyvale-library-aimusic-lunar-new-year-2027', 'milpitas-civic-center-aimusic-lunar-new-year-2027',
  'sf-chinese-new-year-flower-market-2027', 'sf-choy-sun-doe-day-2027', 'sf-symphony-lunar-new-year-2027', 'paloalto-community-threads-felt-goat-2027',
  'sf-lunar-new-year-basketball-jamboree-2027', 'sunnyvale-lakewood-aimusic-lunar-new-year-2027', 'sj-cpaa-spring-festival-gala-2027', 'sf-miss-chinatown-usa-pageant-2027',
  'sf-chinese-new-year-community-fair-2027', 'sf-chinese-new-year-parade-2027'];
const HOLIDAY = 'bay-area-holiday-hours-thanksgiving-new-year-2026';
const PICKS_1024 = ['r2-petaluma-lumafest-20261024', 'menlo-park-halloween-hoopla-2026', 'sfpl-chinatown-creative-saturdays-fall-2026', 'acl-cherryland-chinese-storytimes-oct24-2026', 'san-jose-sjma-dia-muertos-community-2026'];
// Chinatown Creative Saturdays (3rd pick) is for adults, so a family ask never offers it.
const FAMILY_1024 = PICKS_1024.filter(id => id !== 'sfpl-chinatown-creative-saturdays-fall-2026');
// 10/31–11/1: the picks for children and families, in the editor's order (Fruitvale's Día de los Muertos is for "湾区居民与
// 访客", Chinatown Creative Saturdays for adults).
const FAMILY_1031 = ['mcm-halloween-spectacular-20261031', 'san-jose-avenida-altares-2026', 'smcl-foster-city-nidhi-chanani-2026'];

test('the Wave 7 A events and the holiday hours guide are in every catalog copy, with the same ids', () => {
  assert.deepEqual(eventCatalog.map(row => row.id).sort(), planner.events.map(row => row.id).sort());
  for (const id of NEW_EVENTS) {
    assert.ok(event(id), id);
    assert.ok(eventCatalog.some(row => row.id === id), id);
    assert.ok(event(id).aliases.some(alias => !CJK.test(alias)), `${id} has an English alias`);
  }
  // The Portola Valley sewing series is split in two: the machine basics (11/7, 12/5, 1/2) and the beginners' project days.
  assert.deepEqual(event('smcl-portola-valley-sewing-machine-basics-2026').occurrenceDates, ['2026-11-07', '2026-12-05', '2027-01-02']);
  assert.deepEqual(event('smcl-portola-valley-sewing-beginners-2026').occurrenceDates, ['2026-11-21', '2026-12-19']);
  for (const catalog of [guides, guidesEn, planner.guides]) assert.ok(catalog.some(row => row.slug === HOLIDAY), HOLIDAY);
  for (const catalog of [guides, guidesEn]) {
    const guide = catalog.find(row => row.slug === HOLIDAY);
    assert.equal(guide.updatedAt, '2026-10-17');
    assert.ok(guide.sources.length >= 20);
    for (const source of guide.sources) assert.ok(registry.some(row => row.url === source.url && row.contentIds.includes(HOLIDAY)), source.url);
  }
  // The sold-out and postponed rows keep their status; the sync adds none.
  assert.deepEqual(planner.events.filter(row => row.status).map(row => `${row.id}:${row.status}`).sort(), ['napa-harvest-after-dark-2026:sold_out',
    'november-north-jack-london-author-2026:sold_out', 'san-jose-waterways-art-climate-2026:sold_out', 'south-sf-state-of-city-2026:postponed']);
});

test('the shipped weekend picks file: three weekends, editor order, every pick a catalog event on its listed days', () => {
  const picks = loadWeekendPicks();
  assert.deepEqual([...picks.keys()], ['2026-10-17', '2026-10-24', '2026-10-31']);
  assert.deepEqual(picks.get('2026-10-24').map(pick => pick.id), PICKS_1024);
  for (const weekend of picksFile.weekends) {
    for (const pick of weekend.picks) {
      assert.ok(event(pick.id), pick.id);
      for (const day of pick.dates) assert.ok(eventOccursOn(event(pick.id), day), `${pick.id} on ${day}`);
    }
  }
  // The 10/24 picks run on Saturday only, so a Sunday 10/25 ask lifts none of them; a month span lifts none (API-BB-9).
  assert.deepEqual([...picksForAsk({ date: '2026-10-24' })].map(([id]) => id), PICKS_1024);
  assert.equal(picksForAsk({ date: '2026-10-25' }).size, 0);
  assert.deepEqual([...picksForAsk({ date: '2026-11-01' })], [['nov2026-fruitvale-dia-muertos', 1], ['smcl-foster-city-nidhi-chanani-2026', 4]]);
  assert.equal(picksForAsk({ dateRange: { start: '2026-10-22', end: '2026-10-31' } }).size, 0);
});

// Before this sync the API had no picks file: the 10/24 ask's candidates had Cherryland first, then a haunted house,
// Alcatraz, Angel Island and the Baylands; LumaFest and Halloween Hoopla were not offered.
test('BayBay: a 10/24 family ask on 10/22 or 10/23 offers the editor\'s 10/24 picks first, in the editor\'s order', () => {
  for (const today of ['2026-10-22', '2026-10-23']) {
    const result = evidence('10月24号周末带娃去哪玩', today);
    assert.deepEqual(candidateIds(result).slice(0, 4), FAMILY_1024, today);
    // Among the model items: LumaFest 4th and Halloween Hoopla 8th; Cherryland and SJMA reach the model only as plan
    // candidates (Cherryland was the 4th item before this sync: a TODO below).
    assert.ok(itemIds(result).slice(0, 5).includes('event:r2-petaluma-lumafest-20261024'), `${today}: ${itemIds(result).join(', ')}`);
    // "这个周末" on Thursday or Friday is 10/24–25: the first pick is among the first two candidates (none before this sync).
    const weekend = evidence('这个周末湾区有什么亲子活动？', today);
    assert.ok(candidateIds(weekend).slice(0, 2).includes('r2-petaluma-lumafest-20261024'), `${today}: ${candidateIds(weekend).join(', ')}`);
  }
  // The same for the 带娃 wording with or without a date, in zh-Hans and zh-Hant (before this sync: Cherryland first and
  // no other pick among the first four candidates).
  for (const [message, locale] of [['这周末带娃去哪玩', 'zh-Hans'], ['10/24 带娃去哪玩？', 'zh-Hans'], ['10月24号带娃去哪玩', 'zh-Hans'], ['这周六带娃去哪玩？', 'zh-Hans'], ['這週六帶娃去哪玩？', 'zh-Hant']]) {
    assert.deepEqual(candidateIds(evidence(message, TODAY, locale)).slice(0, 4), FAMILY_1024, message);
  }
  // An ask that is not about children keeps the adults' pick, in the editor's order.
  assert.deepEqual(candidateIds(evidence('这周末有什么好玩的')).slice(0, 4), PICKS_1024.slice(0, 4));
  // The next weekend asked on Thursday 10-29: its family picks first, in the editor's order.
  assert.deepEqual(candidateIds(evidence('这周末带娃去哪玩', '2026-10-29')).slice(0, 3), FAMILY_1031);
  // A Sunday ask and a month ask take no 10/24 pick.
  for (const message of ['10月25号周日带娃去哪玩', '10月带娃去哪玩']) {
    const state = resolveTaskState({ message, today: TODAY, catalog: planner, carry: true }).state;
    assert.equal(picksForAsk(state).size, 0, message);
  }
  assert.ok(!candidateIds(evidence('10月25号周日带娃去哪玩')).some(id => PICKS_1024.includes(id)));
});

// Not met by this sync (no lib/ change; see the PR's "Captain decision"). The pick lift is a fifth of the best text score,
// so whether the picks surface depends on the ask's words, not on whether it has a date: on 10-22 the 带娃 asks above get
// all four family picks first, "这周六有什么活动" two, "这个周末湾区有什么亲子活动？" only LumaFest, and the 带孩子 / 带小孩 /
// English asks below none (nor does the 10/31 weekend asked on 10-29). The acceptance check for the next BayBay lane.
const GENERIC_1024 = [['这个周末湾区有什么亲子活动？', 'zh-Hans'], ['这周末带孩子去哪玩', 'zh-Hans'], ['周末带小孩去哪里玩', 'zh-Hans'], ['这周六带孩子去哪玩？', 'zh-Hans'],
  ['10月24号带孩子去哪玩', 'zh-Hans'], ['10月24号周末带孩子去哪玩', 'zh-Hans'], ['這個週末灣區有什麼親子活動？', 'zh-Hant'], ['週六帶小孩去哪裡玩？', 'zh-Hant'],
  ['Family things to do in the Bay Area this weekend', 'en'], ['What should we do with the kids this Saturday?', 'en'], ['Where to take the kids this Saturday?', 'en'],
  ['What can kids do on October 24?', 'en'], ['Things to do with kids on Saturday October 24', 'en']];
test('BayBay: every family wording of a 10/24–25 or 10/31–11/1 ask offers the editor\'s family picks first', { todo: 'API-SYNC-3h follow-up: picks rank first on family weekend asks whatever the wording (带孩子, 带小孩, 亲子, English), not only 带娃 (next BayBay lane, before 10/24)' }, () => {
  const misses = [];
  for (const [message, locale] of GENERIC_1024) {
    const cands = candidateIds(evidence(message, TODAY, locale));
    if (JSON.stringify(cands.slice(0, 4)) !== JSON.stringify(FAMILY_1024)) misses.push(`${message}: ${cands.join(', ')}`);
  }
  for (const [message, locale] of [['这个周末湾区有什么亲子活动？', 'zh-Hans'], ['Family things to do in the Bay Area this weekend', 'en']]) {
    const cands = candidateIds(evidence(message, '2026-10-29', locale));
    if (JSON.stringify(cands.slice(0, 3)) !== JSON.stringify(FAMILY_1031)) misses.push(`${message} (10-29): ${cands.join(', ')}`);
  }
  assert.deepEqual(misses, []);
});

// API-SYNC-3h loss: passes on the api base data (3faef61), fails on the Wave 7 A copy. With the picks first among the plan
// candidates, the model items of the 10/24 family ask hold LumaFest (4th) and Halloween Hoopla (8th), and Cherryland's
// Chinese-language storytimes (the 4th item before this sync) is only a plan candidate.
test('BayBay: the 10/24 family ask keeps Cherryland\'s Chinese-language storytimes among the model items', { todo: 'API-SYNC-3h follow-up: the editor\'s family picks should all reach the model items of a dated family ask, not only the plan candidates (next BayBay lane)' }, () => {
  for (const today of ['2026-10-22', '2026-10-23']) {
    const result = evidence('10月24号周末带娃去哪玩', today);
    assert.ok(itemIds(result).includes('event:acl-cherryland-chinese-storytimes-oct24-2026'), `${today}: ${itemIds(result).join(', ')}`);
  }
});

test('offer regions (CNT-REGION-4): Randall Museum and the Cable Car Museum are San Francisco, Happy Hollow and Poppy & Claro South Bay', () => {
  for (const english of [false, true]) {
    assert.equal(discovery('offer', 'randall-museum-free', english).region, 'sf');
    assert.equal(discovery('offer', 'cable-car-museum-free', english).region, 'sf');
    assert.equal(discovery('offer', 'happy-hollow-senior-safari-oct22', english).region, 'south-bay');
    assert.equal(discovery('offer', 'poppy-claro-doggie-dinners-fall', english).region, 'south-bay');
  }
});

// Before this sync none of these asks had Randall, the Cable Car Museum, Happy Hollow or Poppy & Claro (their offers had no region).
test('BayBay: San Francisco family and free asks see Randall Museum or the Cable Car Museum; South Bay asks see Happy Hollow and Poppy & Claro, other regions never', () => {
  for (const [message, today, id] of [['这周六带 6 岁的孩子在旧金山玩，有什么推荐？', '2026-10-12', 'offer:randall-museum-free'], // I-PLAN-SF-1
    ['这周六旧金山有哪些完全免费的亲子活动？', '2026-10-12', 'offer:randall-museum-free'], // J-W2-FREE
    ['My parents are visiting. Where can they see the Golden Gate Bridge without much walking?', '2026-10-12', 'offer:randall-museum-free'], // J-EN-GGB-CARDS
    ['周六上午 10 点 出发，下午 3 点半前回家，带 6 岁孩子在旧金山有什么免费的？', '2026-10-13', 'offer:randall-museum-free'], // K-TIME-2
    ['Any free museum days in SF this month?', '2026-10-07', 'offer:cable-car-museum-free'], // C14
    ['Which San Francisco museums are free to visit this weekend?', '2026-10-14', 'offer:cable-car-museum-free'], // L-LEAD-1
    ['San Jose 有没有讲中文的长者服务？我妈想找人陪她参加活动', '2026-10-12', 'offer:happy-hollow-senior-safari-oct22'], // J-SJ-SENIOR
    ['10月22日 San Jose 老人有什么免费的地方可以去？', '2026-10-20', 'offer:happy-hollow-senior-safari-oct22'],
    ['南湾周五带狗去哪里吃饭？', '2026-10-20', 'offer:poppy-claro-doggie-dinners-fall']]) {
    const found = itemIds(evidence(message, today));
    assert.ok(found.includes(id), `${message}: ${found.join(', ')}`);
  }
  for (const message of ['10月22日旧金山老人有什么免费的地方可以去？', '旧金山周五带狗去哪里吃饭？', '东湾带狗去哪里吃饭有优惠？']) {
    const found = itemIds(evidence(message, '2026-10-20'));
    assert.ok(!found.some(id => /happy-hollow|poppy-claro/.test(id)), `${message}: ${found.join(', ')}`);
  }
});

// Before this sync these asks had no holiday hours guide (it did not exist) and no 2027 figures.
test('BayBay: holiday hours and 2027 figure asks reach the new guide and the 2027 lines (zh and en)', () => {
  for (const message of ['感恩节图书馆开门吗？', 'Are Bay Area libraries open on Thanksgiving?']) {
    const result = evidence(message);
    assert.equal(itemIds(result)[0], `guide:${HOLIDAY}`, `${message}: ${itemIds(result).join(', ')}`);
    assert.ok(modelItems(result.items).some(view => /SFPL 旧金山公共图书馆：11\/26、11\/27、12\/25 和 2027 年 1\/1 闭馆|San Francisco Public Library: closed 11\/26, 11\/27, 12\/25 and 1\/1\/2027/.test(view.text)), message);
  }
  const transit = evidence('元旦那天 BART 和 Muni 怎么开？');
  assert.ok(modelItems(transit.items).some(view => /BART：11\/26、12\/25 和 2027 年 1\/1 按周日班表/.test(view.text)), itemIds(transit).join(', '));
  const cola = evidence('What is the 2027 Social Security COLA?');
  assert.ok(modelItems(cola.items).some(view => /3\.6% in 2027/.test(view.text)), itemIds(cola).join(', '));
  const wage = evidence('2027 年加州最低工资是多少？');
  assert.ok(modelItems(wage.items).some(view => /2027 年 1 月 1 日起是每小时 \$17\.40/.test(view.text)), itemIds(wage).join(', '));
  const [zh, en] = [guides, guidesEn].map(catalog => JSON.stringify(catalog.find(row => row.slug === 'bay-area-senior-transit-clipper-discounts-guide').content));
  assert.match(zh, /2027 年 1 月 4 日起：Clipper 单程 \$1\.50/);
  assert.match(en, /From January 4, 2027: \$1\.50 single ride on Clipper/);
});

// Before this sync the 2027 parade and flower market asks had no Lunar New Year record at all.
test('BayBay: 2027 Lunar New Year asks get the dated 2027 events', () => {
  const parade = evidence('2027 旧金山春节游行是哪天？');
  assert.equal(itemIds(parade)[0], 'event:sf-chinese-new-year-parade-2027', itemIds(parade).join(', '));
  assert.match(modelItems(parade.items)[0].when, /2月20日（周六） 17:15/);
  assert.ok(candidateIds(evidence('When is the 2027 San Francisco Chinese New Year Parade?')).includes('sf-chinese-new-year-parade-2027'));
  assert.ok(itemIds(evidence('旧金山 2027 年春节花市在哪里？')).slice(0, 3).includes('event:sf-chinese-new-year-flower-market-2027'));
});

test('the 11/28–12/13 weekend review (CNT-WEEKEND-1128) reaches the event rows and BayBay', () => {
  assert.equal(event('fairyland-fairy-winterland-2026').costLabel, '成人 $23、儿童 $21，会员和 Fairyland for All 另有优惠价；11/1 开卖');
  assert.equal(event('grace-cathedral-sing-merry-christmas-2026').costLabel, '$18–$35，票价已含全部手续费');
  assert.match(event('octnov-los-altos-lights-parade-2026').dateLabel, /11\/29（周日）· 18:00/);
  // Three library sales whose pages give no entry fee are no longer "free entry".
  for (const id of ['sccl-gilroy-big-book-sale-dec12-2026', 'sjpl-tully-friends-book-sale-dec5-2026', 'scl-guerneville-winter-wreath-sale-dec5-2026']) {
    assert.equal(event(id).cost, 'unknown', id);
    assert.match(event(id).costLabel, /^活动页没有写入场费/, id);
  }
  const fairyland = evidence('Fairy Winterland 门票多少钱？').items.find(row => row.id === 'fairyland-fairy-winterland-2026');
  assert.match(modelItems([fairyland])[0].cost, /成人 \$23、儿童 \$21/);
  const sale = evidence('12月12日 Gilroy 图书馆旧书义卖要钱吗？').items.find(row => row.id === 'sccl-gilroy-big-book-sale-dec12-2026');
  assert.doesNotMatch(modelItems([sale])[0].cost, /免费入场/);
});

test('the new 2027 Lunar New Year events can be saved (they answered 404 ITEM_NOT_IN_CATALOG before this sync)', async t => {
  const users = [{ id: 'member', nickname: 'member', email: 'member@private.test', password: 'private', accountStatus: 'active', isPhoneVerified: true, city: 'San Francisco' }];
  const application = createApplication({ config: { NODE_ENV: 'test', JWT_SECRET: SECRET }, models: createMemoryModels({ User: users }),
    plannerNow: () => NOW, eventNow: () => NOW, outingNow: () => NOW });
  await new Promise(resolve => application.server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise(resolve => application.io.close(resolve)));
  const token = jwt.sign({ id: 'member', sessionIssuedAt: Date.now() }, SECRET, { algorithm: 'HS256', expiresIn: '1h' });
  for (const [kind, id] of [['event', 'sf-chinese-new-year-parade-2027'], ['event', 'sf-chinese-new-year-flower-market-2027'], ['event', 'sj-cpaa-spring-festival-gala-2027'], ['guide', HOLIDAY]]) {
    const response = await fetch(`http://127.0.0.1:${application.server.address().port}/api/planner/favorites/${kind}/${id}`, { method: 'PUT', headers: { Authorization: `Bearer ${token}` } });
    const data = await response.json();
    assert.equal(response.status, 200, `${kind}:${id}: ${JSON.stringify(data)}`);
    assert.ok(data.favorites.some(row => row.kind === kind && row.id === id), id);
  }
});
