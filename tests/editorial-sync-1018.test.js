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
    // Among the model items (API-BB-12): the four family picks, in the editor's order, right after the records the ask names
    // by its date (two craft offers on 10/24); with the old lib/ Cherryland and SJMA reached the model only as candidates.
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

// With the old lib/ the pick lift was a fifth of the best text score, so whether the picks surfaced depended on the ask's
// words: on 10-22 the 带娃 asks above got all four family picks first, "这周六有什么活动" two, "这个周末湾区有什么亲子活动？"
// only LumaFest, and the 带孩子 / 带小孩 / English asks below none (nor did the 10/31 weekend asked on 10-29). API-BB-12: on a
// family outing ask (the planner's family flag or a child's age; goal discover or day-plan) the family picks come first.
const GENERIC_1024 = [['这个周末湾区有什么亲子活动？', 'zh-Hans'], ['这周末带孩子去哪玩', 'zh-Hans'], ['周末带小孩去哪里玩', 'zh-Hans'], ['这周六带孩子去哪玩？', 'zh-Hans'],
  ['10月24号带孩子去哪玩', 'zh-Hans'], ['10月24号周末带孩子去哪玩', 'zh-Hans'], ['這個週末灣區有什麼親子活動？', 'zh-Hant'], ['週六帶小孩去哪裡玩？', 'zh-Hant'],
  ['Family things to do in the Bay Area this weekend', 'en'], ['What should we do with the kids this Saturday?', 'en'], ['Where to take the kids this Saturday?', 'en'],
  ['What can kids do on October 24?', 'en'], ['Things to do with kids on Saturday October 24', 'en']];
test('BayBay: every family wording of a 10/24–25 or 10/31–11/1 ask offers the editor\'s family picks first', () => {
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

// API-SYNC-3h loss, fixed by API-BB-12 (it passed on the api base data 3faef61 and failed on the Wave 7 A copy with the old
// lib/): with the picks first among the plan candidates, the model items of the 10/24 family ask held LumaFest (4th) and
// Halloween Hoopla (8th), and Cherryland's Chinese-language storytimes (the 4th item before the sync) was only a candidate.
test('BayBay: the 10/24 family ask keeps Cherryland\'s Chinese-language storytimes among the model items', () => {
  for (const today of ['2026-10-22', '2026-10-23']) {
    const result = evidence('10月24号周末带娃去哪玩', today);
    assert.ok(itemIds(result).includes('event:acl-cherryland-chinese-storytimes-oct24-2026'), `${today}: ${itemIds(result).join(', ')}`);
    // All four family picks are model items, in the editor's order.
    assert.deepEqual(itemIds(result).filter(id => FAMILY_1024.some(pick => id === `event:${pick}`)), FAMILY_1024.map(id => `event:${id}`), itemIds(result).join(', '));
  }
});

// API-BB-12: fresh wordings (zh-Hans, zh-Hant, English; 10-22, 10-23, 10-29) put the family picks first, and the rules
// around them hold: an adults' pick is never offered on a family ask, a Saturday-only pick never on a Sunday, a month ask
// lifts none, an ask that is not about children keeps its order, and a service or Chinese-language programme ask with a
// child, or a stated home city, keeps its own order first.
test('BayBay: the family picks lead in fresh wordings; the adults\' pick, Sunday, month, service and home-city rules hold', () => {
  for (const [message, today] of [['周六带小朋友去哪里玩比较好', TODAY], ['周末有啥亲子活动推荐', TODAY], ['这周末适合儿童的活动', TODAY], ['周六遛娃去哪', TODAY],
    ['這週末帶孩子去哪玩？', TODAY], ['這個週末有什麼親子活動', TODAY], ['What can we do with the kids this weekend?', TODAY], ['Kids activities this weekend?', TODAY],
    ['Where should I take my kids on Saturday?', TODAY], ['这周末带孩子去哪玩', '2026-10-23'], ['明天带孩子去哪玩', '2026-10-23']]) {
    assert.deepEqual(candidateIds(evidence(message, today)).slice(0, 4), FAMILY_1024, `${message} (${today})`);
  }
  for (const [message, today] of [['这周末带孩子去哪玩', '2026-10-29'], ['這週末帶小孩去哪', '2026-10-29'], ['Family things to do this weekend', '2026-10-29']]) {
    assert.deepEqual(candidateIds(evidence(message, today)).slice(0, 3), FAMILY_1031, `${message} (${today})`);
  }
  // The adults' pick (华埠分馆周六午后, audience 成人) is neither a candidate nor an item on a family ask.
  // Review of API-BB-12: nor on an ask with a baby or a stroller, which the planner's family flag does not read.
  for (const message of ['这周六带娃去哪玩？', '周六带小朋友去哪里玩比较好', '这周六带孩子去旧金山玩', '周六遛娃去哪', 'Where can we go with a baby this weekend?',
    'Stroller-friendly things to do this Saturday', '这周六推婴儿车能去哪']) {
    const result = evidence(message);
    assert.ok(![...itemIds(result), ...candidateIds(result)].some(id => /chinatown-creative-saturdays/.test(id)), message);
  }
  // Sunday 10/25: the 10/24 picks run on Saturday only.
  for (const message of ['这周日带孩子去哪玩', '週日帶小孩去哪裡玩？', 'What can kids do on Sunday October 25?']) {
    const result = evidence(message);
    assert.ok(![...itemIds(result), ...candidateIds(result)].some(id => PICKS_1024.some(pick => id.endsWith(pick))), message);
  }
  // A service ask with a child and a Chinese-language programme ask keep their own order (no pick leads, no pick item).
  for (const message of ['这周六带孩子去哪里打疫苗', '这周末湾区有粤语或国语的亲子活动吗？']) {
    const result = evidence(message);
    assert.notDeepEqual(candidateIds(result).slice(0, 4), FAMILY_1024, message);
  }
  // A stated home city orders by nearness first: Fremont's own records lead.
  assert.ok(!FAMILY_1024.includes(candidateIds(evidence('我们住 Fremont，这周末带孩子去哪玩'))[0]));
  // A month ask lifts none.
  assert.equal(picksForAsk(resolveTaskState({ message: '十月带孩子去哪玩', today: TODAY, catalog: planner, carry: true }).state).size, 0);
});

// Review of API-BB-12: "where to take" read as an outing phrase for any object made every "Where to take X in <city>" ask an
// outing ask, so service asks lost the guides that answer them (the HHW, ESL, driver's license and naturalization guides) to
// outing records. It is an outing only when what it takes is company and nothing but a day, a time or a place follows.
const TAKE_SERVICE = ['Where to take old batteries in San Jose', 'Where to take e-waste in Oakland this Saturday', 'Where to take a COVID test in San Francisco',
  'Where to take hazardous waste in Santa Clara County', 'Where to take English classes in Oakland', 'Where to take the DMV written test in Fremont',
  'Where to take a sick child at night in San Jose', 'Where to take a toddler with a high fever tonight in Fremont', 'Where to take my toddler to see a pediatrician in Oakland',
  'Where to take my grandma to the ER tonight in San Jose', 'Where to take a dog to the vet in Oakland', 'Where to take the citizenship test in San Francisco?',
  'Where to take a free English class in Oakland?', 'Where to take hazardous waste in San Mateo?', 'Where to take donated clothes this Saturday?', 'Where to take a blood test this Saturday',
  'Where to take my kids for flu shots this Saturday', 'Where to take the kids tonight with a fever', 'Where to take my son to the dentist in Fremont'];
test('BayBay: "where to take" is an outing only with company as its object; service asks keep their reading and their guides', () => {
  const goal = message => resolveTaskState({ message, today: TODAY, catalog: planner, carry: true }).state.goal;
  for (const message of TAKE_SERVICE) {
    assert.notEqual(goal(message), 'discover', message);
    const result = evidence(message);
    assert.ok(!result.familyPicks, `${message}: ${result.familyPicks}`);
    assert.ok(![...itemIds(result), ...candidateIds(result)].some(id => PICKS_1024.some(pick => id.endsWith(pick))), `${message}: ${itemIds(result).join(', ')}`);
  }
  for (const [message, slug] of [['Where to take hazardous waste in San Mateo?', 'bay-area-bulky-items-ewaste-hhw-guide'], ['Where to take the DMV written test in San Jose?', 'california-driver-license-id-preparation-guide'],
    ['Where to take a free English class in Oakland?', 'bay-area-free-esl-adult-learning-guide'], ['Where to take the citizenship test in San Francisco?', 'bay-area-naturalization-official-path-guide']]) {
    assert.ok(itemIds(evidence(message)).includes(`guide:${slug}`), message);
  }
  for (const message of ['Where to take the kids this Saturday?', 'Where to take my parents in Oakland?', 'Where to take my 4 year old this Saturday', 'Where to take out-of-town guests in the Bay Area?']) {
    assert.equal(goal(message), 'discover', message);
  }
});

// Review round 4 of API-BB-12: grandkids, grandchildren and little ones are children the planner's family flag does not read,
// so "where to take" outings with them (and the sync's own "Things to do with the grandkids …" / 带孙子 asks) offered the
// adults' pick 华埠分馆周六午后 first. They get the adult filters, as a baby or a stroller does (not the picks first).
test('BayBay: grandkids, grandchildren and little-ones asks never offer the adults\' pick', () => {
  for (const message of ['Where to take my grandkids this weekend in San Francisco', 'Where to take the grandchildren this Saturday in SF', 'Where to take the little ones on Saturday in San Francisco',
    'Where to take my grandkids this Saturday in the Bay Area', 'Where to take my little ones this Saturday', 'Where to take the grandkids this Saturday?',
    'Things to do with the grandkids this Saturday in San Francisco', '這週六帶孫子去舊金山哪裡玩', '这周六带孙子在旧金山去哪玩', '周末带外孙去旧金山玩什么', '這週末帶孫女去哪玩',
    'Where can I take my grandson this Saturday in San Francisco?']) {
    const result = evidence(message);
    assert.ok(![...itemIds(result), ...candidateIds(result)].some(id => /chinatown-creative-saturdays/.test(id)), `${message}: ${itemIds(result).join(', ')}`);
    assert.ok(!result.familyPicks, `${message}: ${result.familyPicks}`);
  }
  // An ask that is not about children keeps it.
  assert.ok(candidateIds(evidence('这周末有什么好玩的')).includes('sfpl-chinatown-creative-saturdays-fall-2026'));
});

// Review of API-BB-12: a setting (室内, indoor) or 附近 with no home city is a constraint the picks may not meet, so those
// asks keep their own order (indoor storytimes and museums first) rather than the outdoor LumaFest and Halloween Hoopla.
test('BayBay: indoor and 附近 family asks keep their own order; no outdoor pick leads them', () => {
  for (const message of ['这周六带孩子去室内玩', 'Indoor activities for kids this Saturday', '这周末带孩子去哪玩？要室内的', '这周末带孩子去哪玩 附近的']) {
    const result = evidence(message);
    assert.ok(!result.familyPicks, `${message}: ${result.familyPicks}`);
    assert.notEqual(candidateIds(result)[0], 'r2-petaluma-lumafest-20261024', message);
    assert.ok(!itemIds(result).slice(0, 2).includes('event:menlo-park-halloween-hoopla-2026'), `${message}: ${itemIds(result).join(', ')}`);
  }
});

// Review of API-BB-12: the first senior discount rule dropped every catalog record that did not speak to older people, the
// asked venue's own records included. Only a members' or programme price (Fairy Winterland's "会员和 Fairyland for All 另有
// 优惠价") on a plain senior discount ask is left out; an ask with its own subject keeps the records it is about.
test('BayBay: a senior discount ask about a venue or a show keeps that venue\'s and show\'s records', () => {
  const offered = result => [...itemIds(result), ...candidateIds(result).map(id => `event:${id}`)];
  for (const [message, ids] of [['老人去 ZooLights 有优惠吗', ['sfzoo-zoolights-2026']], ['Does the SF Zoo have a senior discount?', ['sfzoo-zoolights-2026']],
    ['老人去 Fairyland 有优惠吗', ['fairyland-fairy-winterland-2026']], ['Senior discount Fairyland Oakland', ['fairyland-fairy-winterland-2026']],
    ['老人看胡桃夹子有优惠吗', ['berkeley-ballet-nutcracker-bird-2026', 'new-ballet-san-jose-nutcracker-2026', 'oakland-ballet-nutcracker-paramount-2026']],
    ['老人去 Chase Center 看球有优惠吗', ['sf-warriors-grizzlies-2026']], ['Any senior discounts at the Oakland Zoo?', ['oakland-zoo-glowfari-2026']],
    ['老年人去 Filoli 有优惠吗', ['filoli-holidays-from-nov14-2026']]]) {
    const result = evidence(message);
    for (const id of ids) assert.ok(offered(result).includes(`event:${id}`), `${message}: ${id} not in ${offered(result).join(', ')}`);
  }
  // A plain senior discount ask in other words still never offers the member price.
  for (const message of ['老年人有什么优惠活动', '退休老人有什么折扣', 'Any deals for seniors this weekend?', '长者 12 月有什么优惠']) {
    const result = evidence(message);
    assert.ok(!offered(result).some(id => /fairyland-fairy-winterland-2026/.test(id)), `${message}: ${offered(result).join(', ')}`);
  }
});

// Review of API-BB-12: on a named-agency fare ask the excerpt filled its space with other rows' later sentences, nameless
// ("$1.50 cash; monthly pass $43; AC Transit (East Bay): …" put Muni's cash fare and monthly pass beside the asked row).
// A row's later sentences now come only with the row's own name, and on a named ask only from the asked rows.
test('BayBay: a senior fare excerpt never offers another agency\'s figures without its name', () => {
  for (const [message, locale, stray] of [['How much is AC Transit for seniors?', 'en', /monthly pass \$43|\$1\.50 cash;/], ['AC Transit senior fare?', 'en', /monthly pass \$43/],
    ['SamTrans fare for seniors', 'en', /monthly pass \$43/], ['Will BART fares go up next year for seniors?', 'en', /monthly pass \$43/], ['AC Transit 長者票價多少？', 'zh-Hant', /月票 \$43|这是 2026 年 10 月 17 日官网上的现行票价/]]) {
    const views = modelItems(evidence(message, TODAY, locale).items);
    assert.ok(views.some(view => /\$1\.37|\$1\.00 on Clipper|62\.5%|no fare increase/.test(view.text)), message);
    assert.ok(!views.some(view => view.kind === 'guide' && stray.test(view.text)), `${message}: ${views.filter(view => stray.test(view.text)).map(view => view.text).join(' | ')}`);
  }
});

// Review of API-BB-12, round 3: the row rules held only on senior fare asks, so a senior ask about a pass, the cable car or
// what is free ("老人月票", "Senior cable car ticket", "长者免费") read Muni's "月票 $43" and VTA's "$30" with no name, right
// after BART's row. Every excerpt of a priced table (priced rows for three or more names) now keeps them: a row's later
// sentence comes only after the row's own name, in the guide's words. Checked from the published table itself: each row's
// name and later sentences, read from the shipped guide catalogs.
const LEAD = /^\s*([A-Za-z][A-Za-z0-9.&'’ -]{0,30}?|[^\s:：（(，,。；;]{1,12}?)\s*(?:[（(][^）)\n]{0,40}[）)])?\s*[:：]/;
const tableRowsOf = (catalog, slug) => catalog.find(guide => guide.slug === slug).content.split(/\n\s*\n/).flatMap(paragraph => {
  const rows = paragraph.split('\n').filter(line => /\$\s?\d|\d\s?%/.test(line) && LEAD.exec(line)?.[1].trim());
  return new Set(rows.map(line => LEAD.exec(line)[1].trim())).size >= 3 ? rows.map(line => ({ name: LEAD.exec(line)[1].trim(),
    later: line.replace(/[ \t]+/g, ' ').split(/(?<=[。！？；;!?\n])|(?<=\.)\s+/).map(value => value.trim()).filter(value => value.length >= 6).slice(1) })) : [];
});
test('BayBay: every excerpt of a priced table names a row before its later sentences, fare ask or not', () => {
  const tables = { 'zh-Hans': [], en: [] };
  for (const slug of ['bay-area-senior-transit-clipper-discounts-guide', 'bay-area-social-security-retirement-preparation-guide']) {
    tables['zh-Hans'].push(...tableRowsOf(guides, slug).map(row => ({ ...row, slug })));
    tables.en.push(...tableRowsOf(guidesEn, slug).map(row => ({ ...row, slug })));
  }
  assert.ok(tables['zh-Hans'].length >= 8 && tables.en.length >= 8);
  let checked = 0;
  for (const message of ['老人月票', '老人买月票多少钱', '老人日票多少钱', '長者月票幾錢', '老人坐缆车要钱吗', '长者缆车票价', '长者免费', '老人有什么免费的', '长者有什么免费午餐',
    'Senior cable car ticket', 'Do seniors pay on the cable car?', 'Cable car price for seniors', 'Senior monthly pass', 'How much is the senior monthly pass?', 'Do seniors get a cheaper monthly pass?',
    "What's free for seniors in SF?", 'How much will Social Security go up in 2027?', 'SSI payment 2027 amount', '2027 年社安金调整多少']) {
    const locale = /[㐀-鿿]/.test(message) ? 'zh-Hans' : 'en';
    const result = evidence(message, TODAY, locale);
    for (const item of result.items.filter(entry => entry.kind === 'guide')) {
      for (const row of tables[locale].filter(entry => entry.slug === item.id)) for (const sentence of row.later) {
        const at = item.text.indexOf(sentence);
        if (at < 0) continue;
        checked++;
        assert.ok(item.text.slice(0, at).includes(row.name), `${message}: "${sentence}" without "${row.name}" in: ${item.text}`);
      }
    }
  }
  assert.ok(checked >= 20, `only ${checked} later sentences offered`);
  // The asks the review read: Muni's and VTA's passes come with their names.
  for (const [message, figure] of [['老人月票', /月票 \$43/], ['Senior cable car ticket', /cable car \$4/], ['老人坐缆车要钱吗', /缆车在早上 7 点前或晚上 9 点后 \$4/]]) {
    const text = modelItems(evidence(message).items).filter(view => view.kind === 'guide').map(view => view.text).find(value => figure.test(value)) || '';
    assert.ok(text && text.slice(0, figure.exec(text).index).includes('Muni'), `${message}: ${text}`);
  }
});

// Review of API-BB-12, round 3: "rides" (the plural noun) made "Senior rides to the grocery store" a senior fare ask, whose
// rules dropped the senior transit guide's link to the without-car guide, its only paragraph on groceries; the guide was
// gone. "rides" is a ride service, not a way of riding; "ride" and "riding" still are ("Senior price for a single ride").
test('BayBay: "Senior rides to the grocery store" keeps the senior transit guide; a single ride is still a fare ask', () => {
  for (const message of ['Senior rides to the grocery store in Oakland', 'Senior rides to grocery stores in San Jose']) {
    const views = modelItems(evidence(message).items);
    // The senior transit guide's paratransit section, with its link to the without-car guide ("… grocery runs").
    assert.ok(views.some(view => /senior-transit-clipper-discounts-guide/.test(view.page) && /ADA paratransit/.test(view.text) && /without a car/.test(view.text)),
      `${message}: ${views.map(view => view.page).join(', ')}`);
  }
  // A single ride and riding BART are still fare asks: the fares paragraph is offered.
  assert.ok(modelItems(evidence('Senior price for a single ride').items).some(view => view.kind === 'guide' && /62\.5%/.test(view.text) && /\$1\.40/.test(view.text)));
  assert.ok(modelItems(evidence('Can seniors ride BART for free?').items).some(view => view.kind === 'guide' && /62\.5%/.test(view.text)));
});

// Review of API-BB-12: an opening's startDate is the day it opened, so an open restaurant or shop is never labelled ended
// (Yutori, the Oakland game parlour and Sergeant Ma read "已结束" before; the cards dropped them as past).
test('BayBay: an open opening is never labelled ended', () => {
  for (const [message, today] of [['Senior discounts at restaurants', TODAY], ['这周末有适合小朋友的粤语或者国语故事会吗？', '2026-10-13'], ['周末有没有一家适合朋友聚会的地方 旧金山', TODAY]]) {
    const result = evidence(message, today);
    const openings = result.items.filter(item => item.kind === 'opening');
    assert.ok(openings.every(item => !/已结束|已結束|ended/.test(item.status || '') && item.temporalStatus !== 'past'), `${message}: ${openings.map(item => `${item.id} ${item.status}`).join(', ')}`);
  }
});

// Review of API-BB-12: which asks are senior fare asks. A senior ask about riding with no price word had the fares on the api
// base data and lost them with the sync ("长者坐车", "老人坐地铁", "Senior transit in the Bay Area"); an ask about rides to the
// doctor keeps the paratransit paragraph first, as on the base data; a discount word on an ask with its own subject and
// 圣诞老人 (Santa Claus) do not make a fare ask.
test('BayBay: senior riding asks keep the fares; ride-service, own-subject and Santa asks keep their own first items', () => {
  for (const message of ['长者坐车', '老人坐公交需要什么卡', '老人坐地铁', 'Senior transit in the Bay Area', 'Seniors riding the bus in Oakland']) {
    const views = modelItems(evidence(message).items);
    assert.ok(views.some(view => view.kind === 'guide' && /62\.5%|\$1\.40|\$1\.37/.test(view.text)), `${message}: ${itemIds(evidence(message)).join(', ')}`);
  }
  const rides = modelItems(evidence('老人坐公交去医院有接送吗').items);
  assert.match(rides[0].text, /辅助交通（paratransit）/);
  // A Santa photo ask is not a senior ask: the autumn freebies guide stays its 10th item, as before the sync.
  assert.ok(itemIds(evidence('哪里可以和圣诞老人拍照，门票多少钱')).includes('guide:bay-area-freebies-deals-2026-10'));
  // A discount ask about a show or a venue: no fares row takes a place of the show's own records.
  assert.ok(itemIds(evidence('老人看胡桃夹子有优惠吗')).includes('event:oakland-ballet-nutcracker-paramount-2026'));
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

// Not met by the sync alone (it fails on the api base data too, which has no 2027 fares). The senior transit guide carries
// Muni's 2027 senior fares (pinned above) at the end of the long "Fares for 65+" / "65 岁及以上的各家票价" section, past the
// 400-character excerpt, so with the old lib/ a senior 2027 Muni ask never saw them: the English ask got no 2027 line and
// the Chinese ask only the commute guide's adult $3.00 line (10th item). API-BB-12: the excerpt keeps the asked agency's
// row, 2027 line included. The adult 2027 Muni asks keep the commute guide's $3.00 line, and "BART 明年涨价吗 老人" keeps the
// 2026–27 budget's no-increase line.
test('BayBay: senior 2027 Muni asks see the senior transit guide\'s 2027 senior fare', () => {
  for (const message of ['What will Muni cost for seniors in 2027?', '2027 年 Muni 长者票价多少']) {
    const result = evidence(message);
    assert.ok(modelItems(result.items).some(view => view.kind === 'guide' && /January 4, 2027: \$1\.50 single ride on Clipper|2027 年 1 月 4 日起：Clipper 单程 \$1\.50/.test(view.text)), `${message}: ${itemIds(result).join(', ')}`);
  }
  for (const message of ['Muni 2027 年票价', 'How much is Muni in 2027?']) assert.ok(modelItems(evidence(message).items).some(view => /\$3\.00/.test(view.text)), message);
  assert.ok(modelItems(evidence('BART 明年涨价吗 老人').items).some(view => /不涨票价/.test(view.text)));
  assert.ok(modelItems(evidence('Will BART fares go up next year for seniors?').items).some(view => /no fare increase/.test(view.text)));
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
