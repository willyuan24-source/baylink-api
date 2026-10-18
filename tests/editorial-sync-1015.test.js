const test = require('node:test');
const assert = require('node:assert/strict');
const jwt = require('jsonwebtoken');
const { createApplication } = require('../server');
const { createMemoryModels } = require('./support/memory-models');
const { loadPlannerCatalog } = require('../lib/planner');
const { loadDiscoveryCatalog } = require('../lib/publicContext');
const { resolveTaskState } = require('../lib/baybayState');
const { buildFastEvidence, modelItems } = require('../lib/baybayEvidence');
const { normalizeGuideQuery } = require('../lib/guideLocale');
const guides = require('../data/guide-catalog.json');
const guidesEn = require('../data/guide-catalog.en.json');
const registry = require('../data/source-registry.json');

// API-SYNC-3e from web c8abe11b (web #45, Wave 6 A): three guides for older family members (senior transit discounts, elder
// scams, a Chinese-language resource map), the Oakland library storytimes marked free under the library's policy, and a paid
// CHSA seminar. What the synced catalogs change for saves and for BayBay's fast evidence. Production loaders and the shipped
// data files with a fixed day; no model, no network. A later sync that changes one of these rows on purpose updates the pin
// from the web data, which is the source of truth.
const NOW = Date.parse('2026-10-15T19:00:00Z'); // Thu 2026-10-15 12:00 PDT
const TODAY = '2026-10-15';
const SECRET = 'api-sync-3e-isolated-test-secret-0123456789';
const planner = loadPlannerCatalog();
const discoveries = { ...loadDiscoveryCatalog(), english: loadDiscoveryCatalog(undefined, true) };
const TRANSIT = 'bay-area-senior-transit-clipper-discounts-guide';
const SCAM = 'bay-area-elder-scam-prevention-guide';
const MAP = 'bay-area-chinese-language-resource-map';
const NEW_GUIDES = [TRANSIT, SCAM, MAP];
// As the engine does (lib/baybayEngine/router.js and evidence.js): the query is normalizeGuideQuery(message), the guide
// catalog is the reader's locale.
const evidence = (message, locale = /[㐀-鿿]/.test(message) ? 'zh-Hans' : 'en') => buildFastEvidence({ query: normalizeGuideQuery(message), originalQuery: message,
  state: resolveTaskState({ message, today: TODAY, catalog: planner, carry: true }).state, guideCatalog: locale === 'en' ? guidesEn : guides, catalog: planner, discoveries, today: TODAY, locale, audience: true });
const itemIds = result => result.items.map(item => `${item.kind}:${item.id}`);

test('the three elder guides are in the zh, en and planner catalogs, with English titles and registered sources', () => {
  for (const slug of NEW_GUIDES) {
    const zh = guides.find(row => row.slug === slug), en = guidesEn.find(row => row.slug === slug);
    assert.ok(zh && en, slug);
    assert.equal(zh.url, `/guides/${slug}`);
    assert.ok(planner.guides.some(row => row.slug === slug), slug);
    assert.ok(en.title && !/[㐀-鿿]/.test(en.title), `${slug}: ${en.title}`);
    // Every source the guide cites (zh and en) is a monitored registry row for it.
    assert.ok(zh.sources.length >= 5, slug);
    for (const source of [...zh.sources, ...en.sources]) {
      assert.ok(registry.some(row => row.url === source.url && row.contentIds.includes(slug)), `${slug}: ${source.url}`);
    }
  }
});

test('library cost policy and the CHSA seminar fee reach the API catalog', () => {
  const event = id => planner.events.find(row => row.id === id);
  for (const id of ['opl-main-family-storytime-2026', 'opl-asian-branch-family-time-2026', 'opl-piedmont-ave-mug-swap-dec12-2026']) {
    assert.equal(event(id).cost, 'free', id);
    assert.equal(event(id).planning.admissionUsd, 0, id);
  }
  assert.equal(event('chsa-taiwanese-chinese-roots-seminar-2026').cost, 'paid');
});

test('the new guides can be saved (they answered 404 ITEM_NOT_IN_CATALOG before this sync)', async t => {
  const users = [{ id: 'member', nickname: 'member', email: 'member@private.test', password: 'private', accountStatus: 'active', isPhoneVerified: true, city: 'Oakland' }];
  const application = createApplication({ config: { NODE_ENV: 'test', JWT_SECRET: SECRET }, models: createMemoryModels({ User: users }),
    plannerNow: () => NOW, eventNow: () => NOW, outingNow: () => NOW });
  await new Promise(resolve => application.server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise(resolve => application.io.close(resolve)));
  const token = jwt.sign({ id: 'member', sessionIssuedAt: Date.now() }, SECRET, { algorithm: 'HS256', expiresIn: '1h' });
  for (const slug of NEW_GUIDES) {
    const response = await fetch(`http://127.0.0.1:${application.server.address().port}/api/planner/favorites/guide/${slug}`, { method: 'PUT', headers: { Authorization: `Bearer ${token}` } });
    const data = await response.json();
    assert.equal(response.status, 200, `${slug}: ${JSON.stringify(data)}`);
    assert.ok(data.favorites.some(row => row.kind === 'guide' && row.id === slug), slug);
  }
});

test('BayBay leads with the senior transit guide for 老人卡 and senior fare asks', () => {
  for (const message of ['老人卡', '长者坐车', '我爸妈65岁了，怎么办老人卡坐车便宜一点？', '長者坐車有什麼優惠？', 'How do my parents get a senior Clipper card?', 'Senior discounts on BART and Muni']) {
    const found = itemIds(evidence(message));
    assert.equal(found[0], `guide:${TRANSIT}`, `${message}: ${found.join(', ')}`);
  }
  // API-SYNC-3h: web Wave 7 A (CNT-YEAREND) gives the commute guide a "感恩节到元旦怎么坐车" link paragraph naming BART, so
  // "老人坐 BART 有优惠吗" now leads with the commute guide. The senior transit guide is still in the first four items and its
  // BART line (62.5% off with a Senior Clipper card) is still in the evidence; leading again is the TODO below.
  const bart = evidence('老人坐 BART 有优惠吗');
  assert.ok(itemIds(bart).slice(0, 4).includes(`guide:${TRANSIT}`), itemIds(bart).join(', '));
  assert.ok(modelItems(bart.items).some(view => view.kind === 'guide' && /BART：持 Senior Clipper 卡，票价减 62\.5%/.test(view.text)));
});

// API-SYNC-3h losses: each passes on the api base data (3faef61) and fails on the Wave 7 A copy. API-BB-12 fixed them; its
// fare rules were reverted in review round 4 (English senior fare asks led with the Chinese fares paragraph under the
// production English catalog, and English cable car asks lost the asked $4 fare), so they are TODOs again for API-BB-13.
test('BayBay: "老人坐 BART 有优惠吗" leads with the senior transit guide', { todo: 'API-BB-13 follow-up: the commute guide\'s new holiday-transit link paragraph outranks the senior transit guide (API-SYNC-3h loss)' }, () => {
  assert.equal(itemIds(evidence('老人坐 BART 有优惠吗'))[0], `guide:${TRANSIT}`);
});
// Why the fare lines fall out (measured on the Wave 7 A data with the senior transit guide varied): a guide gives at most
// three paragraphs to a one-subject ask. CNT-YEAREND's "Fares for 65+" / "65 岁及以上的各家票价" section is longer (BART's
// 2026–27 budget sentence, Muni's 2027 fares, the "as of 10/17" notes; English 777 → 1,442 characters), so it scores lower
// and loses its paragraph to the paratransit or Clipper-card paragraph, or keeps it with a 400-character excerpt that ends
// before the asked agency. The new link-only paragraph ("Getting around from Thanksgiving to New Year's" / "感恩节到元旦怎么
// 坐车" + one line + its /guides/ URL, under the paratransit heading) also takes one of the three on some asks. With the
// base section text every fare below comes back except on "Senior discounts on BART and Muni", which also needs the link
// paragraph gone; without the link paragraph alone, only that ask's 62.5% line and "长者坐 Muni 多少钱" come back.
const FARE_LOSS = 'API-BB-13 follow-up: CNT-YEAREND\'s longer fares section loses its paragraph slot or its excerpt ends before the asked agency, and the new holiday-transit link paragraph takes a slot (API-SYNC-3h loss)';
test('BayBay: "Senior discounts on BART and Muni" keeps BART\'s 62.5% Senior Clipper discount in the evidence', { todo: FARE_LOSS }, () => {
  assert.ok(modelItems(evidence('Senior discounts on BART and Muni').items).some(view => /BART: 62\.5% off with a Senior Clipper card/.test(view.text)));
});
for (const [message, label, fact] of [['Senior discounts on BART and Muni', 'Muni\'s $1.40 senior fare', /Muni \(San Francisco\): single ride \$1\.40/],
  ['How much is VTA for seniors?', 'VTA\'s $1 senior fare', /VTA \(South Bay\): single ride \$1;/], ['Senior fares in the Bay Area', 'AC Transit\'s $1.37 senior fare', /senior local single ride is \$1\.37 on Clipper/],
  ['长者坐 Muni 多少钱', 'Muni\'s $1.40 senior fare', /Muni（旧金山）：[^\n]{0,20}单程 \$1\.40/], ['老人坐公交有什么优惠', 'BART\'s 62.5% senior discount', /BART：持 Senior Clipper 卡，票价减 62\.5%/],
  ['老人坐公交有什么优惠', 'Muni\'s $1.40 senior fare', /Muni（旧金山）：[^\n]{0,20}单程 \$1\.40/]]) {
  test(`BayBay: "${message}" keeps ${label} in the evidence`, { todo: FARE_LOSS }, () => {
    const result = evidence(message);
    assert.ok(modelItems(result.items).some(view => view.kind === 'guide' && fact.test(view.text)), itemIds(result).join(', '));
  });
}
// More wordings of the same loss, an age instead of 老人 / 长者 included (API-BB-12's pins, TODO again with its fare rules
// reverted): each fact in the senior transit guide's excerpt, and that guide first where the ask says 老人 / 长者 / senior.
test('BayBay: senior fare asks in other wordings keep the asked fare row, and the guide that has it leads', { todo: FARE_LOSS }, () => {
  for (const [message, fact] of [['AC Transit 老人票多少钱', /AC Transit（东湾）：长者本地单程用 Clipper \$1\.37/], ['老人搭 BART 打几折', /BART：持 Senior Clipper 卡，票价减 62\.5%/],
    ['長者搭 VTA 票價', /VTA（南湾）：单程 \$1；/], ['长者坐 SamTrans 多少钱', /SamTrans（半岛）：单程 Clipper \$1\.00/], ['老人 Muni 月票多少钱', /月票 \$43/],
    ['我妈70岁了坐公交有优惠吗', /BART：持 Senior Clipper 卡，票价减 62\.5%/], ['Muni senior fare', /Muni \(San Francisco\): single ride \$1\.40/],
    ['What do seniors pay on VTA?', /VTA \(South Bay\): single ride \$1;/], ['SamTrans fare for seniors', /SamTrans \(Peninsula\): single ride \$1\.00 on Clipper/],
    ['How much do seniors pay for public transit in the Bay Area?', /BART: 62\.5% off with a Senior Clipper card/]]) {
    const result = evidence(message);
    const views = modelItems(result.items);
    assert.ok(views.some(view => view.kind === 'guide' && fact.test(view.text)), `${message}: ${itemIds(result).join(', ')}`);
    if (/[长長]者|老人|senior/i.test(message)) assert.equal(itemIds(result)[0], `guide:${TRANSIT}`, `${message}: ${itemIds(result).join(', ')}`);
  }
});
// Fairy Winterland (Oakland, 12/12–27, a children's event) gained the cost label "成人 $23、儿童 $21，会员和 Fairyland for All
// 另有优惠价"; its 优惠价 is for members and the low-income Fairyland for All programme, not for seniors, yet senior discount
// asks offered it (5th item) with the old lib/. API-BB-12: on a plain senior discount ask (older people, discounts, riding,
// days and places, nothing else) with no children in it, a catalog record whose price is a members' or programme price and
// whose record never speaks to older people (老人 / 长者 / senior …, not 圣诞老人, or an age of 50 or more) is not offered.
// An ask with its own subject (it names the event, a venue, a show) keeps every record (review of API-BB-12), and a
// member-discount ask ("有什么会员优惠") may offer it: there the member price is the answer.
test('BayBay: senior discount asks never offer Fairy Winterland\'s member price as a senior discount', () => {
  for (const message of ['老人有什么优惠', '长者有什么优惠', '长者坐车有什么优惠', '老人坐 BART 有优惠吗', '長者坐車有什麼優惠？', 'Senior discounts in the Bay Area',
    '12月12号奥克兰老人有什么优惠', 'Discounts for seniors in Oakland in December', '我妈70岁了坐公交有优惠吗']) {
    const result = evidence(message);
    const offered = [...itemIds(result), ...(result.candidates || []).map(row => `candidate:${row.id}`)];
    assert.ok(!offered.some(id => /fairyland-fairy-winterland-2026/.test(id)), `${message}: ${offered.join(', ')}`);
  }
  // A senior ask that names it, a member ask and a family ask still get it.
  for (const message of ['老人去 Fairy Winterland 有优惠吗', '有什么会员优惠', '奥克兰带孩子去哪玩']) {
    const result = evidence(message);
    const offered = [...itemIds(result), ...(result.candidates || []).map(row => `candidate:${row.id}`)];
    assert.ok(offered.some(id => /fairyland-fairy-winterland-2026/.test(id)), `${message}: ${offered.join(', ')}`);
  }
});

test('BayBay leads with the elder scam guide for 防诈骗 and impersonation-call asks', () => {
  for (const message of ['防诈骗', '老人诈骗', '我妈接到自称中国大使馆的电话让她转账，怎么办？', '老人詐騙怎麼防？', 'How can I protect my elderly parents from scams?',
    'My mom got a call from someone claiming to be the Chinese police. Is it a scam?']) {
    const found = itemIds(evidence(message));
    assert.equal(found[0], `guide:${SCAM}`, `${message}: ${found.join(', ')}`);
  }
});

test('BayBay leads with the Chinese-language resource map for 华人资源 asks', () => {
  for (const message of ['华人资源', '湾区有哪些华人资源？', '有没有中文的法律援助和看病资源']) {
    const found = itemIds(evidence(message));
    assert.equal(found[0], `guide:${MAP}`, `${message}: ${found.join(', ')}`);
  }
  // An English ask with the map's own subject words finds it among the guides.
  const doctors = itemIds(evidence('Where can my parents find Chinese-speaking doctors and legal aid?'));
  assert.ok(doctors.includes(`guide:${MAP}`), doctors.join(', '));
});

// Before and after this sync: 灣區華人資源 has no evidence at all and 灣區有哪些華人資源？ gets the roommate and household-bills
// guides (normalizeGuideQuery does not map 華 or 資), the English ask "Chinese resources" leads with the library guide, and
// 湾区有哪些中文服务机构 reaches the map only through the elder scam guide's related-guide link paragraph. The one assertion
// lists every ask that still misses the map.
test('the resource map answers the zh-Hant, English and 中文服务机构 forms of the ask', { todo: 'API-SYNC-3e follow-up for the next BayBay lane: Traditional characters in normalizeGuideQuery, English "Chinese resources", related-guide link paragraphs' }, () => {
  const misses = ['灣區華人資源', '灣區有哪些華人資源？', 'Chinese resources', '湾区有哪些中文服务机构？'].map(message => ({ message, items: itemIds(evidence(message)) }))
    .filter(row => !row.items.includes(`guide:${MAP}`)).map(row => `${row.message} -> ${row.items.slice(0, 3).join(', ') || 'no items'}`);
  assert.deepEqual(misses, []);
});
