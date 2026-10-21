const test = require('node:test');
const assert = require('node:assert/strict');
const { loadPlannerCatalog, eventOccursOn } = require('../lib/planner');
const { loadDiscoveryCatalog } = require('../lib/publicContext');
const { resolveTaskState } = require('../lib/baybayState');
const { buildFastEvidence, modelItems } = require('../lib/baybayEvidence');
const { normalizeGuideQuery } = require('../lib/guideLocale');
const { loadWeekendPicks, picksForAsk } = require('../lib/weekendPicks');
const guides = require('../data/guide-catalog.json');
const guidesEn = require('../data/guide-catalog.en.json');
const discoveriesZh = require('../data/discoveries.json');
const discoveriesEn = require('../data/discoveries.en.json');
const registry = require('../data/source-registry.json');
const picksFile = require('../data/weekend-picks.json');

// API-SYNC-3i from web 32352639 (web #50–#57): CNT-W1024's 10/24–25 weekly review of 10/21 (the editor's new 10/24–25
// picks, 68 events and 9 dated offers whose official pages were read on 10/21, four corrections), #54's new-shop signs
// (what each shop sells) and VTA ACCESS lines, #55 / #57 image fields. What the synced catalogs change for BayBay's fast
// evidence. Production loaders and the shipped data files with fixed days; no model, no network. A later sync that changes
// one of these rows on purpose updates the pin from the web data, the source of truth.
const TODAY = '2026-10-22'; // Thu 2026-10-22, the day before the deploy deadline
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
/** The model's view of one evidence item (what lib/baybayEngine sends), or undefined. */
const modelItem = (result, key) => { const index = itemIds(result).indexOf(key); return index < 0 ? undefined : modelItems(result.items)[index]; };

const CHERRYLAND = 'acl-cherryland-chinese-storytimes-oct24-2026';
const LUMAFEST = 'r2-petaluma-lumafest-20261024';
const PLANNING_DAY = 'sf-financial-planning-day-oct24-2026';
const DUMPLINGS = 'sf-world-of-dumplings-2026';
const OMCA = 'oakland-omca-dia-muertos-2026';
const EXPLORATORIUM = 'sf-exploratorium-family-science-oct24-2026';
const MONSTER_MASH = 'cupertino-monster-mash-2026';

test('the 10/24–25 picks: Cherryland, LumaFest and the Financial Planning Day on Saturday; World of Dumplings and OMCA on Sunday', () => {
  assert.equal(picksFile.generatedAt, '2026-10-21');
  assert.deepEqual([...loadWeekendPicks().keys()], ['2026-10-24', '2026-10-31']);
  const weekend = picksFile.weekends.find(row => row.start === '2026-10-24');
  assert.equal(weekend.end, '2026-10-25');
  assert.deepEqual(weekend.picks.map(pick => [pick.rank, pick.id, pick.dates.join(' ')]), [
    [1, CHERRYLAND, '2026-10-24'], [2, LUMAFEST, '2026-10-24'], [3, PLANNING_DAY, '2026-10-24'],
    [4, DUMPLINGS, '2026-10-25'], [5, OMCA, '2026-10-25']]);
  for (const pick of weekend.picks) for (const day of pick.dates) assert.ok(eventOccursOn(event(pick.id), day), `${pick.id} on ${day}`);
  // The elder-friendly picks and the reasons the site prints.
  assert.deepEqual(weekend.picks.filter(pick => pick.elderFriendly).map(pick => pick.id), [LUMAFEST, PLANNING_DAY]);
  assert.equal(weekend.picks[2].reason_zh, '免费英文理财讲座，现场入座不用报名');
  assert.equal(weekend.picks[2].reason_en, 'Free money talks in English; no sign-up to sit in');
  // A Saturday ask lifts the three Saturday picks, a Sunday ask the two standbys, each at its editor rank.
  assert.deepEqual([...picksForAsk({ date: '2026-10-24' })], [[CHERRYLAND, 0], [LUMAFEST, 1], [PLANNING_DAY, 2]]);
  assert.deepEqual([...picksForAsk({ date: '2026-10-25' })], [[DUMPLINGS, 3], [OMCA, 4]]);
  // The Financial Planning Day is for adults (成人); World of Dumplings is not a family audience (亲友出游); OMCA is (亲子家庭).
  assert.deepEqual(event(PLANNING_DAY).audience, ['成人', '实用生活']);
  assert.deepEqual(event(DUMPLINGS).audience, ['美食与文化', '亲友出游']);
  assert.ok(event(OMCA).audience.includes('亲子家庭'));
});

test('BayBay: the 10/24 picks lead in the editor\'s order; family asks never get the adults\' pick; Sunday 10/25 asks get the Sunday standbys', () => {
  for (const today of ['2026-10-22', '2026-10-23']) {
    // A Saturday family ask: Cherryland, then LumaFest.
    for (const message of ['这周六带孩子去哪玩？', '這週六帶小孩去哪裡玩？', 'Where to take the kids this Saturday?']) {
      const result = evidence(message, today);
      assert.deepEqual(candidateIds(result).slice(0, 2), [CHERRYLAND, LUMAFEST], `${message} (${today})`);
      assert.deepEqual(itemIds(result).filter(id => [CHERRYLAND, LUMAFEST].includes(id.split(':')[1])), [`event:${CHERRYLAND}`, `event:${LUMAFEST}`], `${message} (${today})`);
      assert.ok(![...itemIds(result), ...candidateIds(result)].some(id => id.endsWith(PLANNING_DAY)), `${message} (${today})`);
    }
    // A weekend family ask: Sunday's OMCA follows them.
    for (const message of ['这周末带孩子去哪玩', 'Family things to do in the Bay Area this weekend']) {
      assert.deepEqual(candidateIds(evidence(message, today)).slice(0, 3), [CHERRYLAND, LUMAFEST, OMCA], `${message} (${today})`);
    }
    // An ask that is not about children: all three Saturday picks, the adults' Financial Planning Day third.
    assert.deepEqual(candidateIds(evidence('这周末有什么好玩的', today)).slice(0, 3), [CHERRYLAND, LUMAFEST, PLANNING_DAY], today);
  }
  // Sunday 10/25: a family ask leads with OMCA; an ask that is not about children with World of Dumplings, then OMCA. No
  // Saturday pick is offered on Sunday.
  for (const message of ['这周日带孩子去哪玩', '10月25号周日带娃去哪玩', 'What can kids do on Sunday October 25?']) {
    const result = evidence(message);
    assert.equal(candidateIds(result)[0], OMCA, `${message}: ${candidateIds(result).join(', ')}`);
    assert.ok(![...itemIds(result), ...candidateIds(result)].some(id => [CHERRYLAND, LUMAFEST, PLANNING_DAY].some(pick => id.endsWith(pick))), message);
  }
  assert.deepEqual(candidateIds(evidence('这周日有什么好玩的')).slice(0, 2), [DUMPLINGS, OMCA]);
});

test('the 10/21 review\'s corrections: the Exploratorium orchestra 13:00–16:00, Monster Mash $22 / $26, Ameswell\'s closed contest, the Eames page', () => {
  const exploratorium = event(EXPLORATORIUM);
  assert.match(exploratorium.dateLabel, /乐团 13:00–16:00/);
  assert.match(exploratorium.dateNote, /乐团 13:00–16:00/);
  assert.match(exploratorium.plan[1], /合奏 13:00–16:00（馆方和乐团页面一致）/);
  assert.doesNotMatch([exploratorium.dateLabel, exploratorium.dateNote, ...exploratorium.plan].join('\n'), /11:00–16:00/);
  // Its prices are only in the museum's ticketing app, which the review could not read: the check date stays.
  assert.equal(exploratorium.verifiedAt, '2026-09-29');
  const mash = event(MONSTER_MASH);
  assert.equal(mash.costLabel, '现在报名：居民 $22／非居民 $26（10/19 前的早鸟价已截止）；每份登记含一名 2 岁以上儿童和两名成人');
  assert.deepEqual([mash.price.min, mash.price.max], [22, 26]);
  assert.equal(mash.verifiedAt, '2026-10-21');
  assert.match(event('ameswell-barks-boos-2026').costLabel, /装扮比赛登记已在 10\/16 截止/);
  const eames = event('november-north-eames-exhibition-2026');
  assert.equal(eames.officialUrl, 'https://napavalleymuseum.org/blogs/exhibitions/eames-eames');
  assert.ok(registry.some(row => row.url === eames.officialUrl && row.contentIds.includes(eames.id)), 'the new Eames page is a registered source');
  for (const catalog of [guides, guidesEn]) {
    const text = catalog.find(row => row.slug === 'bay-area-101-city-exploration-living-guide').content;
    assert.match(text, /napavalleymuseum\.org\/blogs\/exhibitions\/eames-eames/);
    assert.doesNotMatch(text, /upcoming-exhibitions\/eames-eames/);
  }
  // SFPL's Financial Planning Day says its talks are in English (official page: "conducted in English unless otherwise noted").
  assert.match(event(PLANNING_DAY).plan[0], /^讲座和咨询以英文进行/);
});

test('the 10/21 review dates: 68 events and 9 dated offers read on 10/21; the held Thrill-O-Ween and the unread pages keep theirs', () => {
  assert.equal(planner.events.filter(row => row.verifiedAt === '2026-10-21').length, 68);
  for (const english of [false, true]) {
    const offers = (english ? discoveriesEn : discoveriesZh).items.filter(row => row.verifiedAt === '2026-10-21').map(row => `${row.kind}:${row.id}`).sort();
    assert.deepEqual(offers, ['offer:hayward-compost-giveaway-oct24-2026', 'offer:lakeshore-halloween-craft-oct25-31-2026', 'offer:lakeshore-stained-glass-oct24-2026',
      'offer:lego-ghost-street-stoneridge-oct25-2026', 'offer:michaels-chenille-ghost-oct24-2026', 'offer:michaels-costume-demo-oct25-2026', 'offer:petsmart-tricks-treats-oct25-2026',
      'offer:sfmoma-family-oct25', 'offer:sjpl-booktacular-oct24-31'], english ? 'en' : 'zh');
  }
  // Every pick of 10/24–25 was read on 10/21.
  for (const id of [CHERRYLAND, LUMAFEST, PLANNING_DAY, DUMPLINGS, OMCA]) assert.equal(event(id).verifiedAt, '2026-10-21', id);
  // Owner's hold list (Thrill-O-Ween, 10/24) and pages behind bot checks: not re-dated.
  assert.equal(event('sf-thrive-thrill-o-ween-2026').verifiedAt, '2026-09-28');
  for (const id of ['san-jose-sjma-dia-muertos-community-2026', 'mountain-view-monster-bash-2026', 'belmont-centennial-fest-2026']) assert.notEqual(event(id).verifiedAt, '2026-10-21', id);
  assert.notEqual(discovery('offer', 'lowes-mrbeast-swarms-oct24-2026').verifiedAt, '2026-10-21');
});

test('BayBay: the corrected records reach the model with the new facts', () => {
  const exploratorium = modelItem(evidence('10月24日 Exploratorium 家庭科学日乐团几点？'), `event:${EXPLORATORIUM}`);
  assert.ok(exploratorium, 'the Exploratorium is an item');
  assert.match(exploratorium.text, /乐团 13:00–16:00/);
  assert.doesNotMatch(JSON.stringify(exploratorium), /乐团 11:00–16:00|馆方写 11:00–16:00/);
  const orchestra = modelItem(evidence('What time is the orchestra at the Exploratorium on October 24?'), `event:${EXPLORATORIUM}`);
  assert.ok(orchestra, 'the English ask reaches the Exploratorium');
  assert.match(JSON.stringify(orchestra), /13:00[–-]16:00|1(?::00)? ?(?:p\.?m\.?)?[–-]4(?::00)? ?p\.?m\.?/i);
  for (const message of ['Cupertino Monster Mash 多少钱？', 'How much is the Cupertino Monster Mash?']) {
    const mash = modelItem(evidence(message), `event:${MONSTER_MASH}`);
    assert.ok(mash, message);
    assert.match(mash.cost, /\$22/, message);
    assert.match(mash.cost, /\$26/, message);
    assert.doesNotMatch(mash.cost, /\$17/, message);
  }
  const planning = modelItem(evidence('Is the SFPL Financial Planning Day on October 24 in Chinese?'), `event:${PLANNING_DAY}`);
  assert.ok(planning, 'the Financial Planning Day is an item');
  assert.match(JSON.stringify(planning), /English|英文/);
});

test('BayBay: #54\'s shop signs and the guides\' new lines reach the model', () => {
  // What each new shop sells (the third detail line), zh and en.
  assert.equal(discovery('opening', 'sergeant-ma').details[2], '亚洲风味加州菜');
  assert.equal(discovery('opening', 'sergeant-ma', true).details[2], 'Asian-inspired California food');
  assert.equal(discovery('opening', 'marufuku-burlingame-announced').details[2], '博多豚骨拉面');
  assert.match(discovery('opening', 'berkeley-cere-tea-opening-2026').dateLabel, /^试营业中/);
  assert.match(modelItem(evidence('Sergeant Ma 是什么餐厅'), 'opening:sergeant-ma')?.text || '', /亚洲风味加州菜/);
  // VTA ACCESS in the senior transit guide's paratransit paragraph (zh and en), and Alameda County's senior information and
  // assistance line in the resource map.
  assert.match(guides.find(row => row.slug === 'bay-area-senior-transit-clipper-discounts-guide').content, /VTA ACCESS/);
  assert.match(guidesEn.find(row => row.slug === 'bay-area-senior-transit-clipper-discounts-guide').content, /VTA ACCESS: call \(408\) 321-2381/);
  const paratransit = modelItem(evidence('How do I apply for paratransit in Santa Clara County?'), 'guide:bay-area-senior-transit-clipper-discounts-guide');
  assert.match(paratransit?.text || '', /VTA ACCESS: call \(408\) 321-2381/);
  const alameda = modelItem(evidence('奥克兰长者资讯与协助电话'), 'guide:bay-area-chinese-language-resource-map');
  assert.match(alameda?.text || '', /长者资讯与协助 510-577-3530/);
});

// Measured losses of this sync (old lib/, new data), each passing on the api base data 83e8683 and failing here. They are the
// picks' audience and price meeting asks lib/ does not read yet; left to API-BB-13 (no new BayBay feature in a sync lane).
test('a free family weekend ask keeps a Sunday 10/25 family event', { todo: 'API-BB-13: the 10/24 family picks are not free (Cherryland: no price on its page; LumaFest: free entry, food extra; OMCA $10), so on 这周末有什么免费的亲子活动 no pick leads and the rule that keeps each other day\'s best family event never runs: Millbrae\'s Sunday Chinese storytime (item 3 on base) leaves the items and no Sunday event is left' }, () => {
  const sunday = itemIds(evidence('这周末有什么免费的亲子活动')).filter(id => id.startsWith('event:') && eventOccursOn(event(id.slice(6)), '2026-10-25'));
  assert.ok(sunday.length > 0);
});

test('a weekend ask with one\'s parents does not lead with a storytime for children 0–5', { todo: 'API-BB-13 (parents and grandparents as an older audience): 这周末带爸妈去哪玩 / 周末带父母去哪 is not a family ask, so the picks keep their lift in the editor\'s order and Cherryland\'s storytime (0–5 岁儿童与家长) is the first candidate and item 2; on base it was LumaFest (elder-friendly)' }, () => {
  for (const message of ['这周末带爸妈去哪玩', '周末带父母去哪']) assert.notEqual(candidateIds(evidence(message))[0], CHERRYLAND, message);
});

test('an English free family weekend ask offers no paid pick', { todo: 'API-BB-13: "Free things to do with kids this weekend" does not set freeOnly (English "free" is read only in a few phrasings), so OMCA\'s $10 celebration is a family pick and item 4' }, () => {
  const result = evidence('Free things to do with kids this weekend');
  assert.ok(![...itemIds(result), ...candidateIds(result)].some(id => id.endsWith(OMCA)), itemIds(result).join(', '));
});

test('a Chinese-community ask is not offered the English-language Financial Planning Day', { todo: 'API-BB-13: the picks keep their lift on a Chinese-community ask, so 这周六旧金山有什么华人活动 offers the Financial Planning Day (talks in English) as candidate 2 and item 4' }, () => {
  const result = evidence('这周六旧金山有什么华人活动');
  assert.ok(![...itemIds(result), ...candidateIds(result)].some(id => id.endsWith(PLANNING_DAY)), itemIds(result).join(', '));
});

test('a San Francisco dog-friendly dining ask keeps the Mess Hall\'s dog patio', { todo: 'API-BB-13: #54 rewrote the Mess Hall sign ("适合公园散步后吃午餐" is gone), so 旧金山周五带狗去哪里吃饭？ no longer scores it; it was item 7 of 8 on base, the one record with a dog patio' }, () => {
  assert.ok(itemIds(evidence('旧金山周五带狗去哪里吃饭？')).includes('opening:mess-hall-presidio-breadwinner'));
});
