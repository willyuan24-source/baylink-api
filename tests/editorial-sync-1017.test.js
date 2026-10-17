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
const guides = require('../data/guide-catalog.json');
const guidesEn = require('../data/guide-catalog.en.json');
const eventCatalog = require('../data/event-catalog.json');
const discoveriesZh = require('../data/discoveries.json');
const discoveriesEn = require('../data/discoveries.en.json');
const registry = require('../data/source-registry.json');

// API-SYNC-3g from web 4169a5c (web #48, Wave 6 C): Dec–Jan Chinese-language events, the elder-guide fixes (AC Transit's
// senior fare, the library starter record), the openings and offers freshness review, the CHSA registration line.
// What the synced catalogs change for saves and for BayBay's fast evidence. Production loaders and the shipped data
// files with a fixed day; no model, no network. A later sync that changes one of these rows on purpose updates the pin
// from the web data, which is the source of truth.
const NOW = Date.parse('2026-10-17T19:00:00Z'); // Sat 2026-10-17 12:00 PDT
const TODAY = '2026-10-17';
const SECRET = 'api-sync-3g-isolated-test-secret-0123456789';
const planner = loadPlannerCatalog();
const discoveries = { ...loadDiscoveryCatalog(), english: loadDiscoveryCatalog(undefined, true) };
const event = id => planner.events.find(row => row.id === id);
const discovery = (kind, id, english = false) => (english ? discoveriesEn : discoveriesZh).items.find(row => row.kind === kind && row.id === id);
// As the engine does (lib/baybayEngine/router.js and evidence.js): the query is normalizeGuideQuery(message), the guide
// catalog is the reader's locale.
const evidence = (message, locale = /[㐀-鿿]/.test(message) ? 'zh-Hans' : 'en', today = TODAY) => buildFastEvidence({ query: normalizeGuideQuery(message), originalQuery: message,
  state: resolveTaskState({ message, today, catalog: planner, carry: true }).state, guideCatalog: locale === 'en' ? guidesEn : guides, catalog: planner, discoveries, today, locale, audience: true });
const itemIds = result => result.items.map(item => `${item.kind}:${item.id}`);
const CJK = /[㐀-鿿]/;
const NEW_EVENTS = ['sfpl-visitacion-valley-calligraphy-chess-nov14-2026', 'sfpl-sunset-mahjong-nov28-2026', 'sanleandro-main-mandarin-storytime-dec5-2026',
  'sfpl-main-liu-zongkun-author-talk-dec12-2026', 'sfpl-visitacion-calligraphy-chess-dec12-2026', 'sf-dharma-treasury-winter-foqi-talks-2026',
  'sf-dharma-treasury-winter-chanqi-talks-2026', 'sf-shen-yun-war-memorial-2026-27'];
const SAN_LEANDRO = 'sanleandro-main-mandarin-storytime-dec5-2026';
const CHSA = 'chsa-taiwanese-chinese-roots-seminar-2026';
const AC_OLD = /AC Transit（东湾）：车票和月票都是五折|AC Transit（東灣）：車票和月票都是五折|AC Transit \(East Bay\): half price on fares and passes/;

test('the Dec–Jan Chinese-language events are in every catalog copy, with the same ids', () => {
  assert.deepEqual(eventCatalog.map(row => row.id).sort(), planner.events.map(row => row.id).sort());
  for (const id of NEW_EVENTS) {
    assert.ok(event(id), id);
    assert.ok(eventCatalog.some(row => row.id === id), id);
    assert.ok(event(id).aliases.some(alias => !CJK.test(alias)), `${id} has an English alias`);
  }
  assert.equal(event(SAN_LEANDRO).dateLabel, '12/5（周六）· 10:30–11:00');
  assert.deepEqual(event(SAN_LEANDRO).sessions, [{ date: '2026-12-05', start: '10:30', end: '11:00' }]);
  assert.equal(event(SAN_LEANDRO).cost, 'unknown'); // the city's page gives no fee or registration; the record says so
  assert.deepEqual(event('sf-shen-yun-war-memorial-2026-27').occurrenceDates, ['2026-12-30', '2026-12-31', '2027-01-02', '2027-01-03']);
  // Millbrae's Cafe is open now, so it joins the planner places; zh and en discovery ids still match.
  assert.ok(planner.places.some(row => row.id === 'opening-millbrae-cafe-announced-2026'));
  assert.deepEqual(discoveriesZh.items.map(row => `${row.kind}:${row.id}`).sort(), discoveriesEn.items.map(row => `${row.kind}:${row.id}`).sort());
});

test('the editor\'s 10/24–25 and 10/31 picks are catalog events on their days', () => {
  // web src/data/weekend-picks.ts (not copied to the API; the picks' events are).
  for (const [day, ids] of [['2026-10-24', ['r2-petaluma-lumafest-20261024', 'menlo-park-halloween-hoopla-2026', 'sfpl-chinatown-creative-saturdays-fall-2026', 'acl-cherryland-chinese-storytimes-oct24-2026', 'san-jose-sjma-dia-muertos-community-2026']],
    ['2026-10-31', ['mcm-halloween-spectacular-20261031', 'sfpl-chinatown-creative-saturdays-fall-2026', 'san-jose-avenida-altares-2026']],
    ['2026-11-01', ['nov2026-fruitvale-dia-muertos', 'smcl-foster-city-nidhi-chanani-2026']]]) {
    for (const id of ids) assert.ok(event(id) && eventOccursOn(event(id), day), `${id} on ${day}`);
  }
  assert.match(event('san-jose-sjma-dia-muertos-community-2026').costLabel, /^全天免费入场/);
});

test('the elder and library guide fixes cite only registered sources', () => {
  for (const slug of ['bay-area-senior-transit-clipper-discounts-guide', 'bay-area-library-starter-guide', 'bay-area-chinese-language-resource-map',
    'bay-area-newcomer-first-month-checklist', 'bay-area-chinese-senior-services-referral-guide']) {
    for (const catalog of [guides, guidesEn]) {
      const guide = catalog.find(row => row.slug === slug);
      assert.ok(guide, slug);
      assert.equal(guide.updatedAt, '2026-10-16', slug);
      for (const source of guide.sources) assert.ok(registry.some(row => row.url === source.url && row.contentIds.includes(slug)), `${slug}: ${source.url}`);
    }
  }
  const transit = slugText => [guides, guidesEn].map(catalog => catalog.find(row => row.slug === slugText).content);
  const [zh, en] = transit('bay-area-senior-transit-clipper-discounts-guide');
  assert.match(zh, /AC Transit（东湾）：长者本地单程用 Clipper \$1\.37、现金 \$1\.50，是成人票的一半左右/);
  assert.match(en, /AC Transit \(East Bay\): a senior local single ride is \$1\.37 on Clipper or \$1\.50 in cash/);
  for (const text of [zh, en]) assert.doesNotMatch(text, AC_OLD);
  const [libraryZh, libraryEn] = transit('bay-area-library-starter-guide');
  assert.match(libraryZh, /SFPL Discover & Go：旧金山市县居民用借书证号和 PIN 登录/);
  assert.match(libraryEn, /Discover & Go/);
});

test('openings: Bruma and Florecita stay announced with no first day; Millbrae\'s Cafe is open', () => {
  for (const english of [false, true]) {
    const bruma = discovery('opening', 'bruma-ritz-carlton-sf', english);
    assert.equal(bruma.status, 'announced');
    assert.match(bruma.dateLabel, english ? /^First day not announced/ : /^首日未公布/);
    assert.doesNotMatch(bruma.dateLabel, /10月12日|Oct(?:ober)? 12/);
    const florecita = discovery('opening', 'florecita-mission', english);
    assert.equal(florecita.status, 'announced');
    assert.match(florecita.dateLabel, english ? /not announced/ : /新址开业日期未公布/);
    assert.equal(discovery('opening', 'millbrae-cafe-announced-2026', english).status, 'open');
  }
});

test('CHSA\'s 11/15 seminar gives the flyer\'s registration page and never the broken short link', () => {
  const row = event(CHSA);
  assert.ok(row.plan.some(line => /LoveBoatAlumni\.org\/roots2026/.test(line)), row.plan.join(' | '));
  for (const copy of [row, eventCatalog.find(item => item.id === CHSA)]) assert.doesNotMatch(JSON.stringify(copy), /tinyurl|bit\.ly/i);
});

test('the new Chinese-language events can be saved (they answered 404 ITEM_NOT_IN_CATALOG before this sync)', async t => {
  const users = [{ id: 'member', nickname: 'member', email: 'member@private.test', password: 'private', accountStatus: 'active', isPhoneVerified: true, city: 'San Francisco' }];
  const application = createApplication({ config: { NODE_ENV: 'test', JWT_SECRET: SECRET }, models: createMemoryModels({ User: users }),
    plannerNow: () => NOW, eventNow: () => NOW, outingNow: () => NOW });
  await new Promise(resolve => application.server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise(resolve => application.io.close(resolve)));
  const token = jwt.sign({ id: 'member', sessionIssuedAt: Date.now() }, SECRET, { algorithm: 'HS256', expiresIn: '1h' });
  for (const [kind, id] of [['event', SAN_LEANDRO], ['event', 'sf-shen-yun-war-memorial-2026-27'], ['event', 'sfpl-main-liu-zongkun-author-talk-dec12-2026']]) {
    const response = await fetch(`http://127.0.0.1:${application.server.address().port}/api/planner/favorites/${kind}/${id}`, { method: 'PUT', headers: { Authorization: `Bearer ${token}` } });
    const data = await response.json();
    assert.equal(response.status, 200, `${kind}:${id}: ${JSON.stringify(data)}`);
    assert.ok(data.favorites.some(row => row.kind === kind && row.id === id), id);
  }
});

// Before this sync no Mandarin storytime fell on 12/5 in the East Bay: the zh-Hant and English asks got none.
test('BayBay: a 12/5 Mandarin storytime ask gets San Leandro\'s 10:30 storytime, labelled as a Mandarin storytime', () => {
  for (const [message, locale] of [['12月5日有普通话故事会吗？', 'zh-Hans'], ['12月5日东湾有什么中文故事会？', 'zh-Hans'], ['12月5日東灣有中文故事時間嗎？', 'zh-Hant'], ['Is there a Mandarin storytime in the East Bay on December 5?', 'en']]) {
    const result = evidence(message, locale);
    const rank = result.items.findIndex(item => item.id === SAN_LEANDRO);
    assert.ok(rank >= 0 && rank < 3, `${message}: ${itemIds(result).join(', ')}`);
    assert.ok(result.candidates.some(row => row.id === SAN_LEANDRO), message);
    const [view] = modelItems([result.items[rank]]);
    assert.match(view.text, /12\/5（周六）· 10:30–11:00/, message);
    assert.match(view.title, locale === 'en' ? /^Mandarin Storytime at San Leandro Main Library/ : /普通[话話]故事[会會]/, message);
    assert.match(view.cost, /活动页没写费用和报名/, message); // no fee claimed
  }
});

test('BayBay: an AC Transit senior fare ask cites the $1.37 Clipper fare, never a blanket half price', () => {
  for (const [message, locale, fare] of [['我爸妈 65 岁了，坐 AC Transit 有老人优惠吗？多少钱？', 'zh-Hans', /长者本地单程用 Clipper \$1\.37/], ['長者坐 AC Transit 多少錢？', 'zh-Hant', /长者本地单程用 Clipper \$1\.37/],
    ['How much is AC Transit for seniors?', 'en', /senior local single ride is \$1\.37 on Clipper/]]) {
    const result = evidence(message, locale);
    const views = modelItems(result.items);
    assert.ok(views.some(view => view.kind === 'guide' && fare.test(view.text)), `${message}: ${itemIds(result).join(', ')}`);
    assert.ok(!views.some(view => AC_OLD.test(view.text)), message);
  }
});

test('BayBay: a Bruma ask gets the announced opening with no first day, never an open venue', () => {
  for (const [message, locale, label] of [['Ritz-Carlton 的 Bruma 酒廊开了吗？', 'zh-Hans', '尚未开始'], ['Bruma 开了吗？', 'zh-Hans', '尚未开始'], ['Is Bruma at the Ritz-Carlton San Francisco open yet?', 'en', 'not started yet']]) {
    const result = evidence(message, locale);
    assert.equal(itemIds(result)[0], 'opening:bruma-ritz-carlton-sf', `${message}: ${itemIds(result).join(', ')}`);
    const [view] = modelItems(result.items);
    assert.equal(view.status, label, message);
    assert.match(view.text, /首日未公布/, message);
    assert.doesNotMatch(view.text, /计划10月12日开业/, message);
  }
});

const CHSA_ASKS = [['11月15日 CHSA 台湾华人寻根讲座怎么报名？', 'zh-Hans'], ['How do I register for the CHSA Taiwanese Chinese roots seminar on November 15?', 'en']];
test('BayBay: a CHSA 11/15 seminar ask never carries the broken short link; the Chinese ask gets the flyer\'s registration page', () => {
  for (const [message, locale] of CHSA_ASKS) {
    const result = evidence(message, locale);
    const item = result.items.find(row => row.id === CHSA);
    assert.ok(item, `${message}: ${itemIds(result).join(', ')}`);
    const [view] = modelItems([item]);
    assert.match(view.text, /CHSA 活动页上的报名短链接现在会跳到一个无关的网页/, message);
    if (locale !== 'en') assert.match(view.text, /LoveBoatAlumni\.org\/roots2026/, message);
    assert.ok(!modelItems(result.items).some(row => /tinyurl|bit\.ly/i.test(row.text)), message);
  }
  // Before this sync the English ask found no record of the seminar at all.
});

test('BayBay: the 12/12 and 11/28 San Francisco Chinese-language asks see the new library programmes', () => {
  const december = itemIds(evidence('12月12日旧金山有什么华人活动？'));
  for (const id of ['event:sfpl-main-liu-zongkun-author-talk-dec12-2026', 'event:sfpl-chinatown-creative-saturdays-dec-2026']) assert.ok(december.includes(id), december.join(', '));
  const mahjong = itemIds(evidence('11月28日旧金山图书馆有麻将活动吗？'));
  assert.ok(mahjong.slice(0, 3).includes('event:sfpl-sunset-mahjong-nov28-2026'), mahjong.join(', '));
  const shenYun = itemIds(evidence('神韵旧金山演出什么时候？票价多少？'));
  assert.ok(shenYun.includes('event:sf-shen-yun-war-memorial-2026-27'), shenYun.join(', '));
});

const JACK_LONDON = 'november-north-jack-london-author-2026';
const JACK_LONDON_ASKS = ['Jack London 州立公园 11月15日的作家讲座还能去吗？', '11月15日北湾有什么活动？', 'Is the Jack London author talk on November 15 still available?'];
test('the sold-out Jack London Park author talk (11/15) is never a bookable option', () => {
  assert.equal(event(JACK_LONDON).status, 'sold_out');
  assert.match(event(JACK_LONDON).costLabel, /官网 10\/16 显示已售罄/);
  // Before this sync it had no status and was the second item for the named asks.
  for (const message of JACK_LONDON_ASKS) {
    const result = evidence(message);
    assert.ok(!result.candidates.some(row => row.id === JACK_LONDON), message);
    assert.ok(!result.items.some(row => row.id === JACK_LONDON && !row.mismatch), message);
  }
});

// Follow-ups for the next BayBay lane, measured on this sync's data. Each is a TODO until fixed.
test('a sold-out event asked about by its place and kind carries its sold-out note', { todo: 'API-SYNC-3g follow-up (the general named-recall rule of editorial-sync-1016): "Jack London 州立公园 11月15日的作家讲座还能去吗？" and the English ask do not name "Jack London 公园作家下午会：The Second Mrs. London", so the sold-out row is left out and the model cannot say it is sold out (before this sync it was the second item, with no status)' }, () => {
  for (const message of [JACK_LONDON_ASKS[0], JACK_LONDON_ASKS[2]]) {
    const item = evidence(message).items.find(row => row.id === JACK_LONDON);
    assert.equal(item?.mismatch, 'sold_out', message);
  }
});

test('a one-word name finds its opening', { todo: 'API-SYNC-3g follow-up (before this sync too): "Florecita 开了吗？" and "Is Florecita open yet?" find no opening for "Florecita Panadería"; "Florecita 新店开了吗？" found it only through 新店 in the old text, which web #48 reworded (新址)' }, () => {
  for (const message of ['Florecita 开了吗？', 'Florecita 新店开了吗？', 'Is Florecita open yet?']) {
    assert.ok(itemIds(evidence(message)).includes('opening:florecita-mission'), message);
  }
});

test('the English CHSA ask keeps the flyer\'s registration page in the item text', { todo: 'API-SYNC-3g follow-up: an English reader gets the Chinese record text plus its cost line, and the text budget cuts it just before "主办方传单写的报名页是 LoveBoatAlumni.org/roots2026" (the Chinese view, without the cost line, keeps it). English event text is API-SYNC-3e follow-up 2' }, () => {
  const [message, locale] = CHSA_ASKS[1];
  const item = evidence(message, locale).items.find(row => row.id === CHSA);
  assert.match(modelItems([item])[0].text, /LoveBoatAlumni\.org\/roots2026/);
});

test('a dated one-day event\'s when gives its session hours', { todo: 'API-SYNC-3g follow-up: a single-day event\'s model view gives only the date in when (San Leandro: "12月5日（周六）"); its 10:30–11:00 is in the text only. API-BB-7 added session hours for multi-date events' }, () => {
  const item = evidence('12月5日有普通话故事会吗？').items.find(row => row.id === SAN_LEANDRO);
  assert.match(modelItems([item])[0].when, /10:30–11:00/);
});
