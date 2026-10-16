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
const eventCatalog = require('../data/event-catalog.json');
const discoveriesZh = require('../data/discoveries.json');
const discoveriesEn = require('../data/discoveries.en.json');
const registry = require('../data/source-registry.json');

// API-SYNC-3f from web 531f6434 (web #47, Wave 6 B, after #46 CNT-MEDIA-3): 81 winter-break events to 1/3, 35 perk cards,
// the birthday-perk and retail-freebies guides, and SJMA's 10/16–17 symposium marked sold out. What the synced catalogs
// change for saves and for BayBay's fast evidence. Production loaders and the shipped data files with a fixed day; no
// model, no network. A later sync that changes one of these rows on purpose updates the pin from the web data, which is the
// source of truth.
const NOW = Date.parse('2026-10-16T19:00:00Z'); // Fri 2026-10-16 12:00 PDT: this Saturday is 10/17
const TODAY = '2026-10-16';
const SECRET = 'api-sync-3f-isolated-test-secret-0123456789';
const planner = loadPlannerCatalog();
const discoveries = { ...loadDiscoveryCatalog(), english: loadDiscoveryCatalog(undefined, true) };
const event = id => planner.events.find(row => row.id === id);
const SJMA = 'san-jose-waterways-art-climate-2026';
// As the engine does (lib/baybayEngine/router.js and evidence.js): the query is normalizeGuideQuery(message), the guide
// catalog is the reader's locale.
const evidence = (message, locale = /[㐀-鿿]/.test(message) ? 'zh-Hans' : 'en') => buildFastEvidence({ query: normalizeGuideQuery(message), originalQuery: message,
  state: resolveTaskState({ message, today: TODAY, catalog: planner, carry: true }).state, guideCatalog: locale === 'en' ? guidesEn : guides, catalog: planner, discoveries, today: TODAY, locale, audience: true });
const itemIds = result => result.items.map(item => `${item.kind}:${item.id}`);
const CJK = /[㐀-鿿]/;

test('the winter-break events and perk cards are in every catalog copy, with the same ids', () => {
  assert.deepEqual(eventCatalog.map(row => row.id).sort(), planner.events.map(row => row.id).sort());
  for (const id of ['sfpl-bernal-family-dance-party-dec26-2026', 'ccclib-danville-noon-years-eve-storytime-dec26-2026', 'union-square-holiday-ice-rink-2026',
    'sfzoo-zoolights-2026', 'oakland-ballet-nutcracker-paramount-2026', 'sfpl-main-cantonese-storytime-dec31-2026', 'hacienda-hills-kids-trail-run-jan2-2027']) {
    assert.ok(event(id), id);
    assert.ok(eventCatalog.some(row => row.id === id), id);
  }
  assert.ok(planner.events.some(row => row.endDate >= '2027-01-02'), 'the winter break runs to the first weekend of January');
  const zh = new Map(discoveriesZh.items.map(row => [`${row.kind}:${row.id}`, row])), en = new Map(discoveriesEn.items.map(row => [`${row.kind}:${row.id}`, row]));
  assert.deepEqual([...zh.keys()].sort(), [...en.keys()].sort());
  for (const id of ['homedepot-holiday-train-dec5-2026', 'homedepot-christmas-car-ornament-nov21-2026', 'benihana-kabuki-kids-birthday', 'jamba-birthday-small-smoothie',
    'safeway-for-u-birthday-treat', 'rei-berkeley-hella-bae-run-dec16-2026', 'dunkin-birthday-triple-points']) {
    assert.ok(zh.has(`offer:${id}`), id);
    assert.ok(en.get(`offer:${id}`)?.title && !CJK.test(en.get(`offer:${id}`).title), id);
  }
});

test('the four updated guides cite only registered sources', () => {
  for (const slug of ['bay-area-birthday-perks', 'bay-area-retail-freebies-family-deals', 'bay-area-freebies-deals-2026-10', 'bay-area-freebies-deals-2026-11']) {
    for (const catalog of [guides, guidesEn]) {
      const guide = catalog.find(row => row.slug === slug);
      assert.ok(guide, slug);
      for (const source of guide.sources) assert.ok(registry.some(row => row.url === source.url && row.contentIds.includes(slug)), `${slug}: ${source.url}`);
    }
  }
  assert.equal(guides.find(row => row.slug === 'bay-area-birthday-perks').updatedAt, '2026-10-15');
});

test('SJMA\'s 10/16–17 symposium is marked sold out in the API catalog', () => {
  assert.equal(event(SJMA).status, 'sold_out');
  assert.match(event(SJMA).costLabel, /^已售罄/);
  assert.match(event(SJMA).dateNote, /William Street Park/);
});

test('new winter events and perk cards can be saved (they answered 404 ITEM_NOT_IN_CATALOG before this sync)', async t => {
  const users = [{ id: 'member', nickname: 'member', email: 'member@private.test', password: 'private', accountStatus: 'active', isPhoneVerified: true, city: 'San Francisco' }];
  const application = createApplication({ config: { NODE_ENV: 'test', JWT_SECRET: SECRET }, models: createMemoryModels({ User: users }),
    plannerNow: () => NOW, eventNow: () => NOW, outingNow: () => NOW });
  await new Promise(resolve => application.server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise(resolve => application.io.close(resolve)));
  const token = jwt.sign({ id: 'member', sessionIssuedAt: Date.now() }, SECRET, { algorithm: 'HS256', expiresIn: '1h' });
  for (const [kind, id] of [['event', 'sfpl-bernal-family-dance-party-dec26-2026'], ['event', 'union-square-holiday-ice-rink-2026'], ['offer', 'homedepot-holiday-train-dec5-2026'], ['offer', 'benihana-kabuki-kids-birthday']]) {
    const response = await fetch(`http://127.0.0.1:${application.server.address().port}/api/planner/favorites/${kind}/${id}`, { method: 'PUT', headers: { Authorization: `Bearer ${token}` } });
    const data = await response.json();
    assert.equal(response.status, 200, `${kind}:${id}: ${JSON.stringify(data)}`);
    assert.ok(data.favorites.some(row => row.kind === kind && row.id === id), id);
  }
});

// Before this sync no catalog event fell on Saturday 12/26 (the catalog stopped at 12/20): these asks got venues, offers
// and guides only.
test('BayBay: a 12/26 family ask gets that day\'s programmes in San Francisco and the East Bay', () => {
  const onDay = (id, city, region) => event(id)?.occurrenceDates?.includes('2026-12-26') && (!city || event(id).city === city) && (!region || event(id).region === region);
  const sf = evidence('12月26日旧金山带孩子去哪');
  assert.equal(itemIds(sf)[0], 'event:sfpl-bernal-family-dance-party-dec26-2026', itemIds(sf).join(', '));
  assert.ok(sf.items.filter(item => item.kind === 'event' && onDay(item.id, 'San Francisco')).length >= 4, itemIds(sf).join(', '));
  const english = evidence('What can kids do in San Francisco on December 26?');
  assert.equal(itemIds(english)[0], 'event:sfpl-bernal-family-dance-party-dec26-2026', itemIds(english).join(', '));
  assert.doesNotMatch(english.items[0].title, CJK);
  const eastBay = evidence('12月26日东湾有什么亲子活动');
  const firstFour = eastBay.items.slice(0, 4);
  assert.ok(firstFour.every(item => item.kind === 'event' && onDay(item.id, null, 'east-bay')), itemIds(eastBay).join(', '));
  // Every event among the plan candidates of an outing ask falls on the asked day.
  for (const result of [sf, english, eastBay]) for (const row of result.candidates.filter(row => row.kind === 'event')) assert.ok(onDay(row.id), row.id);
});

test('BayBay: birthday-perk asks lead with the birthday guide and see the new perk cards', () => {
  const zh = itemIds(evidence('生日福利有哪些'));
  assert.equal(zh[0], 'guide:bay-area-birthday-perks', zh.join(', '));
  assert.ok(zh.includes('offer:dunkin-birthday-triple-points'), zh.join(', '));
  const english = itemIds(evidence('Where can I get free stuff on my birthday?'));
  assert.equal(english[0], 'guide:bay-area-birthday-perks', english.join(', '));
  assert.ok(english.includes('offer:jamba-birthday-small-smoothie'), english.join(', '));
  const kids = itemIds(evidence('孩子过生日有什么免费的东西可以领？'));
  for (const id of ['guide:bay-area-birthday-perks', 'offer:benihana-kabuki-kids-birthday']) assert.ok(kids.includes(id), kids.join(', '));
});

test('BayBay: an East Bay farmers\' market ask on Saturday 10/17 sees Downtown Berkeley and Grand Lake (re-checked 10/15)', () => {
  for (const message of ['这周六东湾有什么农夫市集？', 'Any farmers markets in the East Bay on Saturday morning?']) {
    const found = itemIds(evidence(message));
    for (const id of ['event:berkeley-downtown-saturday-farmers-market-2026', 'event:oakland-grand-lake-farmers-market-2026']) assert.ok(found.includes(id), `${message}: ${found.join(', ')}`);
  }
  for (const id of ['berkeley-downtown-saturday-farmers-market-2026', 'oakland-grand-lake-farmers-market-2026']) assert.equal(event(id).verifiedAt, '2026-10-15', id);
});

test('BayBay: the sold-out SJMA symposium is never a bookable option', () => {
  // Named in Chinese: a reference marked 已售罄, with the note that forbids recommending it, and no plan candidate.
  const named = evidence('San José 水道与气候艺术论坛还能报名吗？');
  const item = named.items.find(row => row.id === SJMA);
  assert.ok(item, itemIds(named).join(', '));
  assert.equal(item.status, '已售罄');
  assert.equal(item.mismatch, 'sold_out');
  assert.match(modelItems([item])[0].note, /^Sold out: .*never recommend it/);
  // Named in English, or an outing on Saturday 10/17 in San Jose: never a candidate (before this sync it was one).
  for (const message of ['San José 水道与气候艺术论坛还能报名吗？', 'Can I still sign up for the San Jose Art and Climate Symposium on October 17?', '这周六 San Jose 有什么活动？', '10月17日 San Jose 有什么艺术活动', 'Art events in San Jose this Saturday?']) {
    const result = evidence(message);
    assert.ok(!result.candidates.some(row => row.id === SJMA), message);
    assert.ok(!result.items.some(row => row.id === SJMA && !row.mismatch), message);
  }
});

// Follow-ups for the next BayBay lane (API-BB-6), measured on this sync's data. Each is a TODO until fixed.
test('the English SJMA ask carries the symposium with its sold-out note', { todo: 'API-SYNC-3f follow-up: English named recall misses "San Jose Art and Climate Symposium" (the English alias keeps its ": From the Gallery to Coyote Creek" tail and the é of San José), so the model is not told it is sold out' }, () => {
  const found = evidence('Can I still sign up for the San Jose Art and Climate Symposium on October 17?').items.find(row => row.id === SJMA);
  assert.equal(found?.mismatch, 'sold_out');
});

test('the English Thanksgiving weekend ask keeps Bernal\'s family game night', { todo: 'API-SYNC-3f follow-up: the Calabazas children\'s book club (11/23) and a 1/2 kids\' trail run outrank it on children/kids synonyms; it is the 5th of six candidates, past the four the items take' }, () => {
  assert.ok(itemIds(evidence('Thanksgiving weekend things to do with kids')).includes('event:sfpl-bernal-family-game-night-nov28-2026'));
});

test('a December Christmas lights or parade ask leads with the parade, not a guide paragraph matched by the month\'s digits', { todo: 'API-SYNC-3f follow-up: the 12 of 12月 matches "建议 5–12 岁" in the Home Depot ornament paragraph (11/21), which comes first as a guide item' }, () => {
  assert.equal(itemIds(evidence('12月有什么圣诞点灯或者游行？'))[0], 'event:pleasanton-hometown-holiday-2026');
});

test('an 11/14 San Francisco ask is not matched by the date\'s digits', { todo: 'API-SYNC-3f follow-up: the 11 and 14 of 11月14日 match ZooLights (11/6, 14 个主题区) and the Union Square rink (11/4, 晚上 11 点), which take candidate slots of a Chinese book club or community ask' }, () => {
  for (const message of ['11月14日旧金山有什么中文读书会', '11月14日旧金山有什么华人活动']) {
    const ids = evidence(message).candidates.map(row => row.id);
    assert.ok(!ids.some(id => ['sfzoo-zoolights-2026', 'union-square-holiday-ice-rink-2026'].includes(id)), `${message}: ${ids.join(', ')}`);
  }
});

test('a kid\'s birthday freebie ask leads with the birthday guide', { todo: 'API-SYNC-3f follow-up (before this sync too): 孩子过生日有什么免费的东西可以领 leads with the farmers\' market guide (东西, 免费); the birthday guide is 7th' }, () => {
  assert.equal(itemIds(evidence('孩子过生日有什么免费的东西可以领？'))[0], 'guide:bay-area-birthday-perks');
});
