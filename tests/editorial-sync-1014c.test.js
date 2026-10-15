const test = require('node:test');
const assert = require('node:assert/strict');
const jwt = require('jsonwebtoken');
const { createApplication } = require('../server');
const { createMemoryModels } = require('./support/memory-models');
const { loadPlannerCatalog, active } = require('../lib/planner');
const { loadEventCatalog } = require('../lib/eventEngagement');
const { loadDiscoveryCatalog } = require('../lib/publicContext');
const { resolveTaskState } = require('../lib/baybayState');
const { buildFastEvidence } = require('../lib/baybayEvidence');
const guides = require('../data/guide-catalog.json');
const guidesEn = require('../data/guide-catalog.en.json');

// API-SYNC-3c from web 47481977 (CNT-SUPPLY-2, web PR #42): 56 new sourced events 10/17-12/20, among them three East Bay
// farmers' markets, December family programmes and Chinese-language or Chinese-community items for 11/21-12/13. What the
// synced catalogs change for saves and for BayBay's fast evidence. Production loaders and the shipped data files with a
// fixed day; no model, no network. A later sync that changes one of these rows on purpose updates the pin from the web
// data, which is the source of truth.
const NOW = Date.parse('2026-10-14T19:00:00Z'); // Wed 2026-10-14 12:00 PDT
const TODAY = '2026-10-14'; // Wednesday, so "this Saturday" is 10/17 and "this Sunday" 10/18
const SECRET = 'api-sync-3c-isolated-test-secret-0123456789';
const planner = loadPlannerCatalog();
const discoveries = { ...loadDiscoveryCatalog(), english: loadDiscoveryCatalog(undefined, true) };
const event = id => planner.events.find(row => row.id === id);
const firstDay = id => event(id).occurrenceDates.find(day => day >= TODAY);
const nextDay = id => (event(id).occurrenceDates || []).find(day => day >= TODAY) || event(id).startDate;
const stateOf = message => resolveTaskState({ message, today: TODAY, carry: true }).state;
const evidence = (message, locale = 'zh-Hans') => buildFastEvidence({ query: message, originalQuery: message, state: stateOf(message),
  guideCatalog: locale === 'en' ? guidesEn : guides, catalog: planner, discoveries, today: TODAY, locale, audience: true });
const ids = result => (result.candidates || []).map(row => row.id);

const MARKETS = ['berkeley-downtown-saturday-farmers-market-2026', 'oakland-grand-lake-farmers-market-2026', 'fremont-irvington-farmers-market-2026'];
// SF events on or before 11/30 wait for /opus-bay's placement (web WORLD_IMPORT_PENDING): in the API's complete catalogs,
// not in /opus-bay's planner-catalog.json.
const HELD_SF = ['sfpl-chinatown-creative-saturdays-late-nov-2026', 'sfpl-bernal-family-game-night-nov28-2026', 'sfpl-main-california-xiangqi-invitational-nov28-2026'];
const SAMPLE = [...MARKETS, ...HELD_SF, 'dickens-christmas-fair-2026', 'pleasanton-hometown-holiday-2026', 'scl-windsor-gingerbread-houses-dec5-2026',
  'opl-asian-branch-family-time-2026', 'sjpl-berryessa-mandarin-ell-club-winter-2026', 'sjpl-calabazas-chinese-tea-hour-nov21-2026', 'sfpl-chinatown-family-storytime-dec-2026'];

test('both API catalogs carry the CNT-SUPPLY-2 events with the same confirmed days, the East Bay markets included', () => {
  const events = loadEventCatalog();
  // No pinned total: later syncs add events. The two complete catalogs cover the same ids.
  assert.deepEqual([...events.keys()].sort(), planner.events.map(row => row.id).sort());
  for (const id of SAMPLE) {
    const row = event(id);
    assert.ok(row, id);
    assert.ok(active(row), id);
    assert.ok(firstDay(id), `${id} has a day ahead`);
    for (const field of ['startDate', 'endDate', 'occurrenceDates']) assert.deepEqual(events.get(id)[field], row[field], `${id}.${field}`);
  }
  for (const id of MARKETS) assert.equal(event(id).region, 'east-bay', id);
  for (const id of HELD_SF) assert.equal(event(id).region, 'sf', id);
  // Each operator's page gives a weekly day and hours and no entry fee: cost stays unknown, never invented.
  for (const id of MARKETS) assert.equal(event(id).cost, 'unknown', id);
});

async function fixture(t) {
  const users = ['member'].map(id => ({ id, nickname: id, email: `${id}@private.test`, password: 'private', accountStatus: 'active', isPhoneVerified: true, city: 'Oakland' }));
  const application = createApplication({ config: { NODE_ENV: 'test', JWT_SECRET: SECRET }, models: createMemoryModels({ User: users }),
    plannerNow: () => NOW, eventNow: () => NOW, outingNow: () => NOW });
  await new Promise(resolve => application.server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise(resolve => application.io.close(resolve)));
  const request = async (path, { as, method = 'GET', body } = {}) => {
    const response = await fetch(`http://127.0.0.1:${application.server.address().port}/api${path}`, { method,
      headers: { ...(as ? { Authorization: `Bearer ${jwt.sign({ id: as, sessionIssuedAt: Date.now() }, SECRET, { algorithm: 'HS256', expiresIn: '1h' })}` } : {}), ...(body !== undefined ? { 'Content-Type': 'application/json' } : {}) },
      ...(body !== undefined ? { body: JSON.stringify(body) } : {}) });
    return { status: response.status, data: await response.json() };
  };
  return { request };
}

test('the new events resolve for favorites, plans and participation counts (no ITEM_NOT_IN_CATALOG)', async t => {
  const { request } = await fixture(t);
  for (const id of SAMPLE) {
    const saved = await request(`/planner/favorites/event/${id}`, { as: 'member', method: 'PUT' });
    assert.equal(saved.status, 200, `${id}: ${JSON.stringify(saved.data)}`);
    const plan = await request('/planner/plans', { as: 'member', method: 'POST', body: { title: `去 ${id}`, date: firstDay(id), stops: [{ kind: 'event', id }] } });
    assert.equal(plan.status, 201, `${id}: ${JSON.stringify(plan.data)}`);
  }
  const batch = await request(`/events/engagement?ids=${SAMPLE.join(',')}`);
  assert.equal(batch.status, 200);
  assert.deepEqual(batch.data.events.map(row => row.eventId), SAMPLE);
  assert.deepEqual(batch.data.unknown, []);
});

test('East Bay farmers\' market asks find the new markets (the 10-13 live check found none)', () => {
  for (const [message, locale] of [['这周六东湾有什么农夫市集？', 'zh-Hans'], ['這週六東灣有什麼農夫市集？', 'zh-Hant'], ['Any farmers markets in the East Bay this Saturday?', 'en']]) {
    const found = ids(evidence(message, locale));
    for (const id of ['berkeley-downtown-saturday-farmers-market-2026', 'oakland-grand-lake-farmers-market-2026']) assert.ok(found.includes(id), `${message}: ${found.join(', ')}`);
  }
  assert.ok(ids(evidence('奥克兰周末有农夫市集吗')).includes('oakland-grand-lake-farmers-market-2026'));
  assert.ok(ids(evidence('10月24日 Berkeley 有农夫市集吗')).includes('berkeley-downtown-saturday-farmers-market-2026'));
  // First, not the whole list: a later sync may add another Fremont Sunday item.
  const fremont = ids(evidence('Fremont 这周日有农夫市集吗'));
  assert.equal(fremont[0], 'fremont-irvington-farmers-market-2026', fremont.join(', '));
});

test('December weekend family asks get dated December programmes', () => {
  const eastBay = evidence('12月5日东湾有什么适合孩子的活动');
  for (const id of ['pleasanton-hometown-holiday-2026', 'opl-asian-branch-family-time-2026']) assert.ok(ids(eastBay).includes(id), ids(eastBay).join(', '));
  // Every catalog event or place among the candidates is in the East Bay (anything else, if a later engine adds it, is skipped).
  for (const id of ids(eastBay)) {
    const row = event(id) ?? planner.places.find(entry => entry.id === id);
    if (row) assert.equal(row.region, 'east-bay', id);
  }
  const sf = evidence('12月12日旧金山有什么适合小朋友的活动');
  for (const id of ['sfpl-chinatown-family-storytime-dec-2026', 'sfpl-glen-park-saturday-playtimes-dec-2026']) assert.ok(ids(sf).includes(id), ids(sf).join(', '));
  // Before this sync the plain 12/5 ask had no event candidate on that day (openings and venues only).
  const plain = ids(evidence('12月5日周末带孩子去哪玩？')).filter(id => event(id)?.occurrenceDates?.includes('2026-12-05'));
  assert.ok(plain.length >= 3, plain.join(', '));
  assert.ok(plain.includes('scl-windsor-gingerbread-houses-dec5-2026'), plain.join(', '));
  const lighting = ids(evidence('12月5日 Pleasanton 点灯是几点'));
  assert.equal(lighting[0], 'pleasanton-hometown-holiday-2026', lighting.join(', '));
});

test('Chinese-community asks for 11/21 find the new Chinese-language programmes', () => {
  const zh = ids(evidence('11月21日有什么中文活动'));
  for (const id of ['sfpl-chinatown-creative-saturdays-late-nov-2026', 'sjpl-berryessa-mandarin-ell-club-winter-2026', 'sjpl-calabazas-chinese-tea-hour-nov21-2026']) assert.ok(zh.includes(id), zh.join(', '));
  const hant = ids(evidence('11月21日灣區有什麼華人社區活動？', 'zh-Hant'));
  for (const id of ['sfpl-chinatown-creative-saturdays-late-nov-2026', 'sjpl-berryessa-mandarin-ell-club-winter-2026']) assert.ok(hant.includes(id), hant.join(', '));
  const en = ids(evidence('Chinese-community events in the Bay Area on November 21-22?', 'en'));
  for (const id of ['sfpl-chinatown-creative-saturdays-late-nov-2026', 'sjpl-berryessa-mandarin-ell-club-winter-2026']) assert.ok(en.includes(id), en.join(', '));
  for (const [message, locale] of [['11月28日旧金山有象棋比赛吗', 'zh-Hans'], ['Is there a Chinese chess tournament in San Francisco on November 28?', 'en']]) {
    assert.ok(ids(evidence(message, locale)).includes('sfpl-main-california-xiangqi-invitational-nov28-2026'), message);
  }
});

// Follow-ups for the next BayBay lane (lib/baybayState.js, lib/entityAliases.js; not this sync's files). The new December
// and 11/21-22 events reach these asks only through their words today: the asked days are not read, so off-date events
// (10/17, 11/8) stay among the candidates.
test('two-day and weekend-of asks become a date range', () => {
  for (const [message, start, end] of [['11月21日、22日周末湾区有什么华人社区活动？', '2026-11-21', '2026-11-22'], ['11月21日到22日有适合华人长辈的活动吗', '2026-11-21', '2026-11-22'],
    ['12月12日、13日湾区有什么亲子活动', '2026-12-12', '2026-12-13'], ['Chinese-community events in the Bay Area on November 21-22?', '2026-11-21', '2026-11-22'],
    ['Family-friendly things to do in the Bay Area on the weekend of December 5?', '2026-12-05', '2026-12-06']]) {
    const state = stateOf(message);
    assert.deepEqual(state.dateRange || (state.date && { start: state.date, end: state.date }), { start, end }, message);
  }
});

test('"12月第一个周末" is the first weekend of December, not this weekend', () => {
  const state = stateOf('12月第一个周末有什么亲子活动');
  assert.notEqual(state.date, '2026-10-17');
  assert.deepEqual(state.dateRange || null, { start: '2026-12-05', end: '2026-12-06' });
});

// Follow-up 2 (lib/baybayState.js, lib/baybayEvidence.js; not this sync's files). A bare 周末 resolves no date (这周末 and 周六
// do), so rows whose titles say 周末 or 周六 rank first whatever their day. This predates the sync (on the base data each top
// three already held one row dated 11/1 to 11/28), but the new late-November and December library programmes now take #1:
// on 10-14 the Milpitas Tiny Toots concert (12/12) for the family ask and the Bernal game night (11/28) for the SF ask.
// Acceptance on 10-14: each ask's top three candidates are places or have a session by 10/25 (this weekend or next).
test('undated weekend asks lead with this weekend and next, not events six to eight weeks out', () => {
  for (const message of ['周末带孩子去哪玩', '旧金山周末有什么好玩的', '湾区周末有什么免费活动']) {
    const top = ids(evidence(message)).slice(0, 3);
    assert.deepEqual(top.filter(id => event(id) && nextDay(id) > '2026-10-25'), [], `${message}: ${top.map(id => `${id} ${event(id) ? nextDay(id) : 'place'}`).join(', ')}`);
  }
});
