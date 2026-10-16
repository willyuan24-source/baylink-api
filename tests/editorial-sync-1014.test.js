const test = require('node:test');
const assert = require('node:assert/strict');
const jwt = require('jsonwebtoken');
const { createApplication } = require('../server');
const { createMemoryModels } = require('./support/memory-models');
const { loadPlannerCatalog, active } = require('../lib/planner');
const { loadEventCatalog } = require('../lib/eventEngagement');
const { loadOutingCatalog, validateOutingInput } = require('../lib/outings');
const { resolveTaskState } = require('../lib/baybayState');
const { buildFastEvidence } = require('../lib/baybayEvidence');
const guides = require('../data/guide-catalog.json');

// API-SYNC-3b from web eb193bb6 (WEB-HOLDOUT, H07): the API copies the web's complete planner catalog, so the nine San
// Francisco programmes /opus-bay still holds back reach favorites, plans, participation, outings and BayBay.
// Production loaders and the shipped data files; no network.
const FORMERLY_HELD = [
  'chsa-lily-qi-book-talk-nov8-2026', 'sfpl-bernal-dia-de-los-muertos-2026', 'sfpl-chinatown-creative-saturdays-fall-2026',
  'sfpl-chinese-book-club-nov14-2026', 'sfpl-excelsior-multilingual-tech-help-2026', 'sfpl-marina-wild-goose-qigong-oct-2026',
  'sfpl-north-beach-open-house-oct31-2026', 'sfpl-richmond-hk-film-hard-boiled-2026', 'sfpl-richmond-hk-film-the-killer-2026',
];
const NOW = Date.parse('2026-10-14T19:00:00Z'); // Wed 2026-10-14 12:00 PDT
const TODAY = '2026-10-14';
const SECRET = 'api-sync-3b-isolated-test-secret-0123456789';
const planner = loadPlannerCatalog();
const event = id => planner.events.find(row => row.id === id);
const firstDay = id => event(id).occurrenceDates.find(day => day >= TODAY);

test('both API catalogs carry the nine formerly held SF programmes with the same confirmed days', () => {
  const events = loadEventCatalog();
  assert.ok(planner && events);
  // No pinned total: later syncs add events. The two complete catalogs cover the same ids.
  assert.deepEqual([...events.keys()].sort(), planner.events.map(row => row.id).sort());
  for (const id of FORMERLY_HELD) {
    const row = event(id);
    assert.ok(row, id);
    assert.equal(row.region, 'sf', id);
    assert.ok(active(row), id);
    assert.equal(row.status, undefined, id);
    assert.ok(firstDay(id), `${id} still has a day ahead`);
    for (const field of ['startDate', 'endDate', 'occurrenceDates']) assert.deepEqual(events.get(id)[field], row[field], `${id}.${field}`);
  }
});

async function fixture(t) {
  const users = ['member', 'host'].map(id => ({ id, nickname: id, email: `${id}@private.test`, password: 'private', accountStatus: 'active', isPhoneVerified: true, city: 'San Francisco' }));
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

test('the nine resolve for favorites, plans, participation counts and outings through the shipped catalogs', async t => {
  const { request } = await fixture(t);
  for (const id of FORMERLY_HELD) {
    const saved = await request(`/planner/favorites/event/${id}`, { as: 'member', method: 'PUT' });
    assert.equal(saved.status, 200, `${id}: ${JSON.stringify(saved.data)}`);
    assert.notEqual(saved.data.code, 'ITEM_NOT_IN_CATALOG');
    const plan = await request('/planner/plans', { as: 'member', method: 'POST', body: { title: `去 ${id}`, date: firstDay(id), stops: [{ kind: 'event', id }] } });
    assert.equal(plan.status, 201, `${id}: ${JSON.stringify(plan.data)}`);
    assert.deepEqual(plan.data.plan.stops, [{ kind: 'event', id }]);
    const one = await request(`/events/engagement?ids=${id}`);
    assert.equal(one.status, 200, id);
    assert.deepEqual(one.data, { events: [{ eventId: id, interestedCount: 0, buddyCount: 0, me: null }], unknown: [] }, id);
  }
  assert.deepEqual((await request('/planner/me', { as: 'member' })).data.favorites.map(row => row.id), FORMERLY_HELD);
  const batch = await request(`/events/engagement?ids=${FORMERLY_HELD.join(',')}`, { as: 'member' });
  assert.equal(batch.status, 200);
  assert.deepEqual(batch.data.events.map(row => row.eventId), FORMERLY_HELD);
  assert.deepEqual(batch.data.unknown, []);
  const interest = await request(`/events/${FORMERLY_HELD[2]}/interest`, { as: 'member', method: 'PUT', body: { interested: true, lookingForBuddy: true } });
  assert.equal(interest.status, 200, JSON.stringify(interest.data));
  assert.deepEqual(interest.data.me, { interested: true, lookingForBuddy: true });

  // Outings: the route's own validator on the shipped catalog for all nine, and one created end to end.
  const outingCatalog = loadOutingCatalog();
  const outing = id => ({ title: '一起去图书馆活动', description: '活动结束后可以一起喝杯茶', eventId: id, date: firstDay(id), startTime: '10:00', endTime: '12:00', city: 'San Francisco',
    venue: '图书馆正门口', capacity: 3, costNote: '各自承担交通', transport: 'transit', language: 'any', adultConsent: true, publicPlaceConsent: true });
  for (const id of FORMERLY_HELD) assert.equal(validateOutingInput(outing(id), outingCatalog, NOW).eventTitle, event(id).title, id);
  const created = await request('/outings', { as: 'host', method: 'POST', body: { ...outing(FORMERLY_HELD[0]), idempotencyKey: 'api-sync-3b-outing-1' } });
  assert.equal(created.status, 200, JSON.stringify(created.data));
  assert.equal(created.data.outing.eventId, FORMERLY_HELD[0]);
});

test('BayBay retrieves the nine as candidates for the San Francisco day they happen', () => {
  const asks = [
    ['这周六旧金山有什么华人活动', ['sfpl-chinatown-creative-saturdays-fall-2026', 'sfpl-marina-wild-goose-qigong-oct-2026', 'sfpl-richmond-hk-film-the-killer-2026']],
    ['10月25日旧金山哪里可以用粤语问电脑问题', ['sfpl-excelsior-multilingual-tech-help-2026']],
    ['10月31日旧金山带孩子去哪', ['sfpl-north-beach-open-house-oct31-2026']],
    ['11月1日旧金山亡灵节活动', ['sfpl-bernal-dia-de-los-muertos-2026']],
    ['11月8日旧金山有什么华人讲座', ['chsa-lily-qi-book-talk-nov8-2026']],
    // API-SYNC-3f: Hard Boiled shares no word with 中文读书会; it was the 6th candidate there only through the 11 and 14 of
    // the date, and web #47's ZooLights and Union Square ice rink (open on 11/14) take those slots. It is asked as a film.
    ['11月14日旧金山有什么中文读书会', ['sfpl-chinese-book-club-nov14-2026']],
    ['11月14日旧金山有什么粤语电影', ['sfpl-richmond-hk-film-hard-boiled-2026']],
  ];
  const found = new Set();
  for (const [message, ids] of asks) {
    const { state } = resolveTaskState({ message, today: TODAY, carry: true });
    assert.equal(state.city, 'San Francisco', message);
    const evidence = buildFastEvidence({ query: message, originalQuery: message, state, guideCatalog: guides, catalog: planner, today: TODAY, locale: 'zh-Hans', audience: true });
    const candidates = evidence.candidates.map(row => row.id);
    for (const id of ids) {
      assert.ok(candidates.includes(id), `${message}: ${candidates.join(', ')}`);
      found.add(id);
    }
  }
  assert.deepEqual([...found].sort(), FORMERLY_HELD);
});
