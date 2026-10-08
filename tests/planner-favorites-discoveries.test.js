const test = require('node:test');
const assert = require('node:assert/strict');
const jwt = require('jsonwebtoken');
const { createApplication } = require('../server');
const { createMemoryModels } = require('./support/memory-models');
const shipped = require('../data/discoveries.json');

const NOW = Date.parse('2026-10-08T19:00:00Z');
const SECRET = 'isolated-planner-favorites-tests-only';
const plannerCatalog = { version: 1, checkedAt: '2026-10-07', events: [
  { id: 'fleet-week', title: 'Fleet Week', region: 'sf', city: 'San Francisco', category: 'family', startDate: '2026-10-10', endDate: '2026-10-11' },
], places: [], guides: [{ slug: 'weekend-guide', title: 'Weekend guide' }] };
const discoveryCatalog = { version: 1, checkedAt: '2026-10-07', items: [
  { kind: 'offer', id: 'free-pumpkin-oct10', title: 'Free pumpkin', status: 'dated' },
  { kind: 'opening', id: 'new-noodle-house', title: 'New noodle house', status: 'open' },
  { kind: 'offer', id: 'ended-offer', title: 'Ended offer', status: 'ended' },
  { kind: 'post', id: 'not-a-discovery-kind', title: 'Ignored' },
  { kind: 'offer', id: '../bad id', title: 'Ignored' },
] };

async function fixture(t, options = {}) {
  const models = options.models || createMemoryModels({ User: ['owner', 'other'].map(id => ({ id, email: `${id}@private.test`, accountStatus: 'active', password: 'private' })) });
  const application = createApplication({ config: { NODE_ENV: 'test', JWT_SECRET: SECRET }, models,
    plannerCatalog: 'plannerCatalog' in options ? options.plannerCatalog : plannerCatalog,
    ...('discoveryCatalog' in options ? options.discoveryCatalog === undefined ? {} : { discoveryCatalog: options.discoveryCatalog } : { discoveryCatalog }),
    plannerNow: () => NOW });
  await new Promise(resolve => application.server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise(resolve => application.io.close(resolve)));
  const request = async (path, { as = 'owner', method = 'GET', body } = {}) => {
    const response = await fetch(`http://127.0.0.1:${application.server.address().port}/api/planner${path}`, { method,
      headers: { ...(as ? { Authorization: `Bearer ${jwt.sign({ id: as }, SECRET, { expiresIn: '1h' })}` } : {}), ...(body !== undefined ? { 'Content-Type': 'application/json' } : {}) },
      ...(body !== undefined ? { body: JSON.stringify(body) } : {}),
    });
    return { status: response.status, data: await response.json() };
  };
  return { request, models };
}

test('offers and openings can be saved, listed, re-saved idempotently and removed like the other kinds', async t => {
  const { request, models } = await fixture(t);
  for (const [kind, id] of [['offer', 'free-pumpkin-oct10'], ['opening', 'new-noodle-house'], ['offer', 'free-pumpkin-oct10'], ['event', 'fleet-week'], ['guide', 'weekend-guide']]) {
    assert.equal((await request(`/favorites/${kind}/${id}`, { method: 'PUT' })).status, 200, `${kind}:${id}`);
  }
  // Saving does not depend on the item being current: ended offers stay saveable, as events do.
  assert.equal((await request('/favorites/offer/ended-offer', { method: 'PUT' })).status, 200);
  const me = (await request('/me')).data;
  assert.deepEqual(me.favorites, [
    { kind: 'offer', id: 'free-pumpkin-oct10' }, { kind: 'opening', id: 'new-noodle-house' },
    { kind: 'event', id: 'fleet-week' }, { kind: 'guide', id: 'weekend-guide' }, { kind: 'offer', id: 'ended-offer' },
  ]);
  assert.deepEqual((await request('/me', { as: 'other' })).data.favorites, []);
  const removed = await request('/favorites/opening/new-noodle-house', { method: 'DELETE' });
  assert.equal(removed.status, 200);
  assert.ok(!removed.data.favorites.some(row => row.kind === 'opening'));
  // Only the {kind, id} pair is stored: no title, summary or source URL is copied into the account.
  for (const row of models.PlannerAccount.rows[0].favorites) assert.deepEqual(Object.keys(row).sort(), ['id', 'kind']);
});

test('an id the API catalog does not have answers 404 ITEM_NOT_IN_CATALOG and stores nothing', async t => {
  const { request, models } = await fixture(t);
  for (const [kind, id] of [['offer', 'published-on-web-after-last-sync'], ['opening', 'free-pumpkin-oct10'], ['offer', 'new-noodle-house'], ['event', 'invented-event'], ['offer', 'not-a-discovery-kind']]) {
    const response = await request(`/favorites/${kind}/${id}`, { method: 'PUT' });
    assert.equal(response.status, 404, `${kind}:${id}`);
    assert.equal(response.data.code, 'ITEM_NOT_IN_CATALOG');
    assert.equal(typeof response.data.error, 'string');
  }
  assert.ok(models.PlannerAccount.rows.every(row => !row.favorites?.length));
});

test('unknown kinds and malformed ids are still 400 without a catalog code', async t => {
  const { request } = await fixture(t);
  for (const path of ['/favorites/post/free-pumpkin-oct10', '/favorites/offers/free-pumpkin-oct10', '/favorites/offer/-leading-dash', `/favorites/offer/${'x'.repeat(121)}`]) {
    const response = await request(path, { method: 'PUT' });
    assert.equal(response.status, 400, path);
    assert.equal(response.data.code, undefined);
  }
  assert.equal((await request('/favorites/offer/free-pumpkin-oct10', { method: 'PUT', body: { title: 'injected' } })).status, 400);
  assert.equal((await request('/favorites/offer/free-pumpkin-oct10', { as: null, method: 'PUT' })).status, 401);
});

test('a retired offer can still be removed after the catalog refresh drops it', async t => {
  const models = createMemoryModels({ User: [{ id: 'owner', email: 'owner@private.test', accountStatus: 'active', password: 'private' }],
    PlannerAccount: [{ userId: 'owner', preferences: { regions: [], interests: [], travelMode: 'any' }, favorites: [{ kind: 'offer', id: 'retired-offer' }, { kind: 'opening', id: 'new-noodle-house' }], plans: [], revision: 3 }] });
  const { request } = await fixture(t, { models });
  assert.equal((await request('/favorites/offer/retired-offer', { method: 'PUT' })).status, 404);
  const removed = await request('/favorites/offer/retired-offer', { method: 'DELETE' });
  assert.equal(removed.status, 200);
  assert.deepEqual(removed.data.favorites, [{ kind: 'opening', id: 'new-noodle-house' }]);
});

test('offer and opening favorites keep working when the planner catalog is unavailable', async t => {
  const { request } = await fixture(t, { plannerCatalog: { version: 2 } });
  assert.equal((await request('/favorites/event/fleet-week', { method: 'PUT' })).status, 503);
  assert.equal((await request('/favorites/offer/free-pumpkin-oct10', { method: 'PUT' })).status, 200);
  assert.equal((await request('/favorites/offer/unknown-offer', { method: 'PUT' })).status, 404);
});

test('plan stops still accept only events and places', async t => {
  const { request } = await fixture(t);
  const response = await request('/plans', { method: 'POST', body: { title: 'Saturday', date: '2026-10-10', stops: [{ kind: 'offer', id: 'free-pumpkin-oct10' }] } });
  assert.equal(response.status, 400);
  assert.equal((await request('/me')).data.plans.length, 0);
});

test('the shipped discoveries catalog backs the default: every offer and opening id is saveable', async t => {
  const { request } = await fixture(t, { discoveryCatalog: undefined });
  const offers = shipped.items.filter(row => row.kind === 'offer'), openings = shipped.items.filter(row => row.kind === 'opening');
  assert.ok(offers.length >= 100 && openings.length >= 30, 'catalog shape changed; update this guard');
  for (const row of [offers[0], offers.at(-1), openings[0], openings.at(-1)]) {
    assert.equal((await request(`/favorites/${row.kind}/${row.id}`, { method: 'PUT' })).status, 200, `${row.kind}:${row.id}`);
  }
  const ID = /^[a-zA-Z0-9][a-zA-Z0-9_-]{0,119}$/;
  const unsaveable = shipped.items.filter(row => ['offer', 'opening'].includes(row.kind) && !ID.test(row.id));
  assert.deepEqual(unsaveable, [], 'every shipped offer/opening id must fit the favorites id format');
});
