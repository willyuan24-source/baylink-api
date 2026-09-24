const test = require('node:test');
const assert = require('node:assert/strict');
const jwt = require('jsonwebtoken');
const { createApplication } = require('../server');
const { createMemoryModels } = require('./support/memory-models');
const { inferFilters, loadPlannerCatalog, recommend } = require('../lib/planner');

const NOW = Date.parse('2026-09-23T19:00:00Z');
const SECRET = 'isolated-planner-tests-only-not-a-real-key';
const event = (id, fields = {}) => ({ id, title: id, region: 'east-bay', city: 'Fremont', startDate: '2026-09-26', endDate: '2026-09-26', cost: 'paid', planning: { setting: 'indoor', reservation: 'required' }, ...fields });
const catalog = { version: 1, checkedAt: '2026-09-23', events: [
  event('known', { planning: { setting: 'indoor', admissionUsd: 20, reservation: 'required' }, location: { lat: 37.55, lng: -121.98, precision: 'venue' } }),
  event('unknown'), event('expensive', { planning: { setting: 'indoor', admissionUsd: 70 } }),
  event('free', { cost: 'free' }), event('adults', { planning: { setting: 'indoor', admissionUsd: 5, minAge: 21 } }),
  event('outside', { cost: 'free', planning: { setting: 'outdoor' } }),
  event('expired', { startDate: '2026-09-20', endDate: '2026-09-22' }),
  event('paused', { status: 'suspended' }),
], places: [{ id: 'nearby', title: 'Nearby place', region: 'east-bay', city: 'Fremont', location: { lat: 37.551, lng: -121.98, precision: 'venue' }, planning: { setting: 'indoor' } }, { id: 'distant', title: 'Distant place', location: { lat: 38, lng: -122.5, precision: 'venue' } }], guides: [{ slug: 'weekend-guide', title: 'Weekend guide' }] };
const copy = value => JSON.parse(JSON.stringify(value));
function accountModel() {
  const rows = [];
  const match = (row, query) => Object.entries(query).every(([key, value]) => row[key] === value);
  return { rows,
    updateOne: async (query, update, options) => {
      if (!rows.some(row => match(row, query)) && options.upsert) rows.push(copy(update.$setOnInsert));
    },
    findOne: query => ({ lean: async () => copy(rows.find(row => match(row, query)) || null) }),
    findOneAndUpdate: async (query, update) => {
      const row = rows.find(row => match(row, query));
      if (!row) return null;
      Object.assign(row, copy(update.$set)); row.revision += update.$inc.revision;
      return copy(row);
    },
    init: async () => {},
  };
}
async function fixture(t, options = {}) {
  const models = options.models || { ...createMemoryModels({ User: ['owner', 'other'].map(id => ({ id, email: `${id}@private.test`, accountStatus: 'active', password: 'private' })) }), PlannerAccount: accountModel() };
  const application = createApplication({ config: { NODE_ENV: 'test', JWT_SECRET: SECRET }, models, plannerCatalog: options.catalog || catalog, plannerNow: () => NOW, ai: options.ai });
  await new Promise(resolve => application.server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise(resolve => application.io.close(resolve)));
  const request = async (path, { as, method = 'GET', body, auth } = {}) => {
    const token = as ? jwt.sign({ id: as }, SECRET, { expiresIn: '1h' }) : undefined;
    const response = await fetch(`http://127.0.0.1:${application.server.address().port}/api/planner${path}`, { method,
      headers: { ...(token ? { Authorization: `Bearer ${token}` } : {}), ...(auth ? { Authorization: auth } : {}), ...(body !== undefined ? { 'Content-Type': 'application/json' } : {}) },
      ...(body !== undefined ? { body: JSON.stringify(body) } : {}),
    });
    return { status: response.status, data: await response.json(), headers: response.headers };
  };
  return { request, models };
}
const plan = { title: 'Saturday together', date: '2026-09-26', stops: [{ kind: 'event', id: 'known' }, { kind: 'place', id: 'nearby' }] };

test('Chinese and mixed language filters resolve Pacific dates, region, budget, age and setting', () => {
  assert.deepEqual(inferFilters('这周六 Fremont 出发，5岁孩子，预算40，室内公共交通', '2026-09-23'), { date: '2026-09-26', region: 'east-bay', budget: 40, childAge: 5, setting: 'indoor', travelMode: 'transit' });
  assert.equal(inferFilters('10/03 San Francisco under $30', '2026-09-23').date, '2026-10-03');
  assert.equal(inferFilters('下周六', '2026-09-23').date, '2026-10-03');
  assert.equal(inferFilters('tomorrow', '2026-09-23').date, '2026-09-24');
  assert.equal(inferFilters('带五岁孩子', '2026-09-23').childAge, 5);
  assert.equal(inferFilters('October 3 San Francisco', '2026-09-23').date, '2026-10-03');
  assert.equal(inferFilters('星期五', '2026-09-23').date, '2026-09-25');
  assert.equal(inferFilters('这周末', '2026-09-27').date, '2026-09-27');
  assert.equal(inferFilters('下周六', '2026-09-27').date, '2026-10-03');
  assert.throws(() => inferFilters('2026-02-30 Fremont', '2026-09-23'), /日期无效/);
  assert.equal(loadPlannerCatalog({ ...catalog, events: [event('bad', { startDate: '2026-02-30' })] }), null);
});

test('real IDs, indoor/date/age constraints and unknown cost survive recommendation with no AI', async () => {
  const response = await recommend({ body: { message: '这周六Fremont 5岁孩子预算40室内', locale: 'en' }, catalog, now: () => NOW });
  assert.equal(response.responseMode, 'rules');
  assert.deepEqual(response.suggestions.map(row => row.eventId), ['free', 'known', 'unknown']);
  assert.match(response.suggestions[2].unknowns.join(' '), /not verified within your budget/);
  assert.deepEqual(response.suggestions[1].placeIds, ['nearby']);
  assert.match(response.suggestions[1].unknowns.join(' '), /hours, admission and route/);
  assert.ok(!JSON.stringify(response).includes('expensive'));
});

test('AI output cannot inject IDs, fake price facts, forbidden dates or bypass explicit filters', async () => {
  const response = await recommend({ body: { filters: { date: '2026-09-26', budget: 30, region: 'east-bay', childAge: 5, setting: 'indoor' }, message: 'Please pick', excludeEventIds: ['free'] }, catalog, now: () => NOW,
    ai: async () => ({ filters: { region: 'sf', budget: 500, date: '2026-09-21' }, rankedEventIds: ['forged-id', 'expensive', 'known'], reason: 'All free with a five-minute train ride', admissionUsd: 0 }),
  });
  assert.equal(response.responseMode, 'ai');
  assert.equal(response.filters.region, 'east-bay');
  assert.equal(response.filters.budget, 30);
  assert.deepEqual(response.suggestions.map(row => row.eventId), ['known', 'unknown']);
  assert.ok(!JSON.stringify(response).includes('five-minute'));
  const failed = await recommend({ body: { filters: { date: '2026-09-26' }, message: 'Saturday' }, catalog, now: () => NOW, ai: async () => { throw new Error('timeout'); } });
  assert.equal(failed.responseMode, 'rules');
});

test('past Pacific dates are rejected while the current local final date is eligible', async () => {
  await assert.rejects(recommend({ body: { filters: { date: '2026-09-22' } }, catalog, now: () => NOW }), /未来日期/);
  const current = await recommend({ body: { filters: { date: '2026-09-26' } }, catalog, now: () => Date.parse('2026-09-27T06:59:59Z') });
  assert.ok(current.suggestions.length > 0);
  await assert.rejects(recommend({ body: { filters: { date: '2026-09-26' } }, catalog, now: () => Date.parse('2026-09-27T07:00:00Z') }), /未来日期/);
});

test('without a date the catalog offers upcoming days and each card carries its actual date', async () => {
  const response = await recommend({ body: {}, catalog, now: () => NOW });
  assert.equal(response.filters.date, undefined);
  assert.ok(response.suggestions.length > 0);
  assert.ok(response.suggestions.every(row => row.date === '2026-09-26'));
});

test('unrestricted UI defaults never hide natural date, city, budget, age, setting or travel mode', async () => {
  const response = await recommend({ body: { message: '周六Fremont\n带五岁孩子\t预算40室内公共交通', filters: { region: 'all', budget: null, childAge: null, setting: 'any', travelMode: 'any' } }, catalog, now: () => NOW });
  assert.deepEqual(response.filters, { region: 'east-bay', budget: 40, childAge: 5, setting: 'indoor', travelMode: 'transit', date: '2026-09-26' });
  assert.ok(response.suggestions.every(row => !row.eventId.includes('adults') && !row.eventId.includes('outside')));
  assert.ok(response.suggestions.every(row => row.unknowns.some(note => note.includes('成人陪同要求'))));
  assert.ok(response.suggestions.every(row => !/适合.{0,8}孩子/.test(row.reason)));
});

test('nearby optional stops require exact venues and the same city, with a tighter walk radius', async () => {
  const target = catalog.events.find(row => row.id === 'known');
  const nearby = catalog.places[0];
  const local = { ...catalog, events: [target], places: [
    { ...nearby, id: 'city-centroid', location: { ...nearby.location, precision: 'area' } },
    { ...nearby, id: 'across-city', city: 'Newark' },
    { ...nearby, id: 'three-km', location: { ...nearby.location, lat: 37.58 } },
  ] };
  const walking = await recommend({ body: { filters: { travelMode: 'walk' } }, catalog: local, now: () => NOW });
  assert.deepEqual(walking.suggestions[0].placeIds, []);
  const driving = await recommend({ body: { filters: { travelMode: 'drive' } }, catalog: local, now: () => NOW });
  assert.deepEqual(driving.suggestions[0].placeIds, ['three-km']);
  const approximateAnchor = await recommend({ body: {}, catalog: { ...local, events: [{ ...target, location: { ...target.location, precision: 'area' } }] }, now: () => NOW });
  assert.deepEqual(approximateAnchor.suggestions[0].placeIds, []);
});

test('multiline questions stay inert bounded text and never permit control bytes', async () => {
  const response = await recommend({ body: { message: 'Fremont\n' + 'a'.repeat(792) }, catalog, now: () => NOW });
  assert.equal(response.filters.region, 'east-bay');
  await assert.rejects(recommend({ body: { message: 'a'.repeat(801) }, catalog, now: () => NOW }), /800/);
  await assert.rejects(recommend({ body: { message: 'Fremont\u0000' }, catalog, now: () => NOW }), /800/);
});

test('account routes require auth, reject forged owners and keep every private collection isolated', async t => {
  const { request, models } = await fixture(t);
  for (const [path, method, body] of [['/me', 'GET'], ['/preferences', 'PATCH', { regions: ['sf'] }], ['/favorites/event/known', 'PUT'], ['/plans', 'POST', plan]]) assert.equal((await request(path, { method, body })).status, 401);
  assert.equal((await request('/me', { auth: 'Bearer invalid' })).status, 401);
  assert.equal((await request('/preferences', { as: 'owner', method: 'PATCH', body: { userId: 'other', regions: ['sf'] } })).status, 400);
  await request('/preferences', { as: 'owner', method: 'PATCH', body: { regions: ['east-bay'], interests: ['family'], travelMode: 'drive' } });
  await request('/favorites/event/known', { as: 'owner', method: 'PUT' });
  const saved = await request('/plans', { as: 'owner', method: 'POST', body: plan });
  assert.equal(saved.status, 201);
  const other = await request('/me', { as: 'other' });
  assert.deepEqual(other.data, { preferences: { regions: [], interests: [], travelMode: 'any' }, favorites: [], plans: [] });
  assert.equal(other.headers.get('cache-control'), 'no-store');
  assert.equal((await request(`/plans/${saved.data.plan.id}`, { as: 'other', method: 'PUT', body: { ...plan, version: 1 } })).status, 404);
  assert.equal((await request('/plans', { as: 'owner', method: 'POST', body: { ...plan, userId: 'other' } })).status, 400);
  const freshInstance = await fixture(t, { models });
  const persisted = (await freshInstance.request('/me', { as: 'owner' })).data;
  assert.equal(persisted.plans.length, 1);
  assert.deepEqual(persisted.favorites, [{ kind: 'event', id: 'known' }]);
  assert.deepEqual(Object.keys(persisted).sort(), ['favorites', 'plans', 'preferences']);
});

test('favorites are idempotent and concurrent independent writes are preserved', async t => {
  const { request } = await fixture(t);
  const write = (kind, id) => request(`/favorites/${kind}/${id}`, { as: 'owner', method: 'PUT' });
  const responses = await Promise.all([write('event', 'known'), write('event', 'known'), write('place', 'nearby'), write('guide', 'weekend-guide')]);
  assert.ok(responses.every(response => response.status === 200));
  const me = (await request('/me', { as: 'owner' })).data;
  assert.equal(me.favorites.length, 3);
  assert.equal((await write('event', 'fake')).status, 404);
  assert.equal((await request('/favorites/event/known', { as: 'owner', method: 'PUT', body: { userId: 'other' } })).status, 400);
  await request('/favorites/event/known', { as: 'owner', method: 'DELETE' });
  await request('/favorites/event/known', { as: 'owner', method: 'DELETE' });
  assert.equal((await request('/me', { as: 'owner' })).data.favorites.length, 2);
});

test('simultaneous plan revisions allow only one writer and stale deletion cannot erase it', async t => {
  const { request } = await fixture(t);
  const saved = (await request('/plans', { as: 'owner', method: 'POST', body: plan })).data.plan;
  const updates = await Promise.all(['Device A', 'Device B'].map(title => request(`/plans/${saved.id}`, { as: 'owner', method: 'PUT', body: { ...plan, title, version: 1 } })));
  assert.deepEqual(updates.map(row => row.status).sort(), [200, 409]);
  assert.equal((await request(`/plans/${saved.id}`, { as: 'owner', method: 'DELETE', body: { version: 1 } })).status, 409);
  const current = (await request('/me', { as: 'owner' })).data.plans[0];
  assert.equal(current.version, 2);
  assert.equal((await request(`/plans/${saved.id}`, { as: 'owner', method: 'DELETE', body: { version: 2 } })).status, 200);
  assert.equal((await request('/me', { as: 'owner' })).data.plans.length, 0);
});

test('plan validation rejects unpublished stops, impossible dates, injection and overlong data', async t => {
  const { request } = await fixture(t);
  const invalid = [
    { ...plan, date: '2026-02-30' }, { ...plan, date: '2026-09-27' },
    { ...plan, stops: [{ kind: 'event', id: 'paused' }] },
    { ...plan, stops: [{ kind: 'event', id: 'invented' }] },
    { ...plan, stops: [{ kind: 'event', id: { $ne: '' } }] },
    { ...plan, stops: Array(7).fill(plan.stops[0]) },
    { ...plan, title: 'x'.repeat(81) }, { ...plan, stops: [plan.stops[0], plan.stops[0]] },
  ];
  for (const body of invalid) assert.ok([400, 404, 410].includes((await request('/plans', { as: 'owner', method: 'POST', body })).status));
  assert.equal((await request('/me', { as: 'owner' })).data.plans.length, 0);
  assert.equal((await request('/recommend', { method: 'POST', body: { filters: { budget: { $gt: 0 } } } })).status, 400);
});
