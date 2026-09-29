const test = require('node:test');
const assert = require('node:assert/strict');
const jwt = require('jsonwebtoken');
const { createApplication } = require('../server');
const { createMemoryModels } = require('./support/memory-models');
const { loadPlannerCatalog } = require('../lib/planner');

const NOW = Date.parse('2026-09-29T19:00:00Z');
const SECRET = 'isolated-planner-details-tests-not-a-real-key';
const catalog = { version: 1, checkedAt: '2026-09-29', events: [
  { id: 'museum', title: 'Museum visit', region: 'east-bay', city: 'Oakland', startDate: '2026-10-03', endDate: '2026-10-03', cost: 'paid' },
], places: ['cafe', 'park'].map(id => ({ id, title: id, region: 'east-bay', city: 'Oakland' })), guides: [] };
const plan = { title: 'Saturday together', date: '2026-10-03', stops: [{ kind: 'event', id: 'museum' }, { kind: 'place', id: 'cafe' }] };
const details = () => ({ startTime: '14:00', finishBy: '18:00', partySize: 4, totalBudgetUsd: 100.5, extraCostUsd: 12.25, travelMode: 'transit',
  stopSettings: [{ kind: 'event', id: 'museum', durationMinutes: 60, travelMinutes: 20, fixedStartTime: '15:00' },
    { kind: 'place', id: 'cafe', durationMinutes: 30, travelMinutes: 10 }],
  constraints: { date: '2026-10-03', region: 'east-bay', city: 'Oakland', budget: 100.5, childAge: 5, childAges: [5, 7],
    setting: 'indoor', travelMode: 'transit', partySize: 4, budgetScope: 'total', freeOnly: false, topic: 'arts' },
});

async function fixture(t, sharedModels, suppliedCatalog = catalog) {
  const models = sharedModels || createMemoryModels({ User: ['owner', 'other'].map(id => ({ id, email: `${id}@private.test`, accountStatus: 'active', password: 'private' })) });
  const application = createApplication({ config: { NODE_ENV: 'test', JWT_SECRET: SECRET }, models, plannerCatalog: suppliedCatalog, plannerNow: () => NOW });
  await new Promise(resolve => application.server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise(resolve => application.io.close(resolve)));
  const request = async (path, { as = 'owner', method = 'GET', body } = {}) => {
    const token = jwt.sign({ id: as }, SECRET, { expiresIn: '1h' });
    const response = await fetch(`http://127.0.0.1:${application.server.address().port}/api/planner${path}`, { method,
      headers: { Authorization: `Bearer ${token}`, ...(body !== undefined ? { 'Content-Type': 'application/json' } : {}) },
      ...(body !== undefined ? { body: JSON.stringify(body) } : {}),
    });
    return { status: response.status, data: await response.json() };
  };
  return { models, request, create: value => request('/plans', { method: 'POST', body: value }) };
}

test('legacy plan CRUD remains compatible and details are optional', async t => {
  const { request, create } = await fixture(t);
  const saved = await create(plan);
  assert.equal(saved.status, 201);
  assert.equal(Object.hasOwn(saved.data.plan, 'details'), false);
  const path = `/plans/${saved.data.plan.id}`;
  const updated = await request(path, { method: 'PUT', body: { ...plan, title: 'Renamed', version: 1 } });
  assert.equal(updated.status, 200);
  assert.equal(Object.hasOwn(updated.data.plan, 'details'), false);
  assert.deepEqual((await request('/me')).data.plans, [updated.data.plan]);
  assert.equal((await request(path, { method: 'DELETE', body: { version: 2 } })).status, 200);
  assert.deepEqual((await request('/me')).data.plans, []);
});

test('all user estimates and query constraints round trip across create, reload and update privately', async t => {
  const { request, create, models } = await fixture(t);
  const value = details();
  const saved = await create({ ...plan, details: value });
  assert.equal(saved.status, 201);
  assert.deepEqual(saved.data.plan.details, value);
  const reloaded = await fixture(t, models);
  assert.deepEqual((await reloaded.request('/me')).data.plans[0].details, value);
  assert.deepEqual((await request('/me', { as: 'other' })).data.plans, []);
  const path = `/plans/${saved.data.plan.id}`;
  const nextDetails = { ...value, finishBy: '19:00', extraCostUsd: 17.75, stopSettings: value.stopSettings.slice(0, 1) };
  assert.equal((await request(path, { as: 'other', method: 'PUT', body: { ...plan, details: nextDetails, version: 1 } })).status, 404);
  const updated = await request(path, { method: 'PUT', body: { ...plan, details: nextDetails, version: 1 } });
  assert.equal(updated.status, 200);
  assert.deepEqual(updated.data.plan.details, nextDetails);
  assert.equal(updated.data.plan.version, 2);
  assert.equal((await request(path, { method: 'DELETE', body: { version: 1 } })).status, 409);
  assert.deepEqual((await request('/me')).data.plans[0].details, nextDetails);
  assert.equal((await request(path, { method: 'DELETE', body: { version: 2 } })).status, 200);
});

test('legacy updates preserve estimates while discarding removed stop settings', async t => {
  const { request, create } = await fixture(t);
  const value = details();
  const saved = (await create({ ...plan, details: value })).data.plan;
  const unchanged = await request(`/plans/${saved.id}`, { method: 'PUT', body: { ...plan, title: 'Old client', version: 1 } });
  assert.deepEqual(unchanged.data.plan.details, value);
  const stops = [plan.stops[0], { kind: 'place', id: 'park' }];
  const replaced = await request(`/plans/${saved.id}`, { method: 'PUT', body: { ...plan, stops, version: 2 } });
  assert.equal(replaced.status, 200);
  assert.deepEqual(replaced.data.plan.details, { ...value, stopSettings: value.stopSettings.slice(0, 1) });
});

test('concurrent details updates keep one complete winning version and reject stale writers', async t => {
  const { request, create } = await fixture(t);
  const saved = (await create({ ...plan, details: details() })).data.plan;
  const path = `/plans/${saved.id}`;
  const responses = await Promise.all([3, 5].map(partySize => request(path, { method: 'PUT', body: { ...plan, version: 1,
    details: { ...details(), partySize, totalBudgetUsd: partySize * 25 },
  } })));
  assert.deepEqual(responses.map(row => row.status).sort(), [200, 409]);
  const winner = responses.find(row => row.status === 200).data.plan;
  assert.equal(winner.version, 2);
  assert.deepEqual((await request('/me')).data.plans, [winner]);
});

test('details reject missing required fields, non-objects and unknown keys without saving', async t => {
  const { request, create } = await fixture(t);
  const invalid = [null, [], true, 'estimates', {}, { ...details(), verifiedRoute: true }];
  for (const key of ['startTime', 'finishBy', 'partySize', 'totalBudgetUsd', 'extraCostUsd', 'travelMode', 'stopSettings']) {
    const value = details(); delete value[key]; invalid.push(value);
  }
  for (const value of invalid) assert.equal((await create({ ...plan, details: value })).status, 400, JSON.stringify(value));
  assert.equal((await create({ ...plan, details: details(), estimates: {} })).status, 400);
  assert.deepEqual((await request('/me')).data.plans, []);
});

test('details enforce same-day clock times, integer party size and finite bounded costs without coercion', async t => {
  const { request, create } = await fixture(t);
  const invalid = [
    ...['9:00', '24:00', '14:60', '14:00:00', 1400, null].map(startTime => ({ startTime })),
    ...['14:00', '13:59', '00:00', '24:00', null].map(finishBy => ({ finishBy })),
    ...[0, 51, 2.5, '4', null].map(partySize => ({ partySize })),
    ...[-0.01, 100000.01, '100', {}, true].map(totalBudgetUsd => ({ totalBudgetUsd })),
    ...[-1, 100000.01, '12', null, true].map(extraCostUsd => ({ extraCostUsd })),
    ...['public-transit', 'bike', null, {}].map(travelMode => ({ travelMode })),
  ];
  for (const patch of invalid) assert.equal((await create({ ...plan, details: { ...details(), ...patch } })).status, 400, JSON.stringify(patch));
  assert.deepEqual((await request('/me')).data.plans, []);
});

test('stop settings reject foreign or duplicate stops, nested unknowns and invalid duration or travel values', async t => {
  const { request, create } = await fixture(t);
  const original = details().stopSettings[0];
  const invalidStops = [null, [], { ...original, route: { minutes: 10 } }, { ...original, kind: 'guide' },
    { ...original, kind: 'place' }, { ...original, id: 'park', kind: 'place' }, { ...original, id: 'not-published' },
    { ...original, id: { $ne: '' } },
    ...[4, 721, 30.5, '30', null].map(durationMinutes => ({ ...original, durationMinutes })),
    ...[-1, 361, 1.5, '20', null].map(travelMinutes => ({ ...original, travelMinutes })),
    ...['9:00', '24:00', '14:61', null, {}].map(fixedStartTime => ({ ...original, fixedStartTime })),
  ];
  for (const key of ['kind', 'id', 'durationMinutes', 'travelMinutes']) { const stop = { ...original }; delete stop[key]; invalidStops.push(stop); }
  const settings = [...invalidStops.map(stop => [stop]), [original, original], Array(7).fill(original), null, {}];
  for (const stopSettings of settings) assert.equal((await create({ ...plan, details: { ...details(), stopSettings } })).status, 400, JSON.stringify(stopSettings));
  assert.deepEqual((await request('/me')).data.plans, []);
});

test('stored query constraints reuse deep filter validation and reject nested injection or unknown fields', async t => {
  const { request, create } = await fixture(t);
  const invalid = [null, [], { departure: 'Fremont' }, { budget: { $lte: 100 } }, { childAges: [5, { age: 7 }] },
    { childAges: [18] }, { childAges: Array(11).fill(5) }, { childAges: [5, 7], partySize: 1 },
    { partySize: 51 }, { date: '2026-02-30' }, { region: 'outside' }, { city: { name: 'Oakland' } },
    { budgetScope: 'all' }, { freeOnly: 'true' }, { topic: { type: 'music' } }, { setting: ['indoor'] }, { travelMode: 'public-transit' },
    JSON.parse('{"__proto__":{"polluted":true}}'),
  ];
  for (const constraints of invalid) assert.equal((await create({ ...plan, details: { ...details(), constraints } })).status, 400, JSON.stringify(constraints));
  assert.deepEqual((await request('/me')).data.plans, []);
  assert.equal({}.polluted, undefined);
});

test('valid boundaries, zero budgets and empty or partial settings remain user-editable estimates', async t => {
  const { create } = await fixture(t);
  for (const travelMode of ['any', 'drive', 'transit', 'walk']) {
    const value = { startTime: '00:00', finishBy: '23:59', partySize: 50, totalBudgetUsd: null, extraCostUsd: 100000, travelMode,
      stopSettings: [{ kind: 'event', id: 'museum', durationMinutes: 720, travelMinutes: 360, fixedStartTime: '00:00' }],
    };
    const saved = await create({ ...plan, details: value });
    assert.equal(saved.status, 201);
    assert.deepEqual(saved.data.plan.details, value);
  }
  for (const stopSettings of [[], [{ kind: 'place', id: 'cafe', durationMinutes: 5, travelMinutes: 0 }]]) {
    const value = { ...details(), partySize: 1, totalBudgetUsd: 0, extraCostUsd: 0, stopSettings, constraints: {} };
    const saved = await create({ ...plan, details: value });
    assert.equal(saved.status, 201);
    assert.deepEqual(saved.data.plan.details, value);
  }
  assert.equal((await create({ ...plan, details: { ...details(), totalBudgetUsd: 100000 } })).status, 201);
});

test('invalid details updates cannot alter saved values or advance the version', async t => {
  const { request, create } = await fixture(t);
  const saved = (await create({ ...plan, details: details() })).data.plan;
  const path = `/plans/${saved.id}`;
  for (const value of [{ ...details(), finishBy: '13:00' }, { ...details(), stopSettings: [{ kind: 'place', id: 'park', durationMinutes: 30, travelMinutes: 10 }] },
    { ...details(), constraints: { freeOnly: { $ne: false } } }]) {
    assert.equal((await request(path, { method: 'PUT', body: { ...plan, details: value, version: 1 } })).status, 400);
  }
  assert.deepEqual((await request('/me')).data.plans, [saved]);
});

test('meal and rest blocks plus itemized costs survive private saves and legacy updates', async t => {
  const { request, create } = await fixture(t);
  const value = { ...details(), extraCostUsd: 36.75, costBreakdown: { foodUsd: 25, transportUsd: 10.5, otherUsd: 1.25 },
    stopSettings: details().stopSettings.map((stop, index) => ({ ...stop, breakBeforeMinutes: index ? 45 : 10, breakLabel: index ? 'meal' : 'rest' })),
  };
  const saved = await create({ ...plan, details: value });
  assert.equal(saved.status, 201);
  assert.deepEqual(saved.data.plan.details, value);
  const legacy = await request(`/plans/${saved.data.plan.id}`, { method: 'PUT', body: { ...plan, version: 1 } });
  assert.equal(legacy.status, 200);
  assert.deepEqual(legacy.data.plan.details, value);
  assert.deepEqual((await request('/me')).data.plans[0].details, value);
  assert.deepEqual((await request('/me', { as: 'other' })).data.plans, []);
});

test('cost breakdowns and break settings reject mismatches, coercion and nested fields without changing a saved plan', async t => {
  const { request, create } = await fixture(t);
  const saved = (await create({ ...plan, details: details() })).data.plan;
  const invalidBreakdowns = [null, [], {}, { foodUsd: 12.25, transportUsd: 0 }, { foodUsd: 10, transportUsd: 0, otherUsd: 0 },
    { foodUsd: '12.25', transportUsd: 0, otherUsd: 0 }, { foodUsd: -1, transportUsd: 13.25, otherUsd: 0 },
    { foodUsd: 12.25, transportUsd: 0, otherUsd: 0, verified: true }, { foodUsd: { $gt: 0 }, transportUsd: 0, otherUsd: 0 }];
  const invalid = invalidBreakdowns.map(costBreakdown => ({ ...details(), costBreakdown }));
  for (const patch of [...[-1, 181, 30.5, '30', null].map(breakBeforeMinutes => ({ breakBeforeMinutes })), ...['lunch', '', null, {}].map(breakLabel => ({ breakLabel }))]) {
    invalid.push({ ...details(), stopSettings: [{ ...details().stopSettings[0], ...patch }] });
  }
  for (const value of invalid) assert.equal((await request(`/plans/${saved.id}`, { method: 'PUT', body: { ...plan, version: 1, details: value } })).status, 400);
  assert.deepEqual((await request('/me')).data.plans, [saved]);
  const zero = { ...details(), extraCostUsd: 0, costBreakdown: { foodUsd: 0, transportUsd: 0, otherUsd: 0 }, stopSettings: [{ ...details().stopSettings[0], breakBeforeMinutes: 0, breakLabel: 'rest' }] };
  assert.equal((await create({ ...plan, details: zero })).status, 201);
});

test('new restaurant catalog entries remain place references and accept verified schedules without a new stop kind', async t => {
  const restaurant = { id: 'opening-verified-cafe', title: 'Verified cafe', city: 'Oakland', region: 'east-bay', category: 'cafe', path: '/openings/verified-cafe', address: 'Test address', offerIds: [],
    planning: { schedule: { sourceUrl: 'https://example.com/hours', verifiedAt: '2026-09-29', weekly: { 6: [{ open: '10:00', close: '17:00' }] } } },
  };
  const { create } = await fixture(t, undefined, { ...catalog, places: [...catalog.places, restaurant] });
  const result = await create({ ...plan, stops: [...plan.stops, { kind: 'place', id: restaurant.id }] });
  assert.equal(result.status, 201);
  assert.deepEqual(result.data.plan.stops.at(-1), { kind: 'place', id: restaurant.id });
  assert.equal((await create({ ...plan, stops: [{ kind: 'restaurant', id: restaurant.id }] })).status, 400);
});

test('the exported Ferry full-day catalog and itemized details round trip through the planner API', async t => {
  const published = loadPlannerCatalog();
  assert.ok(published);
  const eventId = 'ferry-plaza-farmers-market-2026-autumn';
  const restaurantId = 'restaurant-gotts-ferry-building';
  const venueId = 'venue-exploratorium-daytime';
  for (const id of [restaurantId, venueId]) {
    const place = published.places.find(item => item.id === id);
    assert.ok(place?.planning?.schedule?.sourceUrl);
    assert.equal(place.guideSlug, '');
    assert.equal(place.cost, 'unknown');
    assert.equal(place.planning.admissionUsd, null);
  }
  assert.equal(published.events.find(item => item.id === 'san-jose-first-friday-ballet-2026')?.planning?.programTimeUnconfirmed, true);
  assert.equal(published.places.find(item => item.id === 'restaurant-town-fare-omca')?.planning?.schedule?.weekly?.[0]?.[0]?.lastOrder, '15:15');
  const { create, request } = await fixture(t, undefined, published);
  const value = { title: 'Ferry market, lunch and science museum', date: '2026-10-03',
    stops: [{ kind: 'event', id: eventId }, { kind: 'place', id: restaurantId }, { kind: 'place', id: venueId }],
    details: { startTime: '10:00', finishBy: '15:00', partySize: 2, totalBudgetUsd: null, extraCostUsd: 50.5,
      costBreakdown: { foodUsd: 40, transportUsd: 10.5, otherUsd: 0 }, travelMode: 'walk',
      constraints: { date: '2026-10-03', partySize: 2, travelMode: 'walk' },
      stopSettings: [{ kind: 'event', id: eventId, durationMinutes: 90, travelMinutes: 0, fixedStartTime: '10:00' },
        { kind: 'place', id: restaurantId, durationMinutes: 60, travelMinutes: 30 },
        { kind: 'place', id: venueId, durationMinutes: 90, travelMinutes: 30 }],
    },
  };
  const saved = await create(value);
  assert.equal(saved.status, 201);
  assert.deepEqual(saved.data.plan.stops, value.stops);
  assert.deepEqual(saved.data.plan.details, value.details);
  assert.deepEqual((await request('/me')).data.plans[0].details, value.details);
});
