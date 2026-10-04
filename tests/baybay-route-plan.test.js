const test = require('node:test');
const assert = require('node:assert/strict');
const { enrichPlanRoutes } = require('../lib/baybayRoutePlan');
const { buildItinerary } = require('../lib/baybayPlan');

const NOW = Date.parse('2026-10-04T16:00:00Z'), DATE = '2026-10-05';
const state = { date: DATE, city: 'Fremont', origin: 'Fremont station', originCandidateId: 'station', startTime: '09:00', finishBy: '17:00', travelMode: 'transit', partySize: 2 };
const location = { lat: 37.55, lng: -121.98, precision: 'venue' };
const candidate = (id, extra = {}) => ({ id, kind: 'place', title: `Place ${id}`, city: 'Fremont', officialUrl: 'https://example.org/visit', location,
  planning: { admissionUsd: 0, reservation: 'none', suggestedDurationMinutes: 60, schedule: { sourceUrl: 'https://example.org/hours', verifiedAt: '2026-10-04', dates: { [DATE]: [{ open: '10:00', close: '17:00' }] } } }, ...extra });
const estimate = ({ fromId, toId, time }, minutes = 15) => ({ ok: true, from: { id: fromId }, to: { id: toId }, durationMinutes: minutes, date: DATE, departureTime: time, checkedAt: new Date(NOW).toISOString(), travelMode: 'transit', provider: 'google-maps' });
const options = extra => ({ state, deadline: Date.now() + 10000, ...extra });

test('sequential real-engine rebuilds use opening waits and each actual stop end before querying onward and return legs', async () => {
  const candidates = [candidate('a'), candidate('b')], travelEstimates = [], calls = [], selections = [];
  const build = ids => buildItinerary({ state, candidates, selectedIds: ids, travelEstimates, now: NOW });
  const initial = build(['a', 'b']);
  assert.equal(initial.stops[0].endTime, undefined);
  const result = await enrichPlanRoutes(options({ plan: initial,
    route: async args => { calls.push(args); const value = estimate(args); travelEstimates.push(value); return value; },
    makePlan: ids => { selections.push(ids); return build(ids); },
  }));
  assert.deepEqual(calls, [
    { fromId: 'origin', toId: 'a', time: '09:00' },
    { fromId: 'a', toId: 'b', time: '11:00' },
    { fromId: 'b', toId: 'origin', time: '12:15' },
  ]);
  assert.deepEqual(selections, [['a', 'b'], ['a', 'b'], ['a', 'b']]);
  assert.deepEqual(result.stops.map(stop => [stop.entityId, stop.startTime, stop.endTime]), [['a', '10:00', '11:00'], ['b', '11:15', '12:15']]);
  assert.equal(result.returnTime, '12:30');
  assert.equal(initial.stops[0].endTime, undefined, 'the original plan is not mutated');
});

test('existing accepted legs consume no calls and selected stop order remains fixed', async () => {
  const candidates = [candidate('a'), candidate('b')], travelEstimates = [estimate({ fromId: 'origin', toId: 'b', time: '09:00' })], calls = [];
  const build = ids => buildItinerary({ state, candidates, selectedIds: ids, travelEstimates, now: NOW });
  const result = await enrichPlanRoutes(options({ plan: build(['b', 'a']), makePlan: build,
    route: async args => { calls.push(args); const value = estimate(args); travelEstimates.push(value); return value; },
  }));
  assert.deepEqual(calls, [{ fromId: 'b', toId: 'a', time: '11:00' }, { fromId: 'a', toId: 'origin', time: '12:15' }]);
  assert.deepEqual(result.stops.map(stop => stop.entityId), ['b', 'a']);
});

test('three-call total includes origin and does not invent a fourth call for return', async () => {
  const candidates = ['a', 'b', 'c'].map(id => candidate(id)), travelEstimates = [], calls = [];
  const build = ids => buildItinerary({ state, candidates, selectedIds: ids, travelEstimates, now: NOW });
  const result = await enrichPlanRoutes(options({ plan: build(['a', 'b', 'c']), makePlan: build,
    route: async args => { calls.push(args); const value = estimate(args); travelEstimates.push(value); return value; },
  }));
  assert.equal(calls.length, 3); assert.equal(calls[2].toId, 'c');
  assert.equal(result.returnTime, undefined);
  assert.ok(result.checks.some(check => check.code === 'return_time' && check.status === 'unknown'));
});

test('a city-only origin is never routed, while known published end times can support later precise legs', async () => {
  const localState = { ...state, origin: 'Fremont', originCandidateId: null }, calls = [], travelEstimates = [];
  const event = candidate('show', { kind: 'event', startDate: DATE, endDate: DATE, planning: { schedule: { sourceUrl: 'https://example.org/show', verifiedAt: '2026-10-04', sessions: [{ date: DATE, start: '10:00', end: '11:30' }] } } });
  const build = ids => buildItinerary({ state: localState, candidates: [event, candidate('b')], selectedIds: ids, travelEstimates, now: NOW });
  const result = await enrichPlanRoutes(options({ state: localState, plan: build(['show', 'b']), makePlan: build,
    route: async args => { calls.push(args); const value = estimate(args); travelEstimates.push(value); return value; },
  }));
  assert.deepEqual(calls, [{ fromId: 'show', toId: 'b', time: '11:30' }]);
  assert.equal(result.returnTime, undefined); assert.equal(result.stops[1].startTime, '11:45');
});

test('missing source hours or an unknown session end blocks onward guesses even after a successful first route', async () => {
  for (const first of [candidate('a', { planning: {} }), candidate('a', { kind: 'event', startDate: DATE, endDate: DATE, planning: { schedule: { sourceUrl: 'https://example.org/show', verifiedAt: '2026-10-04', sessions: [{ date: DATE, start: '10:00' }] } } })]) {
    const travelEstimates = [], calls = [];
    const build = ids => buildItinerary({ state, candidates: [first, candidate('b')], selectedIds: ids, travelEstimates, now: NOW });
    const result = await enrichPlanRoutes(options({ plan: build(['a', 'b']), makePlan: build,
      route: async args => { calls.push(args); const value = estimate(args); travelEstimates.push(value); return value; },
    }));
    assert.equal(calls.length, 1); assert.equal(result.stops[0].endTime, undefined); assert.equal(result.returnTime, undefined);
  }
});

test('imprecise endpoints, absent departure time or transport choice, and expired deadline make no route requests', async () => {
  const base = { stops: [{ id: 'place:a', entityId: 'a', location, endTime: '11:00' }], travelLegs: [] };
  for (const patch of [{ state: { ...state, startTime: null } }, { state: { ...state, date: null } }, { state: { ...state, date: '2026-02-30' } }, { state: { ...state, travelMode: 'any' } }, { deadline: Date.now() - 1 }, { plan: { ...base, stops: [{ ...base.stops[0], location: { ...location, precision: 'area' } }] } }, { plan: { ...base, stops: [{ ...base.stops[0], location: { ...location, lat: NaN } }] } }]) {
    let calls = 0;
    const result = await enrichPlanRoutes(options({ plan: base, makePlan: () => base, route: async () => { calls++; return {}; }, ...patch }));
    assert.equal(calls, 0); assert.equal(result, patch.plan || base);
  }
});

test('tool failures and mismatched endpoints do not rebuild or spend further route calls', async () => {
  const plan = { stops: [{ id: 'place:a', entityId: 'a', location, endTime: '11:00' }, { id: 'place:b', entityId: 'b', location, endTime: '12:00' }], travelLegs: [] };
  for (const reply of [{ error: 'quota' }, { ok: false }, { ...estimate({ fromId: 'other', toId: 'a', time: '09:00' }) }, null, new Error('transport failed')]) {
    let calls = 0, rebuilds = 0;
    const result = await enrichPlanRoutes(options({ plan, makePlan: () => { rebuilds++; return plan; }, route: async () => { calls++; if (reply instanceof Error) throw reply; return reply; } }));
    assert.equal(result, plan); assert.equal(calls, 1); assert.equal(rebuilds, 0);
  }
});

test('a rebuild may neither change selected order nor promote an estimate the plan engine rejected', async () => {
  const plan = { stops: [{ id: 'place:a', location, endTime: '11:00' }, { id: 'place:b', location, endTime: '12:00' }], travelLegs: [] };
  for (const rebuilt of [{ ...plan, stops: [...plan.stops].reverse() }, { ...plan, stops: plan.stops.slice(0, 1) }, plan]) {
    const calls = [], selections = [];
    const result = await enrichPlanRoutes(options({ plan, route: async args => { calls.push(args); return estimate(args); }, makePlan: ids => { selections.push(ids); return rebuilt; } }));
    assert.equal(result, plan); assert.equal(calls.length, 1); assert.deepEqual(selections, [['a', 'b']]);
  }
});

test('deadline bounds a stalled callback and late results cannot replace the returned plan', async t => {
  t.mock.timers.enable({ apis: ['Date', 'setTimeout'], now: NOW });
  const plan = { stops: [{ id: 'a', location, endTime: '11:00' }], travelLegs: [] };
  let resolveRoute, rebuilds = 0;
  const pending = enrichPlanRoutes(options({ plan, deadline: NOW + 30, makePlan: () => { rebuilds++; return plan; }, route: () => new Promise(resolve => { resolveRoute = resolve; }) }));
  await Promise.resolve();
  assert.equal(typeof resolveRoute, 'function');
  t.mock.timers.tick(31);
  const result = await pending;
  assert.equal(result, plan); assert.equal(rebuilds, 0);
  resolveRoute(estimate({ fromId: 'origin', toId: 'a', time: '09:00' }));
  await new Promise(resolve => setImmediate(resolve));
  assert.equal(rebuilds, 0);
});
