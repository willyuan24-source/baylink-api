const member = require('./support/member-session');
const test = require('node:test');
const assert = require('node:assert/strict');
const express = require('express');
const { travelInput, travelResult, computeTravel, travelWithDeadline, registerPlannerTravel } = require('../lib/plannerTravel');
const { createMemoryModels } = require('./support/memory-models');
const NOW = Date.parse('2026-10-01T19:00:00Z');
const catalog = { version: 1, checkedAt: '2026-10-01', events: [], guides: [], places: [
  { id: 'a', title: 'A', location: { lat: 37.8, lng: -122.4, precision: 'venue' } },
  { id: 'b', title: 'B', location: { lat: 37.78, lng: -122.42, precision: 'venue' } },
  { id: 'area', title: 'Area', location: { lat: 37.8, lng: -122.4, precision: 'area' } },
] };
const body = () => ({ from: { kind: 'place', id: 'a' }, to: { kind: 'place', id: 'b' }, date: '2026-10-03', time: '12:30', travelMode: 'transit', locale: 'en' });
const raw = () => ({ routes: [{ duration: '1201s', distanceMeters: 4200, warnings: ['Check station access.'] }] });

test('only known precise public catalog points reach routing; time is resolved in Pacific', () => {
  const value = travelInput(body(), catalog, NOW);
  assert.equal(value.departureAt, '2026-10-03T19:30:00.000Z');
  assert.deepEqual(value.from.location, { lat: 37.8, lng: -122.4 });
  for (const patch of [{ from: { kind: 'place', id: 'area' } }, { from: { kind: 'place', id: 'missing' } }, { from: { kind: 'place', id: 'a', address: 'private' } }, { travelMode: '__proto__' }, { travelMode: 'constructor' }, { date: '2026-02-30' }, { date: '2026-11-01', time: '01:30' }, { date: '2026-09-30' }, { date: '2027-04-01' }, { to: { kind: 'place', id: 'a' } }, { coordinates: [0, 0] }]) assert.throws(() => travelInput({ ...body(), ...patch }, catalog, NOW));
});

test('fixed Google endpoint, bounded field mask and no private user details', async () => {
  let sent;
  const input = travelInput({ ...body(), travelMode: 'drive' }, catalog, NOW);
  await computeTravel(input, { apiKey: 'synthetic-only', signal: new AbortController().signal, fetchImpl: async (url, options) => { sent = { url, ...options }; return { ok: true, json: async () => raw() }; } });
  assert.equal(sent.url, 'https://routes.googleapis.com/directions/v2:computeRoutes');
  assert.equal(sent.headers['X-Goog-FieldMask'], 'routes.duration,routes.distanceMeters,routes.warnings');
  assert.equal(JSON.parse(sent.body).routingPreference, 'TRAFFIC_AWARE');
  assert.equal(JSON.parse(sent.body).departureTime, input.departureAt);
  assert.ok(!sent.body.includes('private'));
  assert.equal(travelResult(raw(), input, NOW).durationMinutes, 21);
  for (const value of [{}, { routes: [{ duration: '-1s', distanceMeters: 2 }] }, { routes: [{ duration: 'Infinitys', distanceMeters: 2 }] }, { routes: [{ duration: '4s', distanceMeters: -5 }] }]) assert.throws(() => travelResult(value, input, NOW));
});

async function fixture(t, options = {}) {
  const app = express(), models = createMemoryModels({ User: [member.user] }); app.use(express.json());
  registerPlannerTravel(app, { webAccessForRequest: member.accessForModels(models), catalog, now: () => NOW, Quota: models.PostTranslationQuota, checkRateLimit: () => true, isTest: true, ...options });
  const server = await new Promise(resolve => { const listener = app.listen(0, '127.0.0.1', () => resolve(listener)); });
  t.after(() => new Promise(resolve => server.close(resolve)));
  const request = async () => { const res = await fetch(`http://127.0.0.1:${server.address().port}/api/planner/travel-estimate`, { method: 'POST', headers: { 'Content-Type': 'application/json', ...member.headers() }, body: JSON.stringify(body()) }); return { status: res.status, cache: res.headers.get('cache-control'), data: await res.json() }; };
  request.capabilities = async () => { const res = await fetch(`http://127.0.0.1:${server.address().port}/api/planner/travel-capabilities`, { headers: member.headers() }); return { status: res.status, cache: res.headers.get('cache-control'), data: await res.json() }; };
  return request;
}

test('routing defaults off, even with a key; no provider response is stored or leaked', async t => {
  const request = await fixture(t, { config: { GOOGLE_ROUTES_API_KEY: 'synthetic-only' } });
  const result = await request();
  assert.equal(result.status, 503); assert.equal(result.cache, 'no-store');
  assert.ok(!JSON.stringify(result).includes('synthetic-only'));
});

test('daily quota is atomic across concurrent requests and counts failed provider calls', async t => {
  let calls = 0;
  const request = await fixture(t, { config: { PLANNER_TRAVEL_DAILY_LIMIT: '2' }, compute: async () => { calls++; return raw(); } });
  const results = await Promise.all([request(), request(), request()]);
  assert.deepEqual(results.map(x => x.status).sort(), [200, 200, 429]); assert.equal(calls, 2);
  assert.equal(results.find(x => x.status === 200).data.provider, 'google-maps');
  const failed = await fixture(t, { config: { PLANNER_TRAVEL_DAILY_LIMIT: '1' }, compute: async () => { throw Error('provider-secret'); } });
  assert.equal((await failed()).status, 503); assert.equal((await failed()).status, 429);
});

test('capability is a secret-free switch that never allocates quota or invokes paid routing', async t => {
  let calls = 0;
  const compute = async () => { calls++; return raw(); };
  const enabled = await fixture(t, { compute, config: { GOOGLE_ROUTES_API_KEY: 'synthetic-secret' } });
  const capability = await enabled.capabilities();
  assert.equal(capability.status, 200); assert.equal(capability.cache, 'no-store'); assert.deepEqual(capability.data, { available: true, webRequiresAuth: true, webAccess: { authenticated: true, allowed: true } });
  assert.equal(calls, 0);
  for (const options of [{}, { compute, Quota: null }, { compute, config: { PLANNER_TRAVEL_DAILY_LIMIT: '0' } }]) {
    const disabled = await fixture(t, options);
    assert.deepEqual((await disabled.capabilities()).data, { available: false, webRequiresAuth: true, webAccess: { authenticated: true, allowed: true } });
    assert.equal((await disabled()).status, 503);
  }
  assert.equal(calls, 0, 'off endpoints and availability checks cannot invoke a paid provider');
});

test('route deadline bounds an ignored abort and a stalled response JSON body', async () => {
  let seenSignal;
  const input = travelInput(body(), catalog, NOW);
  await assert.rejects(travelWithDeadline(signal => computeTravel(input, { apiKey: 'synthetic-secret', signal,
    fetchImpl: async (_url, options) => { seenSignal = options.signal; return { ok: true, json: () => new Promise(() => {}) }; } }), 20), /超时/);
  assert.equal(seenSignal.aborted, true);
  assert.equal(await travelWithDeadline(async () => 'finished', 20), 'finished');
});
