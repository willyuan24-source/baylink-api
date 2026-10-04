const test = require('node:test');
const assert = require('node:assert/strict');
const { createEvidenceStore, createResearchTools, verifiedCandidate, canonical } = require('../lib/baybayTools');
const { buildItinerary } = require('../lib/baybayPlan');

const NOW = Date.parse('2026-10-04T16:00:00Z');
const today = '2026-10-04', date = '2026-10-05';
const state = { date, city: 'Fremont', travelMode: 'transit', partySize: 2, budget: 100, budgetScope: 'total' };
const candidate = (id, fields = {}) => ({ id, kind: 'place', title: `Place ${id}`, city: 'Fremont', officialUrl: `https://example.org/${id}`, location: { lat: 37.55, lng: -121.98, precision: 'venue' }, ...fields });
const storeFor = rows => createEvidenceStore({ candidates: rows });
function setup(options = {}) {
  const store = options.store || storeFor([candidate('a'), candidate('b')]);
  const research = createResearchTools({ store, state, today, locale: 'en', searchMode: 'smart', isTest: true, now: () => NOW, deadline: Date.now() + 30000, ...options });
  return { store, research };
}
const rawRoute = { routes: [{ duration: '1200s', distanceMeters: 9000 }] };
function proofFixture({ kind = 'event', text, city = 'Fremont' }) {
  const store = storeFor([candidate('web-test', { title: 'City Festival', kind, city, origin: 'web', verification: 'search-result' })]);
  const row = store.candidates.get('web-test');
  const source = store.addSource({ ...store.sources.get(row.sourceIds[0]), text, checkedAt: new Date(NOW).toISOString(), verification: 'page-read' });
  return { row, source };
}

test('evidence URLs are canonicalized and source duplicates retain stable IDs', () => {
  const store = createEvidenceStore();
  const a = store.addSource({ title: 'One', url: 'https://example.org/page/?utm_source=ad&n=1#section', verification: 'search-result' });
  const b = store.addSource({ title: 'Two', url: 'https://example.org/page/?n=1', verification: 'page-read', text: 'Confirmed source body.' });
  assert.equal(a.id, b.id);
  assert.equal(store.sources.size, 1);
  assert.equal(canonical('javascript:alert(1)'), null);
  assert.equal(canonical('https://127.0.0.1/private'), null);
});

test('page-read evidence is not downgraded by another search summary', () => {
  const store = createEvidenceStore();
  const read = store.addSource({ title: 'Verified', url: 'https://example.org/page', verification: 'page-read', checkedAt: '2026-10-04', text: 'Exact page text.' });
  store.addSource({ title: 'Search hit', url: read.url, verification: 'search-result', checkedAt: '2026-10-05', text: 'A paraphrased summary.' });
  assert.equal(store.sources.get(read.id).text, 'Exact page text.');
  assert.equal(store.sources.get(read.id).checkedAt, '2026-10-04');
  assert.equal(store.sources.get(read.id).verification, 'page-read');
});

test('separate relevant paragraphs of the same site guide remain available', () => {
  const store = createEvidenceStore({ guides: [
    { title: 'Moving guide', url: '/guides/utilities', text: 'Fremont water service uses the local water district. Call the official service desk.' },
    { title: 'Moving guide', url: '/guides/utilities', text: 'Electric service setup is a separate step. Check whether the property already has service.' },
  ] });
  const evidence = [...store.sources.values()].map(row => row.text).join('\n');
  assert.match(evidence, /Fremont water service/);
  assert.match(evidence, /Electric service setup/);
});

test('official guide reference links become readable source IDs with editorial dates preserved', async () => {
  let read;
  const store = createEvidenceStore({ guides: [{ title: 'Museum guide', url: '/guides/museums', text: 'Visitor guide excerpt.', updatedAt: '2026-10-02', sourceUrls: [{ title: 'Official visitor information', url: 'https://example.org/official-visit' }] }] });
  const guide = [...store.sources.values()].find(row => row.kind === 'guide');
  assert.equal(guide.recordedAt, '2026-10-02');
  assert.equal(guide.referenceSourceIds.length, 1);
  const official = store.sources.get(guide.referenceSourceIds[0]);
  assert.equal(official.verification, 'catalog');
  assert.equal(official.checkedAt, '2026-10-02');
  const { research } = setup({ store, sourceFetch: async source => { read = source.url; return { text: 'Official visitor information with a readable exact source body.' }; } });
  assert.equal((await research.readSource(official.id)).verification, 'page-read');
  assert.equal(read, 'https://example.org/official-visit');
});

test('partial verification updates retain stronger prior facts without reviving stale planning prices', () => {
  const store = storeFor([candidate('a', { planning: { admissionUsd: 0, schedule: { old: true } } })]);
  store.addCandidate({ ...store.candidates.get('a'), planning: { admissionUsd: null, schedule: { old: true } }, cost: 'paid', costLabel: 'General admission $20', verification: 'page-verified', verifiedFacts: { city: 'Fremont', admission: 'General admission $20' } });
  store.addCandidate({ ...candidate('a'), planning: { admissionUsd: 0, schedule: null }, verifiedFacts: { hours: 'Wednesday closed.' }, verification: 'partial' });
  const row = store.candidates.get('a');
  assert.equal(row.cost, 'paid');
  assert.equal(row.planning.admissionUsd, null);
  assert.equal(row.planning.schedule, null);
  assert.equal(row.verification, 'page-verified');
  assert.equal(row.verifiedFacts.hours, 'Wednesday closed.');
  assert.equal(row.verifiedFacts.admission, 'General admission $20');
});

test('a catalog refresh cannot overwrite verified candidate admission facts', () => {
  const store = storeFor([candidate('a', { cost: 'free', costLabel: 'Old free admission', verification: 'site-record' })]);
  store.addCandidate({ ...store.candidates.get('a'), cost: 'paid', costLabel: 'General admission $20', verification: 'page-verified', verifiedFacts: { admission: 'General admission $20', city: 'Fremont' } });
  store.addCandidate(candidate('a', { cost: 'free', costLabel: 'Old free admission', verification: 'site-record' }));
  assert.equal(store.candidates.get('a').cost, 'paid');
  assert.equal(store.candidates.get('a').costLabel, 'General admission $20');
  assert.equal(store.candidates.get('a').verification, 'page-verified');
});

test('fresh paid admission evidence invalidates an old catalog zero price before planning', () => {
  const store = storeFor([candidate('museum', { title: 'City Museum', cost: 'free', planning: { admissionUsd: 0 } })]);
  const row = store.candidates.get('museum');
  const source = store.addSource({ ...store.sources.get(row.sourceIds[0]), text: 'City Museum in Fremont. General admission $30. Fees may apply.', verification: 'page-read', checkedAt: new Date(NOW).toISOString() });
  const updated = verifiedCandidate({ candidate: row, source, state, today, proofs: { name: 'City Museum', city: 'Fremont', admission: 'General admission $30.' } });
  assert.equal(updated.cost, 'paid');
  const plan = buildItinerary({ state, candidates: [updated], now: NOW });
  assert.notEqual(plan.stops[0].admissionUsd, 0);
  assert.equal(buildItinerary({ state: { ...state, freeOnly: true }, candidates: [updated], now: NOW }).stops.length, 0);
});

test('private query patterns are refused before any external search', async () => {
  let calls = 0;
  const { research } = setup({ webSearch: async () => { calls++; return { sources: [], candidates: [] }; } });
  for (const query of ['I live at 123 Main Street, plan my trip', 'api_key=sk-1234567890123456', 'Find events for person@example.org', 'SSN 123-45-6789']) {
    assert.ok((await research.searchWeb(query)).error, query);
  }
  assert.equal(calls, 0);
});

test('a web lookup cannot start when the remaining research deadline is too short', async () => {
  let calls = 0;
  const { research } = setup({ deadline: Date.now() + 1000, webSearch: async () => { calls++; return { sources: [], candidates: [] }; } });
  assert.ok((await research.searchWeb('museum hours')).error);
  assert.equal(calls, 0);
});

test('candidate verification requires the candidate own page and exact unmodified quotations', () => {
  const { row, source } = proofFixture({ text: 'City Festival. Fremont. October 5, 2026. General admission is free.' });
  const valid = verifiedCandidate({ candidate: row, source, state, today, kind: 'event', proofs: { name: 'City Festival', city: 'Fremont', date: 'October 5, 2026', admission: 'General admission is free.' } });
  assert.equal(valid.verification, 'page-verified');
  assert.deepEqual(valid.occurrenceDates, [date]);
  assert.equal(valid.cost, 'free');
  const invented = verifiedCandidate({ candidate: row, source, state, today, kind: 'event', proofs: { name: 'City Festival', city: 'Fremont', date: 'October 5, 2026', admission: 'General admission is $99.' } });
  assert.equal(invented.verifiedFacts.admission, undefined);
  assert.equal(verifiedCandidate({ candidate: row, source: { ...source, id: 'unrelated' }, state, today, proofs: { name: 'City Festival' } }).error !== undefined, true);
});

test('a page with an old year cannot be converted to the requested year by quoting only month/day', () => {
  const { row, source } = proofFixture({ text: 'City Festival in Fremont. October 5, 2025. Last year event details remain here.' });
  const result = verifiedCandidate({ candidate: row, source, state, today, kind: 'event', proofs: { name: 'City Festival', city: 'Fremont', date: 'October 5' } });
  assert.notEqual(result.verification, 'page-verified');
  assert.equal(result.verifiedFacts.date, undefined);
});

test('free parking or a buy-one-get-one promotion does not prove free admission', () => {
  for (const admission of ['Free parking; general admission $30.', 'Buy one ticket, get one free.', 'Free admission with a $50 purchase.']) {
    const { row, source } = proofFixture({ kind: 'place', text: `City Festival in Fremont. ${admission}` });
    const result = verifiedCandidate({ candidate: row, source, state, today, proofs: { name: 'City Festival', city: 'Fremont', admission } });
    assert.notEqual(result.cost, 'free', admission);
    const plan = buildItinerary({ candidates: [result], state: { ...state, freeOnly: true }, now: NOW });
    assert.equal(plan.stops.length, 0, admission);
  }
});

test('an exact unavailable quote blocks the candidate from a plan', () => {
  const { row, source } = proofFixture({ text: 'City Festival in Fremont. October 5, 2026. Event full. Join the waitlist.' });
  const result = verifiedCandidate({ candidate: row, source, state, today, kind: 'event', proofs: { name: 'City Festival', city: 'Fremont', date: 'October 5, 2026', closed: 'Event full.' } });
  assert.equal(result.availability, 'unavailable');
  assert.equal(buildItinerary({ candidates: [result], state, now: NOW }).stops.length, 0);
});

test('same-name web places in different cities never merge their sources', async () => {
  const store = storeFor([candidate('central', { title: 'Central Park', city: 'Fremont' })]);
  const { research } = setup({ store, state: { ...state, city: null }, webSearch: async () => ({ sources: [{ title: 'Central Park', url: 'https://example.org/san-mateo-park' }], candidates: [{ name: 'Central Park', city: 'San Mateo', sourceUrls: ['https://example.org/san-mateo-park'] }], checkedAt: '2026-10-04', answer: 'A park in San Mateo.' }) });
  const originalSources = [...store.candidates.get('central').sourceIds];
  const found = await research.searchWeb('parks');
  assert.equal(found.candidates[0].city, 'San Mateo');
  assert.notEqual(found.candidates[0].id, 'central');
  assert.equal(found.candidates[0].kind, 'unknown');
  assert.deepEqual(store.candidates.get('central').sourceIds, originalSources);
});

test('web permanent venues need an exact named venue quote before becoming a place', () => {
  const store = storeFor([candidate('web-museum', { title: 'City Museum', kind: 'unknown', origin: 'web', verification: 'search-result' })]);
  const row = store.candidates.get('web-museum');
  const source = store.addSource({ ...store.sources.get(row.sourceIds[0]), text: 'City Museum is an art museum in Fremont. General admission is free.', verification: 'page-read' });
  const proofs = { name: 'City Museum', city: 'Fremont', venue: 'City Museum is an art museum in Fremont.' };
  const valid = verifiedCandidate({ candidate: row, source, state, today, kind: 'place', proofs });
  assert.equal(valid.kind, 'place');
  assert.equal(valid.verification, 'page-verified');
  assert.equal(valid.verifiedFacts.venue, proofs.venue);
  const missingVenue = verifiedCandidate({ candidate: row, source, state, today, kind: 'place', proofs: { name: proofs.name, city: proofs.city } });
  assert.equal(missingVenue.kind, 'unknown');
  assert.equal(missingVenue.verification, 'partial');
  assert.equal(buildItinerary({ candidates: [missingVenue], state, now: NOW }).stops.length, 0);
});

test('an event cannot bypass occurrence verification by being classified as a place at a museum', () => {
  const { row, source } = proofFixture({ text: 'City Festival is an event at a museum in Fremont. Come celebrate with us.' });
  const result = verifiedCandidate({ candidate: { ...row, kind: 'unknown' }, source, state, today, kind: 'place', proofs: { name: 'City Festival', city: 'Fremont', venue: 'City Festival is an event at a museum in Fremont.' } });
  assert.equal(result.kind, 'unknown');
  assert.equal(result.verification, 'partial');
  assert.equal(buildItinerary({ candidates: [result], state, now: NOW }).stops.length, 0);
});

test('new verified hours invalidate an older structured schedule instead of silently overruling the page', () => {
  const store = storeFor([candidate('museum', { title: 'City Museum', planning: { schedule: { sourceUrl: 'https://example.org/museum', weekly: { 3: [{ open: '10:00', close: '17:00' }] } } } })]);
  const row = store.candidates.get('museum');
  const source = store.addSource({ ...store.sources.get(row.sourceIds[0]), verification: 'page-read', text: 'City Museum in Fremont. Regular hours: Wednesday closed.' });
  const updated = verifiedCandidate({ candidate: row, source, state, today, proofs: { name: 'City Museum', city: 'Fremont', hours: 'Regular hours: Wednesday closed.' } });
  assert.equal(updated.planning.schedule, null);
  assert.equal(updated.verifiedFacts.hours, 'Regular hours: Wednesday closed.');
});

test('web lookup has a two-distinct-query budget and no duplicate charge', async () => {
  let calls = 0;
  const { research } = setup({ webSearch: async () => { calls++; return { sources: [], candidates: [], answer: '' }; } });
  await research.searchWeb('museum hours');
  assert.ok((await research.searchWeb('museum hours')).error);
  await research.searchWeb('park hours');
  assert.ok((await research.searchWeb('another query')).error);
  assert.equal(calls, 2);
});

test('source read budget includes failed attempts and prevents a repeated failing page loop', async () => {
  let calls = 0;
  const { store, research } = setup({ sourceFetch: async () => { calls++; return { text: '' }; } });
  const id = store.candidates.get('a').sourceIds[0];
  for (let count = 0; count < 6; count++) await research.readSource(id);
  assert.ok(calls <= 3, `source fetches: ${calls}`);
});

test('site-only mode forbids every external research operation, including paid routing', async () => {
  let routeCalls = 0, webCalls = 0, sourceCalls = 0, weatherCalls = 0;
  const { store, research } = setup({ searchMode: 'site', routeCompute: async () => { routeCalls++; return rawRoute; }, webSearch: async () => { webCalls++; }, sourceFetch: async () => { sourceCalls++; }, fetchImpl: async () => { weatherCalls++; } });
  assert.ok((await research.searchWeb('parks')).error);
  assert.ok((await research.readSource(store.candidates.get('a').sourceIds[0])).error);
  assert.ok((await research.weather('a')).error);
  assert.ok((await research.route({ fromId: 'a', toId: 'b', time: '09:00' })).error);
  assert.deepEqual({ routeCalls, webCalls, sourceCalls, weatherCalls }, { routeCalls: 0, webCalls: 0, sourceCalls: 0, weatherCalls: 0 });
});

test('area coordinates cannot masquerade as a verified route entrance', async () => {
  let calls = 0;
  const store = storeFor([candidate('a', { location: { lat: 37.55, lng: -121.98, precision: 'area' } }), candidate('b')]);
  const { research } = setup({ store, routeCompute: async () => { calls++; return rawRoute; } });
  assert.ok((await research.route({ fromId: 'a', toId: 'b', time: '09:00' })).error);
  assert.equal(calls, 0);
});

test('route budget and global quota prevent a fourth paid lookup', async () => {
  let calls = 0, claims = 0;
  const { research } = setup({ claimRoute: async () => { claims++; return true; }, routeCompute: async () => { calls++; return rawRoute; } });
  for (let index = 0; index < 3; index++) assert.equal((await research.route({ fromId: 'a', toId: 'b', time: `09:0${index}` })).ok, true);
  assert.ok((await research.route({ fromId: 'a', toId: 'b', time: '09:03' })).error);
  assert.equal(calls, 3); assert.equal(claims, 3);
  const capped = setup({ claimRoute: async () => false, routeCompute: async () => { throw new Error('must not call'); } });
  assert.ok((await capped.research.route({ fromId: 'a', toId: 'b', time: '09:00' })).error);
});

test('published plan IDs resolve to exact known endpoints and duplicate route lookups share one charge', async () => {
  let calls = 0, claims = 0;
  const { research } = setup({ claimRoute: async () => { claims++; return true; }, routeCompute: async input => { calls++; assert.equal(input.from.id, 'a'); return rawRoute; } });
  const first = await research.route({ fromId: 'place:a', toId: 'place:b', time: '09:00' });
  assert.equal(first.ok, true);
  assert.deepEqual(await research.route({ fromId: 'a', toId: 'b', time: '09:00' }), first);
  assert.equal((await research.route({ fromId: 'event:a', toId: 'place:b', time: '09:00' })).code, 'route_coordinates_missing');
  assert.equal(calls, 1); assert.equal(claims, 1);
});

test('route errors distinguish unusable departure times and provider failures without leaking responses', async () => {
  let calls = 0;
  const { research } = setup({ routeCompute: async () => { calls++; throw new Error('private provider response'); } });
  assert.equal((await research.route({ fromId: 'a', toId: 'b', time: '25:00' })).code, 'route_time_invalid');
  assert.equal((await setup({ state: { ...state, date: '2026-10-03' } }).research.route({ fromId: 'a', toId: 'b', time: '09:00' })).code, 'route_time_invalid');
  const failed = await research.route({ fromId: 'a', toId: 'b', time: '09:00' });
  assert.equal(failed.code, 'route_provider_unavailable');
  assert.doesNotMatch(JSON.stringify(failed), /private provider/);
  assert.equal(calls, 1);
});

test('routing not configured stays unavailable and never guesses a duration', async () => {
  const { research } = setup();
  const result = await research.route({ fromId: 'a', toId: 'b', time: '09:00' });
  assert.equal(result.available, false);
  assert.equal(result.durationMinutes, undefined);
});

test('weather keeps requested date periods and marks dates beyond forecast unknown', async () => {
  let calls = 0;
  const fetchImpl = async url => { calls++; return { ok: true, json: async () => url.includes('/points/')
    ? { properties: { forecast: 'https://api.weather.gov/gridpoints/MTR/99,77/forecast' } }
    : { properties: { periods: [{ name: 'Monday', startTime: '2026-10-05T06:00:00-07:00', endTime: '2026-10-05T18:00:00-07:00', temperature: 70, shortForecast: 'Sunny' }, { name: 'Tuesday', startTime: '2026-10-06T06:00:00-07:00', temperature: 71 }] } } }; };
  const { store, research } = setup({ fetchImpl });
  const result = await research.weather('a');
  assert.equal(result.periods.length, 1);
  assert.equal(result.periods[0].name, 'Monday');
  assert.match(result.notice, /not a guarantee/);
  assert.equal(store.sources.get(result.sourceId).verification, 'api');
  assert.ok((await research.weather('b')).error);
  assert.equal(calls, 2);
  const future = setup({ fetchImpl, state: { ...state, date: '2027-01-01' } });
  const unknown = await future.research.weather('a');
  assert.deepEqual(unknown.periods, []);
  assert.match(unknown.notice, /outside/);
});

test('weather refuses non-NWS forecast endpoints and out-of-region coordinates', async () => {
  let calls = 0;
  const { research } = setup({ fetchImpl: async () => { calls++; return { ok: true, json: async () => ({ properties: { forecast: 'https://evil.example.net/forecast' } }) }; } });
  await assert.rejects(research.weather('a'), /Invalid weather endpoint/);
  assert.equal(calls, 1);
  const invalid = setup({ store: storeFor([candidate('a', { location: { lat: 31.23, lng: 121.47, precision: 'venue' } })]), fetchImpl: async () => { throw new Error('must not fetch'); } });
  assert.ok((await invalid.research.weather('a')).error);
});
