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
  assert.equal(store.sources.get(read.id).title, 'Verified');
});

const realPlace = id => ({ ...require('../data/planner-catalog.json').places.find(row => row.id === id), kind: 'place', sourceKind: 'site-catalog', verification: 'site-record' });

test('real bilingual editorial venue labels verify against exact official primary names', () => {
  const cases = [
    ['venue-sjma', 'San Jose Museum of Art', 'San José, California'],
    ['venue-sj-king-library', 'Dr. Martin Luther King, Jr. Library', 'San Jose, California'],
  ];
  for (const [id, name, city] of cases) {
    const store = storeFor([realPlace(id)]), row = store.candidates.get(id);
    const source = store.addSource({ ...store.sources.get(row.sourceIds[0]), text: `${name}\nVisitor information: ${city}.`, verification: 'page-read' });
    const result = verifiedCandidate({ candidate: row, source, state, today, proofs: { name, city } });
    assert.equal(result.error, undefined, id);
    assert.equal(result.verifiedFacts.name, name);
    assert.equal(result.verification, 'page-verified');
    assert.ok(verifiedCandidate({ candidate: row, source, state, today, proofs: { name: `${name} invented suffix`, city } }).error);
  }
});

test('a parent museum or partial new web name cannot authenticate the cafe on its shared page', () => {
  const cafe = realPlace('restaurant-el-cafecito-sjma');
  for (const row of [cafe, { ...cafe, id: 'web-cafe', origin: 'web', kind: 'unknown' }]) {
    const store = storeFor([row]), stored = store.candidates.get(row.id);
    const source = store.addSource({ ...store.sources.get(stored.sourceIds[0]), text: 'San José Museum of Art is an art museum in San Jose. El Cafecito serves lunch.', verification: 'page-read' });
    assert.ok(verifiedCandidate({ candidate: stored, source, state, today, proofs: { name: 'San José Museum of Art', city: 'San Jose' } }).error);
    const byPrimary = verifiedCandidate({ candidate: stored, source, state, today, proofs: { name: 'El Cafecito', city: 'San Jose' } });
    if (row.origin === 'web') assert.ok(byPrimary.error);
    else assert.equal(byPrimary.error, undefined);
  }
});

test('shared real museum and cafe URLs use a neutral label until a source supplies a page title', () => {
  for (const ids of [['venue-sjma', 'restaurant-el-cafecito-sjma'], ['restaurant-el-cafecito-sjma', 'venue-sjma']]) {
    const store = storeFor(ids.map(realPlace));
    const sourceId = store.candidates.get('venue-sjma').sourceIds[0];
    assert.equal(store.sources.get(sourceId).title, 'sjmusart.org/visit');
    assert.equal(store.candidates.get(ids[0]).sourceIds[0], store.candidates.get(ids[1]).sourceIds[0]);
    store.addSource({ url: 'https://sjmusart.org/visit', title: 'Visit | San José Museum of Art', verification: 'search-result' });
    store.addCandidate(realPlace('restaurant-el-cafecito-sjma'));
    assert.equal(store.sources.get(sourceId).title, 'Visit | San José Museum of Art');
    store.addSource({ ...store.sources.get(sourceId), text: 'Museum visitor information and exact admission evidence.', verification: 'page-read' });
    store.addCandidate(realPlace('venue-sjma'));
    assert.equal(store.sources.get(sourceId).title, 'Visit | San José Museum of Art');
  }
});

test('searches for a real museum merge into the museum rather than its cafe title suffix', async () => {
  const store = storeFor([realPlace('restaurant-el-cafecito-sjma'), realPlace('venue-sjma')]);
  const { research } = setup({ store, state: { ...state, city: 'San Jose' }, webSearch: async () => ({ sources: [{ title: 'Visit | San José Museum of Art', url: 'https://sjmusart.org/visit' }], candidates: [{ name: 'San Jose Museum of Art', city: 'San Jose', sourceUrls: ['https://sjmusart.org/visit'] }], checkedAt: '2026-10-04', answer: 'Museum visitor information.' }) });
  const result = await research.searchWeb('San Jose Museum of Art admission');
  assert.equal(result.candidates[0].id, 'venue-sjma');
  assert.equal(store.sources.get(result.candidates[0].sourceIds[0]).title, 'Visit | San José Museum of Art');
});

test('same shared URL does not merge a newly found parent museum into a known cafe', async () => {
  const store = storeFor([realPlace('restaurant-el-cafecito-sjma')]);
  const { research } = setup({ store, state: { ...state, city: 'San Jose' }, webSearch: async () => ({ sources: [{ title: 'Museum visit', url: 'https://sjmusart.org/visit' }], candidates: [{ name: 'San José Museum of Art', city: 'San Jose', sourceUrls: ['https://sjmusart.org/visit'] }], checkedAt: '2026-10-04' }) });
  const result = await research.searchWeb('museum admission');
  assert.match(result.candidates[0].id, /^web-/);
  assert.equal(result.candidates[0].kind, 'unknown');
});

test('conditional and cropped free admission quotations cannot turn a paid museum into zero dollars', () => {
  for (const sentence of ['Free admission on the first Friday after 6 pm.', 'Members receive free admission.', 'Free admission for children; adult admission $20.', 'General admission $20 and free admission on Friday.', 'Free admission for Bank of America cardholders.', 'Free admission. Offer valid only for Bank of America cardholders.']) {
    const store = storeFor([candidate('museum', { title: 'City Museum', cost: 'free', planning: { admissionUsd: 0 } })]);
    const row = store.candidates.get('museum');
    const source = store.addSource({ ...store.sources.get(row.sourceIds[0]), text: `City Museum in Fremont. ${sentence}`, verification: 'page-read' });
    const quote = sentence.match(/free admission/i)[0];
    const result = verifiedCandidate({ candidate: row, source, state, today, proofs: { name: 'City Museum', city: 'Fremont', admission: quote } });
    assert.notEqual(result.cost, 'free', sentence);
    assert.equal(result.planning.admissionUsd, null, sentence);
    assert.equal(buildItinerary({ candidates: [result], state: { ...state, freeOnly: true }, now: NOW }).stops.length, 0, sentence);
  }
});

test('unconditional free admission is not invalidated by an unrelated neighboring footer', () => {
  const store = storeFor([candidate('museum', { title: 'City Museum' })]);
  const row = store.candidates.get('museum');
  const source = store.addSource({ ...store.sources.get(row.sourceIds[0]), text: 'City Museum in Fremont. Free admission. Contact the museum with questions. Members receive a newsletter.', verification: 'page-read' });
  for (const admission of ['Free admission', 'Free admission.']) {
    const result = verifiedCandidate({ candidate: row, source, state, today, proofs: { name: 'City Museum', city: 'Fremont', admission } });
    assert.equal(result.cost, 'free');
  }
});

test('real SJMA mixed ticket evidence remains unknown instead of making a library-plus-museum plan free', () => {
  const store = storeFor([realPlace('venue-sjma'), realPlace('venue-sj-king-library')]);
  const row = store.candidates.get('venue-sjma');
  const admission = 'General admission $20; seniors $15; members free. Free admission on the first Friday after 6 pm.';
  const source = store.addSource({ ...store.sources.get(row.sourceIds[0]), text: `San José Museum of Art in San Jose. ${admission}`, verification: 'page-read', checkedAt: new Date(NOW).toISOString() });
  const result = verifiedCandidate({ candidate: row, source, state, today, proofs: { name: 'San José Museum of Art', city: 'San Jose', admission } });
  assert.equal(result.error, undefined); assert.notEqual(result.cost, 'free'); assert.equal(result.planning.admissionUsd, null);
  const plan = buildItinerary({ state: { ...state, date: '2026-10-10', city: 'San Jose' }, candidates: [store.candidates.get('venue-sj-king-library'), result], selectedIds: ['venue-sj-king-library', 'venue-sjma'], now: NOW });
  const museum = plan.stops.find(stop => stop.entityId === 'venue-sjma');
  assert.equal(museum.admissionStatus, 'incomplete'); assert.equal(museum.admissionUsd, undefined);
  assert.ok(plan.budget.unknownItems.some(item => item.includes(row.title)));
  assert.equal(plan.checks.find(check => check.type === 'budget' || check.key === 'budget' || check.code === 'budget')?.status, 'unknown');
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

test('source reads expose real same-origin eligibility links as unread sources within the existing page budget', async () => {
  const store = createEvidenceStore(), calls = [];
  const source = store.addSource({ title: 'Museums on Us partners', url: 'https://about.bankofamerica.com/en/making-an-impact/museums-on-us-partners', verification: 'catalog' });
  const links = [
    ...Array.from({ length: 8 }, (_, i) => ({ title: `Visitor hours ${i}`, url: `https://about.bankofamerica.com/visit-${i}` })),
    { title: 'Review Museums on Us eligibility terms', url: 'https://about.bankofamerica.com/en/making-an-impact/arts-and-culture' },
    { title: 'Eligibility on an unrelated site', url: 'https://other.example.org/eligibility' },
    { title: 'Eligibility internal', url: 'https://127.0.0.1/eligibility' },
    { title: 'Eligibility private', url: 'https://10.0.0.1/eligibility' },
    { title: 'Eligibility fake authority', url: 'https://about.bankofamerica.com.evil.example/eligibility' },
    { title: 'Eligibility credential URL', url: 'https://user:secret@about.bankofamerica.com/eligibility' },
    { title: 'Eligibility insecure URL', url: 'http://about.bankofamerica.com/eligibility' },
    { title: 'Eligibility unsupported port', url: 'https://about.bankofamerica.com:444/eligibility' },
    { title: 'Eligibility script', url: 'javascript:alert(1)' },
    { title: 'Current page duplicate eligibility', url: `${source.url}#terms` },
  ];
  const { research } = setup({ store, sourceFetch: async row => { calls.push(row.url); return { text: 'Official museum visitor information with eligibility terms available at the linked source.', ...(row.id === source.id ? { links } : {}) }; } });
  const read = await research.readSource(source.id);
  assert.equal(calls.length, 1); assert.equal(read.relatedSources.length, 6);
  assert.equal(read.relatedSources[0].url, 'https://about.bankofamerica.com/en/making-an-impact/arts-and-culture');
  assert.ok(read.relatedSources.every(row => new URL(row.url).origin === 'https://about.bankofamerica.com'));
  assert.ok(read.relatedSources.every(row => store.sources.get(row.id).verification === 'catalog' && !store.sources.get(row.id).text));
  assert.deepEqual((await research.readSource(source.id)).relatedSources, read.relatedSources); assert.equal(calls.length, 1);
  assert.equal((await research.readSource(read.relatedSources[0].id)).verification, 'page-read');
  assert.equal((await research.readSource(read.relatedSources[1].id)).verification, 'page-read');
  assert.match((await research.readSource(read.relatedSources[2].id)).error, /limit/i); assert.equal(calls.length, 3);
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
