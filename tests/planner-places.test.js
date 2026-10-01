const test = require('node:test');
const assert = require('node:assert/strict');
const { recommend, loadPlannerCatalog } = require('../lib/planner');
const { searchScore } = require('../lib/plannerSearch');
const now = () => Date.parse('2026-09-29T19:00:00Z');
const date = '2026-10-03';
const hours = { sourceUrl: 'https://official.org/hours', verifiedAt: '2026-09-29', dates: { [date]: [{ open: '10:00', close: '20:00' }] } };
const place = (id, patch = {}) => ({ id, title: id, region: 'sf', city: 'San Francisco', category: 'attraction', cost: 'free', summary: 'Local museum', planning: { admissionUsd: 0, schedule: hours }, ...patch });
const event = { id: 'festival', title: 'Music festival', city: 'San Francisco', region: 'sf', category: 'culture', cost: 'free', startDate: date, endDate: date, occurrenceDates: [date] };
const catalog = (places) => ({ version: 1, checkedAt: '2026-09-29', events: [event], places, guides: [] });
const request = (places, body = {}, extra = {}) => recommend({ body: { filters: { date }, ...body }, catalog: catalog(places), now, ...extra });

test('explicit restaurants, cafes and new stores become real place anchors without unrelated events', async () => {
  const places = [place('opening-restaurant', { category: 'restaurant', summary: 'New dining', cost: 'unknown', planning: {} }), place('coffee', { category: 'cafe' }), place('retail', { category: 'shop' }), place('museum')];
  for (const [message, expected] of [['推荐餐厅', ['opening-restaurant']], ['coffee shops', ['coffee']], ['购物商店', ['retail']], ['新店', ['opening-restaurant']]]) {
    const result = await request(places, { message });
    assert.deepEqual(result.suggestions, []);
    assert.deepEqual(result.placeSuggestions.map(row => row.placeId), expected, message);
    assert.ok(result.placeSuggestions.every(row => row.date === date && row.id.startsWith('place-plan-')));
  }
});
test('old event suggestions preserve their schema while place references are separate', async () => {
  const result = await request([place('museum')]);
  assert.equal(result.suggestions[0].eventId, 'festival');
  assert.ok(Array.isArray(result.suggestions[0].placeIds));
  assert.equal(result.placeSuggestions[0].placeId, 'museum');
  assert.equal('eventId' in result.placeSuggestions[0], false);
});
test('real named venues support apostrophes, accents and venue-only city inference', async () => {
  const published = loadPlannerCatalog();
  const result = await recommend({ body: { message: "Gott's Roadside", filters: { date } }, catalog: published, now });
  assert.deepEqual(result.suggestions, []);
  assert.deepEqual(result.placeSuggestions.map(row => row.placeId), ['restaurant-gotts-ferry-building']);
  assert.equal(result.placeSuggestions[0].budgetStatus, 'unknown');
  assert.match(result.placeSuggestions[0].unknowns.join(' '), /餐饮或购物/);
  const sj = await request([place('venue', { title: 'San José Museum of Art', city: 'San Jose', region: 'south-bay' })], { message: 'San José museum', filters: { date } });
  assert.equal(sj.filters.city, 'San Jose'); assert.equal(sj.filters.region, 'south-bay');
  assert.equal(sj.placeSuggestions[0].placeId, 'venue');
});
test('generic dining prioritizes usable time and venue evidence without replacing named or new-store requests', async () => {
  const published = loadPlannerCatalog();
  const result = await recommend({ body: { message: '10月3日旧金山找家餐厅，再去附近逛逛', filters: { date } }, catalog: published, now });
  assert.equal(result.placeSuggestions[0].placeId, 'restaurant-gotts-ferry-building');
  assert.ok(result.placeSuggestions.length > 1, 'unknown-hour alternatives remain available');
  const named = await recommend({ body: { message: 'Kaiyo 餐厅', filters: { date } }, catalog: published, now });
  assert.ok(named.placeSuggestions.length > 0);
  assert.ok(named.placeSuggestions.every(row => /kaiyo/.test(row.placeId)));
  const opening = await recommend({ body: { message: '旧金山新店餐厅', filters: { date } }, catalog: published, now });
  assert.ok(opening.placeSuggestions.length > 0);
  assert.ok(opening.placeSuggestions.every(row => row.placeId.startsWith('opening-')));
});
test('named-place and category exclusions cannot be reversed by AI ranking', async () => {
  const places = [place('museum'), place('gotts', { title: 'Gotts Roadside', category: 'restaurant' }), place('delage', { title: 'Delage', category: 'restaurant' })];
  const excluded = await request(places, { message: 'restaurants, avoid Gotts' }, { ai: async () => ({ rankedPlaceIds: ['gotts', 'invented', 'delage'], rankedEventIds: ['festival'] }) });
  assert.deepEqual(excluded.suggestions, []);
  assert.deepEqual(excluded.placeSuggestions.map(row => row.placeId), ['delage']);
  const cafe = await request([...places, place('cafe', { category: 'cafe' })], { message: 'coffee，不要餐厅' });
  assert.deepEqual(cafe.placeSuggestions.map(row => row.placeId), ['cafe']);
});
test('known opening dates and current closed-day evidence exclude places; stale or absent hours stay honest', async () => {
  const places = [place('closed', { planning: { schedule: { ...hours, dates: { [date]: [] } } } }), place('announced', { openingStatus: 'announced' }), place('future', { openedOn: '2026-10-04' }),
    place('stale', { planning: { schedule: { ...hours, verifiedAt: '2026-01-01', dates: { [date]: [] } } } }), place('unknown', { planning: {} })];
  const result = await request(places);
  assert.deepEqual(result.placeSuggestions.map(row => row.placeId).sort(), ['stale', 'unknown']);
  assert.ok(result.placeSuggestions.every(row => row.unknowns.some(note => /时段未核实/.test(note))));
});

test('optional nearby stops respect the event day, closures and opening dates before entering a plan', async () => {
  const location = { lat: 37.78, lng: -122.42, precision: 'venue' };
  const main = { ...event, location };
  for (const patch of [
    { planning: { admissionUsd: 0, schedule: { ...hours, dates: { [date]: [] } } } },
    { openingStatus: 'announced' },
    { openedOn: '2026-10-04' },
  ]) {
    const candidate = place('nearby', { location, ...patch });
    // No selected date: the anchor's next occurrence, not today's date, is authoritative.
    const result = await recommend({ body: {}, catalog: { ...catalog([candidate]), events: [main] }, now });
    assert.equal(result.suggestions[0].date, date);
    assert.deepEqual(result.suggestions[0].placeIds, []);
  }
  const unknown = place('unknown', { location, planning: { admissionUsd: 0 } });
  const result = await recommend({ body: {}, catalog: { ...catalog([unknown]), events: [main] }, now });
  assert.deepEqual(result.suggestions[0].placeIds, ['unknown'], 'unknown hours remain explicitly unverified options');
  assert.match(result.suggestions[0].unknowns.join(' '), /开放日.*另查/);
});

test('optional nearby stops never reintroduce replaced IDs or explicitly excluded places and categories', async () => {
  const location = { lat: 37.78, lng: -122.42, precision: 'venue' };
  const main = { ...event, location };
  const candidate = place('nearby', { title: 'Crescent Museum', location });
  for (const body of [
    { excludePlaceIds: ['nearby'] },
    { message: '音乐活动，不去 Crescent' },
    { message: '音乐活动，不要博物馆' },
  ]) {
    const result = await recommend({ body, catalog: { ...catalog([candidate]), events: [main] }, now });
    assert.equal(result.suggestions.length, 1);
    assert.deepEqual(result.suggestions[0].placeIds, [], JSON.stringify(body));
  }
});
test('region, setting, all child ages, group admission caps and free-only remain hard constraints', async () => {
  const places = [place('valid', { planning: { setting: 'indoor', admissionUsd: 10 } }), place('wrong-city', { city: 'Oakland' }), place('age', { planning: { setting: 'indoor', admissionUsd: 0, maxAge: 10 } }), place('over', { planning: { setting: 'indoor', admissionUsd: 30 } }), place('adult', { planning: { setting: 'indoor', minAge: 18 } })];
  const filters = { date, city: 'San Francisco', setting: 'indoor', childAges: [5, 12], partySize: 4, budgetScope: 'total', budget: 80 };
  const result = await request(places, { filters });
  assert.deepEqual(result.filters.childAges, [5, 12]);
  assert.deepEqual(result.placeSuggestions.map(row => row.placeId), ['valid']);
  const free = await request([place('unknown', { cost: 'unknown', planning: {} }), place('paid', { cost: 'paid', planning: { admissionUsd: 10 } }), place('free')], { filters: { date, freeOnly: true } });
  assert.deepEqual(free.placeSuggestions.map(row => row.placeId), ['free']);
});
test('both admission budget scopes retain unknown-price anchors as unverified alternatives', async () => {
  const places = [place('unknown-museum', { cost: 'unknown', planning: { schedule: hours } }), place('over-budget', { cost: 'paid', planning: { admissionUsd: 100, schedule: hours } })];
  for (const budgetScope of ['person', 'total']) {
    const result = await request(places, { message: '推荐景点', filters: { date, budget: 20, budgetScope, partySize: 4 } });
    assert.deepEqual(result.placeSuggestions.map(row => row.placeId), ['unknown-museum']);
    assert.equal(result.placeSuggestions[0].budgetStatus, 'unknown');
    assert.ok(result.placeSuggestions[0].unknowns.some(note => /入场金额尚未确认/.test(note)));
    assert.equal(result.filters.budgetScope, budgetScope);
  }
  assert.deepEqual((await request(places, { message: '推荐景点', filters: { date, budget: 20, freeOnly: true } })).placeSuggestions, []);
});
test('AI place ordering can use only filtered and actually supplied IDs', async () => {
  let payload;
  const places = Array.from({ length: 100 }, (_, i) => place(`place-${String(i).padStart(3, '0')}`));
  const result = await request(places, { message: 'find local places', excludePlaceIds: ['place-000'] }, { ai: async input => { payload = input; return { rankedPlaceIds: ['fake', 'place-000', 'place-099', 'place-002', 'place-001'] }; } });
  assert.equal(payload.places.length, 80);
  assert.equal(payload.places.some(row => row.id === 'place-000'), false);
  assert.deepEqual(result.placeSuggestions.slice(0, 2).map(row => row.placeId), ['place-002', 'place-001']);
  assert.equal(result.placeSuggestions.some(row => ['fake', 'place-000', 'place-099'].includes(row.placeId)), false);
});
test('search scores reflect title and summary terms and malformed excluded IDs fail before AI', async () => {
  assert.ok(searchScore('quiet waterfront', place('a', { summary: 'Quiet waterfront seating' })) > searchScore('quiet waterfront', place('b')));
  for (const excludePlaceIds of [null, {}, [{ $ne: '' }], Array(101).fill('id'), ['bad/id']]) {
    await assert.rejects(request([], { excludePlaceIds }, { ai: () => assert.fail('must not call AI') }), error => error.status === 400);
  }
});
