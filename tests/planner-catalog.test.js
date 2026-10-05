const test = require('node:test');
const assert = require('node:assert/strict');
const { loadPlannerCatalog, recommend, distanceKm, priceOf, REGIONS } = require('../lib/planner');
const { MAX_EVENT_IDS_PER_REQUEST } = require('../lib/eventEngagement');

// This smoke test exercises the same exported, published catalog production loads.
// It is intentionally deterministic: no AI provider, network or account/database writes.
const catalog = loadPlannerCatalog();
const checkedCatalog = () => {
  assert.ok(catalog, 'Export the frontend rich catalog to data/planner-catalog.json before running deployment checks.');
  return catalog;
};
const request = body => {
  const current = checkedCatalog();
  return recommend({ body, catalog: current, now: () => Date.parse(`${current.checkedAt}T19:00:00Z`), isTest: true });
};

test('published catalog defaults return three future suggestions with canonical dates and IDs', async t => {
  const response = await request({});
  assert.equal(response.responseMode, 'rules');
  assert.equal(response.suggestions.length, 3);
  assert.equal(new Set(response.suggestions.map(row => row.eventId)).size, 3);
  for (const suggestion of response.suggestions) {
    const event = catalog.events.find(row => row.id === suggestion.eventId);
    assert.ok(event);
    assert.ok(suggestion.date >= catalog.checkedAt && suggestion.date >= event.startDate && suggestion.date <= event.endDate);
  }
  t.diagnostic(response.suggestions.map(row => `${row.eventId} (${row.date})`).join(', '));
});

test('published Fremont departure request respects Chinese language without inventing a destination restriction', async t => {
  const response = await request({ message: '这周六从 Fremont 出发，带五岁孩子，预算40美元', filters: { region: 'all', setting: 'any', travelMode: 'any' } });
  assert.equal(response.filters.region, 'all');
  assert.equal(response.filters.city, undefined);
  assert.equal(response.filters.childAge, 5);
  assert.equal(response.filters.budget, 40);
  assert.equal(new Date(`${response.filters.date}T12:00:00Z`).getUTCDay(), 6);
  for (const suggestion of response.suggestions) {
    const event = catalog.events.find(row => row.id === suggestion.eventId);
    assert.ok(event.startDate <= response.filters.date && event.endDate >= response.filters.date);
    assert.match(suggestion.reason, /活动日期覆盖/);
    assert.ok(suggestion.unknowns.some(note => note.includes('儿童票')));
  }
  t.diagnostic(`${response.filters.date}: ${response.suggestions.length} verified catalog matches; empty means no invented alternatives.`);
});

test('live Fremont five-year-old regression returns Nemo alone and cannot be broadened by AI', async () => {
  // Preserve the date of this historical production regression. Advancing the
  // catalog verification date must not turn it into a past-date validation test.
  const historicalRequest = (body, ai) => recommend({ body, catalog: checkedCatalog(), now: () => Date.parse('2026-10-02T19:00:00Z'), isTest: true, ai });
  const body = { message: '10月2日在Fremont带五岁孩子，门票预算30美元', filters: { region: 'all', setting: 'any', travelMode: 'any' } };
  for (const ai of [undefined, async () => ({ filters: { region: 'east-bay', city: 'Oakland', childAge: null }, rankedEventIds: ['oakland-civic-ai-design-sprint-2026', 'fremont-finding-nemo-outdoor-movie-2026'] })]) {
    const response = await historicalRequest(body, ai);
    assert.equal(response.filters.city, 'Fremont');
    assert.equal(response.filters.childAge, 5);
    assert.deepEqual(response.suggestions.map(row => row.eventId), ['fremont-finding-nemo-outdoor-movie-2026']);
    assert.ok(response.notices.some(note => note.includes('只有 1 项')));
  }
  const eastBay = await historicalRequest({ message: '10月2日在东湾带五岁孩子' });
  assert.ok(eastBay.suggestions.some(row => row.eventId === 'fremont-finding-nemo-outdoor-movie-2026'));
  for (const suggestion of eastBay.suggestions) {
    const event = catalog.events.find(row => row.id === suggestion.eventId);
    assert.equal(event.region, 'east-bay');
    assert.equal(event.category, 'family', 'additional regional options retain explicit family evidence');
    assert.ok(!event.planning?.minAge || event.planning.minAge <= 5);
    assert.ok(!event.planning?.maxAge || event.planning.maxAge >= 5);
  }
  const oakland = await historicalRequest({ message: '10月2日在Oakland带五岁孩子' });
  assert.deepEqual(oakland.suggestions, []);
  const adult = await historicalRequest({ message: '10月2日在Oakland参加AI技术活动' });
  assert.ok(adult.suggestions.some(row => row.eventId === 'oakland-civic-ai-design-sprint-2026'));
});

test('published indoor recommendations use only explicitly confirmed settings', async t => {
  const response = await request({ message: '找室内活动', filters: { region: 'all', setting: 'any' } });
  assert.equal(response.filters.setting, 'indoor');
  assert.ok(response.suggestions.length > 0);
  for (const suggestion of response.suggestions) assert.equal(catalog.events.find(row => row.id === suggestion.eventId).planning?.setting, 'indoor');
  t.diagnostic(response.suggestions.map(row => row.eventId).join(', '));
});

test('published AWS Builder Loft event cannot be recommended to an underage group', async () => {
  const event = checkedCatalog().events.find(row => row.id === 'surrealdb-mastra-shared-memory-2026');
  assert.ok(event, 'The AWS-hosted event must be present for this admission regression check.');
  assert.equal(event.planning?.minAge, 18);
  const response = await request({ filters: { date: event.startDate, region: event.region, childAge: 17 } });
  assert.ok(!response.suggestions.some(row => row.eventId === event.id));
  const otherRegionalIds = catalog.events.filter(row => row.region === event.region && row.id !== event.id).map(row => row.id);
  assert.ok(otherRegionalIds.length <= MAX_EVENT_IDS_PER_REQUEST);
  const adults = await request({ filters: { date: event.startDate, region: event.region }, excludeEventIds: otherRegionalIds });
  assert.deepEqual(adults.suggestions.map(row => row.eventId), [event.id]);
});

test('excluding every published event in each selected region returns no substitute or excluded event', async () => {
  const current = checkedCatalog();
  for (const region of REGIONS) {
    const ids = current.events.filter(row => row.region === region).map(row => row.id);
    assert.ok(ids.length > 0 && ids.length <= MAX_EVENT_IDS_PER_REQUEST);
    assert.ok((await request({ filters: { region } })).suggestions.length > 0, `${region} has real candidates before exclusions`);
    const response = await request({ filters: { region }, excludeEventIds: ids });
    assert.deepEqual(response.suggestions, [], `${region} exclusions cannot introduce a substitute from another region`);
    assert.ok(response.notices.some(note => note.includes('暂无符合条件')));
  }
});

test('published unknown admission stays unknown rather than becoming a free or budget-confirmed recommendation', async () => {
  const current = checkedCatalog();
  const unknown = current.events.filter(row => row.cost === 'unknown');
  assert.ok(unknown.length > 0, 'the released catalog includes explicit unknown fees');
  for (const event of unknown) {
    assert.equal(event.planning?.admissionUsd, null, event.id);
    assert.equal(priceOf(event), null, event.id);
  }
  const target = unknown.find(row => row.startDate >= current.checkedAt && row.occurrenceDates === undefined);
  assert.ok(target);
  const excluded = current.events.filter(row => row.region === target.region && row.id !== target.id).map(row => row.id);
  assert.ok(excluded.length <= MAX_EVENT_IDS_PER_REQUEST);
  const response = await request({ filters: { date: target.startDate, region: target.region, budget: 0 }, excludeEventIds: excluded });
  assert.deepEqual(response.suggestions.map(row => row.eventId), [target.id]);
  assert.ok(response.suggestions[0].unknowns.some(note => note.includes('不能认定符合预算')));
  assert.ok(!response.suggestions[0].reasons.some(note => note.includes('免费入场')));
});

test('published nearby stops never invent coordinates or attach distant and approximate places', async () => {
  const current = checkedCatalog();
  const dates = [...new Set(current.events.map(row => row.startDate).filter(day => day >= current.checkedAt))];
  let withoutLocation = 0;
  for (const date of dates) {
    const response = await request({ filters: { date } });
    for (const suggestion of response.suggestions) {
      const event = current.events.find(row => row.id === suggestion.eventId);
      assert.ok(!('location' in suggestion), 'Only catalog references are returned, never invented coordinates.');
      if (!event.location) { withoutLocation++; assert.deepEqual(suggestion.placeIds, []); }
      for (const id of suggestion.placeIds) {
        const place = current.places.find(row => row.id === id);
        assert.ok(place);
        assert.equal(event.location?.precision, 'venue');
        assert.equal(place.location?.precision, 'venue');
        assert.equal(place.city.trim().toLowerCase(), event.city.trim().toLowerCase());
        assert.ok(distanceKm(event.location, place.location) <= 5);
      }
    }
  }
  assert.ok(withoutLocation > 0, 'Real unlocated catalog events exercise the no-invented-pin path.');
});
