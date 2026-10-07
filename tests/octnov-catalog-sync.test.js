const test = require('node:test');
const assert = require('node:assert/strict');
const { loadPlannerCatalog, eventOccursOn, recommend } = require('../lib/planner');
const { loadEventCatalog } = require('../lib/eventEngagement');
const { loadOutingCatalog } = require('../lib/outings');
const { loadDiscoveryCatalog, createPublicContext } = require('../lib/publicContext');

// Use production's default file loaders. No provider, network, account or database writes.
const planner = loadPlannerCatalog();
const events = loadEventCatalog();
const outings = loadOutingCatalog();
const guides = require('../data/guide-catalog.json');
const guidesEn = require('../data/guide-catalog.en.json');
const registry = require('../data/source-registry.json');
const sfEastIds = [
  'foodwise-market-memories-demo', 'arion-press-public-tours', 'sf-renegade-craft-winter',
  'fort-mason-farmers-market', 'presidio-free-yoga', 'presidio-250-years-walk',
  'fort-point-history-talks', 'presidio-campfire-history-talks', 'redwood-green-friday-hike',
  'redwood-saturday-stroll', 'tilden-good-night-farm', 'big-break-accessible-winter-birding',
  'coyote-hills-tule-work-play', 'ardenwood-chestnut-treats', 'crab-cove-bay-bird-morning',
].map(id => `nov2026-${id}`);
const regionalSentinels = ['octnov-midpen-return-to-green-2026', 'octnov-san-jose-tommy-2026', 'octnov-point-reyes-open-studios-2026'];
const freshEvent = id => {
  assert.ok(planner, 'Production planner catalog must load');
  const event = planner.events.find(row => row.id === id);
  assert.ok(event, `Final October/November export is missing ${id}`);
  return event;
};
const canonical = value => { const url = new URL(value); url.hash = ''; return url.href; };

test('runtime event, outing and planner loaders read the same published IDs and occurrence dates', () => {
  assert.ok(events && outings && planner);
  const ids = planner.events.map(row => row.id).sort();
  assert.deepEqual([...events.keys()].sort(), ids);
  assert.deepEqual([...outings.keys()].sort(), ids);
  for (const row of planner.events) {
    assert.deepEqual(events.get(row.id), { id: row.id, startDate: row.startDate, endDate: row.endDate });
    assert.deepEqual(outings.get(row.id).occurrenceDates, row.occurrenceDates, row.id);
    assert.equal(outings.get(row.id).officialUrl, row.officialUrl, row.id);
  }
});

test('new event dates survive all catalogs without turning series gaps or multiple sessions into extra dates', () => {
  for (const id of [...sfEastIds, ...regionalSentinels]) {
    const row = freshEvent(id);
    assert.ok(events.has(id) && outings.has(id), id);
    assert.ok(Array.isArray(row.occurrenceDates) && row.occurrenceDates.length > 0, id);
    assert.deepEqual(row.occurrenceDates, [...new Set(row.occurrenceDates)].sort(), id);
    assert.equal(row.startDate, row.occurrenceDates[0], id);
    assert.equal(row.endDate, row.occurrenceDates.at(-1), id);
    for (const date of row.occurrenceDates) assert.ok(date >= '2026-10-07' && date <= '2026-11-30', id);
  }
  assert.equal(sfEastIds.reduce((count, id) => count + freshEvent(id).occurrenceDates.length, 0), 46);
  const arion = freshEvent('nov2026-arion-press-public-tours');
  assert.equal(eventOccursOn(arion, '2026-11-12'), true);
  assert.equal(eventOccursOn(arion, '2026-11-13'), false);
  const yoga = freshEvent('nov2026-presidio-free-yoga');
  assert.equal(eventOccursOn(yoga, '2026-11-22'), true);
  assert.equal(eventOccursOn(yoga, '2026-11-29'), false);
  const fort = freshEvent('nov2026-fort-point-history-talks');
  assert.equal(fort.occurrenceDates.length, 6);
  assert.equal(fort.planning.schedule.sessions.length, 18);
  assert.deepEqual(fort.planning.schedule.sessions.filter(row => row.date === '2026-11-29').map(row => [row.start, row.end]),
    [['11:30', '11:45'], ['13:30', '13:45'], ['14:30', '14:45']]);
});

test('new schedules only contain published dates and required bookings reach recommendation reasons', async () => {
  for (const id of sfEastIds) {
    const row = freshEvent(id);
    const schedule = row.planning?.schedule;
    assert.ok(schedule, id);
    assert.deepEqual(Object.keys(schedule.dates).sort(), row.occurrenceDates, id);
    for (const session of schedule.sessions || []) {
      assert.ok(row.occurrenceDates.includes(session.date), id);
      assert.ok(schedule.dates[session.date].some(window => window.open <= session.start && session.end <= window.close), id);
    }
  }
  for (const id of ['nov2026-arion-press-public-tours', 'nov2026-presidio-free-yoga', 'nov2026-crab-cove-bay-bird-morning']) {
    const row = freshEvent(id);
    assert.equal(row.planning.reservation, 'required', id);
    // Narrow to the real loaded row so unrelated ranking changes cannot hide an admission regression.
    const result = await recommend({ body: { filters: { date: row.startDate } }, catalog: { ...planner, events: [row], places: [] },
      now: () => Date.parse('2026-10-07T19:00:00Z'), isTest: true });
    assert.deepEqual(result.suggestions.map(item => item.eventId), [id]);
    assert.ok(result.suggestions[0].reasons.some(reason => reason.includes('预约或购票')), id);
  }
  assert.equal(freshEvent('nov2026-ardenwood-chestnut-treats').planning.admissionUsd, null,
    'Different Nov22 and Green Friday gate fees must not become one free admission claim');
});

test('Crab Cove six-year minimum excludes younger children with the real loaded catalog row', async () => {
  const row = freshEvent('nov2026-crab-cove-bay-bird-morning');
  assert.equal(row.planning.minAge, 6);
  const request = childAge => recommend({ body: { filters: { date: '2026-11-22', childAge } },
    catalog: { ...planner, events: [row], places: [] }, now: () => Date.parse('2026-10-07T19:00:00Z'), isTest: true });
  assert.deepEqual((await request(5)).suggestions, []);
  assert.deepEqual((await request(6)).suggestions.map(item => item.eventId), [row.id]);
});

test('default discovery loader and public context use refreshed discoveries filenames in both languages', () => {
  for (const english of [false, true]) {
    const loaded = loadDiscoveryCatalog(undefined, english);
    assert.strictEqual(loaded, require(`../data/discoveries${english ? '.en' : ''}.json`));
    const selected = loaded.items.find(row => row.kind === 'opening' && row.id === 'old-post-office-burlingame');
    assert.ok(selected, 'Updating only discovery-context.json leaves the preferred runtime file stale');
    const result = createPublicContext().resolve({ currentPath: '/openings/old-post-office-burlingame',
      today: '2026-10-07', locale: english ? 'en' : 'zh-Hans' }).contextReferences;
    assert.equal(result.length, 1);
    assert.equal(result[0].title, selected.title);
    assert.equal(result[0].summary, selected.summary);
    if (english) assert.doesNotMatch(`${result[0].title} ${result[0].summary}`, /\p{Script=Han}/u);
  }
});

test('refreshed bilingual guides and discoveries retain identical identity sets and public guide context', () => {
  assert.deepEqual(guides.map(row => row.slug).sort(), guidesEn.map(row => row.slug).sort());
  const key = row => `${row.kind}:${row.id}`;
  assert.deepEqual(loadDiscoveryCatalog().items.map(key).sort(), loadDiscoveryCatalog(undefined, true).items.map(key).sort());
  for (const slug of ['sf-autumn-art-half-day-2026', 'east-bay-redwoods-green-friday-2026', 'half-moon-bay-autumn-coast-2026',
    'alviso-autumn-wetlands-2026', 'sonoma-autumn-art-plaza-2026']) assert.ok(guides.some(row => row.slug === slug), slug);
  const slug = 'east-bay-redwoods-green-friday-2026';
  const result = createPublicContext({ guideCatalog: guides, englishGuideCatalog: guidesEn }).resolve({
    currentPath: `/guides/${slug}`, today: '2026-10-07', locale: 'en',
  }).contextReferences;
  assert.equal(result[0]?.title, guidesEn.find(row => row.slug === slug)?.title);
  assert.ok(result[0]?.title);
});

test('every new event and refreshed discovery has its own official source association without claiming a fresh review', () => {
  for (const id of [...sfEastIds, ...regionalSentinels]) freshEvent(id);
  const newEvents = planner.events.filter(row => /^(?:nov2026-|octnov-)/.test(row.id));
  const newDiscoveries = loadDiscoveryCatalog().items.filter(row => ['old-post-office-burlingame', 'shinka-the-jay-announced',
    'flora-santana-row-announced', 'excelsior-san-rafael-announced', 'east-bay-green-friday-nov27-2026',
    'yogurtland-anniversary-nov20-2026', 'botanical-thanksgiving-nov26-2026'].includes(row.id));
  assert.equal(newDiscoveries.length, 7);
  for (const row of [...newEvents, ...newDiscoveries]) {
    const url = canonical(row.officialUrl || row.sourceUrl);
    assert.ok(registry.some(source => canonical(source.url) === url && source.contentIds.includes(row.id)), `${row.id}: ${url}`);
  }
  for (const source of registry) assert.equal(source.verifiedAt, undefined, source.id);
});
