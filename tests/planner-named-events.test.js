const test = require('node:test');
const assert = require('node:assert/strict');
const { recommend } = require('../lib/planner');
const { recognizeNamedEvent } = require('../lib/namedEventSearch');

const id = 'foster-city-water-lantern-festival-2026';
const lantern = { id, title: 'San Francisco 水灯节：Foster City 湖畔两晚', region: 'peninsula', city: 'Foster City',
  startDate: '2026-10-03', endDate: '2026-10-04', occurrenceDates: ['2026-10-03', '2026-10-04'],
  cost: 'mixed', category: 'family', summary: 'San Francisco Water Lantern Festival in Foster City',
  planning: { admissionUsd: null, setting: 'outdoor' } };
const sf = { id: 'other-sf-event', title: 'Unrelated San Francisco community activity', region: 'sf', city: 'San Francisco',
  startDate: '2026-09-30', endDate: '2026-10-05', cost: 'free', category: 'culture', planning: { admissionUsd: 0 } };
const catalog = events => ({ version: 1, checkedAt: '2026-09-29', events, places: [], guides: [] });
const run = (message, filters = {}, events = [lantern, sf], extra = {}) => recommend({
  body: { message, filters: { date: '2026-10-03', ...filters }, ...extra }, catalog: catalog(events),
  now: () => Date.parse('2026-09-29T19:00:00Z'), isTest: true,
});

test('known water lantern aliases return only the canonical Foster City event, including mixed city and official name', async () => {
  for (const name of ['水灯节', '水燈節', 'SF水灯节', 'SF 水灯节', 'SF的水灯节', 'SF 的水灯节', '旧金山的水灯节', '舊金山的水燈節', 'sf  水燈節', 'San Francisco Water Lantern Festival', 'SAN  FRANCISCO  WATER LANTERN FESTIVAL', 'San Francisco 水灯节', 'Foster City 水灯节', 'Foster City San Francisco Water Lantern Festival']) {
    const result = await run(name);
    assert.equal(result.responseMode, 'rules');
    assert.deepEqual(result.suggestions.map(row => row.eventId), [id], name);
    assert.notEqual(result.filters.city, 'San Francisco', name);
    assert.notEqual(result.filters.region, 'sf', name);
  }
});

test('named events remain subject to separate destination, exclusion, date, free-only, budget and age constraints', async () => {
  for (const message of ['在旧金山找水灯节', '仅限SF水灯节', '仅限SF的水灯节', '水灯节 排除半岛', '水灯节 不要去半岛', 'Water Lantern Festival outside the peninsula', '不要水灯节']) {
    assert.deepEqual((await run(message)).suggestions, [], message);
  }
  for (const filters of [{ city: 'San Francisco' }, { region: 'sf' }, { date: '2026-10-05' }, { freeOnly: true }, { setting: 'indoor' }]) {
    assert.deepEqual((await run('San Francisco Water Lantern Festival', filters)).suggestions, [], JSON.stringify(filters));
  }
  assert.deepEqual((await run('免费 SF水灯节')).suggestions, []);
  assert.deepEqual((await run('水灯节', { budget: 30 }, [{ ...lantern, planning: { ...lantern.planning, admissionUsd: 50 } }, sf])).suggestions, []);
  assert.deepEqual((await run('水灯节', { childAge: 5 }, [{ ...lantern, planning: { ...lantern.planning, minAge: 18 } }, sf])).suggestions, []);
  assert.deepEqual((await run('水灯节', {}, [lantern, sf], { excludeEventIds: [id] })).suggestions, []);
});

test('ordinary SF questions stay in SF and a missing canonical event cannot produce unrelated replacements', async () => {
  for (const message of ['SF明天有什么', 'water', 'water festival', 'San Francisco festival']) assert.deepEqual(recognizeNamedEvent(message).eventIds, [], message);
  const tomorrow = await run('SF明天有什么', { date: '2026-09-30' });
  assert.equal(tomorrow.filters.city, 'San Francisco');
  assert.equal(tomorrow.filters.region, 'sf');
  assert.deepEqual(tomorrow.suggestions.map(row => row.eventId), [sf.id]);
  assert.deepEqual((await run('SF水灯节', {}, [sf])).suggestions, []);
});

test('AI cannot restore the official-name city or rank unrelated alternatives over the verified event', async () => {
  for (const message of ['San Francisco Water Lantern Festival', 'Foster City San Francisco Water Lantern Festival']) {
    let calls = 0;
    const result = await recommend({
      body: { message, filters: { date: '2026-10-03' } }, catalog: catalog([lantern, sf]),
      now: () => Date.parse('2026-09-29T19:00:00Z'), isTest: true,
      ai: async payload => {
        calls += 1;
        assert.deepEqual(payload.events.map(event => event.id), [id]);
        return { filters: { city: 'San Francisco', region: 'sf' }, rankedEventIds: [sf.id, id] };
      },
    });
    assert.equal(calls, 1);
    assert.equal(result.responseMode, 'ai');
    assert.deepEqual(result.suggestions.map(row => row.eventId), [id]);
    assert.notEqual(result.filters.city, 'San Francisco');
    assert.notEqual(result.filters.region, 'sf');
  }
});
