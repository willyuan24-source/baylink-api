const test = require('node:test');
const assert = require('node:assert/strict');
const { selectConversationGuides, guideSourceExcerpt } = require('../lib/guideConversation');
const { recommend } = require('../lib/planner');
const { buildSiteEvidence } = require('../lib/baybayEvidence');
const { resolveTaskState } = require('../lib/baybayState');
const zh = require('../data/guide-catalog.json');
const en = require('../data/guide-catalog.en.json');
const plannerCatalog = require('../data/planner-catalog.json');
const northSlug = 'north-bay-markets-nature-culture-through-november-15-2026';

for (const [catalog, query, required] of [
  [zh, '11月13日Sips and Stars带5岁孩子能去吗', ['Sips and Stars', '仅21岁以上', '不能拿来替代亲子观星场']],
  [en, 'Is the Eames exhibition at the museum in Yountville on November 8?', ['Eames & Eames', '607 St Helena Highway', 'not the Yountville museum']],
]) {
  test(`published named-event retrieval preserves its eligibility or correct campus: ${query}`, () => {
    const selected = selectConversationGuides(catalog, query, 'other', '/', [], '2026-10-05');
    const guide = selected.find(row => row.slug === northSlug);
    assert.ok(guide, 'A named event in a short regional guide must not be displaced by generic family or museum words in long benefits guides.');
    const excerpt = guideSourceExcerpt(guide, query);
    assert.ok(excerpt.length <= 9000);
    for (const fact of required) assert.ok(excerpt.includes(fact), `Missing ${fact}`);
  });
  test(`v2 actual paragraph evidence retains complete named-event conditions: ${query}`, () => {
    const { state } = resolveTaskState({ message: query, today: '2026-10-05', catalog: plannerCatalog });
    const result = buildSiteEvidence({ query, originalQuery: query, state, guideCatalog: catalog, catalog: plannerCatalog, today: '2026-10-05' });
    assert.ok(result.guides.some(guide => required.every(fact => guide.text.includes(fact))), 'The whole restriction or address correction must reach v2 in one evidence paragraph.');
    if (query.includes('Sips')) assert.ok(!result.candidates.some(row => row.id === 'november-north-sips-stars-2026'));
  });
}

test('a short event-name-only request remains discoverable without generic filler words', () => {
  assert.equal(selectConversationGuides(zh, 'Sips and Stars', 'other', '/', [], '2026-10-05')[0]?.slug, northSlug);
});

test('November workshop retrieval keeps booking, child age and registration conditions together', () => {
  const query = '朋友说Lowe’s十一月有免费小火车，5岁能做吗？我是不是11月14号直接去就行？';
  const selected = selectConversationGuides(zh, query, 'other', '/', [], '2026-10-05');
  const excerpts = selected.map(guide => guideSourceExcerpt(guide, query));
  assert.ok(excerpts.some(text => ['Holiday Engine', '11/14', 'Kids Profile', '4–11', '提前预约'].every(fact => text.includes(fact))));
});

test('published Sips and Stars cannot become a five-year-old family recommendation', async () => {
  const event = plannerCatalog.events.find(row => row.id === 'november-north-sips-stars-2026');
  assert.ok(event);
  const excludeEventIds = plannerCatalog.events.filter(row => row.region === event.region && row.id !== event.id).map(row => row.id);
  const request = childAge => recommend({
    body: { filters: { date: '2026-11-13', region: event.region, ...(childAge === undefined ? {} : { childAge }) }, excludeEventIds },
    catalog: plannerCatalog, now: () => Date.parse('2026-10-05T19:00:00Z'), isTest: true,
  });
  assert.deepEqual((await request(5)).suggestions, [], 'No invented substitute or adult-only event for the child.');
  assert.deepEqual((await request()).suggestions.map(row => row.eventId), [event.id], 'The actual adult event remains discoverable.');
});
