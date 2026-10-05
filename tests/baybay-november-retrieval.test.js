const test = require('node:test');
const assert = require('node:assert/strict');
const { buildSiteEvidence } = require('../lib/baybayEvidence');
const guideCatalog = require('../data/guide-catalog.json');
const catalog = require('../data/planner-catalog.json');
const today = '2026-10-05';
const sfFamily = { goal: 'information', city: 'San Francisco', region: 'sf', date: '2026-11-07', childAges: [5] };
const search = (query, state, overrides = {}) => buildSiteEvidence({ query, originalQuery: query, state, guideCatalog, catalog, today, ...overrides });

test('the audited November family discovery and negative followup retain the actual free daytime program', () => {
  for (const query of [
    '11月7号那个周末想带5岁娃去旧金山晃晃，有什么不买东西也能参加的？别给我十月份过期的。',
    '别给晚上的，也不要必须先买东西的。白天挑两三个就好，不用排整天行程。',
  ]) {
    const result = search(query, sfFamily);
    const festival = result.candidates.find(row => row.id === 'nov2026-presidio-dia-muertos-diwali');
    assert.ok(festival, query);
    assert.equal(festival.cost, 'mixed');
    assert.equal(festival.planning.admissionUsd, 0);
    assert.match(festival.costLabel, /停车另付/);
    assert.equal(festival.planning.minAge, 0);
    assert.deepEqual(festival.planning.schedule.dates['2026-11-07'], [{ open: '12:00', close: '15:00' }]);
    assert.equal(festival.planning.reservation, 'unknown');
    assert.equal(festival.officialUrl, 'https://presidio.gov/explore/events/dia-de-los-muertos-and-diwali-festival');
    assert.equal(festival.verifiedLive, false);
    assert.ok(result.candidates.filter(row => row.kind === 'event').every(row => row.catalogDateMatch));
    assert.ok(result.candidates.length <= 6 && result.guides.length <= 8);
  }
});

test('public free admission with separately paid parking survives free-only, but eligibility and purchase gates do not', () => {
  const makeEvent = (id, overrides = {}) => ({ id, title: 'Community celebration', kind: 'event', city: 'San Francisco', region: 'sf', startDate: '2026-11-07', endDate: '2026-11-07', cost: 'mixed', costLabel: 'Free public admission; parking and food sold separately.', summary: 'A public cultural program.', officialUrl: `https://example.org/events/${id}`, planning: { admissionUsd: 0 }, ...overrides });
  const fixture = { version: 1, checkedAt: today, places: [], guides: [], events: [
    makeEvent('public', { plan: ['活动免门票，无需购买任何东西。'] }),
    makeEvent('purchase', { costLabel: '活动免费；需购买指定商品才能参加。' }),
    makeEvent('members', { costLabel: 'Free admission for members; other visitors pay $20.' }),
    makeEvent('members-only', { costLabel: 'Free public admission; members only.' }),
    makeEvent('structured-eligibility', { planning: { admissionUsd: 0, admissionEligibility: 'cardholder' } }),
    makeEvent('children', { costLabel: 'Free for children; adults pay $20.' }),
    makeEvent('gift', { costLabel: 'Free gift; admission conditions not published.' }),
    makeEvent('unpriced', { planning: {} }),
    makeEvent('wrong-day', { startDate: '2026-11-08', endDate: '2026-11-08' }),
    makeEvent('wrong-city', { city: 'Oakland', region: 'east-bay' }),
    makeEvent('older-children', { planning: { admissionUsd: 0, minAge: 8 } }),
  ] };
  const result = search('这周末有什么活动可以参加？', { ...sfFamily, freeOnly: true }, { catalog: fixture, guideCatalog: [] });
  assert.deepEqual(result.candidates.map(row => row.id), ['public']);
  const topicQuestion = search('How do I open a utility account?', { ...sfFamily, childAges: [] }, { catalog: fixture, guideCatalog: [] });
  assert.deepEqual(topicQuestion.candidates, []);
});

test('a brand correction retrieves the named product terms while preserving their actual date and retained user state', () => {
  const state = { goal: 'information', date: '2026-11-14', childAges: [5] };
  const original = JSON.stringify(state);
  for (const query of [
    '那Target那个毛绒包呢？我不买东西能拿吗？别把Lowe’s规则套过去。',
    '那Target那個毛絨包呢？我不買東西能拿嗎？別把Lowe’s規則套過來。',
    "What about Target's fuzzy pouch? Can I get it without buying anything? Don't apply Lowe's rules.",
  ]) {
    const result = search(query, state);
    const eos = result.guides.find(row => /TARGET · eos/.test(row.text));
    assert.ok(eos, query);
    assert.match(eos.text, /10\/10/);
    assert.match(eos.text, /12:00–16:00/);
    assert.match(eos.text, /需购买 eos/);
    assert.match(eos.text, /16 岁及以上/);
    assert.match(eos.text, /参与门店|官方名单/);
    assert.match(eos.text, /送完为止/);
    assert.ok(eos.sourceUrls.some(row => row.url === 'https://www.target.com/c/eos-fall-scents-demo-event/-/N-s0gmo'));
    assert.equal(eos.verifiedLive, false);
    assert.ok(result.guides.length <= 8);
    assert.equal(JSON.stringify(state), original, 'retrieval must not silently change November 14 into October 10');
  }
});
