const test = require('node:test');
const assert = require('node:assert/strict');
const { selectConversationGuides, groundedGuideFallback, guideEditionThroughDate, isGuideArchived } = require('../lib/guideConversation');
const { localizeGuidePayload } = require('../lib/guideLocale');
const { buildSiteEvidence } = require('../lib/baybayEvidence');
const zh = require('../data/guide-catalog.json');
const en = require('../data/guide-catalog.en.json');
const catalog = require('../data/planner-catalog.json');
const north = zh.find(guide => guide.slug === 'north-bay-markets-nature-culture-through-november-15-2026');

test('published half-month editions are searchable on November 15 and archived on November 16', () => {
  const dated = zh.filter(guide => guide.editionThroughDate === '2026-11-15');
  assert.ok(dated.length >= 8, 'All published first-half regional and benefits editions export their deadline.');
  for (const guide of dated) {
    assert.equal(isGuideArchived(guide, '2026-11-15'), false, guide.slug);
    assert.equal(isGuideArchived(guide, '2026-11-16'), true, guide.slug);
    const selected = selectConversationGuides([guide], guide.title, 'other', '/', [], '2026-11-15');
    assert.equal(selected[0]?.slug, guide.slug);
    assert.deepEqual(selectConversationGuides([guide], guide.title, 'other', '/', [], '2026-11-16'), []);
    assert.equal(en.find(row => row.slug === guide.slug)?.editionThroughDate, guide.editionThroughDate);
  }
});

test('v2 rechecks edition expiry per request even when its paragraph index is cached', () => {
  const request = (today, extra = {}) => buildSiteEvidence({ query: 'Sips and Stars', state: { goal: 'information' }, guideCatalog: zh, catalog, today, ...extra });
  const current = request('2026-11-15').guides.filter(guide => guide.slug === north.slug);
  assert.ok(current.length);
  assert.ok(current.every(guide => guide.archived === false));
  assert.ok(!request('2026-11-16').guides.some(guide => guide.slug === north.slug));
  assert.ok(!request('2026-11-16', { currentPath: north.url }).guides.some(guide => guide.slug === north.slug), 'A passive open tab does not make an expired guide current.');
  const archived = request('2026-11-16', { query: '总结这篇 Sips and Stars 攻略', currentPath: north.url }).guides.filter(guide => guide.slug === north.slug);
  assert.ok(archived.length, 'Explicit reading of the archived article remains possible.');
  assert.ok(archived.every(guide => guide.archived && guide.editionThroughDate === '2026-11-15'));
});

test('explicit legacy reading keeps an archive notice with its exact cutoff in Chinese and English', () => {
  const selected = selectConversationGuides(zh, '总结这篇 Sips and Stars 攻略', 'other', north.url, [], '2026-11-16');
  assert.equal(selected[0]?.slug, north.slug);
  assert.match(groundedGuideFallback(selected, '2026-11-16'), /2026-11-15 归档/);
  const payload = localizeGuidePayload({ responseMode: 'fallback' }, { locale: 'en', intent: 'leisure', category: 'other', readingRequest: true,
    selectedGuides: selected, englishCatalog: new Map(en.map(guide => [guide.slug, guide])), today: '2026-11-16' });
  assert.match(payload.answer, /archive: 2026-11-15/);
});

test('only real ISO calendar dates override month-level expiry', () => {
  for (const value of ['2026-11-31', '2026-02-29', '2026-13-01', '11/15/2026', '2026-11-15T00:00:00Z', {}, 20261115]) {
    const guide = { editionMonth: '2026-11', editionThroughDate: value };
    assert.equal(guideEditionThroughDate(guide), '', String(value));
    assert.equal(isGuideArchived(guide, '2026-11-16'), false);
    assert.equal(isGuideArchived(guide, '2026-12-01'), true);
  }
  const leap = { editionMonth: '2028-02', editionThroughDate: '2028-02-29' };
  assert.equal(isGuideArchived(leap, '2028-02-29'), false);
  assert.equal(isGuideArchived(leap, '2028-03-01'), true);
  assert.equal(isGuideArchived({ slug: 'evergreen-library' }, '2026-11-16'), false);
});
