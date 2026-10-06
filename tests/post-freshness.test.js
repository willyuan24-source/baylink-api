const test = require('node:test');
const assert = require('node:assert/strict');
const { publicPostAvailability, publicPostFilters } = require('../lib/postLifecycle');
const { keywordFilter } = require('../lib/postSearch');
const now = Date.parse('2026-10-06T19:00:00Z');
const day = 86400000;

test('availability uses the actual owner confirmation, 30/60 day boundaries and never mistakes an edit for renewal', () => {
  for (const category of ['租屋', '闲置', '兼职']) {
    assert.equal(publicPostAvailability({ category, confirmedAt: now - 30 * day }, now), 'confirmed');
    assert.equal(publicPostAvailability({ category, confirmedAt: now - 30 * day - 1, updatedAt: now }, now), 'needs_confirmation');
  }
  assert.equal(publicPostAvailability({ category: '清洁', confirmedAt: now - 60 * day }, now), 'confirmed');
  assert.equal(publicPostAvailability({ category: '清洁', confirmedAt: now - 60 * day - 1 }, now), 'needs_confirmation');
  for (const confirmedAt of [undefined, null, NaN, 0, now + 1, '2026-10-06']) assert.equal(publicPostAvailability({ category: '租屋', confirmedAt }, now), 'needs_confirmation');
  assert.equal(publicPostAvailability({ status: 'closed', confirmedAt: now }, now), 'closed');
  assert.equal(publicPostAvailability({ category: '租屋', confirmedAt: now, expiresAt: now }, now), 'needs_confirmation');
  assert.equal(publicPostAvailability({ category: '租屋', confirmedAt: now, expiresAt: '2026-10-05T00:00:00Z' }, now), 'needs_confirmation');
});

test('current inventory filters before pagination and composes expiry, category, region and literal search; history is explicit', () => {
  const current = publicPostFilters({ availability: 'current', category: 'rent', city: '东湾' }, now);
  assert.deepEqual(current.category, { $in: ['租屋', '租房', '出租'] });
  assert.equal(current.city, '东湾');
  assert.equal(current.$and.length, 2);
  assert.equal(current.$and[0].$or[0].confirmedAt.$gte, now - 30 * day);
  assert.equal(current.$and[0].$or[1].confirmedAt.$gte, now - 60 * day);
  const search = keywordFilter('东湾租房');
  const combined = { ...current, $and: [...current.$and, ...search.$and] };
  assert.equal(combined.$and.length, 4);
  assert.equal(publicPostFilters({ availability: 'all' }, now).$and, undefined);
  assert.throws(() => publicPostFilters({ availability: ['current'] }, now));
  assert.throws(() => publicPostFilters({ availability: 'invented' }, now));
});
