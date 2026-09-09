const test = require('node:test');
const assert = require('node:assert/strict');
const { normalizeContact, allowedOrigins } = require('../lib/security');
const { publicPostFilters, postLifecycleChanges } = require('../lib/postLifecycle');

test('contact validation rejects unexpected structures and accepts common international phone punctuation', () => {
  assert.ok(normalizeContact('phone', 'letters1234567').error);
  assert.ok(normalizeContact('wechat', 'line\nbreak').error);
  assert.ok(normalizeContact({}, 'value').error);
  assert.equal(normalizeContact('phone', '+44 (20) 7946-0958').contactValue, '+44 (20) 7946-0958');
  assert.equal(normalizeContact('email', ' FRIEND@EXAMPLE.TEST ').contactValue, 'friend@example.test');
});

test('production origin config excludes local development and rejects wildcard or insecure overrides', () => {
  assert.deepEqual(allowedOrigins({ NODE_ENV: 'production' }), ['https://www.baylink.us', 'https://baylink.us']);
  assert.throws(() => allowedOrigins({ NODE_ENV: 'production', CORS_ALLOWED_ORIGINS: '*' }));
  assert.throws(() => allowedOrigins({ NODE_ENV: 'production', CORS_ALLOWED_ORIGINS: 'http://preview.example.test' }));
  assert.throws(() => allowedOrigins({ CORS_ALLOWED_ORIGINS: 'https://user:password@example.test' }));
});

test('public filter rejects operator objects and lifecycle never accepts a forged confirmation time', () => {
  assert.throws(() => publicPostFilters({ city: { $ne: '' } }));
  assert.throws(() => postLifecycleChanges({ confirmAvailability: true }, { isOwner: false }));
  assert.throws(() => postLifecycleChanges({ status: 'closed', confirmAvailability: true }, { isOwner: true }));
  assert.deepEqual(postLifecycleChanges({ confirmedAt: 999999 }, { isOwner: true }), {});
  assert.deepEqual(postLifecycleChanges({ confirmAvailability: true }, { isOwner: true, now: 123 }), { status: 'active', confirmedAt: 123 });
});
