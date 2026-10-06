const test = require('node:test');
const assert = require('node:assert/strict');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const crypto = require('node:crypto');
const mongoose = require('mongoose');
const { createMemoryModels } = require('./support/memory-models');
const { accountMemory } = require('./support/account-memory');
const { encodeBase32, encryptSecret, totpAt } = require('../lib/accountTotp');
const { createApplication } = require('../server');
const secret = 'test-only-secret-more-than-thirty-two-characters', password = 'TestPassword7', key = Buffer.alloc(32, 7);

async function fixture(t, overrides = {}) {
  const users = [{ id: 'owner', email: 'owner@fixture.invalid', nickname: 'Owner', role: 'user', contactType: 'email', contactValue: 'fixture-private', password: bcrypt.hashSync(password, 4) },
    { id: 'other', email: 'other@fixture.invalid', nickname: 'Other', role: 'user', contactType: 'email', contactValue: 'other-private', password: bcrypt.hashSync(password, 4) }];
  const models = createMemoryModels({ User: users, Post: [{ id: 'post', authorId: 'owner', title: 'Fixture', description: 'Fixture only', category: '租屋', status: 'active', isDeleted: false, contactPreference: { mode: 'manual_approve', methods: [{ type: 'email', value: 'fixture-private', enabled: true }] } }],
    Conversation: [{ id: 'conv', userIds: ['owner', 'other'] }], Message: [{ id: 'contact', senderId: 'owner', conversationId: 'conv', type: 'contact_card', contactCard: { postId: 'post', methods: [{ value: 'fixture-private' }] }, content: 'Card' }], ContactRequest: [{ id: 'r', postId: 'post', postOwnerId: 'owner', requesterId: 'other', contactSnapshot: [{ value: 'fixture-private' }] }] });
  models.User = accountMemory(overrides.users || users); models.AccountAuthChallenge = accountMemory();
  if (overrides.ProductMetric) models.ProductMetric = overrides.ProductMetric;
  const app = createApplication({ models, config: { NODE_ENV: 'test', JWT_SECRET: secret, ACCOUNT_SECURITY_ENCRYPTION_KEY: key.toString('base64'), ...overrides.config } });
  await new Promise(resolve => app.server.listen(0, '127.0.0.1', resolve)); t.after(() => new Promise(resolve => app.io.close(resolve)));
  const request = async (path, { token, body, method = 'GET' } = {}) => {
    const res = await fetch(`http://127.0.0.1:${app.server.address().port}${path}`, { method,
      headers: { ...(token ? { Authorization: `Bearer ${token}` } : {}), ...(body ? { 'Content-Type': 'application/json' } : {}) }, ...(body ? { body: JSON.stringify(body) } : {}) });
    const text = await res.text(); let data; try { data = JSON.parse(text); } catch { data = text; } return { status: res.status, data };
  };
  const login = async (email = 'owner@fixture.invalid') => (await request('/api/auth/login', { method: 'POST', body: { email, password } })).data;
  return { request, login, models };
}

test('MFA password challenge cannot be used as authenticated bearer; completed MFA can', async t => {
  const shared = encodeBase32(crypto.randomBytes(20));
  const f = await fixture(t, { users: [{ id: 'owner', email: 'owner@fixture.invalid', nickname: 'Admin', role: 'admin', password: bcrypt.hashSync(password, 4), totpEnabledAt: Date.now(), accountSecurity: { secretCipher: encryptSecret(shared, 'owner', key), recoveryHashes: [] } }] });
  const challenge = await f.login(); assert.equal(challenge.mfaRequired, true); assert.equal(challenge.token, undefined);
  assert.equal((await f.request('/api/users/me/security', { token: challenge.challengeToken })).status, 401);
  const completed = await f.request('/api/auth/login/totp', { method: 'POST', body: { challengeToken: challenge.challengeToken, totpCode: totpAt(shared, Date.now()) } });
  assert.equal(completed.status, 200); assert.ok(completed.data.token); assert.equal(completed.data.accountSecurity, undefined);
  assert.equal((await f.request('/api/users/me/security', { token: completed.data.token })).status, 200);
});

test('unconfigured admin remains able to password-login and own security DTO contains no secrets', async t => {
  const f = await fixture(t, { users: [{ id: 'owner', email: 'owner@fixture.invalid', nickname: 'Admin', role: 'admin', password: bcrypt.hashSync(password, 4) }], config: { ACCOUNT_SECURITY_ENCRYPTION_KEY: undefined } }); const user = await f.login(); assert.ok(user.token);
  assert.equal(user.password, undefined); assert.equal(user.activeAccountOperations, undefined); assert.equal(user.accountSecurity, undefined);
  const denied = await f.request('/api/users/me/privacy/export', { method: 'POST', body: { password } }); assert.equal(denied.status, 401);
  const wrong = await f.request('/api/users/me/privacy/export', { token: user.token, method: 'POST', body: { password: 'wrong' } }); assert.equal(wrong.status, 403);
});

test('public profile endpoints hide suspended, banned and deletion-pending accounts', async t => {
  const f = await fixture(t, { users: [{ id: 'pending', nickname: 'Hidden', accountDeletionPending: true }, { id: 'suspended', nickname: 'Hidden', accountStatus: 'suspended' }, { id: 'banned', nickname: 'Hidden', isBanned: true }] });
  for (const id of ['pending', 'suspended', 'banned']) for (const path of [`/api/users/${id}`, `/api/users/${id}/public`]) assert.equal((await f.request(path)).status, 404, path);
});

test('post removal erases saved contact values and old recipients can no longer read them', async t => {
  const f = await fixture(t), owner = await f.login(), other = await f.login('other@fixture.invalid');
  assert.ok(JSON.stringify((await f.request('/api/conversations/conv/messages', { token: other.token })).data).includes('fixture-private'));
  assert.equal((await f.request('/api/posts/post', { method: 'DELETE', token: owner.token })).status, 200);
  const messages = await f.request('/api/conversations/conv/messages', { token: other.token }); assert.equal(messages.status, 200); assert.ok(!JSON.stringify(messages.data).includes('fixture-private'));
  assert.deepEqual(f.models.ContactRequest.rows[0].contactSnapshot, []); assert.deepEqual(f.models.Post.rows[0].contactPreference.methods, []);
});

test('revoke-all invalidates a token even when issued in the same millisecond', async t => {
  const f = await fixture(t), owner = await f.login();
  assert.equal((await f.request('/api/users/me/security/revoke-sessions', { token: owner.token, method: 'POST', body: { password } })).status, 200);
  assert.equal((await f.request('/api/users/me/security', { token: owner.token })).status, 401);
  const fresh = await f.login(); assert.equal(jwt.verify(fresh.token, secret).sessionRevision, 1); assert.equal((await f.request('/api/users/me/security', { token: fresh.token })).status, 200);
});

test('account tests never start a real Mongo connection', () => { assert.equal(mongoose.connection.readyState, 0); });

test('successful registration records an anonymous server-only signup event that public clients cannot forge', async t => {
  const metrics = [], f = await fixture(t, { ProductMetric: { updateOne: async (filter, update) => { metrics.push({ filter, update }); return { matchedCount: 1 }; } } });
  const registered = await f.request('/api/auth/register', { method: 'POST', body: { email: 'new@fixture.invalid', password, nickname: 'New neighbor', contactType: 'email', contactValue: 'new@fixture.invalid', locale: 'en' } });
  assert.equal(registered.status, 200); assert.match(registered.data.id, /^[0-9a-f-]{36}$/);
  assert.equal(metrics.length, 1); assert.equal(metrics[0].filter.event, 'signup_completed'); assert.equal(metrics[0].filter.locale, 'en');
  assert.deepEqual(Object.keys(metrics[0].filter).sort(), ['day', 'event', 'locale']);
  const text = JSON.stringify(metrics); for (const value of ['new@fixture.invalid', registered.data.id, 'New neighbor', password]) assert.ok(!text.includes(value));
  const forged = await f.request('/api/product-events', { method: 'POST', body: { event: 'signup_completed', locale: 'en' } });
  assert.equal(forged.status, 400); assert.equal(metrics.length, 1);
});

test('anonymous signup metric failure does not turn a created account into a failed registration', async t => {
  const f = await fixture(t, { ProductMetric: { updateOne: async () => { throw new Error('Mock metrics offline'); } } });
  const result = await f.request('/api/auth/register', { method: 'POST', body: { email: 'new@fixture.invalid', password, nickname: 'New neighbor', contactType: 'email', contactValue: 'new@fixture.invalid' } });
  assert.equal(result.status, 200); assert.ok(result.data.token); assert.ok(f.models.User.rows.some(user => user.email === 'new@fixture.invalid'));
});
