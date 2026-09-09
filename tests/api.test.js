const test = require('node:test');
const assert = require('node:assert/strict');
const { once } = require('node:events');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const mongoose = require('mongoose');
const dotenv = require('dotenv');
const { io: connectSocket } = require('socket.io-client');
const { createMemoryModels } = require('./support/memory-models');

// Any accidental startup path fails this suite before it can load a real .env or connect to Mongo.
dotenv.config = () => { throw new Error('Tests must not load .env'); };
mongoose.connect = async () => { throw new Error('Tests must not connect to MongoDB'); };
const { createApplication, startProduction } = require('../server');
const { hashSessionToken } = require('../lib/security');
const SECRET = 'isolated-test-secret-with-more-than-32-characters';
const PASSWORD = 'TestPassword7';
const passwordHash = bcrypt.hashSync(PASSWORD, 4);

const makeUser = (id, role = 'user') => ({ id, email: `${id}@example.test`, password: passwordHash, nickname: `Neighbor ${id}`, role, contactType: 'wechat', contactValue: 'fictional-contact', accountStatus: 'active', isBanned: false });
const makePost = (id, overrides = {}) => ({
  id, authorId: 'owner', authorNickname: 'Neighbor owner', type: 'provider', title: 'A sample community listing',
  description: 'A fictional listing used only for isolated tests.', category: '租屋', city: 'San Francisco',
  budget: '100', timeInfo: '', createdAt: 100, confirmedAt: 100, status: 'active', isDeleted: false, adminHidden: false,
  imageUrls: [], comments: [], likes: [], reports: [], contactPreference: { mode: 'manual_approve', methods: [{ type: 'wechat', label: '微信', value: 'fictional-private-value', enabled: true }] },
  ...overrides,
});

async function fixture(t, overrides = {}) {
  const models = overrides.models || createMemoryModels({
    User: [makeUser('owner'), makeUser('other'), makeUser('admin', 'admin')],
    Post: [
      makePost('rent-sf'), makePost('rent-sj', { city: 'San Jose', createdAt: 101 }),
      makePost('request-sf', { type: 'client', createdAt: 102 }),
      makePost('moving-sj', { category: '搬家', city: 'San Jose', createdAt: 103 }),
      makePost('closed', { status: 'closed', createdAt: 104 }),
      makePost('hidden', { adminHidden: true, createdAt: 105 }),
      makePost('deleted', { isDeleted: true, createdAt: 106 }),
      makePost('other-post', { authorId: 'other', category: '闲置', createdAt: 107 }),
    ],
    Conversation: [{ id: 'conversation', userIds: ['owner', 'other'], updatedAt: 100 }],
  });
  const application = createApplication({ config: { NODE_ENV: 'test', JWT_SECRET: SECRET, ...overrides.config }, models });
  await new Promise(resolve => application.server.listen(0, '127.0.0.1', resolve));
  const url = `http://127.0.0.1:${application.server.address().port}`;
  t.after(() => new Promise(resolve => application.io.close(resolve)));
  const request = async (path, { token, body, method = 'GET', origin } = {}) => {
    const response = await fetch(`${url}${path}`, {
      method, headers: { ...(token ? { Authorization: `Bearer ${token}` } : {}), ...(body !== undefined ? { 'Content-Type': 'application/json' } : {}), ...(origin ? { Origin: origin } : {}) },
      ...(body !== undefined ? { body: JSON.stringify(body) } : {}),
    });
    const text = await response.text();
    let data;
    try { data = JSON.parse(text); } catch { data = text; }
    return { status: response.status, data, headers: response.headers };
  };
  const login = async (id = 'owner') => {
    const response = await request('/api/auth/login', { method: 'POST', body: { email: `${id}@example.test`, password: PASSWORD } });
    assert.equal(response.status, 200);
    return response.data.token;
  };
  return { ...application, models, url, request, login };
}

const socketEvent = (socket, event) => Promise.race([
  once(socket, event),
  new Promise((_, reject) => { const timer = setTimeout(() => reject(new Error(`Timed out waiting for ${event}`)), 3000); timer.unref(); }),
]);

test('import and test factory neither read .env nor open Mongo; production start refuses test mode', async () => {
  assert.equal(mongoose.connection.readyState, 0);
  await assert.rejects(startProduction({ NODE_ENV: 'test' }), /isolated models/);
  const application = createApplication({ config: { NODE_ENV: 'test', JWT_SECRET: SECRET } });
  assert.equal(application.server.listening, false);
  const indexes = application.models.RevokedSession.schema.indexes();
  assert.ok(indexes.some(([keys, options]) => keys.expiresAt === 1 && options.expireAfterSeconds === 0));
  assert.ok(indexes.some(([keys, options]) => keys.tokenHash === 1 && options.unique));
  await new Promise(resolve => application.io.close(resolve));
  assert.equal(mongoose.connection.readyState, 0);
});

test('public list applies category, city and type before pagination and omits closed/hidden/deleted posts', async t => {
  const { request } = await fixture(t);
  const response = await request('/api/posts?category=%E7%A7%9F%E5%B1%8B&city=San%20Francisco&type=provider&limit=1');
  assert.equal(response.status, 200);
  assert.deepEqual(response.data.posts.map(post => post.id), ['rent-sf']);
  assert.equal(response.data.hasMore, false);
  assert.equal(response.data.filtersApplied, true);
  assert.equal(response.data.posts[0].contactPreference.methods[0].value, undefined);
  assert.equal(response.data.posts[0].author.email, undefined);
  const service = await request('/api/posts?category=service&city=San%20Jose&type=provider');
  assert.deepEqual(service.data.posts.map(post => post.id), ['moving-sj']);
  const provider = await request('/api/posts?type=provider&limit=1');
  assert.equal(provider.data.hasMore, true);
  assert.equal((await request('/api/posts?type=invalid')).status, 400);
  assert.equal((await request('/api/posts?category[$ne]=x')).status, 400);
});

test('my posts endpoint includes closed and hidden own posts, but excludes deleted and other users posts', async t => {
  const { request, login } = await fixture(t);
  const token = await login();
  const response = await request('/api/users/me/posts', { token });
  assert.equal(response.status, 200);
  const ids = response.data.posts.map(post => post.id);
  assert.ok(ids.includes('closed'));
  assert.ok(ids.includes('hidden'));
  assert.ok(!ids.includes('deleted'));
  assert.ok(!ids.includes('other-post'));
  const paged = await request('/api/users/me/posts?limit=2', { token });
  assert.equal(paged.data.posts.length, 2);
  assert.equal(paged.data.hasMore, true);
  assert.equal((await request('/api/users/me/posts')).status, 401);
});

test('post lifecycle requires ownership for confirmation and never trusts a client confirmedAt/authorId', async t => {
  const { request, login, models } = await fixture(t);
  const ownerToken = await login();
  const otherToken = await login('other');
  const adminToken = await login('admin');
  const body = makePost('rent-sf');
  assert.equal((await request('/api/posts/rent-sf', { method: 'PUT', token: otherToken, body: { ...body, status: 'closed' } })).status, 403);
  assert.equal((await request('/api/posts/rent-sf', { method: 'PUT', token: adminToken, body: { ...body, confirmAvailability: true } })).status, 400);
  const closed = await request('/api/posts/rent-sf', { method: 'PUT', token: ownerToken, body: { ...body, status: 'closed', confirmedAt: 9999999999999, authorId: 'other' } });
  assert.equal(closed.status, 200);
  assert.equal(closed.data.status, 'closed');
  assert.equal(closed.data.confirmedAt, 100);
  assert.equal(closed.data.authorId, 'owner');
  const reopened = await request('/api/posts/rent-sf', { method: 'PUT', token: ownerToken, body: { ...body, status: 'active' } });
  assert.equal(reopened.data.confirmedAt, null);
  const confirmed = await request('/api/posts/rent-sf', { method: 'PUT', token: ownerToken, body: { ...body, confirmAvailability: true } });
  assert.equal(confirmed.status, 200);
  assert.ok(confirmed.data.confirmedAt > Date.now() - 5000);
  assert.equal(models.Post.rows.find(post => post.id === 'rent-sf').authorId, 'owner');
});

test('closed detail remains public while hidden/deleted detail is 404; closed contact request writes nothing', async t => {
  const { request, login, models } = await fixture(t);
  assert.equal((await request('/api/posts/closed')).status, 200);
  assert.equal((await request('/api/posts/hidden')).status, 404);
  assert.equal((await request('/api/posts/deleted')).status, 404);
  const response = await request('/api/posts/closed/contact-requests', { method: 'POST', token: await login('other'), body: {} });
  assert.equal(response.status, 409);
  assert.equal(response.data.status, 'closed');
  assert.equal(models.ContactRequest.rows.length, 0);
  assert.equal(models.Message.rows.length, 0);
});

test('profile contact edits validate type/value and cannot grant account privileges', async t => {
  const { request, login } = await fixture(t);
  const token = await login();
  const response = await request('/api/users/me', { method: 'PATCH', token, body: { contactType: 'phone', contactValue: '+1 (415) 555-0199', role: 'admin', isPhoneVerified: true } });
  assert.equal(response.status, 200);
  assert.equal(response.data.contactType, 'phone');
  assert.equal(response.data.contactValue, '+1 (415) 555-0199');
  assert.equal(response.data.role, 'user');
  assert.notEqual(response.data.isPhoneVerified, true);
  assert.equal(response.data.password, undefined);
  for (const body of [{ contactType: 'invalid', contactValue: 'x' }, { contactType: 'phone', contactValue: 'call me' }, { contactType: 'email', contactValue: 'bad-email' }, { contactType: 'wechat', contactValue: 'has spaces' }, { contactValue: {} }]) {
    assert.equal((await request('/api/users/me', { method: 'PATCH', token, body })).status, 400);
  }
  const email = await request('/api/users/me', { method: 'PATCH', token, body: { contactType: 'email', contactValue: ' Friend@Example.Test ' } });
  assert.equal(email.data.contactValue, 'friend@example.test');
});

test('registration validates contact and always creates a normal user', async t => {
  const { request } = await fixture(t);
  const body = { email: 'new@example.test', password: PASSWORD, nickname: 'New Neighbor', contactType: 'email', contactValue: 'invalid' };
  assert.equal((await request('/api/auth/register', { method: 'POST', body })).status, 400);
  const response = await request('/api/auth/register', { method: 'POST', body: { ...body, contactType: 'phone', contactValue: '+1 415 555 0101', role: 'admin' } });
  assert.equal(response.status, 200);
  assert.equal(response.data.role, 'user');
  assert.equal(response.data.contactType, 'phone');
  assert.equal(response.data.password, undefined);
});

test('logout persists only a token hash, revokes HTTP and optional auth, and leaves another login valid', async t => {
  const { request, login, models } = await fixture(t);
  const token = await login('admin');
  const secondToken = await login('admin');
  assert.notEqual(token, secondToken);
  assert.equal((await request('/api/posts/hidden', { token })).status, 200);
  assert.equal((await request('/api/auth/logout', { method: 'POST', token, body: {} })).status, 200);
  assert.equal(models.RevokedSession.rows[0].tokenHash, hashSessionToken(token));
  assert.ok(!JSON.stringify(models.RevokedSession.rows).includes(token));
  assert.ok(new Date(models.RevokedSession.rows[0].expiresAt).getTime() > Date.now());
  assert.equal((await request('/api/users/me/posts', { token })).status, 401);
  assert.equal((await request('/api/posts/hidden', { token })).status, 404);
  assert.equal((await request('/api/users/me/posts', { token: secondToken })).status, 200);
});

test('revocations remain effective in a separately created application using the same store', async t => {
  const first = await fixture(t);
  const token = await first.login();
  await first.request('/api/auth/logout', { method: 'POST', token, body: {} });
  const second = await fixture(t, { models: first.models });
  assert.equal((await second.request('/api/users/me/posts', { token })).status, 401);
});

test('protected routes reject anonymous and ordinary-user admin access, and auth storage failure fails closed', async t => {
  const { request, login, models } = await fixture(t);
  for (const path of ['/api/admin/reports', '/api/conversations', '/api/users/me/blocks']) assert.equal((await request(path)).status, 401);
  const token = await login();
  assert.equal((await request('/api/admin/reports', { token })).status, 403);
  models.RevokedSession.exists = async () => { throw new Error('Simulated database outage'); };
  assert.equal((await request('/api/users/me/posts', { token })).status, 503);
});

test('CORS uses exact origins for HTTP and emits API safety headers', async t => {
  const { request } = await fixture(t, { config: { CORS_ALLOWED_ORIGINS: 'https://preview.example.test' } });
  const allowed = await request('/api/posts', { origin: 'https://preview.example.test' });
  assert.equal(allowed.status, 200);
  assert.equal(allowed.headers.get('access-control-allow-origin'), 'https://preview.example.test');
  assert.equal(allowed.headers.get('x-content-type-options'), 'nosniff');
  assert.equal(allowed.headers.get('x-frame-options'), 'DENY');
  assert.equal(allowed.headers.get('cache-control'), 'no-store');
  assert.equal(allowed.headers.get('x-powered-by'), null);
  const denied = await request('/api/posts', { origin: 'https://www.baylink.us.evil.example' });
  assert.equal(denied.status, 403);
  assert.equal(denied.headers.get('access-control-allow-origin'), null);
  assert.equal((await request('/api/posts')).status, 200);
});

test('socket logout disconnects the exact session and rejects its reconnect; contact-share acknowledges real content', async t => {
  const { request, login, url, models } = await fixture(t);
  const ownerToken = await login();
  const otherToken = await login('other');
  const socket = connectSocket(url, { auth: { token: ownerToken }, transports: ['websocket'], reconnection: false });
  t.after(() => socket.close());
  await socketEvent(socket, 'connect');
  const incoming = socketEvent(socket, 'new_message');
  const sent = await request('/api/conversations/conversation/messages', { method: 'POST', token: otherToken, body: { type: 'contact-share', content: '' } });
  assert.equal(sent.status, 200);
  assert.equal(sent.data.type, 'contact-share');
  assert.match(sent.data.content, /我的联系方式：微信 fictional-contact/);
  assert.equal((await incoming)[0].id, sent.data.id);
  const disconnected = socketEvent(socket, 'disconnect');
  assert.equal((await request('/api/auth/logout', { method: 'POST', token: ownerToken, body: {} })).status, 200);
  await disconnected;
  assert.equal(socket.connected, false);
  const denied = connectSocket(url, { auth: { token: ownerToken }, transports: ['websocket'], reconnection: false });
  t.after(() => denied.close());
  assert.match((await socketEvent(denied, 'connect_error'))[0].message, /unauthorized/);
  assert.equal(models.Message.rows.length, 1);
});

test('socket handshake refuses disallowed Origin and expired tokens', async t => {
  const { login, url } = await fixture(t);
  const token = await login();
  const socket = connectSocket(url, { auth: { token }, transports: ['websocket'], reconnection: false, extraHeaders: { Origin: 'https://unapproved.example' } });
  t.after(() => socket.close());
  await socketEvent(socket, 'connect_error');
  assert.equal(socket.connected, false);
  const expired = jwt.sign({ id: 'owner' }, SECRET, { algorithm: 'HS256', expiresIn: -1 });
  const expiredSocket = connectSocket(url, { auth: { token: expired }, transports: ['websocket'], reconnection: false });
  t.after(() => expiredSocket.close());
  assert.match((await socketEvent(expiredSocket, 'connect_error'))[0].message, /unauthorized/);
});

test('unconfigured production SMS fails without returning a code or persisting verification state', async t => {
  const { request, login, models } = await fixture(t, { config: { NODE_ENV: 'production', AUTH_DEV_RETURN_TOKENS: 'true' } });
  const response = await request('/api/users/me/phone/start', { method: 'POST', token: await login(), body: { phone: '+14155550101' } });
  assert.equal(response.status, 503);
  assert.equal(response.data.devCode, undefined);
  assert.equal(models.User.rows.find(user => user.id === 'owner').phoneVerificationCodeHash, undefined);
  assert.equal(response.headers.get('strict-transport-security'), 'max-age=31536000');
});

test('simulation requires explicit dev opt-in and exposes its code only in the response', async t => {
  const ordinary = await fixture(t);
  const failure = await ordinary.request('/api/users/me/phone/start', { method: 'POST', token: await ordinary.login(), body: { phone: '+14155550101' } });
  assert.equal(failure.status, 503);
  const enabled = await fixture(t, { config: { AUTH_DEV_RETURN_TOKENS: 'true' } });
  const response = await enabled.request('/api/users/me/phone/start', { method: 'POST', token: await enabled.login(), body: { phone: '+14155550101' } });
  assert.equal(response.status, 200);
  assert.match(response.data.devCode, /^\d{6}$/);
  assert.match(response.data.message, /未发送短信/);
});

test('password changes and suspended accounts consistently invalidate HTTP, optional admin auth and Socket access', async t => {
  const { request, login, url, models } = await fixture(t);
  const adminToken = await login('admin');
  models.User.rows.find(user => user.id === 'admin').passwordChangedAt = Date.now() + 1;
  assert.equal((await request('/api/users/me/posts', { token: adminToken })).status, 401);
  assert.equal((await request('/api/posts/hidden', { token: adminToken })).status, 404);
  const changedSocket = connectSocket(url, { auth: { token: adminToken }, transports: ['websocket'], reconnection: false });
  t.after(() => changedSocket.close());
  assert.match((await socketEvent(changedSocket, 'connect_error'))[0].message, /unauthorized/);

  const ownerToken = await login();
  models.User.rows.find(user => user.id === 'owner').accountStatus = 'suspended';
  assert.equal((await request('/api/users/me/posts', { token: ownerToken })).status, 403);
  const loginAttempt = await request('/api/auth/login', { method: 'POST', body: { email: 'owner@example.test', password: PASSWORD } });
  assert.equal(loginAttempt.status, 403);
  assert.equal(loginAttempt.data.token, undefined);
  const suspendedSocket = connectSocket(url, { auth: { token: ownerToken }, transports: ['websocket'], reconnection: false });
  t.after(() => suspendedSocket.close());
  assert.match((await socketEvent(suspendedSocket, 'connect_error'))[0].message, /unauthorized/);
});
