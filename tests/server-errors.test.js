const test = require('node:test');
const assert = require('node:assert/strict');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { createApplication } = require('../server');
const { createMemoryModels } = require('./support/memory-models');
const { accountMemory } = require('./support/account-memory');
const { describeFailure } = require('../lib/serverErrors');

const secret = 'server-errors-test-secret-at-least-thirty-two-characters';
const password = 'OnlyMockPassword7';
const PRIVATE = 'private-detail@fixture.invalid';
const mongoError = (code, message = `driver said ${PRIVATE}`) => Object.assign(new Error(message), { name: 'MongoServerError', code });

async function fixture(t, { transaction } = {}) {
  const seed = {
    User: ['alice', 'bob'].map(id => ({ id, email: `${id}@fixture.invalid`, nickname: id, role: 'user', password: bcrypt.hashSync(password, 4) })),
    Post: [{ id: 'alice-post', authorId: 'alice', title: '求租 Daly City 一房', description: 'Fixture post body only', category: '租屋', city: 'Daly City',
      status: 'active', isDeleted: false, likes: [], comments: [], reports: [], contactPreference: { methods: [] }, createdAt: 1 }],
    Conversation: [{ id: 'alice-bob', userIds: ['alice', 'bob'], updatedAt: 3 }],
    Message: [
      { id: 'from-alice', conversationId: 'alice-bob', senderId: 'alice', type: 'text', messageType: 'text', content: 'Hello from Alice', createdAt: 1, readBy: ['alice', 'bob'] },
      { id: 'from-bob', conversationId: 'alice-bob', senderId: 'bob', type: 'text', messageType: 'text', content: 'Reply from Bob', createdAt: 2, readBy: ['alice', 'bob'] },
    ],
  };
  const models = createMemoryModels();
  for (const name of ['User', 'Post', 'Message', 'Conversation', 'ContactRequest', 'UserBlock', 'EventInterest',
    'PlannerAccount', 'Outing', 'ServiceBookingAgenda', 'PostTranslation', 'Report', 'ModerationLog', 'AccountAuthChallenge']) {
    models[name] = accountMemory(seed[name] || []);
  }
  const logs = [];
  const application = createApplication({ models, config: { NODE_ENV: 'test', JWT_SECRET: secret, RENDER_GIT_COMMIT: 'a'.repeat(40) },
    accountPrivacyTransaction: transaction || (work => work()), serverErrorLog: line => logs.push(line) });
  await new Promise(resolve => application.server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise(resolve => application.io.close(resolve)));
  const tokens = Object.fromEntries(seed.User.map(user => [user.id, jwt.sign({ id: user.id, purpose: 'session',
    sessionIssuedAt: Date.now(), sessionRevision: 0 }, secret, { expiresIn: '1h' })]));
  const request = async (path, { user, method = 'GET', body } = {}) => {
    const response = await fetch(`http://127.0.0.1:${application.server.address().port}${path}`, {
      method, headers: { ...(user ? { Authorization: `Bearer ${tokens[user]}` } : {}), 'Content-Type': 'application/json' },
      ...(body === undefined ? {} : { body: JSON.stringify(body) }), signal: AbortSignal.timeout(5000),
    });
    const text = await response.text();
    let data; try { data = JSON.parse(text); } catch { data = text; }
    return { status: response.status, type: response.headers.get('content-type') || '', data, text };
  };
  return { models, logs, request };
}

// Count rejections Node would have treated as fatal while a test runs.
function watchUnhandled(t) {
  const seen = [];
  const listener = reason => seen.push(reason);
  process.on('unhandledRejection', listener);
  t.after(() => process.off('unhandledRejection', listener));
  return seen;
}
const turn = () => new Promise(resolve => setImmediate(resolve));

test('a numeric driver error code yields a JSON 500 and exactly one structured log line without the message', async t => {
  const f = await fixture(t), unhandled = watchUnhandled(t);
  const findOne = f.models.User.findOne;
  f.models.User.findOne = filter => filter?.id === 'boom' ? { select: () => Promise.reject(mongoError(40)) } : findOne(filter);
  const response = await f.request('/api/users/boom');
  assert.equal(response.status, 500);
  assert.match(response.type, /application\/json/);
  assert.deepEqual(response.data, { error: '操作失败，请稍后再试' });
  await turn();
  assert.equal(f.logs.length, 1);
  const [line] = f.logs;
  assert.equal(line.level, 'error'); assert.equal(line.event, 'http_5xx'); assert.equal(line.method, 'GET');
  assert.equal(line.route, '/api/users/:id'); assert.equal(line.status, 500); assert.equal(line.error, 'MongoServerError'); assert.equal(line.code, 40);
  assert.equal(line.release, 'aaaaaaaaaaaa'); assert.equal(typeof line.ms, 'number');
  assert.ok(!JSON.stringify(f.logs).includes(PRIVATE)); assert.ok(!JSON.stringify(f.logs).includes('boom'));
  assert.equal(unhandled.length, 0);
  // The process and the app keep serving.
  assert.equal((await f.request('/api/health')).status, 200);
  assert.equal((await f.request('/api/users/bob')).status, 200);
});

test('an AI_* string code stays public, other codes stay private, and 4xx responses are not logged', async t => {
  const f = await fixture(t);
  const findOne = f.models.User.findOne;
  f.models.User.findOne = filter => filter?.id === 'ai' ? { select: () => Promise.reject(Object.assign(new Error(PRIVATE), { status: 503, code: 'AI_PROVIDER_DOWN' })) }
    : filter?.id === 'odd' ? { select: () => Promise.reject(Object.assign(new Error(PRIVATE), { code: 'E_PRIVATE' })) } : findOne(filter);
  const ai = await f.request('/api/users/ai');
  assert.equal(ai.status, 503); assert.deepEqual(ai.data, { code: 'AI_PROVIDER_DOWN', error: '操作失败，请稍后再试' });
  const odd = await f.request('/api/users/odd');
  assert.equal(odd.status, 500); assert.deepEqual(odd.data, { error: '操作失败，请稍后再试' });
  assert.equal((await f.request('/api/users/nobody')).status, 404);
  await turn();
  assert.deepEqual(f.logs.map(line => [line.route, line.status, line.code]), [['/api/users/:id', 503, 'AI_PROVIDER_DOWN'], ['/api/users/:id', 500, 'E_PRIVATE']]);
});

test('DELETE /api/posts/:id turns a database rejection into a logged JSON 500 and the process stays alive', async t => {
  const f = await fixture(t), unhandled = watchUnhandled(t);
  const findOne = f.models.Post.findOne;
  // The authentication gate reads with isDeleted:false; only the route's own lookup fails.
  f.models.Post.findOne = filter => filter && !('isDeleted' in filter) ? Promise.reject(mongoError(91)) : findOne(filter);
  const response = await f.request('/api/posts/alice-post', { user: 'alice', method: 'DELETE' });
  assert.equal(response.status, 500); assert.match(response.type, /application\/json/);
  await turn();
  assert.deepEqual(f.logs.map(line => [line.event, line.method, line.route, line.status, line.code]), [['http_5xx', 'DELETE', '/api/posts/:id', 500, 91]]);
  assert.equal(unhandled.length, 0);
  assert.equal(f.models.User.rows.find(row => row.id === 'alice').activeAccountOperations, 0);
  assert.equal((await f.request('/api/health')).status, 200);
});

test('a route that answers 5xx itself is logged once, without error details', async t => {
  const f = await fixture(t);
  f.models.UserBlock.find = () => ({ sort: () => ({ lean: () => Promise.reject(mongoError(6)) }) });
  const original = console.error; console.error = () => {};
  try {
    const response = await f.request('/api/users/me/blocks', { user: 'alice' });
    assert.equal(response.status, 500);
  } finally { console.error = original; }
  await turn();
  assert.equal(f.logs.length, 1);
  assert.deepEqual({ ...f.logs[0], ms: 0 }, { level: 'error', event: 'http_5xx', method: 'GET', route: '/api/users/me/blocks', status: 500, release: 'aaaaaaaaaaaa', ms: 0 });
});

test('account deletion end to end: 200, then login 401, the post is gone and the other member keeps the thread', async t => {
  const f = await fixture(t);
  const before = await f.request('/api/conversations', { user: 'bob' });
  assert.equal(before.status, 200); assert.equal(before.data.length, 1);
  const deleted = await f.request('/api/users/me/privacy/account', { user: 'alice', method: 'DELETE', body: { password, confirmation: '注销我的账号', locale: 'zh-Hans' } });
  assert.equal(deleted.status, 200); assert.equal(deleted.data.success, true);
  const login = await f.request('/api/auth/login', { method: 'POST', body: { email: 'alice@fixture.invalid', password } });
  assert.equal(login.status, 401);
  assert.equal((await f.request('/api/users/me/blocks', { user: 'alice' })).status, 403);
  assert.equal((await f.request('/api/posts/alice-post')).status, 404);
  assert.equal((await f.request('/api/users/alice')).status, 404);
  const after = await f.request('/api/conversations', { user: 'bob' });
  assert.equal(after.status, 200); assert.equal(after.data.length, 1); assert.equal(after.data[0].id, 'alice-bob');
  const thread = f.models.Conversation.rows[0];
  assert.equal(thread.userIds[0], 'bob'); assert.match(thread.userIds[1], /^deleted_/);
  assert.deepEqual(f.models.Message.rows.map(row => row.id), ['from-bob']);
  await turn();
  assert.equal(f.logs.length, 0);
});

test('a failed deletion is a localized JSON error with one log line, and the same session keeps working', async t => {
  // A real transaction aborts as a whole; this one fails before writing anything.
  const f = await fixture(t, { transaction: async () => { throw mongoError(40); } });
  const response = await f.request('/api/users/me/privacy/account', { user: 'alice', method: 'DELETE', body: { password, confirmation: 'DELETE MY ACCOUNT', locale: 'en' } });
  assert.equal(response.status, 500); assert.match(response.type, /application\/json/);
  assert.equal(response.data.code, 'ACCOUNT_DELETE_FAILED'); assert.match(response.data.error, /still signed in/);
  assert.ok(!response.text.includes(PRIVATE));
  await turn();
  assert.equal(f.logs.length, 1);
  assert.deepEqual({ ...f.logs[0], ms: 0 }, { level: 'error', event: 'http_5xx', method: 'DELETE', route: '/api/users/me/privacy/account', status: 500,
    error: 'Error', code: 'ACCOUNT_DELETE_FAILED', cause: { name: 'MongoServerError', code: 40 }, release: 'aaaaaaaaaaaa', ms: 0 });
  // The token that asked for deletion still works: a failed attempt does not sign the owner out.
  assert.equal((await f.request('/api/users/me/blocks', { user: 'alice' })).status, 200);
  const user = f.models.User.rows.find(row => row.id === 'alice');
  assert.equal(user.accountDeletionPending, false); assert.equal(user.sessionRevision, undefined);
});

test('describeFailure keeps only safe names and codes', () => {
  assert.deepEqual(describeFailure(mongoError(11000)), { error: 'MongoServerError', code: 11000 });
  assert.deepEqual(describeFailure(Object.assign(new Error('x'), { code: 'has spaces and @email' })), { error: 'Error' });
  assert.deepEqual(describeFailure(Object.assign(new TypeError('x'), { cause: { name: 'MongoServerError', code: 40, message: PRIVATE } })), { error: 'TypeError', cause: { name: 'MongoServerError', code: 40 } });
  assert.deepEqual(describeFailure('plain string'), { error: 'string' });
  assert.deepEqual(describeFailure(undefined), { error: 'undefined' });
});

test('an error after a stream has started is logged once and ends the response; middleware 5xx have no route pattern', async t => {
  const express = require('express');
  const { createServerErrors } = require('../lib/serverErrors');
  const logs = [], errors = createServerErrors({ log: line => logs.push(line) });
  const app = express();
  app.use(errors.middleware);
  app.get('/stream/:id', (req, res, next) => { res.write('data: started\n\n'); next(mongoError(50)); });
  app.use('/broken', (req, res, next) => next(Object.assign(new Error(PRIVATE), { status: 502 })));
  app.use(errors.handler);
  const server = app.listen(0, '127.0.0.1');
  await new Promise(resolve => server.once('listening', resolve));
  t.after(() => new Promise(resolve => server.close(resolve)));
  const base = `http://127.0.0.1:${server.address().port}`;
  const stream = await fetch(`${base}/stream/42`);
  assert.equal(stream.status, 200); assert.equal(await stream.text(), 'data: started\n\n');
  const broken = await fetch(`${base}/broken`);
  assert.equal(broken.status, 502); assert.deepEqual(await broken.json(), { error: '操作失败，请稍后再试' });
  await turn();
  assert.deepEqual(logs.map(({ ms, ...line }) => line), [
    { level: 'error', event: 'http_error_after_headers', method: 'GET', route: '/stream/:id', status: 200, error: 'MongoServerError', code: 50, release: null },
    { level: 'error', event: 'http_5xx', method: 'GET', route: 'unmatched', status: 502, error: 'Error', release: null },
  ]);
  assert.ok(!JSON.stringify(logs).includes(PRIVATE));
});
