const test = require('node:test');
const assert = require('node:assert/strict');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { createApplication } = require('../server');
const { createMemoryModels } = require('./support/memory-models');
const { accountMemory } = require('./support/account-memory');

const secret = 'direct-message-report-test-secret-at-least-thirty-two-characters';
const password = 'OnlyMockPassword7';
const deferred = () => { let resolve; const promise = new Promise(done => { resolve = done; }); return { promise, resolve }; };
const nextTurn = () => new Promise(resolve => setImmediate(resolve));

async function fixture(t) {
  const seed = {
    User: ['admin', 'sender', 'recipient', 'outsider'].map(id => ({ id, email: `${id}@fixture.invalid`, nickname: id,
      role: id === 'admin' ? 'admin' : 'user', password: bcrypt.hashSync(password, 4) })),
    Conversation: [{ id: 'private-thread', userIds: ['sender', 'recipient'] }],
    Message: [
      { id: 'real-message', conversationId: 'private-thread', senderId: 'sender', type: 'text', messageType: 'text', content: 'The real selected message', createdAt: 1 },
      { id: 'own-message', conversationId: 'private-thread', senderId: 'recipient', type: 'text', content: 'My own message', createdAt: 2 },
      { id: 'private-card', conversationId: 'private-thread', senderId: 'sender', type: 'contact_card', messageType: 'contact_card',
        content: 'private-contact-copy', contactCard: { methods: [{ value: 'private-contact-value' }] }, replyTo: { content: 'private-reply-copy' }, createdAt: 3 },
      { id: 'system-message', conversationId: 'private-thread', senderId: 'sender', type: 'system', messageType: 'system', content: 'system-only', createdAt: 4 },
      { id: 'deleted-message', conversationId: 'private-thread', senderId: 'sender', type: 'text', content: 'removed', isDeleted: true },
    ],
  };
  const models = createMemoryModels();
  for (const name of ['User', 'Post', 'Message', 'Conversation', 'ContactRequest', 'UserBlock', 'EventInterest',
    'PlannerAccount', 'Outing', 'ServiceBookingAgenda', 'PostTranslation', 'Report', 'ModerationLog', 'AccountAuthChallenge']) {
    models[name] = accountMemory(seed[name] || []);
  }
  const application = createApplication({ models, config: { NODE_ENV: 'test', JWT_SECRET: secret },
    accountPrivacyTransaction: work => work() });
  await new Promise(resolve => application.server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise(resolve => application.io.close(resolve)));
  const tokens = Object.fromEntries(seed.User.map(user => [user.id, jwt.sign({ id: user.id, purpose: 'session',
    sessionIssuedAt: Date.now(), sessionRevision: 0 }, secret, { expiresIn: '1h' })]));
  const request = async (path, user, method = 'GET', body) => {
    const response = await fetch(`http://127.0.0.1:${application.server.address().port}${path}`, {
      method, headers: { ...(user ? { Authorization: `Bearer ${tokens[user]}` } : {}), 'Content-Type': 'application/json' },
      ...(body === undefined ? {} : { body: JSON.stringify(body) }), signal: AbortSignal.timeout(5000),
    });
    return { status: response.status, data: await response.json() };
  };
  const report = (id = 'real-message', user = 'recipient', extra = {}) => request('/api/reports', user, 'POST',
    { targetType: 'message', targetId: id, conversationId: 'private-thread', reason: 'scam', ...extra });
  const erase = user => request('/api/users/me/privacy/account', user, 'DELETE', { password, confirmation: 'DELETE MY ACCOUNT' });
  return { models, request, report, erase };
}

test('a participant reports only the real selected message; forged evidence is ignored and visible only to admins', async t => {
  const f = await fixture(t);
  const result = await f.report('real-message', 'recipient', { evidence: { text: 'FORGED', senderId: 'outsider' },
    content: 'FORGED', targetUserId: 'outsider' });
  assert.equal(result.status, 200);
  const stored = f.models.Report.rows[0];
  assert.equal(stored.targetUserId, 'sender');
  assert.deepEqual(stored.evidence, { messageId: 'real-message', conversationId: 'private-thread', type: 'text',
    createdAt: 1, text: 'The real selected message' });
  assert.ok(!JSON.stringify(result.data).includes('The real selected message'));
  assert.equal((await f.request('/api/admin/reports', 'recipient')).status, 403);
  const admin = await f.request('/api/admin/reports', 'admin');
  assert.equal(admin.status, 200);
  assert.equal(admin.data.reports[0].evidence.text, stored.evidence.text);
});

test('outsiders, unauthenticated callers and missing or deleted messages cannot create or read private reports', async t => {
  const f = await fixture(t);
  assert.equal((await f.report('real-message', 'outsider')).status, 404);
  assert.equal((await f.report('real-message', null)).status, 401);
  assert.equal((await f.report('missing-message')).status, 404);
  assert.equal((await f.report('deleted-message')).status, 404);
  assert.equal((await f.report('real-message', 'recipient', { conversationId: 'another-thread' })).status, 404);
  assert.equal((await f.report('real-message', 'recipient', { conversationId: undefined })).status, 404);
  assert.equal(f.models.Report.rows.length, 0);
});

test('own and system messages are rejected and duplicate reports keep one safety case', async t => {
  const f = await fixture(t);
  assert.equal((await f.report('own-message')).status, 400);
  assert.equal((await f.report('system-message')).status, 404);
  assert.equal((await f.report()).status, 200);
  assert.equal((await f.report()).status, 400);
  assert.equal(f.models.Report.rows.length, 1);
});

test('blocking stops new messages without preventing reporting an already received message', async t => {
  const f = await fixture(t);
  f.models.UserBlock.rows.push({ blockerId: 'recipient', blockedUserId: 'sender' });
  assert.equal((await f.report()).status, 200);
});

test('contact cards and attachments do not copy contact values or reply snapshots into moderation evidence', async t => {
  const f = await fixture(t);
  assert.equal((await f.report('private-card')).status, 200);
  const stored = f.models.Report.rows[0];
  assert.equal(stored.evidence.attachmentOmitted, true);
  for (const privateValue of ['private-contact-copy', 'private-contact-value', 'private-reply-copy']) {
    assert.ok(!JSON.stringify(stored).includes(privateValue));
  }
  assert.equal(stored.evidence.text, undefined);
});

for (const account of ['sender', 'recipient']) test(`erasing the ${account} removes private report evidence while retaining a nonsecret case`, async t => {
  const f = await fixture(t);
  assert.equal((await f.report()).status, 200);
  await nextTurn();
  assert.equal((await f.erase(account)).status, 200);
  assert.equal(f.models.Report.rows.length, 1);
  const stored = f.models.Report.rows[0];
  for (const key of ['evidence', 'detail', 'adminNote', 'reporterNickname', 'targetConversationId']) assert.equal(stored[key], undefined, key);
  assert.ok(!JSON.stringify(stored).includes('The real selected message'));
  if (account === 'sender') assert.match(stored.targetUserId, /^deleted_/);
  else assert.match(stored.reporterId, /^deleted_/);
});

test('a delayed report creation holds both participants and prevents erasure from racing with copied evidence', { timeout: 8000 }, async t => {
  const f = await fixture(t), creating = deferred(), proceed = deferred();
  const create = f.models.Report.create;
  f.models.Report.create = async value => { creating.resolve(); await proceed.promise; return create(value); };
  const pending = f.report();
  try {
    await creating.promise;
    for (const id of ['sender', 'recipient']) assert.equal(f.models.User.rows.find(row => row.id === id).activeAccountOperations, 1);
    const blocked = await f.erase('sender');
    assert.equal(blocked.status, 409);
    assert.equal(blocked.data.code, 'ACCOUNT_OPERATIONS_PENDING');
  } finally { proceed.resolve(); }
  assert.equal((await pending).status, 200);
  await nextTurn();
  assert.equal((await f.erase('sender')).status, 200);
  assert.equal(f.models.Report.rows[0].evidence, undefined);
});

test('erasure winning before author acquisition refuses a late private report instead of restoring evidence', { timeout: 8000 }, async t => {
  const f = await fixture(t), acquiring = deferred(), proceed = deferred();
  const update = f.models.User.findOneAndUpdate;
  f.models.User.findOneAndUpdate = async (filter, changes, options) => {
    if (filter.id === 'sender' && changes.$inc?.activeAccountOperations === 1) { acquiring.resolve(); await proceed.promise; }
    return update(filter, changes, options);
  };
  const pending = f.report();
  try {
    await acquiring.promise;
    assert.equal((await f.erase('sender')).status, 200);
  } finally { proceed.resolve(); }
  assert.equal((await pending).status, 409);
  assert.equal(f.models.Report.rows.length, 0);
});

test('the real Mongo report schema accepts message reports rather than only a mock field', () => {
  const { models } = createApplication({ config: { NODE_ENV: 'test', JWT_SECRET: secret } });
  assert.ok(models.Report.schema.path('targetType').enumValues.includes('message'));
});

test('legacy repeated message IDs are resolved and deduplicated within the actual conversation', async t => {
  const f = await fixture(t);
  f.models.Conversation.rows.push({ id: 'another-thread', userIds: ['outsider', 'recipient'] });
  f.models.Message.rows.unshift({ id: 'real-message', conversationId: 'another-thread', senderId: 'outsider', type: 'text', content: 'Other thread message', createdAt: 0 });
  assert.equal((await f.report()).status, 200);
  assert.equal(f.models.Report.rows[0].targetUserId, 'sender');
  assert.equal(f.models.Report.rows[0].evidence.text, 'The real selected message');
  assert.equal((await f.report('real-message', 'recipient', { conversationId: 'another-thread' })).status, 200);
  assert.equal(f.models.Report.rows.length, 2);
  assert.equal(f.models.Report.rows[1].targetUserId, 'outsider');
  assert.equal(f.models.Report.rows[1].evidence.text, 'Other thread message');
  assert.equal((await f.report('real-message', 'recipient', { conversationId: 'another-thread' })).status, 400);
});
