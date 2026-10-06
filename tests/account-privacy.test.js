const test = require('node:test');
const assert = require('node:assert/strict');
const { EventEmitter } = require('node:events');
const { accountMemory } = require('./support/account-memory');
const { buildAccountExport, erasePostContacts, eraseAccountData, acquireAccountOperation, holdAccountOperation, holdPostOperation, runAccountHandler, registerAccountPrivacy } = require('../lib/accountPrivacy');
const { reactionKey } = require('../lib/memberSocial');

const names = ['User', 'Post', 'Message', 'Conversation', 'ContactRequest', 'UserBlock', 'EventInterest', 'PlannerAccount', 'Outing', 'ServiceBookingAgenda', 'PostTranslation', 'Report', 'ModerationLog', 'AccountAuthChallenge'];
const modelsFor = seed => Object.fromEntries(names.map(name => [name, accountMemory(seed[name] || [])]));
const own = { id: 'me', role: 'user', email: 'me@fixture.invalid', password: 'hashed-password', contactValue: 'my-private-phone' };

test('export includes only owned data and excludes received messages, contact cards and security secrets', () => {
  const result = buildAccountExport({ user: { ...own, accountSecurity: { secretCipher: 'secret' }, passwordResetTokenHash: 'reset', activeAccountOperations: 1 },
    posts: [{ id: 'p', authorId: 'me', title: 'Mine', contactPreference: { methods: [{ value: 'my-phone' }] }, reports: [{ detail: 'internal' }] }, { id: 'other', authorId: 'other', description: 'other-post' }],
    commentedPosts: [{ id: 'p', comments: [{ authorId: 'me', content: 'my-comment' }, { authorId: 'other', content: 'other-comment' }] }],
    messages: [{ id: 'm', senderId: 'me', type: 'text', content: 'my-text', replyTo: { content: 'received-secret' } }, { senderId: 'other', content: 'received-secret' }, { senderId: 'me', messageType: 'contact_card', content: 'other-phone', contactCard: { methods: [{ value: 'other-phone' }] } }],
    contactRequests: [{ requesterId: 'me', requestMessage: 'my-request', contactSnapshot: [{ value: 'other-phone' }] }, { requesterId: 'other', requestMessage: 'their-request' }],
    planner: { userId: 'me', plans: [{ title: 'My plan' }], receipts: [{ token: 'internal' }] }, interests: [],
    outings: [{ id: 'o', hostId: 'other', members: [{ userId: 'me', note: 'my-note' }, { userId: 'other', note: 'their-note' }], messages: [{ senderId: 'me', text: 'my-outing-text' }, { senderId: 'other', text: 'their-outing-text' }] }],
    agendas: [{ providerId: 'me', bookings: [{ customerId: 'other', note: 'their-booking-note', customerName: 'private-name' }] }, { providerId: 'other', bookings: [{ customerId: 'me', note: 'my-booking-note' }] }],
  });
  const text = JSON.stringify(result);
  for (const value of ['my-private-phone', 'my-phone', 'my-text', 'my-comment', 'my-note', 'my-outing-text', 'my-booking-note']) assert.ok(text.includes(value), value);
  for (const value of ['received-secret', 'other-phone', 'other-post', 'other-comment', 'their-request', 'their-note', 'their-outing-text', 'their-booking-note', 'private-name', 'hashed-password', 'secretCipher', 'passwordResetTokenHash', 'receipts', 'activeAccountOperations']) assert.ok(!text.includes(value), value);
});

test('post contact erasure removes snapshots, contact cards and old reply copies without deleting another post', async () => {
  const models = modelsFor({ Post: [{ id: 'mine', contactPreference: { methods: [{ value: 'private-1' }] } }, { id: 'other', contactPreference: { methods: [{ value: 'keep-private' }] } }],
    ContactRequest: [{ postId: 'mine', contactSnapshot: [{ value: 'private-1' }], sharedMethods: ['private-1'] }],
    Message: [{ id: 'card', contactCard: { postId: 'mine', methods: [{ value: 'private-1' }] }, content: 'private-1' }, { id: 'reply', replyTo: { id: 'card', content: 'private-1' } }],
  });
  await erasePostContacts(models, ['mine']);
  assert.deepEqual(models.Post.rows[0].contactPreference.methods, []);
  assert.equal(models.Post.rows[1].contactPreference.methods[0].value, 'keep-private');
  assert.deepEqual(models.ContactRequest.rows[0].contactSnapshot, []); assert.equal(models.ContactRequest.rows[0].sharedMethods, undefined);
  assert.deepEqual(models.Message.rows[0].contactCard.methods, []); assert.ok(!models.Message.rows[0].content.includes('private-1'));
  assert.equal(models.Message.rows[1].replyTo, undefined);
});

test('account erasure clears own private data across real schema containers and retains other people’s authored text', async () => {
  const models = modelsFor({ User: [{ ...own, accountDeletionPending: true }, { id: 'other' }],
    Post: [{ id: 'p', authorId: 'me', title: 'private-title', description: 'private-body', imageUrls: ['my-img'], comments: [], contactPreference: { methods: [{ value: 'my-phone' }] } }, { id: 'other-post', authorId: 'other', likes: ['me', 'other'], comments: [{ authorId: 'me', content: 'my-comment' }, { authorId: 'other', content: 'keep-comment' }], reports: [{ reporterId: 'me' }] }],
    Message: [{ id: 'sent', senderId: 'me', content: 'my-message' }, { id: 'received', senderId: 'other', content: 'keep-message', replyTo: { senderId: 'me', content: 'my-message' }, readBy: ['me', 'other'], reactionVotes: { [reactionKey('me')]: '👍' } }],
    Conversation: [{ id: 'conv', userIds: ['me', 'other'] }], ContactRequest: [{ requesterId: 'other', postOwnerId: 'me', contactSnapshot: ['my-phone'] }],
    UserBlock: [{ blockerId: 'other', blockedUserId: 'me' }], EventInterest: [{ userId: 'me' }], PlannerAccount: [{ userId: 'me', plans: ['private-plan'] }], PostTranslation: [{ postId: 'p', translation: 'private-body' }], AccountAuthChallenge: [{ userId: 'me' }],
    Outing: [{ id: 'hosted', hostId: 'me', title: 'my-group', members: [{ userId: 'other' }], messages: [{ senderId: 'me', text: 'my-note' }] }, { id: 'joined', hostId: 'other', members: [{ userId: 'me', note: 'my-note' }, { userId: 'other' }], messages: [{ senderId: 'me', text: 'my-note' }, { senderId: 'other', text: 'keep-group-text' }], notices: [{ actorId: 'me', text: 'my-note' }], timePoll: { votes: [{ userId: 'me' }, { userId: 'other' }] } }],
    ServiceBookingAgenda: [{ providerId: 'me', bookings: [{ customerId: 'other' }] }, { providerId: 'other', bookings: [{ customerId: 'me', note: 'my-note' }, { customerId: 'someone', note: 'keep-note' }] }],
    Report: [{ reporterId: 'me', targetUserId: 'other', detail: 'my-private-detail', evidence: ['private-evidence'], action: 'safety-action', createdAt: 1 }],
    ModerationLog: [{ targetUserId: 'me', previousValue: { phone: 'my-phone' }, note: 'my-note', action: 'status-changed', createdAt: 1 }],
  });
  const erasedNotifications = [];
  await eraseAccountData(models, own, { now: 5, eraseNotifications: async id => erasedNotifications.push(id) });
  assert.deepEqual(erasedNotifications, ['me']); assert.equal(models.User.rows.length, 1);
  assert.equal(models.Post.rows[0].isDeleted, true); assert.equal(models.Post.rows[0].description, ''); assert.match(models.Post.rows[0].authorId, /^deleted_/);
  assert.deepEqual(models.Post.rows[1].likes, ['other']); assert.equal(models.Post.rows[1].comments[0].content, 'keep-comment');
  assert.equal(models.Message.rows.length, 1); assert.equal(models.Message.rows[0].content, 'keep-message'); assert.equal(models.Message.rows[0].replyTo, undefined); assert.deepEqual(models.Message.rows[0].readBy, ['other']);
  assert.ok(!models.Conversation.rows[0].userIds.includes('me'));
  assert.equal(models.Outing.rows[0].status, 'cancelled'); assert.equal(models.Outing.rows[1].messages[0].text, 'keep-group-text'); assert.deepEqual(models.Outing.rows[1].timePoll.votes, [{ userId: 'other' }]);
  assert.equal(models.ServiceBookingAgenda.rows.length, 1); assert.equal(models.ServiceBookingAgenda.rows[0].bookings[0].note, 'keep-note');
  assert.equal(models.Report.rows[0].detail, undefined); assert.equal(models.Report.rows[0].action, 'safety-action'); assert.equal(models.ModerationLog.rows[0].previousValue, undefined);
  for (const name of ['ContactRequest', 'UserBlock', 'EventInterest', 'PlannerAccount', 'PostTranslation', 'AccountAuthChallenge']) assert.equal(models[name].rows.length, 0, name);
});

function privacyRoutes(seed = {}, failTransaction = false) {
  const models = modelsFor({ User: [own], ...seed }), routes = new Map(), disconnected = [];
  const withTransaction = async work => {
    const snapshot = Object.fromEntries(Object.entries(models).map(([name, model]) => [name, structuredClone(model.rows)]));
    try { const result = await work('mock-session'); if (failTransaction) throw new Error('Mock transaction unavailable'); return result; }
    catch (failure) { for (const [name, model] of Object.entries(models)) model.rows.splice(0, Infinity, ...snapshot[name]); throw failure; }
  };
  registerAccountPrivacy({ post: (path, ...handlers) => routes.set(path, handlers.at(-1)), delete: (path, ...handlers) => routes.set(path, handlers.at(-1)) }, {
    models, authenticateToken: () => {}, limit: () => {}, withTransaction, disconnectUser: id => disconnected.push(id),
    confirmCredentials: async req => { if (req.body.password !== 'current-password') throw Object.assign(new Error('Unconfirmed credentials'), { code: 'CREDENTIAL_CONFIRMATION_REQUIRED' }); return structuredClone(models.User.rows[0]); },
  });
  const call = async (path, body) => { let result; await routes.get(path)({ user: { id: 'me' }, body }, { json: value => { result = value; }, set: () => {} }); return result; };
  return { models, call, disconnected };
}

test('deletion requires a fresh credential and explicit irreversible confirmation, and protects administrator handover', async () => {
  const f = privacyRoutes();
  await assert.rejects(f.call('/api/users/me/privacy/account', { password: 'wrong', confirmation: 'DELETE MY ACCOUNT' }), { code: 'CREDENTIAL_CONFIRMATION_REQUIRED' });
  await assert.rejects(f.call('/api/users/me/privacy/account', { password: 'current-password', confirmation: 'delete' }), { code: 'DELETE_CONFIRMATION_REQUIRED' });
  assert.equal(f.models.User.rows.length, 1);
  const admin = privacyRoutes({ User: [{ ...own, role: 'admin' }] });
  await assert.rejects(admin.call('/api/users/me/privacy/account', { password: 'current-password', confirmation: 'DELETE MY ACCOUNT' }), { code: 'ADMIN_HANDOVER_REQUIRED' });
  assert.equal(admin.models.User.rows[0].accountDeletionPending, undefined);
});

test('DB-backed account request gate refuses deletion with active work and releases exactly once', async () => {
  const f = privacyRoutes(), response = new EventEmitter();
  const release = await acquireAccountOperation(f.models.User, 'me'); assert.equal(f.models.User.rows[0].activeAccountOperations, 1);
  await assert.rejects(f.call('/api/users/me/privacy/account', { password: 'current-password', confirmation: 'DELETE MY ACCOUNT' }), { code: 'ACCOUNT_OPERATIONS_PENDING' });
  release(); release(); await new Promise(resolve => setImmediate(resolve));
  assert.equal(f.models.User.rows[0].activeAccountOperations, 0);
  assert.equal((await f.call('/api/users/me/privacy/account', { password: 'current-password', confirmation: 'DELETE MY ACCOUNT' })).success, true);
  assert.equal(f.models.User.rows.length, 0); assert.deepEqual(f.disconnected, ['me']);
});

test('disconnecting a client cannot release an account gate while its async handler is still writing', async () => {
  const User = accountMemory([own, { id: 'target' }]), request = {}, response = new EventEmitter();
  let continueWrite; const pendingWrite = new Promise(resolve => { continueWrite = resolve; });
  let ready; const started = new Promise(resolve => { ready = resolve; });
  const handler = runAccountHandler(request, response, async () => {
    await holdAccountOperation(User, 'me'); await holdAccountOperation(User, 'target'); await holdAccountOperation(User, 'target'); ready();
    await pendingWrite;
    assert.equal(User.rows[1].activeAccountOperations, 1);
  });
  await started; response.emit('close');
  assert.equal(User.rows[0].activeAccountOperations, 1); assert.equal(User.rows[1].activeAccountOperations, 1);
  continueWrite(); await handler; await new Promise(resolve => setImmediate(resolve));
  assert.equal(User.rows[0].activeAccountOperations, 0); assert.equal(User.rows[1].activeAccountOperations, 0);
});

test('shared post mutation gate prevents account erasure from racing a whole comments-array save', async () => {
  const models = modelsFor({ User: [{ ...own, accountDeletionPending: true }], Post: [{ id: 'shared', authorId: 'other', comments: [{ authorId: 'me', content: 'my-private-comment' }] }] });
  const response = new EventEmitter();
  await runAccountHandler({}, response, async () => {
    await holdPostOperation(models.Post, 'shared');
    await assert.rejects(eraseAccountData(models, own), { code: 'ACCOUNT_OPERATIONS_PENDING' });
    assert.equal(models.Post.rows[0].comments[0].content, 'my-private-comment');
    response.emit('finish');
  });
  await new Promise(resolve => setImmediate(resolve));
  assert.equal(models.Post.rows[0].activePostOperations, 0);
  await eraseAccountData(models, own); assert.deepEqual(models.Post.rows[0].comments, []);
});

test('failed deletion transaction restores all authored data, reopens login and keeps old sessions revoked', async () => {
  const f = privacyRoutes({ Post: [{ id: 'p', authorId: 'me', description: 'must-stay', contactPreference: { methods: ['must-stay-private'] } }] }, true);
  await assert.rejects(f.call('/api/users/me/privacy/account', { password: 'current-password', confirmation: 'DELETE MY ACCOUNT' }), /Mock transaction/);
  assert.equal(f.models.User.rows[0].accountDeletionPending, false); assert.equal(f.models.User.rows[0].sessionRevision, 1);
  assert.equal(f.models.Post.rows[0].description, 'must-stay'); assert.deepEqual(f.models.Post.rows[0].contactPreference.methods, ['must-stay-private']);
  const pending = modelsFor({ User: [{ ...own, accountDeletionPending: true }] });
  await assert.rejects(acquireAccountOperation(pending.User, 'me', new EventEmitter()), { code: 'ACCOUNT_CHANGED' });
});

test('revoke-all requires current credentials and rotates the session revision without deleting the account', async () => {
  const f = privacyRoutes(); await assert.rejects(f.call('/api/users/me/security/revoke-sessions', { password: 'wrong' }), { code: 'CREDENTIAL_CONFIRMATION_REQUIRED' });
  await f.call('/api/users/me/security/revoke-sessions', { password: 'current-password' });
  assert.equal(f.models.User.rows[0].sessionRevision, 1); assert.ok(f.models.User.rows[0].sessionsRevokedAt); assert.equal(f.models.User.rows.length, 1); assert.deepEqual(f.disconnected, ['me']);
});
