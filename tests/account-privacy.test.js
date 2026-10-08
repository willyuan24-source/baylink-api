const test = require('node:test');
const assert = require('node:assert/strict');
const { EventEmitter } = require('node:events');
const { accountMemory, conflictingUpdatePath } = require('./support/account-memory');
const { buildAccountExport, erasePostContacts, eraseAccountData, acquireAccountOperation, holdAccountOperation, holdPostOperation, runAccountHandler, registerAccountPrivacy, confirmsDeletion, DELETE_CONFIRMATIONS } = require('../lib/accountPrivacy');
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

test('account erasure clears traceable owned translations and all unowned legacy hashes, retaining other traceable posts', async () => {
  const models = modelsFor({ User: [{ ...own, accountDeletionPending: true }],
    Post: [{ id: 'mine', authorId: 'me', title: 'Edited public title', description: 'Current body', likes: [], comments: [], reports: [] }],
    PostTranslation: [
      { id: 'post-translation:mine:current-hash', postId: 'mine', translation: { description: 'my-private-phone' } },
      // The old source was edited: its hash cannot be recovered from the current post.
      { id: 'f'.repeat(64), translation: { description: 'my-previous-private-phone' }, expiresAt: new Date('2027-01-01') },
      { id: 'post-translation:someone:their-hash', postId: 'someone', translation: { description: 'keep-public-translation' } },
    ],
  });
  await eraseAccountData(models, own);
  assert.deepEqual(models.PostTranslation.rows.map(row => row.postId), ['someone']);
  assert.equal(models.PostTranslation.rows[0].translation.description, 'keep-public-translation');
  assert.ok(!JSON.stringify(models.PostTranslation.rows).includes('private-phone'));
});

function privacyRoutes(seed = {}, failTransaction = false) {
  const models = modelsFor({ User: [own], ...seed }), routes = new Map(), disconnected = [];
  const withTransaction = async work => {
    const snapshot = Object.fromEntries(Object.entries(models).map(([name, model]) => [name, structuredClone(model.rows)]));
    try { const result = await work('mock-session'); if (failTransaction) throw failTransaction instanceof Error ? failTransaction : new Error('Mock transaction unavailable'); return result; }
    catch (failure) { for (const [name, model] of Object.entries(models)) model.rows.splice(0, Infinity, ...snapshot[name]); throw failure; }
  };
  registerAccountPrivacy({ post: (path, ...handlers) => routes.set(path, handlers.at(-1)), delete: (path, ...handlers) => routes.set(path, handlers.at(-1)) }, {
    models, authenticateToken: () => {}, limit: () => {}, withTransaction, disconnectUser: id => disconnected.push(id), reopenDelayMs: 0,
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

test('failed deletion transaction restores all authored data, reopens the account and keeps the owner signed in', async () => {
  const f = privacyRoutes({ Post: [{ id: 'p', authorId: 'me', description: 'must-stay', contactPreference: { methods: ['must-stay-private'] } }] },
    Object.assign(new Error('Mock transaction unavailable'), { name: 'MongoServerError', code: 112 }));
  await assert.rejects(f.call('/api/users/me/privacy/account', { password: 'current-password', confirmation: 'DELETE MY ACCOUNT' }), failure => {
    assert.equal(failure.status, 500); assert.equal(failure.code, 'ACCOUNT_DELETE_FAILED'); assert.equal(failure.publicSafe, true);
    assert.match(failure.message, /仍保持登录/); assert.deepEqual(failure.cause, { name: 'MongoServerError', code: 112 });
    assert.ok(!failure.message.includes('Mock transaction'));
    return true;
  });
  const user = f.models.User.rows[0];
  assert.equal(user.accountDeletionPending, false); assert.equal(user.accountDeletionClaim, undefined);
  // No session rotation: the token that asked for deletion still verifies after a failure.
  assert.equal(user.sessionRevision, undefined); assert.equal(user.sessionsRevokedAt, undefined);
  assert.equal(f.models.Post.rows[0].description, 'must-stay'); assert.deepEqual(f.models.Post.rows[0].contactPreference.methods, ['must-stay-private']);
  const pending = modelsFor({ User: [{ ...own, accountDeletionPending: true }] });
  await assert.rejects(acquireAccountOperation(pending.User, 'me', new EventEmitter()), { code: 'ACCOUNT_CHANGED' });
});

test('the Mongo mock rejects conflicting operator paths the way MongoDB does (code 40), even when nothing matches', async () => {
  assert.equal(conflictingUpdatePath({ $pull: { userIds: 'me' }, $addToSet: { userIds: 'deleted_x' } }), 'userIds');
  assert.equal(conflictingUpdatePath({ $set: { profile: {} }, $unset: { 'profile.phone': 1 } }), 'profile');
  assert.equal(conflictingUpdatePath({ $set: { 'a.b': 1, 'a.bc': 2 }, $inc: { ab: 1 } }), null);
  const Conversation = accountMemory([]);
  await assert.rejects(Conversation.updateMany({ userIds: 'nobody' }, { $pull: { userIds: 'me' }, $addToSet: { userIds: 'deleted_x' } }), { code: 40, codeName: 'ConflictingUpdateOperators' });
  await assert.rejects(Conversation.updateOne({}, { $set: { a: 1 }, $inc: { 'a.b': 1 } }), { code: 40 });
  await assert.rejects(Conversation.findOneAndUpdate({}, { $set: { a: 1 }, $unset: { a: 1 } }), { code: 40 });
});

test('deleting an account with a direct-message thread succeeds and the other member keeps the thread', async () => {
  const f = privacyRoutes({
    Conversation: [{ id: 'conv', userIds: ['me', 'other'] }, { id: 'unrelated', userIds: ['other', 'third'] }],
    Message: [{ id: 'mine', conversationId: 'conv', senderId: 'me', content: 'my-message' }, { id: 'theirs', conversationId: 'conv', senderId: 'other', content: 'keep-message', readBy: ['me', 'other'] }],
  });
  const result = await f.call('/api/users/me/privacy/account', { password: 'current-password', confirmation: '注销我的账号' });
  assert.equal(result.success, true); assert.equal(f.models.User.rows.length, 0);
  const [conv, unrelated] = f.models.Conversation.rows;
  assert.equal(conv.userIds.length, 2); assert.equal(conv.userIds[0], 'other'); assert.match(conv.userIds[1], /^deleted_/);
  assert.deepEqual(unrelated.userIds, ['other', 'third']);
  assert.deepEqual(f.models.Message.rows.map(row => [row.id, row.content, row.readBy]), [['theirs', 'keep-message', ['other']]]);
});

test('deletion accepts the confirmation phrase in each site language and explains the phrase in the reader’s language', async () => {
  for (const phrase of [...Object.values(DELETE_CONFIRMATIONS), '注销我的帐号', '註銷我的賬號', ' delete  my account ', '注销 我的账号']) assert.equal(confirmsDeletion(phrase), true, phrase);
  for (const phrase of ['', 'delete', 'DELETE MY ACCOUNTS', '删除我的账号', '注销账号', null, 42]) assert.equal(confirmsDeletion(phrase), false, String(phrase));
  for (const [locale, pattern] of [['zh-Hans', /注销我的账号/], ['zh-Hant', /註銷我的帳號/], ['en', /^Type DELETE MY ACCOUNT/], [undefined, /注销我的账号/]]) {
    const f = privacyRoutes();
    await assert.rejects(f.call('/api/users/me/privacy/account', { password: 'current-password', confirmation: 'delete', locale }), failure => failure.code === 'DELETE_CONFIRMATION_REQUIRED' && failure.status === 400 && pattern.test(failure.message));
    assert.equal(f.models.User.rows[0].accountDeletionPending, undefined);
  }
  const hant = privacyRoutes();
  assert.equal((await hant.call('/api/users/me/privacy/account', { password: 'current-password', confirmation: '註銷我的帳號', locale: 'zh-Hant' })).success, true);
  assert.equal(hant.models.User.rows.length, 0);
});

test('a refused reopen after a failed erasure reports an interrupted deletion instead of a generic error', async () => {
  const f = privacyRoutes({}, true);
  const reopen = f.models.User.updateOne; let attempts = 0;
  f.models.User.updateOne = async (filter, changes) => { if (filter.accountDeletionClaim) { attempts++; throw new Error('primary stepped down'); } return reopen(filter, changes); };
  await assert.rejects(f.call('/api/users/me/privacy/account', { password: 'current-password', confirmation: 'DELETE MY ACCOUNT', locale: 'en' }),
    failure => failure.status === 503 && failure.code === 'ACCOUNT_DELETE_INTERRUPTED' && /temporarily unavailable/.test(failure.message));
  assert.equal(attempts, 3);
  // A public, retryable refusal from inside erasure keeps its own status and code.
  const busy = privacyRoutes({ Post: [{ id: 'shared', authorId: 'other', likes: ['me'], activePostOperations: 1 }] });
  await assert.rejects(busy.call('/api/users/me/privacy/account', { password: 'current-password', confirmation: 'DELETE MY ACCOUNT' }), { status: 409, code: 'ACCOUNT_OPERATIONS_PENDING' });
  assert.equal(busy.models.User.rows[0].accountDeletionPending, false);
});

test('revoke-all requires current credentials and rotates the session revision without deleting the account', async () => {
  const f = privacyRoutes(); await assert.rejects(f.call('/api/users/me/security/revoke-sessions', { password: 'wrong' }), { code: 'CREDENTIAL_CONFIRMATION_REQUIRED' });
  await f.call('/api/users/me/security/revoke-sessions', { password: 'current-password' });
  assert.equal(f.models.User.rows[0].sessionRevision, 1); assert.ok(f.models.User.rows[0].sessionsRevokedAt); assert.equal(f.models.User.rows.length, 1); assert.deepEqual(f.disconnected, ['me']);
});
