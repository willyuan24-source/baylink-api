const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { createApplication } = require('../server');
const { createMemoryModels } = require('./support/memory-models');

const SECRET = 'isolated-audit-secret-with-more-than-32-characters';
const password = 'FixturePassword7';
const hashed = bcrypt.hashSync(password, 4);
const makeUser = (id, role = 'user') => ({ id, email: `${id}@example.test`, nickname: `Neighbor ${id}`, password: hashed, role, accountStatus: 'active' });
const makeRequest = (id = 'request') => ({ id, postId: 'listing', postOwnerId: 'owner', requesterId: 'other', status: 'pending', createdAt: Date.now() });
async function fixture(t, seed = {}) {
  const models = createMemoryModels({
    User: [makeUser('owner'), makeUser('other'), makeUser('admin', 'admin')],
    Post: [{ id: 'listing', authorId: 'owner', title: 'Local fixture', isDeleted: false, status: 'active', contactPreference: { mode: 'manual_approve', methods: [{ type: 'wechat', value: 'fictional-private-value', enabled: true }] } }],
    Conversation: [{ id: 'existing', userIds: ['owner', 'other'], updatedAt: 1 }],
    ContactRequest: [makeRequest()], ...seed,
  });
  const application = createApplication({ config: { NODE_ENV: 'test', JWT_SECRET: SECRET }, models });
  await new Promise(resolve => application.server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise(resolve => application.io.close(resolve)));
  const base = `http://127.0.0.1:${application.server.address().port}/api`;
  const tokens = Object.fromEntries(['owner', 'other', 'admin'].map(id => [id, jwt.sign({ id, sessionIssuedAt: Date.now() }, SECRET, { expiresIn: '1h' })]));
  const request = async (path, { as = 'owner', method = 'GET', body } = {}) => {
    const response = await fetch(base + path, { method, headers: { ...(as ? { Authorization: `Bearer ${tokens[as]}` } : {}), ...(body !== undefined ? { 'Content-Type': 'application/json' } : {}) }, ...(body !== undefined ? { body: JSON.stringify(body) } : {}) });
    const raw = await response.text();
    let data;
    try { data = JSON.parse(raw); } catch { data = raw; }
    return { status: response.status, data };
  };
  return { models, request, tokens, io: application.io };
}

// Freeze two genuine read results before either request continues. This makes
// the database race deterministic without requiring Mongo or a real account.
function synchronizeReads(model, matches) {
  const original = model.findOne;
  let arrivals = 0;
  let release;
  const barrier = new Promise(resolve => { release = resolve; });
  model.findOne = query => {
    const result = original(query);
    if (!matches(query) || arrivals >= 2) return result;
    result.then = (resolve, reject) => result.exec().then(async value => {
      arrivals += 1;
      if (arrivals === 2) release();
      await barrier;
      return value;
    }).then(resolve, reject);
    return result;
  };
}

test('contact approval rechecks a block even when the users already have a conversation', async t => {
  for (const [blockerId, blockedUserId] of [['owner', 'other'], ['other', 'owner']]) {
    const { models, request } = await fixture(t, { UserBlock: [{ id: 'block', blockerId, blockedUserId }] });
    const response = await request('/contact-requests/request/approve', { method: 'PATCH', body: {} });
    assert.equal(response.status, blockerId === 'owner' ? 400 : 403);
    assert.equal(models.Message.rows.length, 0, 'a blocked contact must never receive the private card');
    assert.equal(models.ContactRequest.rows[0].status, 'pending');
  }
});

test('administrative contact approval preserves the actual post owner and recipient', async t => {
  const { models, request } = await fixture(t);
  const response = await request('/contact-requests/request/approve', { as: 'admin', method: 'PATCH', body: {} });
  assert.equal(response.status, 200);
  assert.equal(response.data.threadId, 'existing');
  assert.equal(models.Message.rows[0].senderId, 'owner');
  assert.equal(models.Message.rows[0].conversationId, 'existing');
  assert.equal(models.Conversation.rows.length, 1);
});

test('two simultaneous first-contact opens use the same persisted conversation in either direction', async t => {
  const { models, request } = await fixture(t, { Conversation: [] });
  synchronizeReads(models.Conversation, query => Boolean(query.userIds));
  const responses = await Promise.all([
    request('/conversations/open-or-create', { method: 'POST', body: { targetUserId: 'other' } }),
    request('/conversations/open-or-create', { as: 'other', method: 'POST', body: { targetUserId: 'owner' } }),
  ]);
  assert.deepEqual(responses.map(response => response.status), [200, 200]);
  assert.equal(responses[0].data.id, responses[1].data.id);
  assert.equal(models.Conversation.rows.length, 1);
  assert.deepEqual([...models.Conversation.rows[0].userIds].sort(), ['other', 'owner']);
});

test('conversation opens preserve legacy IDs and never select a thread with a third member', async t => {
  const legacy = await fixture(t);
  const reopened = await legacy.request('/conversations/open-or-create', { method: 'POST', body: { targetUserId: 'other' } });
  assert.equal(reopened.data.id, 'existing');
  assert.equal(legacy.models.Conversation.rows.length, 1);
  const group = await fixture(t, { Conversation: [{ id: 'three-members', userIds: ['owner', 'other', 'admin'], updatedAt: 1 }] });
  const opened = await group.request('/conversations/open-or-create', { method: 'POST', body: { targetUserId: 'other' } });
  assert.equal(opened.status, 200);
  assert.notEqual(opened.data.id, 'three-members');
  assert.equal(opened.data.userIds.length, 2);
});

test('a racing conversation upsert recovers its unique-index winner without opening another thread', async t => {
  const { models, request } = await fixture(t, { Conversation: [] });
  const update = models.Conversation.findOneAndUpdate;
  let attempts = 0;
  models.Conversation.findOneAndUpdate = async (query, mutation, options) => {
    const result = await update(query, mutation, options);
    if (options.upsert && attempts++ === 0) throw Object.assign(new Error('Simulated competing insert'), { code: 11000 });
    return result;
  };
  const opened = await request('/conversations/open-or-create', { method: 'POST', body: { targetUserId: 'other' } });
  assert.equal(opened.status, 200);
  assert.equal(models.Conversation.rows.length, 1);
  assert.equal(opened.data.id, models.Conversation.rows[0].id);
});

test('a reset token can replace the password only once, including simultaneous submissions', async t => {
  const resetToken = 'fictional-reset-token';
  const user = { ...makeUser('owner'), passwordResetTokenHash: crypto.createHash('sha256').update(resetToken).digest('hex'), passwordResetExpires: Date.now() + 60000 };
  const { models, request } = await fixture(t, { User: [user, makeUser('other')] });
  synchronizeReads(models.User, query => Boolean(query.passwordResetTokenHash));
  const newPasswords = ['FirstReplacement8', 'SecondReplacement9'];
  const results = await Promise.all(newPasswords.map(newPassword => request('/auth/reset-password', { as: null, method: 'POST', body: { token: resetToken, newPassword } })));
  assert.deepEqual(results.map(result => result.status).sort(), [200, 400]);
  const winner = results.findIndex(result => result.status === 200);
  assert.equal(await bcrypt.compare(newPasswords[winner], models.User.rows[0].password), true);
  assert.equal(models.User.rows[0].passwordResetTokenHash, undefined);
  assert.equal((await request('/users/me/posts')).status, 401, 'password reset must revoke the previously issued session');
});

test('direct messages normalize the default type and reject non-text structures', async t => {
  const { models, request } = await fixture(t);
  const sent = await request('/conversations/existing/messages', { method: 'POST', body: { content: 'Hello neighbor' } });
  assert.equal(sent.status, 200);
  assert.equal(sent.data.type, 'text');
  assert.equal((await request('/conversations/existing/messages')).data[0].type, 'text');
  for (const body of [{ type: {}, content: 'hello' }, { type: 'text', content: { text: 'hello' } }, { type: 'text', content: ['hello'] }]) {
    assert.equal((await request('/conversations/existing/messages', { method: 'POST', body })).status, 400);
  }
  assert.equal(models.Message.rows.length, 1);
});

test('a delayed decline cannot overwrite a request that was approved in another tab', async t => {
  const { models, request } = await fixture(t);
  let release;
  let started;
  const barrier = new Promise(resolve => { release = resolve; });
  const entered = new Promise(resolve => { started = resolve; });
  const find = models.ContactRequest.findOne;
  const update = models.ContactRequest.findOneAndUpdate;
  let held = false;
  models.ContactRequest.findOne = query => {
    const result = find(query);
    if (!held && query.id === 'request' && query.status === undefined) {
      held = true;
      result.then = (resolve, reject) => result.exec().then(async value => { started(); await barrier; return value; }).then(resolve, reject);
    }
    return result;
  };
  models.ContactRequest.findOneAndUpdate = async (query, mutation, options) => {
    if (!held && mutation.$set?.status === 'declined') { held = true; started(); await barrier; }
    return update(query, mutation, options);
  };
  const declining = request('/contact-requests/request/decline', { method: 'PATCH', body: {} });
  await entered;
  try {
    const approved = await request('/contact-requests/request/approve', { method: 'PATCH', body: {} });
    assert.equal(approved.status, 200);
  } finally { release(); }
  const declined = await declining;
  assert.equal(declined.status, 400);
  assert.equal(models.ContactRequest.rows[0].status, 'approved');
  assert.equal(models.ContactRequest.rows[0].messageId, models.Message.rows[0].id);
  assert.equal(models.ContactRequest.rows[0].threadId, 'existing');
});

test('only the owner or administrator can decide a pending contact request, and a decline is final', async t => {
  const { models, request } = await fixture(t);
  for (const action of ['approve', 'decline']) {
    assert.equal((await request(`/contact-requests/request/${action}`, { as: 'other', method: 'PATCH', body: {} })).status, 403);
    assert.equal(models.ContactRequest.rows[0].status, 'pending');
  }
  assert.equal((await request('/contact-requests/request/decline', { method: 'PATCH', body: {} })).status, 200);
  assert.equal((await request('/contact-requests/request/approve', { method: 'PATCH', body: {} })).status, 400);
  assert.equal(models.ContactRequest.rows[0].status, 'declined');
  assert.equal(models.Message.rows.length, 0);
});

test('contact approval retries recover downstream failures without duplicating or changing the saved card', async t => {
  for (const failure of ['conversation-update', 'socket-notification', 'request-save']) {
    await t.test(failure, async t => {
      const { models, request, io } = await fixture(t);
      let failOnce = true;
      if (failure === 'conversation-update') {
        const update = models.Conversation.findOneAndUpdate;
        models.Conversation.findOneAndUpdate = async (query, mutation, options) => {
          if (failOnce && query.id === 'existing' && mutation.updatedAt) { failOnce = false; throw new Error('Simulated conversation update failure'); }
          return update(query, mutation, options);
        };
      } else if (failure === 'socket-notification') {
        const inRoom = io.in.bind(io);
        io.in = room => {
          const operator = inRoom(room);
          const fetchSockets = operator.fetchSockets.bind(operator);
          operator.fetchSockets = async () => {
            if (failOnce) { failOnce = false; throw new Error('Simulated socket adapter failure'); }
            return fetchSockets();
          };
          return operator;
        };
      } else {
        const update = models.ContactRequest.findOneAndUpdate;
        models.ContactRequest.findOneAndUpdate = async (query, mutation, options) => {
          const document = await update(query, mutation, options);
          if (document && mutation.$set?.status === 'approved') {
            const save = document.save.bind(document);
            document.save = async () => {
              if (failOnce) { failOnce = false; throw new Error('Simulated request metadata failure'); }
              return save();
            };
          }
          return document;
        };
      }
      const first = await request('/contact-requests/request/approve', { method: 'PATCH', body: {} });
      assert.equal(first.status, 500);
      assert.equal(models.Message.rows.length, 1);
      const original = structuredClone(models.Message.rows[0]);
      assert.equal(models.ContactRequest.rows[0].status, 'pending');
      models.Post.rows[0].contactPreference.methods[0].value = 'changed-after-the-card-was-sent';
      const retried = await request('/contact-requests/request/approve', { method: 'PATCH', body: {} });
      assert.equal(retried.status, 200);
      assert.equal(models.Message.rows.length, 1, `${failure} retry must reuse the committed card`);
      assert.deepEqual(models.Message.rows[0], original);
      assert.equal(models.ContactRequest.rows[0].status, 'approved');
      assert.equal(models.ContactRequest.rows[0].messageId, original.id);
      assert.equal(models.ContactRequest.rows[0].sentAt, original.createdAt);
      assert.deepEqual(models.ContactRequest.rows[0].contactSnapshot, original.contactCard.methods);
    });
  }
});

test('contact approval recovery reuses a legacy card with a random ID', async t => {
  const legacy = { id: 'legacy-random-card-id', conversationId: 'existing', senderId: 'owner', type: 'contact_card', messageType: 'contact_card', content: 'BAYLINK 联系方式卡片', createdAt: 123, contactCard: { postId: 'listing', contactRequestId: 'request', methods: [{ type: 'wechat', value: 'original-legacy-contact' }] } };
  const { models, request } = await fixture(t, { Message: [legacy] });
  const response = await request('/contact-requests/request/approve', { method: 'PATCH', body: {} });
  assert.equal(response.status, 200);
  assert.equal(models.Message.rows.length, 1);
  assert.equal(response.data.request.messageId, legacy.id);
  assert.deepEqual(models.ContactRequest.rows[0].contactSnapshot, legacy.contactCard.methods);
});

test('contact card upsert handles a lost write acknowledgement and a unique-index race', async t => {
  for (const failure of ['lost-acknowledgement', 'duplicate-key']) {
    const { models, request } = await fixture(t);
    const update = models.Message.findOneAndUpdate;
    let failOnce = true;
    models.Message.findOneAndUpdate = async (query, mutation, options) => {
      const document = await update(query, mutation, options);
      if (options.upsert && failOnce) {
        failOnce = false;
        throw Object.assign(new Error(`Simulated ${failure}`), failure === 'duplicate-key' ? { code: 11000 } : {});
      }
      return document;
    };
    const first = await request('/contact-requests/request/approve', { method: 'PATCH', body: {} });
    if (failure === 'lost-acknowledgement') {
      assert.equal(first.status, 500);
      assert.equal((await request('/contact-requests/request/approve', { method: 'PATCH', body: {} })).status, 200);
    } else assert.equal(first.status, 200);
    assert.equal(models.Message.rows.length, 1);
    assert.equal(models.ContactRequest.rows[0].messageId, models.Message.rows[0].id);
    assert.equal(models.ContactRequest.rows[0].status, 'approved');
  }
});
