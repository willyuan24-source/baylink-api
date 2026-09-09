const test = require('node:test');
const assert = require('node:assert/strict');
const { once } = require('node:events');
const jwt = require('jsonwebtoken');
const { io: connectSocket } = require('socket.io-client');
const { createApplication } = require('../server');
const { createMemoryModels } = require('./support/memory-models');
const { validateProfileImage, PROFILE_IMAGE_MAX_BYTES, reactionKey, publicMessage } = require('../lib/memberSocial');

const SECRET = 'isolated-social-test-secret-with-more-than-32-characters';
const user = (id, fields = {}) => ({ id, nickname: `Neighbor ${id}`, email: `${id}@example.test`, password: '$2-fake', role: 'user', accountStatus: 'active', ...fields });
const text = (id, senderId = 'other', fields = {}) => ({ id, conversationId: 'thread', senderId, type: 'text', content: `Message ${id}`, createdAt: 1000, ...fields });
const png = 'data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAwMCAO+a/q8AAAAASUVORK5CYII=';

async function fixture(t, options = {}) {
  const models = createMemoryModels({
    User: [user('owner', {
      city: 'Oakland', avatar: 'https://res.cloudinary.com/example/avatar.webp', coverImage: 'https://res.cloudinary.com/example/cover.webp',
      email: 'never-public@example.test', phone: 'private-phone', passwordResetTokenHash: 'private-reset', phoneVerificationCodeHash: 'private-code', accountStatusReason: 'private-reason',
      contactType: 'wechat', contactValue: 'private-contact',
    }), user('other'), user('outsider')],
    Conversation: [{ id: 'thread', userIds: ['owner', 'other'], updatedAt: 1000 }, { id: 'elsewhere', userIds: ['other', 'outsider'], updatedAt: 1000 }],
    Message: options.messages || [],
  });
  const application = createApplication({ config: { NODE_ENV: 'test', JWT_SECRET: SECRET }, models, ...(options.upload ? { uploadProfileImage: options.upload } : {}) });
  await new Promise(resolve => application.server.listen(0, '127.0.0.1', resolve));
  const url = `http://127.0.0.1:${application.server.address().port}`;
  t.after(() => new Promise(resolve => application.io.close(resolve)));
  const tokens = Object.fromEntries(['owner', 'other', 'outsider'].map(id => [id, jwt.sign({ id, sessionIssuedAt: Date.now() }, SECRET, { algorithm: 'HS256', expiresIn: '1h' })]));
  const request = async (path, { as = 'owner', method = 'GET', body } = {}) => {
    const response = await fetch(`${url}/api${path}`, {
      method, headers: { ...(as ? { Authorization: `Bearer ${tokens[as]}` } : {}), ...(body !== undefined ? { 'Content-Type': 'application/json' } : {}) },
      ...(body !== undefined ? { body: JSON.stringify(body) } : {}),
    });
    const raw = await response.text();
    let data;
    try { data = JSON.parse(raw); } catch { data = raw; }
    return { status: response.status, data };
  };
  return { ...application, models, tokens, url, request };
}
const event = (socket, name) => Promise.race([
  once(socket, name),
  new Promise((_, reject) => { const timer = setTimeout(() => reject(new Error(`Timed out waiting for ${name}`)), 2000); timer.unref(); }),
]);

test('personalization is bounded, defaults old accounts, and exposes only public fields to other people', async t => {
  const { request, models } = await fixture(t);
  const patch = await request('/users/me', { method: 'PATCH', body: { profileTheme: 'lavender', statusText: '  周末想去海边散步 🌊  ', role: 'admin', isPhoneVerified: true } });
  assert.equal(patch.status, 200);
  assert.equal(patch.data.profileTheme, 'lavender');
  assert.equal(patch.data.statusText, '周末想去海边散步 🌊');
  assert.equal(patch.data.role, 'user');
  for (const field of ['password', 'passwordResetTokenHash', 'phoneVerificationCodeHash', 'accountStatusReason']) assert.equal(patch.data[field], undefined);
  for (const path of ['/users/owner', '/users/owner/public']) {
    const profile = (await request(path, { as: null })).data;
    assert.equal(profile.profileTheme, 'lavender');
    assert.equal(profile.statusText, '周末想去海边散步 🌊');
    assert.match(profile.coverImage, /^https:\/\//);
    for (const field of ['email', 'password', 'phone', 'contactType', 'contactValue', 'passwordResetTokenHash', 'phoneVerificationCodeHash', 'accountStatusReason']) assert.equal(profile[field], undefined, `${path} leaked ${field}`);
  }
  const conversations = (await request('/conversations', { as: 'other' })).data;
  const other = conversations.find(item => item.id === 'thread').otherUser;
  assert.equal(other.profileTheme, 'lavender');
  assert.equal(other.city, 'Oakland');
  assert.equal(other.statusText, '周末想去海边散步 🌊');
  assert.equal(other.email, undefined);
  const opened = await request('/conversations/open-or-create', { as: 'other', method: 'POST', body: { targetUserId: 'owner' } });
  assert.deepEqual(opened.data.otherUser, other);
  assert.equal((await request('/users/other')).data.profileTheme, 'bay');
  for (const body of [{ profileTheme: 'invalid' }, { profileTheme: {} }, { statusText: null }, { statusText: 'x'.repeat(61) }]) assert.equal((await request('/users/me', { method: 'PATCH', body })).status, 400);
  assert.equal(models.User.rows[0].statusText, '周末想去海边散步 🌊');
});

test('avatar and cover use validated bounded raster uploads, explicit failure, and removal', async t => {
  const uploads = [];
  const { request, models } = await fixture(t, { upload: async data => { uploads.push(data); return `https://res.cloudinary.com/example/upload-${uploads.length}.png`; } });
  const invalid = [null, {}, 'https://arbitrary.example/image.png', 'data:image/svg+xml;base64,PHN2Zz48L3N2Zz4=', 'data:image/png;base64,aGVsbG8=', png + '!', `data:image/png;base64,${Buffer.alloc(PROFILE_IMAGE_MAX_BYTES + 1).toString('base64')}`];
  for (const value of invalid) {
    assert.equal((await request('/users/me', { method: 'PATCH', body: { coverImage: value, statusText: 'Must not save' } })).status, 400);
    assert.equal((await request('/users/me', { method: 'PATCH', body: { avatar: value } })).status, 400);
  }
  assert.equal(uploads.length, 0);
  assert.equal(models.User.rows[0].statusText, undefined);
  const saved = await request('/users/me', { method: 'PATCH', body: { avatar: png, coverImage: png } });
  assert.equal(saved.status, 200);
  assert.equal(uploads.length, 2);
  assert.equal(saved.data.coverImage, 'https://res.cloudinary.com/example/upload-2.png');
  const unchanged = await request('/users/me', { method: 'PATCH', body: { avatar: saved.data.avatar, coverImage: saved.data.coverImage } });
  assert.equal(unchanged.status, 200);
  assert.equal(uploads.length, 2);
  await models.Post.create({ id: 'own-post', authorId: 'owner', authorAvatar: saved.data.avatar });
  const removed = await request('/users/me', { method: 'PATCH', body: { avatar: '', coverImage: '' } });
  assert.equal(removed.data.avatar, '');
  assert.equal(removed.data.coverImage, '');
  assert.equal(models.Post.rows[0].authorAvatar, '');
  assert.equal(validateProfileImage(png).ok, true);
});

test('failed image upload preserves the existing stored profile instead of claiming success', async t => {
  const { request, models } = await fixture(t, { upload: async () => { throw new Error('Simulated image provider failure'); } });
  const result = await request('/users/me', { method: 'PATCH', body: { coverImage: png, profileTheme: 'sunset', nickname: 'Another name' } });
  assert.equal(result.status, 502);
  assert.equal(models.User.rows[0].nickname, 'Neighbor owner');
  assert.equal(models.User.rows[0].profileTheme, undefined);
  assert.equal(models.User.rows[0].coverImage, 'https://res.cloudinary.com/example/cover.webp');
});

test('reply previews come only from same-thread text and never trust a client contact-card quote', async t => {
  const { request, models } = await fixture(t, { messages: [
    text('source', 'other', { content: '🌊'.repeat(200) }), text('foreign', 'other', { conversationId: 'elsewhere' }),
    text('contact', 'other', { type: 'contact_card', messageType: 'contact_card', content: 'private-contact', contactCard: { methods: [{ value: 'private-secret' }] } }),
    text('legacy-contact', 'other', { type: 'contact-share', content: 'private-contact' }),
  ] });
  const sent = await request('/conversations/thread/messages', { method: 'POST', body: { type: 'text', content: 'Sounds good!', replyToId: 'source', replyTo: { id: 'contact', content: 'forged-secret' }, reactions: [{ emoji: '👍', userIds: ['other'] }], readBy: ['other'] } });
  assert.equal(sent.status, 200);
  assert.deepEqual(sent.data.replyTo, { id: 'source', senderId: 'other', content: '🌊'.repeat(160) + '…' });
  assert.match(sent.data.id, /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/);
  assert.deepEqual(sent.data.reactions, []);
  assert.equal(sent.data.readBy, undefined);
  for (const replyToId of ['foreign', 'contact', 'legacy-contact', 'missing', { $ne: '' }]) {
    assert.equal((await request('/conversations/thread/messages', { method: 'POST', body: { type: 'text', content: 'Reject this', replyToId } })).status, 400);
  }
  assert.equal(models.Message.rows.length, 5);
  const list = await request('/conversations/thread/messages');
  assert.ok(Array.isArray(list.data));
  assert.deepEqual(list.data.at(-1).replyTo, sent.data.replyTo);
});

test('simultaneous member reactions remain independent, replace one vote, and remove idempotently', async t => {
  const { request, models } = await fixture(t, { messages: [text('message'), text('foreign', 'other', { conversationId: 'elsewhere' })] });
  const endpoint = '/conversations/thread/messages/message/reaction';
  const responses = await Promise.all(['owner', 'other'].map(as => request(endpoint, { as, method: 'PUT', body: { emoji: '👍', userId: 'outsider' } })));
  assert.ok(responses.every(result => result.status === 200));
  const getMessage = async () => (await request('/conversations/thread/messages')).data[0];
  let message = await getMessage();
  assert.deepEqual(message.reactions, [{ emoji: '👍', userIds: ['owner', 'other'] }]);
  assert.equal(message.reactionVersion, 2);
  assert.equal(message.reactionVotes, undefined);
  assert.equal(message.readBy, undefined);
  await request(endpoint, { method: 'PUT', body: { emoji: '❤️' } });
  await request(endpoint, { method: 'PUT', body: { emoji: '❤️' } });
  message = await getMessage();
  assert.deepEqual(message.reactions, [{ emoji: '👍', userIds: ['other'] }, { emoji: '❤️', userIds: ['owner'] }]);
  await request(endpoint, { method: 'PUT', body: { emoji: null } });
  await request(endpoint, { method: 'PUT', body: { emoji: null } });
  assert.deepEqual((await getMessage()).reactions, [{ emoji: '👍', userIds: ['other'] }]);
  assert.equal(Object.keys(models.Message.rows[0].reactionVotes).length, 1);
  assert.equal((await request('/conversations/thread/messages/foreign/reaction', { method: 'PUT', body: { emoji: '👍' } })).status, 404);
  assert.equal((await request(endpoint, { method: 'PUT', body: { emoji: '💣' } })).status, 400);
  assert.equal((await request(endpoint, { method: 'PUT', body: {} })).status, 400);
});

test('messages, replies, reactions and reads enforce membership; reactions enforce blocks, accounts and rate limits', async t => {
  const { request, models } = await fixture(t, { messages: [text('message')] });
  const endpoint = '/conversations/thread/messages/message/reaction';
  for (const as of [null, 'outsider']) {
    const status = as ? 404 : 401;
    assert.equal((await request('/conversations/thread/messages', { as })).status, status);
    assert.equal((await request('/conversations/thread/messages', { as, method: 'POST', body: { type: 'text', content: 'No access', replyToId: 'message' } })).status, status);
    assert.equal((await request(endpoint, { as, method: 'PUT', body: { emoji: '👍' } })).status, status);
    assert.equal((await request('/conversations/thread/read', { as, method: 'POST', body: { messageId: 'message' } })).status, status);
  }
  models.User.rows[0].accountStatus = 'limited';
  assert.equal((await request(endpoint, { method: 'PUT', body: { emoji: '👍' } })).status, 403);
  models.User.rows[0].accountStatus = 'active';
  models.UserBlock.rows.push({ blockerId: 'owner', blockedUserId: 'other' });
  assert.equal((await request(endpoint, { method: 'PUT', body: { emoji: '👍' } })).status, 400);
  models.UserBlock.rows[0] = { blockerId: 'other', blockedUserId: 'owner' };
  assert.equal((await request(endpoint, { method: 'PUT', body: { emoji: '👍' } })).status, 403);
  models.UserBlock.rows.length = 0;
  models.User.rows[1].accountStatus = 'suspended';
  assert.equal((await request(endpoint, { method: 'PUT', body: { emoji: '👍' } })).status, 403);
  models.User.rows[1].accountStatus = 'active';
  for (let index = 0; index < 60; index += 1) assert.equal((await request(endpoint, { method: 'PUT', body: { emoji: '👍' } })).status, 200);
  assert.equal((await request(endpoint, { method: 'PUT', body: { emoji: '👍' } })).status, 429);
});

test('read boundaries stay private and monotonic, exclude own messages, and preserve a same-millisecond arrival', async t => {
  const { request, models } = await fixture(t, { messages: [text('first'), text('own', 'owner'), text('boundary'), text('after'), text('foreign', 'other', { conversationId: 'elsewhere' })] });
  const unread = async (as = 'owner') => (await request('/conversations', { as })).data.find(item => item.id === 'thread').unreadCount;
  assert.equal(await unread(), 3);
  assert.equal(await unread('other'), 1);
  const loaded = await request('/conversations/thread/messages');
  assert.deepEqual(loaded.data.map(item => item.id), ['first', 'own', 'boundary', 'after']);
  assert.equal(await unread(), 3, 'fetching a background thread must not mark it read');
  for (const messageId of ['foreign', 'future']) assert.equal((await request('/conversations/thread/read', { method: 'POST', body: { messageId } })).status, 404);
  assert.equal((await request('/conversations/thread/read', { method: 'POST', body: { messageId: { $ne: '' } } })).status, 400);
  for (const messageIds of [[], ['boundary', 'first'], ['boundary', {}], new Array(501).fill('boundary')]) {
    assert.equal((await request('/conversations/thread/read', { method: 'POST', body: { messageId: 'boundary', messageIds } })).status, 400);
  }
  assert.equal((await request('/conversations/thread/read', { method: 'POST', body: { messageId: 'boundary', messageIds: ['foreign', 'boundary'] } })).status, 404);
  assert.equal(await unread(), 3, 'a mixed foreign/own ID list must not partially acknowledge messages');
  const originalUpdate = models.Message.updateMany;
  let injected = false;
  models.Message.updateMany = async (query, update) => {
    if (!injected) { injected = true; await models.Message.create(text('arrived-during-read', 'other', { _id: '000000000000000000000000' })); }
    return originalUpdate(query, update);
  };
  const read = await request('/conversations/thread/read', { method: 'POST', body: { messageId: 'boundary', messageIds: ['first', 'own', 'boundary'], userId: 'other', createdAt: Date.now() + 999999 } });
  assert.equal(read.status, 200);
  assert.equal(read.data.unreadCount, 2);
  assert.equal(await unread('other'), 1);
  assert.deepEqual(models.Message.rows.find(item => item.id === 'boundary').readBy, ['owner']);
  assert.equal(models.Message.rows.find(item => item.id === 'after').readBy, undefined);
  assert.equal(models.Message.rows.find(item => item.id === 'arrived-during-read').readBy, undefined);
  await Promise.all([
    request('/conversations/thread/read', { method: 'POST', body: { messageId: 'arrived-during-read', messageIds: ['after', 'arrived-during-read'] } }),
    request('/conversations/thread/read', { method: 'POST', body: { messageId: 'first' } }),
  ]);
  assert.equal(await unread(), 0);
  assert.equal(await unread('other'), 1);
  const serialized = JSON.stringify((await request('/conversations/thread/messages', { as: 'other' })).data);
  assert.ok(!serialized.includes('readBy'));
  assert.ok(!serialized.includes('reactionVotes'));
});

test('reaction socket updates reach verified members only and strip private read state', async t => {
  const { request, models, tokens, url } = await fixture(t, { messages: [text('message', 'other', { readBy: ['owner'] })] });
  const sockets = Object.fromEntries(['owner', 'other', 'outsider'].map(id => [id, connectSocket(url, { auth: { token: tokens[id] }, transports: ['websocket'], reconnection: false })]));
  t.after(() => Object.values(sockets).forEach(socket => socket.close()));
  await Promise.all(Object.values(sockets).map(socket => event(socket, 'connect')));
  const outsiderUpdates = [];
  sockets.outsider.on('message_updated', message => outsiderUpdates.push(message));
  sockets.outsider.emit('join_room', 'owner');
  const ownerUpdate = event(sockets.owner, 'message_updated');
  const otherUpdate = event(sockets.other, 'message_updated');
  const response = await request('/conversations/thread/messages/message/reaction', { method: 'PUT', body: { emoji: '🎉' } });
  assert.equal(response.status, 200);
  for (const update of [await ownerUpdate, await otherUpdate]) {
    assert.deepEqual(update[0].reactions, [{ emoji: '🎉', userIds: ['owner'] }]);
    assert.equal(update[0].readBy, undefined);
    assert.equal(update[0].reactionVotes, undefined);
    assert.equal(update[0].reactionVersion, 1);
  }
  assert.deepEqual(outsiderUpdates, []);
  const disconnected = event(sockets.other, 'disconnect');
  models.User.rows[1].passwordChangedAt = Date.now() + 1;
  assert.equal((await request('/conversations/thread/messages/message/reaction', { method: 'PUT', body: { emoji: '🙏' } })).status, 200);
  await disconnected;
  assert.equal(sockets.other.connected, false);
});

test('Mongoose stores reaction votes as validated maps and the client format never includes internal fields', async () => {
  const application = createApplication({ config: { NODE_ENV: 'test', JWT_SECRET: SECRET } });
  const message = new application.models.Message({ id: 'model-message', type: 'text', content: 'Hello', reactionVotes: { [reactionKey('member')]: { userId: 'member', emoji: '👀' } }, readBy: ['member'] });
  assert.equal(message.validateSync(), undefined);
  assert.deepEqual(publicMessage(message).reactions, [{ emoji: '👀', userIds: ['member'] }]);
  assert.equal(publicMessage(message).readBy, undefined);
  assert.equal(publicMessage(message).reactionVotes, undefined);
  const invalid = new application.models.Message({ reactionVotes: { [reactionKey('member')]: { userId: 'member', emoji: 'invalid' } } });
  assert.ok(invalid.validateSync());
  await new Promise(resolve => application.io.close(resolve));
});
